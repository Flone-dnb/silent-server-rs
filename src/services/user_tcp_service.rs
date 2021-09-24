// External.
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};
use bytevec::{ByteDecodable, ByteEncodable};
use chrono::prelude::*;
use num_bigint::{BigUint, ToBigUint};
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use num_traits::cast::FromPrimitive;
use num_traits::cast::ToPrimitive;
use rand::Rng;

// Std.
use std::collections::LinkedList;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
use crate::config_io::ServerConfig;
use crate::config_io::ServerLogger;
use crate::global_params::*;
use crate::services::net_service::*;

#[derive(PartialEq, Copy, Clone)]
pub enum UserState {
    NotConnected,
    Connected,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
enum ConnectServerAnswer {
    Ok = 0,
    WrongVersion = 1,
    UsernameTaken = 2,
    WrongPassword = 3,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum ServerMessageTcp {
    UserConnected = 0,
    UserDisconnected = 1,
    UserMessage = 2,
    UserEntersRoom = 3,
    KeepAliveCheck = 4,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum ClientMessage {
    UserMessage = 0,
    EnterRoom = 1,
    KeepAliveCheck = 2,
}

pub enum IoResult {
    Ok(usize),
    WouldBlock,
    Fin,
    Err(String),
}

pub enum HandleStateResult {
    Ok,
    IoErr(IoResult),
    HandleStateErr(String),
    UserNotConnectedReason(String),
}

pub struct UserTcpService {
    pub user_state: UserState,
    pub last_keep_alive_check_time: DateTime<Local>,
    pub sent_keep_alive: bool,
    pub sent_keep_alive_time: DateTime<Local>,
}

impl UserTcpService {
    pub fn new() -> Self {
        UserTcpService {
            user_state: UserState::NotConnected,
            last_keep_alive_check_time: Local::now(),
            sent_keep_alive: false,
            sent_keep_alive_time: Local::now(),
        }
    }
    pub fn read_from_socket(&self, user_info: &mut UserInfo, buf: &mut [u8]) -> IoResult {
        if buf.is_empty() {
            return IoResult::Err(format!(
                "An error occurred at UserTcpService::read_from_socket_tcp(), error: passed 'buf' has 0 len at [{}, {}]", file!(), line!()
            ));
        }

        let _io_guard = user_info.tcp_io_mutex.lock().unwrap();
        // (non-blocking)
        match user_info.tcp_socket.read(buf) {
            Ok(0) => return IoResult::Fin,
            Ok(n) => {
                if n != buf.len() {
                    return IoResult::Err(format!(
                        "UserNetService::read_from_socket_tcp::read() failed, error: socket ({}) failed to read 'buf' size (got: {}, expected: {}) at [{}, {}]",
                        user_info.tcp_addr, n, buf.len(), file!(), line!()
                    ));
                }

                return IoResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return IoResult::WouldBlock;
            }
            Err(e) => {
                return IoResult::Err(format!(
                    "UserNetService::read_from_socket_tcp::read() failed, error: socket ({}) failed to read with error {} at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
            }
        };
    }
    pub fn write_to_socket(&self, user_info: &mut UserInfo, buf: &mut [u8]) -> IoResult {
        let _io_guard = user_info.tcp_io_mutex.lock().unwrap();
        // (non-blocking)
        match user_info.tcp_socket.write(buf) {
            Ok(0) => {
                return IoResult::Fin;
            }
            Ok(n) => {
                if n != buf.len() {
                    return IoResult::Err(format!(
                        "socket ({}) try_write() failed, error: failed to write 'buf' size (got: {}, expected: {})",
                        user_info.tcp_addr, n, buf.len()
                    ));
                }

                return IoResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return IoResult::WouldBlock;
            }
            Err(e) => {
                return IoResult::Err(format!(
                    "socket ({}) try_write() failed, error: {}",
                    user_info.tcp_addr, e
                ));
            }
        };
    }
    pub fn handle_user_state(
        &mut self,
        current_u16: u16,
        user_info: &mut UserInfo,
        server_config: &ServerConfig,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: &Arc<Mutex<Option<Vec<BannedAddress>>>>,
        user_enters_leaves_server_lock: &Arc<Mutex<()>>,
        logger: &Arc<Mutex<ServerLogger>>,
        server_password: &str,
    ) -> HandleStateResult {
        match self.user_state {
            UserState::NotConnected => self.handle_not_connected_state(
                current_u16,
                user_info,
                server_config,
                users,
                banned_addrs,
                user_enters_leaves_server_lock,
                logger,
                server_password,
            ),
            UserState::Connected => {
                let message_id = ClientMessage::from_u16(current_u16);
                if message_id.is_none() {
                    return HandleStateResult::HandleStateErr(format!(
                        "ClientMessage::from() failed on value {} at [{}, {}]",
                        current_u16,
                        file!(),
                        line!()
                    ));
                }
                let message_id = message_id.unwrap();

                match message_id {
                    ClientMessage::UserMessage => self.handle_user_message(user_info, users),
                    ClientMessage::EnterRoom => self.handle_user_enters_room(user_info, users),
                    ClientMessage::KeepAliveCheck => HandleStateResult::Ok,
                }
            }
        }
    }
    pub fn establish_secure_connection(&self, user_info: &mut UserInfo) -> Result<Vec<u8>, ()> {
        let key_pg = [
            (100005107, 13),
            (100008323, 7),
            (100000127, 13),
            (100008023, 11),
            (100008803, 11),
        ];

        let mut rng = rand::thread_rng();
        let rnd_index = rng.gen_range(0..key_pg.len());

        let p = key_pg[rnd_index].0;
        let g = key_pg[rnd_index].1;

        // Send 2 int values: p, g values.

        let p_buf = u32::encode::<u32>(&p);
        let g_buf = u32::encode::<u32>(&g);

        if let Err(e) = p_buf {
            println!("An error occurred while trying to establish a secure connection, error: {} at [{}, {}]", e, file!(), line!());
            return Err(());
        }
        let mut p_buf = p_buf.unwrap();

        if let Err(e) = g_buf {
            println!("An error occurred while trying to establish a secure connection, error: {} at [{}, {}]", e, file!(), line!());
            return Err(());
        }
        let mut g_buf = g_buf.unwrap();

        p_buf.append(&mut g_buf);

        // Send p and g values.
        loop {
            match self.write_to_socket(user_info, &mut p_buf) {
                IoResult::Fin => {
                    println!(
                        "Received FIN while establishing a secure connection with {} at [{}, {}]",
                        user_info.tcp_addr,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(msg) => {
                    println!(
                        "{} at [{}, {}] (socket: {})",
                        msg,
                        file!(),
                        line!(),
                        user_info.tcp_addr
                    );
                    return Err(());
                }
                IoResult::Ok(_) => {
                    break;
                }
            }
        }

        // Generate secret key 'a'.

        let a = rng.gen_range(1000000u64..10000000000000000000u64);

        // Generate open key 'A'.

        let g_big = g.to_biguint().unwrap();
        let a_big = a.to_biguint().unwrap();
        let p_big = p.to_biguint().unwrap();
        let a_open = g_big.modpow(&a_big, &p_big);

        // Prepare to send open key 'A'.

        let mut a_open_buf = a_open.to_bytes_le();

        // Send open key 'A' size.
        let a_open_len = a_open_buf.len() as u64;
        let a_open_len_buf = u64::encode::<u64>(&a_open_len);
        if let Err(e) = a_open_len_buf {
            println!("An error occurred while trying to establish a secure connection, error: {} at [{}, {}]", e, file!(), line!());
            return Err(());
        }
        let mut a_open_len_buf = a_open_len_buf.unwrap();
        loop {
            match self.write_to_socket(user_info, &mut a_open_len_buf) {
                IoResult::Fin => {
                    println!(
                        "Received FIN while establishing a secure connection with {} at [{}, {}]",
                        user_info.tcp_addr,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(msg) => {
                    println!(
                        "{} at [{}, {}] (socket: {})",
                        msg,
                        file!(),
                        line!(),
                        user_info.tcp_addr
                    );
                    return Err(());
                }
                IoResult::Ok(_) => {
                    break;
                }
            }
        }

        // Send open key 'A'.
        loop {
            match self.write_to_socket(user_info, &mut a_open_buf) {
                IoResult::Fin => {
                    println!(
                        "Received FIN while establishing a secure connection with {} at [{}, {}]",
                        user_info.tcp_addr,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(msg) => {
                    println!(
                        "{} at [{}, {}] (socket: {})",
                        msg,
                        file!(),
                        line!(),
                        user_info.tcp_addr
                    );
                    return Err(());
                }
                IoResult::Ok(_) => {
                    break;
                }
            }
        }

        // Receive open key 'B' size.

        let mut b_open_len_buf = vec![0u8; std::mem::size_of::<u64>()];
        loop {
            match self.read_from_socket(user_info, &mut b_open_len_buf) {
                IoResult::Fin => {
                    println!(
                        "Received FIN while establishing a secure connection with {} at [{}, {}]",
                        user_info.tcp_addr,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(msg) => {
                    println!(
                        "{} at [{}, {}] (socket: {})",
                        msg,
                        file!(),
                        line!(),
                        user_info.tcp_addr
                    );
                    return Err(());
                }
                IoResult::Ok(_) => {
                    break;
                }
            }
        }

        // Receive open key 'B'.
        let b_open_len = u64::decode::<u64>(&b_open_len_buf);
        if let Err(e) = b_open_len {
            println!(
                "u64::decode::<u64>() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return Err(());
        }
        let b_open_len = b_open_len.unwrap();
        let mut b_open_buf = vec![0u8; b_open_len as usize];

        loop {
            match self.read_from_socket(user_info, &mut b_open_buf) {
                IoResult::Fin => {
                    println!(
                        "Received FIN while establishing a secure connection with {} at [{}, {}]",
                        user_info.tcp_addr,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(msg) => {
                    println!(
                        "{} at [{}, {}] (socket: {})",
                        msg,
                        file!(),
                        line!(),
                        user_info.tcp_addr
                    );
                    return Err(());
                }
                IoResult::Ok(_) => {
                    break;
                }
            }
        }

        let b_open_big = BigUint::from_bytes_le(&b_open_buf);

        // Calculate the secret key.

        let secret_key = b_open_big.modpow(&a_big, &p_big);

        let mut secret_key_str = secret_key.to_str_radix(10);

        if secret_key_str.len() < 16 {
            loop {
                secret_key_str += &secret_key_str.clone();

                if secret_key_str.len() >= 16 {
                    break;
                }
            }
        }

        Ok(Vec::from(&secret_key_str[0..16]))
    }
    fn handle_not_connected_state(
        &mut self,
        current_u16: u16,
        user_info: &mut UserInfo,
        server_config: &ServerConfig,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: &Arc<Mutex<Option<Vec<BannedAddress>>>>,
        user_enters_leaves_server_lock: &Arc<Mutex<()>>,
        logger: &Arc<Mutex<ServerLogger>>,
        server_password: &str,
    ) -> HandleStateResult {
        if current_u16 as u32 > MAX_VERSION_STRING_LENGTH {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (NotConnected) failed, reason: version str len ({}) > {} at [{}, {}]",
                user_info.tcp_addr, current_u16, MAX_VERSION_STRING_LENGTH, file!(), line!()
            ));
        }

        // Get version string.
        let mut client_version_buf = vec![0u8; current_u16 as usize];
        let mut _client_version_string = String::new();
        loop {
            match self.read_from_socket(user_info, &mut client_version_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    let res = std::str::from_utf8(&client_version_buf);
                    if let Err(e) = res {
                        return HandleStateResult::HandleStateErr(format!(
                            "std::str::from_utf8() failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }

                    _client_version_string = String::from(res.unwrap());

                    break;
                }
                res => return HandleStateResult::IoErr(res),
            };
        }

        // Get name string size.
        let mut client_name_size_buf = vec![0u8; std::mem::size_of::<u16>()];
        let mut _client_name_size = 0u16;
        loop {
            match self.read_from_socket(user_info, &mut client_name_size_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&client_name_size_buf);
                    if let Err(e) = res {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::decode::<u16>() failed, error: socket ({}) failed to decode (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }

                    _client_name_size = res.unwrap();

                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }
        if _client_name_size as usize > MAX_USERNAME_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (NotConnected) failed because the received username len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, _client_name_size, MAX_USERNAME_SIZE, file!(), line!()
            ));
        }

        // Get name string.
        let mut client_name_buf = vec![0u8; _client_name_size as usize];
        let mut _client_name_string = String::new();
        loop {
            match self.read_from_socket(user_info, &mut client_name_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    let res = std::str::from_utf8(&client_name_buf);
                    if let Err(e) = res {
                        return HandleStateResult::HandleStateErr(format!(
                            "std::str::from_utf8() failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }

                    _client_name_string = String::from(res.unwrap());

                    break;
                }
                res => return HandleStateResult::IoErr(res),
            };
        }

        // Get encrypted password string size.
        let mut encrypted_password_size_buf = vec![0u8; std::mem::size_of::<u16>()];
        let mut _encrypted_password_size = 0u16;
        loop {
            match self.read_from_socket(user_info, &mut encrypted_password_size_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&encrypted_password_size_buf);
                    if let Err(e) = res {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::decode::<u16>() failed, error: socket ({}) failed to decode (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }

                    _encrypted_password_size = res.unwrap();

                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        let mut _password = String::new();
        if _encrypted_password_size != 0 {
            if _encrypted_password_size as usize > MAX_PASSWORD_SIZE {
                return HandleStateResult::HandleStateErr(format!(
                    "An error occurred, error: socket ({}) on state (NotConnected) failed because the received password len is too big ({}) while the maximum is {}, at [{}, {}]",
                    user_info.tcp_addr, _encrypted_password_size, MAX_PASSWORD_SIZE, file!(), line!()
                ));
            }

            // Get encrypted password string.
            let mut encrypted_password_buf = vec![0u8; _encrypted_password_size as usize];
            loop {
                match self.read_from_socket(user_info, &mut encrypted_password_buf) {
                    IoResult::WouldBlock => {
                        thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                        continue;
                    }
                    IoResult::Ok(_bytes) => {
                        // Decrypt password.
                        type Aes128Ecb = Ecb<Aes128, Pkcs7>;
                        let cipher =
                            Aes128Ecb::new_from_slices(&user_info.secret_key, Default::default())
                                .unwrap();
                        let decrypted_password = cipher.decrypt_vec(&encrypted_password_buf);
                        if let Err(e) = decrypted_password {
                            return HandleStateResult::HandleStateErr(format!(
                                "cipher.decrypt_vec() failed, error: {} at [{}, {}]",
                                e,
                                file!(),
                                line!()
                            ));
                        }
                        let decrypted_password = decrypted_password.unwrap();
                        let password = std::str::from_utf8(&decrypted_password);
                        if let Err(e) = password {
                            return HandleStateResult::HandleStateErr(format!(
                                "std::str::from_utf8() failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                                user_info.tcp_addr, e, file!(), line!()
                            ));
                        }
                        _password = String::from(password.unwrap());

                        break;
                    }
                    res => return HandleStateResult::IoErr(res),
                };
            }
        }

        let mut answer = ConnectServerAnswer::Ok;

        {
            let _guard = user_enters_leaves_server_lock.lock().unwrap();

            if !server_password.is_empty() {
                // Check if the password is correct.
                if server_password != _password {
                    answer = ConnectServerAnswer::WrongPassword;

                    let mut banned_addrs_guard = banned_addrs.lock().unwrap();
                    // Find addr.
                    let addr_entry = banned_addrs_guard
                        .as_ref()
                        .unwrap()
                        .iter()
                        .position(|banned_item| banned_item.addr == user_info.tcp_addr.ip());

                    if addr_entry.is_none() {
                        // not found
                        // add it
                        banned_addrs_guard.as_mut().unwrap().push(BannedAddress {
                            banned_at: Local::now(),
                            addr: user_info.tcp_addr.ip(),
                        });
                    }
                }
            }

            // Check if the client version is supported.
            if &_client_version_string[..SUPPORTED_CLIENT_VERSION.len()] != SUPPORTED_CLIENT_VERSION
            {
                // Send error (wrong version).
                answer = ConnectServerAnswer::WrongVersion;
            }

            // Check if the name is unique.
            let mut name_is_unique = true;
            {
                let users_guard = users.lock().unwrap();
                for user in users_guard.iter() {
                    if user.username == _client_name_string {
                        name_is_unique = false;
                        break;
                    }
                }
            }

            if !name_is_unique {
                // Send error (username taken).
                answer = ConnectServerAnswer::UsernameTaken;
            }

            // Send.
            let id = answer.to_u16();
            if id.is_none() {
                return HandleStateResult::HandleStateErr(format!(
                    "ToPrimitive::to_u16() failed, error: socket ({}) on state (NotConnected) failed at [{}, {}]",
                    user_info.tcp_addr,
                    file!(),
                    line!()
                ));
            }
            let answer_id = id.unwrap();
            let answer_buf = u16::encode::<u16>(&answer_id);
            if let Err(e) = answer_buf {
                return HandleStateResult::HandleStateErr(format!(
                    "u16::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed on 'answer_id' (error: {}) at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
            }
            let mut answer_buf = answer_buf.unwrap();
            loop {
                match self.write_to_socket(user_info, &mut answer_buf) {
                    IoResult::WouldBlock => {
                        thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                        continue;
                    }
                    IoResult::Ok(_bytes) => {
                        break;
                    }
                    res => return HandleStateResult::IoErr(res),
                }
            }

            if answer == ConnectServerAnswer::WrongVersion {
                // Also send correct version.
                // Write version string size.
                let supported_client_str_len = SUPPORTED_CLIENT_VERSION.len() as u16;
                let answer_buf = u16::encode::<u16>(&supported_client_str_len);
                if let Err(e) = answer_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "u16::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed on 'supported_client_str_len' (error: {}) at [{}, {}]",
                        user_info.tcp_addr, e, file!(), line!()
                    ));
                }
                let mut answer_buf = answer_buf.unwrap();
                loop {
                    match self.write_to_socket(user_info, &mut answer_buf) {
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Ok(_bytes) => {
                            break;
                        }
                        res => return HandleStateResult::IoErr(res),
                    }
                }

                let mut supported_client_str = Vec::from(SUPPORTED_CLIENT_VERSION.as_bytes());
                loop {
                    match self.write_to_socket(user_info, &mut supported_client_str) {
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Ok(_bytes) => {
                            break;
                        }
                        res => return HandleStateResult::IoErr(res),
                    }
                }
            }

            match answer {
                ConnectServerAnswer::Ok => {}
                ConnectServerAnswer::WrongVersion => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "socket ({}) on state (NotConnected) was not connected, reason: wrong client version, client version ({}) is not supported.",
                        user_info.tcp_addr, _client_version_string,
                    ));
                }
                ConnectServerAnswer::WrongPassword => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "socket ({}) on state (NotConnected) was not connected, reason: wrong password, received password ({}).",
                        user_info.tcp_addr, _password
                    ));
                }
                ConnectServerAnswer::UsernameTaken => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "socket ({}) on state (NotConnected) was not connected, reason: username {} is not unique.",
                        user_info.tcp_addr, _client_name_string,
                    ));
                }
            }

            let mut info_out_buf: Vec<u8> = Vec::new();

            // Send room count.
            let room_count = server_config.rooms.len() as u16;
            let room_count_buf = u16::encode::<u16>(&room_count);
            if let Err(e) = room_count_buf {
                return HandleStateResult::HandleStateErr(format!(
                    "u64::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
            }
            let mut room_count_buf = room_count_buf.unwrap();
            info_out_buf.append(&mut room_count_buf);

            // Send rooms.
            for room in server_config.rooms.iter() {
                // Room len.
                let room_len = room.room_name.len() as u8;
                let room_len_buf = u8::encode::<u8>(&room_len);
                if let Err(e) = room_len_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "u16::encode::<u8> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                        user_info.tcp_addr, e, file!(), line!()
                    ));
                }
                let mut room_len_buf = room_len_buf.unwrap();

                info_out_buf.append(&mut room_len_buf);

                // Room.
                let mut room_str = Vec::from(room.room_name.as_bytes());

                info_out_buf.append(&mut room_str);
            }

            // Send usernames of other users.
            {
                let users_guard = users.lock().unwrap();

                let users_count = users_guard.len() as u64;
                let users_count_buf = u64::encode::<u64>(&users_count);
                if let Err(e) = users_count_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "u64::encode::<u64> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                        user_info.tcp_addr, e, file!(), line!()
                    ));
                }
                let mut users_count_buf = users_count_buf.unwrap();
                info_out_buf.append(&mut users_count_buf);

                for user in users_guard.iter() {
                    // Username len.
                    let username_len = user.username.len() as u16;
                    let user_name_len_buf = u16::encode::<u16>(&username_len);
                    if let Err(e) = user_name_len_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }
                    let mut user_name_len_buf = user_name_len_buf.unwrap();

                    info_out_buf.append(&mut user_name_len_buf);

                    // Username.
                    let mut user_name_buf = Vec::from(user.username.as_bytes());

                    info_out_buf.append(&mut user_name_buf);

                    // Room len.
                    let room_len = user.room_name.len() as u8;
                    let room_len_buf = u8::encode::<u8>(&room_len);
                    if let Err(e) = room_len_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::encode::<u8> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }
                    let mut room_len_buf = room_len_buf.unwrap();

                    info_out_buf.append(&mut room_len_buf);

                    // Room.
                    let mut user_room = Vec::from(user.room_name.as_bytes());

                    info_out_buf.append(&mut user_room);

                    // Last ping.
                    let ping_buf = u16::encode::<u16>(&user.last_ping);
                    if let Err(e) = ping_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::encode::<u8> failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }
                    let mut ping_buf = ping_buf.unwrap();

                    info_out_buf.append(&mut ping_buf);
                }
            }

            loop {
                match self.write_to_socket(user_info, &mut info_out_buf) {
                    IoResult::WouldBlock => {
                        thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                        continue;
                    }
                    IoResult::Ok(_) => {
                        break;
                    }
                    res => return HandleStateResult::IoErr(res),
                }
            }

            // Tell others about this new user.
            // Data:
            // (u16): data ID = new user
            // (u16): username len
            // (size): username
            let mut newuser_info_out_buf: Vec<u8> = Vec::new();

            let data_id = ServerMessageTcp::UserConnected.to_u16();
            if data_id.is_none() {
                return HandleStateResult::HandleStateErr(format!(
                    "ToPrimitive::to_u16() failed, error: socket ({}) on state (NotConnected) at [{}, {}]",
                    user_info.tcp_addr, file!(), line!()
                ));
            }
            let data_id: u16 = data_id.unwrap();
            let data_id_buf = u16::encode::<u16>(&data_id);
            if let Err(e) = data_id_buf {
                return HandleStateResult::HandleStateErr(format!(
                    "u16::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed on 'data_id' (error: {}) at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
            }
            let mut data_id_buf = data_id_buf.unwrap();

            newuser_info_out_buf.append(&mut data_id_buf);
            newuser_info_out_buf.append(&mut client_name_size_buf);
            newuser_info_out_buf.append(&mut client_name_buf);

            // Send info about new user.
            {
                let mut users_guard = users.lock().unwrap();
                for user in users_guard.iter_mut() {
                    loop {
                        match self.write_to_socket(user, &mut newuser_info_out_buf) {
                            IoResult::WouldBlock => {
                                thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                                continue;
                            }
                            IoResult::Ok(_) => {
                                break;
                            }
                            res => return HandleStateResult::IoErr(res),
                        }
                    }
                }
            }

            // New connected user.
            user_info.username = _client_name_string;
            self.user_state = UserState::Connected;

            let mut _users_connected = 0;
            {
                let mut users_guard = users.lock().unwrap();
                let user_info_clone = user_info.clone();
                if let Err(msg) = user_info_clone {
                    return HandleStateResult::HandleStateErr(format!(
                        "{}, unable to clone user_info for socket ({}) AKA ({}) at [{}, {}]",
                        msg,
                        user_info.tcp_addr,
                        user_info.username,
                        file!(),
                        line!()
                    ));
                }
                users_guard.push_back(user_info_clone.unwrap());
                _users_connected = users_guard.len();
            }

            let mut logger_guard = logger.lock().unwrap();
            if let Err(e) = logger_guard.println_and_log(&format!(
                "New connection from ({:?}) AKA ({}) [connected users: {}].",
                user_info.tcp_addr, user_info.username, _users_connected
            )) {
                println!("{} at [{}, {}]", e, file!(), line!());
            }
        }

        HandleStateResult::Ok
    }
    fn handle_user_message(
        &self,
        user_info: &mut UserInfo,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> HandleStateResult {
        // (u16) - data ID (user message)
        // (u16) - username.len()
        // (size) - username
        // (u16) - message (encrypted).len()
        // (size) - message (encrypted)

        // use data ID = ServerMessage::UserMessage
        let data_id = ServerMessageTcp::UserMessage.to_u16();
        if data_id.is_none() {
            return HandleStateResult::HandleStateErr(format!(
                "ServerMessage::UserMessage.to_u16() failed at [{}, {}]",
                file!(),
                line!()
            ));
        }
        let data_id = data_id.unwrap();
        let data_id_buf = u16::encode::<u16>(&data_id);
        if let Err(e) = data_id_buf {
            return HandleStateResult::HandleStateErr(format!(
                "u16::encode::<u16>() failed on value {} (error: {}) at [{}, {}]",
                data_id,
                e,
                file!(),
                line!()
            ));
        }
        let mut data_id_buf = data_id_buf.unwrap();

        // Read username len.
        let mut username_len_buf: Vec<u8> = vec![0u8; std::mem::size_of::<u16>()];
        loop {
            match self.read_from_socket(user_info, &mut username_len_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }
        let username_len = u16::decode::<u16>(&username_len_buf);
        if let Err(e) = username_len {
            return HandleStateResult::HandleStateErr(format!(
                "u16::decode::<u16>() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let username_len = username_len.unwrap();
        if username_len as usize > MAX_USERNAME_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (Connected) failed because the received username len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, username_len, MAX_USERNAME_SIZE, file!(), line!()
            ));
        }

        // Read username.
        let mut username_buf: Vec<u8> = vec![0u8; username_len as usize];
        loop {
            match self.read_from_socket(user_info, &mut username_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        // Read encrypted message len.
        let mut encrypted_message_len_buf: Vec<u8> = vec![0u8; std::mem::size_of::<u16>()];
        loop {
            match self.read_from_socket(user_info, &mut encrypted_message_len_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }
        let encrypted_message_len = u16::decode::<u16>(&encrypted_message_len_buf);
        if let Err(e) = encrypted_message_len {
            return HandleStateResult::HandleStateErr(format!(
                "u16::decode::<u16>() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let encrypted_message_len = encrypted_message_len.unwrap();
        if encrypted_message_len as usize > MAX_MESSAGE_SIZE + 64 {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (Connected) failed because the received encrypted message len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, encrypted_message_len, MAX_MESSAGE_SIZE, file!(), line!()
            ));
        }

        // Read message.
        let mut encrypted_message_buf: Vec<u8> = vec![0u8; encrypted_message_len as usize];
        loop {
            match self.read_from_socket(user_info, &mut encrypted_message_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        // Check spam protection.
        let time_diff = Local::now() - user_info.last_text_message_sent;
        if time_diff.num_seconds() < SPAM_PROTECTION_SEC as i64 {
            // can't happen with the default client version
            return HandleStateResult::HandleStateErr(format!(
                "the user '{}' tried sending text messages too quick (which should not happen with the default client version) at [{}, {}]",
                user_info.username, file!(), line!()
            ));
        }

        user_info.last_text_message_sent = Local::now();

        // Decrypt user message.
        type Aes128Ecb = Ecb<Aes128, Pkcs7>;
        let cipher = Aes128Ecb::new_from_slices(&user_info.secret_key, Default::default()).unwrap();
        let decrypted_message = cipher.decrypt_vec(&encrypted_message_buf);
        if let Err(e) = decrypted_message {
            return HandleStateResult::HandleStateErr(format!(
                "cipher.decrypt_vec() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let user_message = decrypted_message.unwrap();

        // Combine all to one buffer.
        let mut out_buf: Vec<u8> = Vec::new();
        out_buf.append(&mut data_id_buf);
        out_buf.append(&mut username_len_buf);
        out_buf.append(&mut username_buf);

        // Send to all.
        {
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                if user.room_name == user_info.room_name {
                    let mut copy_buf = out_buf.clone();

                    // Encrypt with user key.
                    let cipher =
                        Aes128Ecb::new_from_slices(&user.secret_key, Default::default()).unwrap();
                    let mut encrypted_message = cipher.encrypt_vec(&user_message);

                    // Prepare message len buffer.
                    let encrypted_message_len = encrypted_message.len() as u16;
                    let encrypted_message_len_buf = u16::encode::<u16>(&encrypted_message_len);
                    if let Err(e) = encrypted_message_len_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::encode::<u16>() failed, error: {} at [{}, {}]",
                            e,
                            file!(),
                            line!()
                        ));
                    }
                    let mut encrypted_message_len_buf = encrypted_message_len_buf.unwrap();

                    copy_buf.append(&mut encrypted_message_len_buf);
                    copy_buf.append(&mut encrypted_message);

                    match self.write_to_socket(user, &mut copy_buf) {
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Ok(_) => {}
                        res => return HandleStateResult::IoErr(res),
                    }
                }
            }
        }

        HandleStateResult::Ok
    }

    fn handle_user_enters_room(
        &self,
        user_info: &mut UserInfo,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> HandleStateResult {
        // (u16) - data ID (enters room)
        // (u16) - username.len()
        // (size) - username
        // (u8) - room name.len()
        // (size) - room name

        // use data ID = ServerMessage::UserEntersRoom
        let data_id = ServerMessageTcp::UserEntersRoom.to_u16();
        if data_id.is_none() {
            return HandleStateResult::HandleStateErr(format!(
                "ServerMessage::UserEntersRoom.to_u16() failed at [{}, {}]",
                file!(),
                line!()
            ));
        }
        let data_id = data_id.unwrap();
        let data_id_buf = u16::encode::<u16>(&data_id);
        if let Err(e) = data_id_buf {
            return HandleStateResult::HandleStateErr(format!(
                "u16::encode::<u16>() failed on value {} (error: {}) at [{}, {}]",
                data_id,
                e,
                file!(),
                line!()
            ));
        }
        let mut data_id_buf = data_id_buf.unwrap();

        // Read username len.
        let mut username_len_buf: Vec<u8> = vec![0u8; std::mem::size_of::<u16>()];
        loop {
            match self.read_from_socket(user_info, &mut username_len_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }
        let username_len = u16::decode::<u16>(&username_len_buf);
        if let Err(e) = username_len {
            return HandleStateResult::HandleStateErr(format!(
                "u16::decode::<u16>() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let username_len = username_len.unwrap();
        if username_len as usize > MAX_USERNAME_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (Connected) failed because the received username len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, username_len, MAX_USERNAME_SIZE, file!(), line!()
            ));
        }

        // Read username.
        let mut username_buf: Vec<u8> = vec![0u8; username_len as usize];
        loop {
            match self.read_from_socket(user_info, &mut username_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        // Read roomname len.
        let mut room_name_len_buf: Vec<u8> = vec![0u8; std::mem::size_of::<u8>()];
        loop {
            match self.read_from_socket(user_info, &mut room_name_len_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }
        let room_name_len = u8::decode::<u8>(&room_name_len_buf);
        if let Err(e) = room_name_len {
            return HandleStateResult::HandleStateErr(format!(
                "u16::decode::<u8>() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let room_name_len = room_name_len.unwrap();
        if room_name_len as usize > MAX_MESSAGE_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (Connected) failed because the received room name len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, room_name_len, MAX_MESSAGE_SIZE, file!(), line!()
            ));
        }

        // Read room name.
        let mut room_name_buf: Vec<u8> = vec![0u8; room_name_len as usize];
        loop {
            match self.read_from_socket(user_info, &mut room_name_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        // Check spam protection.
        let time_diff = Local::now() - user_info.last_time_entered_room;
        if time_diff.num_seconds() < SPAM_PROTECTION_SEC as i64 {
            // can't happen with the default client version
            return HandleStateResult::HandleStateErr(format!(
                "the user '{}' tried moving from rooms too quick (which should not happen with the default client version) at [{}, {}]",
                user_info.username, file!(), line!()
            ));
        }

        user_info.last_time_entered_room = Local::now();

        let room_name = String::from_utf8(room_name_buf.clone());
        if let Err(e) = room_name {
            return HandleStateResult::HandleStateErr(format!(
                "String::from_utf8() failed, error: socket ({}) on state (Connected) failed, reason: ({}), at [{}, {}]",
                user_info.tcp_addr, e, file!(), line!()
            ));
        }
        let room_name = room_name.unwrap();
        {
            // change room for this user
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                if user.username == user_info.username {
                    user.room_name = room_name.clone();
                    break;
                }
            }
        }
        user_info.room_name = room_name;

        // Combine all to one buffer.
        let mut out_buf: Vec<u8> = Vec::new();
        out_buf.append(&mut data_id_buf);
        out_buf.append(&mut username_len_buf);
        out_buf.append(&mut username_buf);
        out_buf.append(&mut room_name_len_buf);
        out_buf.append(&mut room_name_buf);

        // Send to all.
        {
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                match self.write_to_socket(user, &mut out_buf) {
                    IoResult::WouldBlock => {
                        thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                        continue;
                    }
                    IoResult::Ok(_) => {}
                    res => return HandleStateResult::IoErr(res),
                }
            }
        }

        HandleStateResult::Ok
    }

    pub fn send_disconnected_notice(
        &mut self,
        user_info: &mut UserInfo,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> HandleStateResult {
        // Tell others about disconnected user.
        // Data:
        // (u16): data ID = user disconnected.
        // (u16): username len.
        // (size): username.
        let mut user_disconnected_info_out_buf: Vec<u8> = Vec::new();

        // Create data_id buffer.
        let data_id = ServerMessageTcp::UserDisconnected.to_u16();
        if data_id.is_none() {
            return HandleStateResult::HandleStateErr(format!(
                "ToPrimitive::to_u16() failed, error: socket ({}) at [{}, {}]",
                user_info.tcp_addr,
                file!(),
                line!()
            ));
        }
        let data_id: u16 = data_id.unwrap();
        let data_id_buf = u16::encode::<u16>(&data_id);
        if let Err(e) = data_id_buf {
            return HandleStateResult::HandleStateErr(format!(
                "u16::encode::<u16> failed, error: socket ({}) failed on 'data_id' (error: {}) at [{}, {}]",
                user_info.tcp_addr, e, file!(), line!()
            ));
        }
        let mut data_id_buf = data_id_buf.unwrap();

        // Create username len buffer.
        let username_len = user_info.username.len() as u16;
        let username_len_buf = u16::encode::<u16>(&username_len);
        if let Err(e) = username_len_buf {
            return HandleStateResult::HandleStateErr(format!(
                "u16::encode::<u16> failed, error: socket ({}) failed on 'username_len' (error: {}) at [{}, {}]",
                user_info.tcp_addr, e, file!(), line!()
            ));
        }
        let mut username_len_buf = username_len_buf.unwrap();

        // Create username buffer.
        let mut username_buf: Vec<u8> = Vec::from(user_info.username.as_bytes());

        user_disconnected_info_out_buf.append(&mut data_id_buf);
        user_disconnected_info_out_buf.append(&mut username_len_buf);
        user_disconnected_info_out_buf.append(&mut username_buf);

        // Send info about new user.
        {
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                loop {
                    match self.write_to_socket(user, &mut user_disconnected_info_out_buf) {
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Ok(_) => {
                            break;
                        }
                        res => return HandleStateResult::IoErr(res),
                    }
                }
            }
        }

        HandleStateResult::Ok
    }
}
