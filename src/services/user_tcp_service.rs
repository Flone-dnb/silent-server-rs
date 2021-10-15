// External.
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::prelude::*;
use num_bigint::{BigUint, RandomBits};
use rand::{Rng, RngCore};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Std.
use std::collections::LinkedList;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
use super::tcp_packets::*;
use crate::config_io::ServerConfig;
use crate::config_io::ServerLogger;
use crate::global_params::*;
use crate::services::net_service::*;

const A_B_BITS: u64 = 2048;

#[derive(PartialEq, Copy, Clone)]
pub enum UserState {
    NotConnected,
    Connected,
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
    pub fn handle_keep_alive_check(&mut self, user_info: &mut UserInfo) -> Result<(), ()> {
        let time_diff = Local::now() - self.last_keep_alive_check_time;
        if time_diff.num_seconds() > INTERVAL_KEEP_ALIVE_CHECK_SEC as i64 {
            if self.sent_keep_alive {
                // Already did that.
                let time_diff = Local::now() - self.sent_keep_alive_time;
                if time_diff.num_seconds() > TIME_TO_ANSWER_TO_KEEP_ALIVE_SEC as i64 {
                    // no answer was received
                    return Err(()); // close connection
                }
            } else {
                // Serialize packet.
                let packet = ServerTcpMessage::KeepAliveCheck;

                let binary_packet = bincode::serialize(&packet);
                if let Err(e) = binary_packet {
                    println!(
                        "bincode::serialize failed, error: {}, at [{}, {}].",
                        e,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                let binary_packet = binary_packet.unwrap();

                // Encrypt with user key.
                let mut rng = rand::thread_rng();
                let mut iv = vec![0u8; IV_LENGTH];
                rng.fill_bytes(&mut iv);
                let cipher = Aes256Cbc::new_from_slices(&user_info.secret_key, &iv).unwrap();
                let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

                // Prepare message len buffer.
                let encrypted_message_len = (encrypted_packet.len() + IV_LENGTH) as u16;
                let encrypted_message_len_buf = bincode::serialize(&encrypted_message_len);
                if let Err(e) = encrypted_message_len_buf {
                    println!(
                        "bincode::serialize failed, error: {} at [{}, {}].",
                        e,
                        file!(),
                        line!()
                    );
                    return Err(());
                }
                let mut encrypted_message_len_buf = encrypted_message_len_buf.unwrap();

                encrypted_message_len_buf.append(&mut iv);
                encrypted_message_len_buf.append(&mut encrypted_packet);

                loop {
                    match self.write_to_socket(user_info, &mut encrypted_message_len_buf) {
                        IoResult::Fin => {
                            println!("FIN from user {} in keep-alive check.", &user_info.username,);
                            return Err(());
                        }
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Err(msg) => {
                            println!("{} at [{}, {}]", msg, file!(), line!());
                            return Err(());
                        }
                        IoResult::Ok(_) => break,
                    }
                }

                self.sent_keep_alive = true;
                self.sent_keep_alive_time = Local::now();
            }
        }

        Ok(())
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
        data_size: u16,
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
                data_size,
                user_info,
                server_config,
                users,
                banned_addrs,
                user_enters_leaves_server_lock,
                logger,
                server_password,
            ),
            UserState::Connected => {
                if data_size > TCP_PACKET_MAX_SIZE {
                    return HandleStateResult::HandleStateErr(format!(
                "The received data size ({}) exceeds the limit ({}) for socket ({} AKA {}) on state: connected, at [{}, {}]",
                data_size, TCP_PACKET_MAX_SIZE, user_info.tcp_addr, user_info.username, file!(), line!()
            ));
                }

                // Receive encrypted packet.
                let mut encrypted_packet = vec![0u8; data_size as usize];
                loop {
                    match self.read_from_socket(user_info, &mut encrypted_packet) {
                        IoResult::WouldBlock => {
                            thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                            continue;
                        }
                        IoResult::Ok(_bytes) => {
                            break;
                        }
                        res => return HandleStateResult::IoErr(res),
                    };
                }

                // Get IV.
                if encrypted_packet.len() < IV_LENGTH {
                    return HandleStateResult::HandleStateErr(format!(
                        "received data is too small, at [{}, {}].",
                        file!(),
                        line!()
                    ));
                }
                let iv = &encrypted_packet[..IV_LENGTH].to_vec();
                encrypted_packet = encrypted_packet[IV_LENGTH..].to_vec();

                // Decrypt packet.
                let cipher = Aes256Cbc::new_from_slices(&user_info.secret_key, &iv).unwrap();
                let decrypted_packet = cipher.decrypt_vec(&encrypted_packet);
                if let Err(e) = decrypted_packet {
                    return HandleStateResult::HandleStateErr(format!(
                        "An error occurred while decrypting a packet, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    ));
                }
                let decrypted_packet = decrypted_packet.unwrap();

                // Deserialize packet.
                let user_packet = bincode::deserialize::<ClientTcpMessage>(&decrypted_packet);
                if let Err(e) = user_packet {
                    return HandleStateResult::HandleStateErr(format!(
                        "An error occurred while deserializing a packet, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    ));
                }
                let user_packet = user_packet.unwrap();

                match user_packet {
                    ClientTcpMessage::UserMessage { message } => {
                        self.handle_user_message(user_info, message, users);
                        HandleStateResult::Ok
                    }
                    ClientTcpMessage::KeepAliveCheck => HandleStateResult::Ok,
                    ClientTcpMessage::UserEnterRoom { room_name } => {
                        self.handle_user_enters_room(user_info, server_config, room_name, users);
                        HandleStateResult::Ok
                    }
                }
            }
        }
    }
    pub fn establish_secure_connection(&self, user_info: &mut UserInfo) -> Result<Vec<u8>, ()> {
        // taken from https://www.rfc-editor.org/rfc/rfc5114#section-2.1
        let p = BigUint::parse_bytes(
            b"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
            16
        ).unwrap();
        let g = BigUint::parse_bytes(
            b"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
            16
        ).unwrap();

        // Send 2 values: p (BigUint), g (BigUint) values.
        let p_buf = bincode::serialize(&p);
        let g_buf = bincode::serialize(&g);

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

        let p_len = p_buf.len() as u64;
        let mut p_len = bincode::serialize(&p_len).unwrap();

        let g_len = g_buf.len() as u64;
        let mut g_len = bincode::serialize(&g_len).unwrap();

        let mut pg_send_buf = Vec::new();
        pg_send_buf.append(&mut p_len);
        pg_send_buf.append(&mut p_buf);
        pg_send_buf.append(&mut g_len);
        pg_send_buf.append(&mut g_buf);

        // Send p and g values.
        loop {
            match self.write_to_socket(user_info, &mut pg_send_buf) {
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
        let mut rng = rand::thread_rng();
        let a: BigUint = rng.sample(RandomBits::new(A_B_BITS));

        // Generate open key 'A'.
        let a_open = g.modpow(&a, &p);

        // Prepare to send open key 'A'.
        let a_open_buf = bincode::serialize(&a_open);
        if let Err(e) = a_open_buf {
            println!("An error occurred while trying to establish a secure connection, error: {} at [{}, {}]", e, file!(), line!());
            return Err(());
        }
        let mut a_open_buf = a_open_buf.unwrap();

        // Send open key 'A'.
        let a_open_len = a_open_buf.len() as u64;
        let a_open_len_buf = bincode::serialize(&a_open_len);
        if let Err(e) = a_open_len_buf {
            println!("An error occurred while trying to establish a secure connection, error: {} at [{}, {}]", e, file!(), line!());
            return Err(());
        }
        let mut a_open_len_buf = a_open_len_buf.unwrap();
        a_open_len_buf.append(&mut a_open_buf);
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
        let b_open_len = bincode::deserialize::<u64>(&b_open_len_buf);
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

        let b_open_big = bincode::deserialize::<BigUint>(&b_open_buf);
        if let Err(e) = b_open_big {
            println!(
                "bincode::deserialize failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return Err(());
        }
        let b_open_big = b_open_big.unwrap();

        // Calculate the secret key.
        let secret_key = b_open_big.modpow(&a, &p);
        let mut secret_key_str = secret_key.to_str_radix(10);

        let key_length = 32;

        if secret_key_str.len() < key_length {
            if secret_key_str.is_empty() {
                println!(
                    "Error: generated secret key is empty, at [{}, {}].",
                    file!(),
                    line!()
                );
                return Err(());
            }

            loop {
                secret_key_str += &secret_key_str.clone();

                if secret_key_str.len() >= key_length {
                    break;
                }
            }
        }

        Ok(Vec::from(&secret_key_str[0..key_length]))
    }
    fn handle_not_connected_state(
        &mut self,
        data_size: u16,
        user_info: &mut UserInfo,
        server_config: &ServerConfig,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: &Arc<Mutex<Option<Vec<BannedAddress>>>>,
        user_enters_leaves_server_lock: &Arc<Mutex<()>>,
        logger: &Arc<Mutex<ServerLogger>>,
        server_password: &str,
    ) -> HandleStateResult {
        if data_size > TCP_PACKET_MAX_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "The received data size ({}) exceeds the limit ({}) for socket ({}) on state: not_connected, at [{}, {}]",
                data_size, TCP_PACKET_MAX_SIZE, user_info.tcp_addr, file!(), line!()
            ));
        }

        // Receive encrypted connect packet.
        let mut encrypted_connect_packet = vec![0u8; data_size as usize];
        loop {
            match self.read_from_socket(user_info, &mut encrypted_connect_packet) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    break;
                }
                res => return HandleStateResult::IoErr(res),
            };
        }

        // Get IV.
        if encrypted_connect_packet.len() < IV_LENGTH {
            return HandleStateResult::HandleStateErr(format!(
                "received data is too small, at [{}, {}].",
                file!(),
                line!()
            ));
        }
        let iv = &encrypted_connect_packet[..IV_LENGTH].to_vec();
        encrypted_connect_packet = encrypted_connect_packet[IV_LENGTH..].to_vec();

        // Decrypt packet.
        let cipher = Aes256Cbc::new_from_slices(&user_info.secret_key, &iv).unwrap();
        let decrypted_packet = cipher.decrypt_vec(&encrypted_connect_packet);
        if let Err(e) = decrypted_packet {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred while decrypting a packet, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let decrypted_packet = decrypted_packet.unwrap();
        let connect_packet = bincode::deserialize::<ClientConnectPacket>(&decrypted_packet);
        if let Err(e) = connect_packet {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred while deserializing a packet, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let connect_packet = connect_packet.unwrap();

        // Prepare answer.
        let mut answer = ConnectServerAnswer::Ok;
        {
            let _guard = user_enters_leaves_server_lock.lock().unwrap();

            if !server_password.is_empty() {
                // Check if the password is correct.
                if server_password != connect_packet.password {
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
                            reason: BanReason::WrongPassword,
                        });
                    }
                }
            }

            // Check if the client protocol is supported.
            if connect_packet.net_protocol_version != NETWORK_PROTOCOL_VERSION {
                // Send error (wrong protocol).
                answer = ConnectServerAnswer::WrongProtocol;
            }

            // Check if the name is unique.
            let mut name_is_unique = true;
            {
                let users_guard = users.lock().unwrap();
                for user in users_guard.iter() {
                    if user.username == connect_packet.username {
                        name_is_unique = false;
                        break;
                    }
                }
            }

            if !name_is_unique {
                // Send error (username taken).
                answer = ConnectServerAnswer::UsernameTaken;
            }

            let mut server_connect_packet = ServerTcpConnectPacket {
                answer,
                correct_net_protocol: None,
                connected_info: None,
            };

            if answer == ConnectServerAnswer::WrongProtocol {
                server_connect_packet.correct_net_protocol = Some(NETWORK_PROTOCOL_VERSION);
            }

            if answer == ConnectServerAnswer::Ok {
                // Get info about rooms and users.
                let mut rooms_info = Vec::new();

                for room in server_config.rooms.iter() {
                    rooms_info.push(RoomNetInfo {
                        room_name: room.room_name.clone(),
                        users: Vec::new(),
                    });
                }

                {
                    let users_guard = users.lock().unwrap();

                    for user in users_guard.iter() {
                        for room in rooms_info.iter_mut() {
                            if room.room_name == user.room_name {
                                room.users.push(UserNetInfo {
                                    username: user.username.clone(),
                                    ping: user.last_ping,
                                });
                                break;
                            }
                        }
                    }
                }

                server_connect_packet.connected_info = Some(rooms_info);
            }

            // Prepare to send.
            let mut _encrypted_binary_packet = Vec::new();
            let mut iv = vec![0u8; IV_LENGTH];
            loop {
                let binary_server_connect_packet = bincode::serialize(&server_connect_packet);
                if let Err(e) = binary_server_connect_packet {
                    return HandleStateResult::HandleStateErr(format!(
                    "An error occurred while serializing, error: socket ({}) on state (NotConnected), error: {}, at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
                }

                let binary_server_connect_packet = binary_server_connect_packet.unwrap();

                // Encrypt packet.
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut iv);
                let cipher = Aes256Cbc::new_from_slices(&user_info.secret_key, &iv).unwrap();
                let encrypted_binary_server_connect_packet =
                    cipher.encrypt_vec(&binary_server_connect_packet);

                if encrypted_binary_server_connect_packet.len()
                    + IV_LENGTH
                    + std::mem::size_of::<u64>()
                    > TCP_CONNECT_ANSWER_PACKET_MAX_SIZE as usize
                {
                    // Let's say the server is full.
                    server_connect_packet = ServerTcpConnectPacket {
                        answer: ConnectServerAnswer::ServerIsFull,
                        correct_net_protocol: None,
                        connected_info: None,
                    };
                } else {
                    _encrypted_binary_packet = encrypted_binary_server_connect_packet;
                    break;
                }
            }

            let mut send_buffer = Vec::new();
            let packet_length = (_encrypted_binary_packet.len() + IV_LENGTH) as u64;
            let mut packet_length = bincode::serialize(&packet_length).unwrap();

            send_buffer.append(&mut packet_length);
            send_buffer.append(&mut iv);
            send_buffer.append(&mut _encrypted_binary_packet);

            loop {
                match self.write_to_socket(user_info, &mut send_buffer) {
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

            match answer {
                ConnectServerAnswer::Ok => {}
                ConnectServerAnswer::ServerIsFull => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "Info: socket ({} AKA {}) was not connected, reason: the server is full.",
                        user_info.tcp_addr, &connect_packet.username
                    ));
                }
                ConnectServerAnswer::WrongProtocol => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "Info: socket ({} AKA {}) was not connected, reason: wrong client protocol, client protocol version ({}) is not supported.",
                        user_info.tcp_addr, &connect_packet.username, connect_packet.net_protocol_version,
                    ));
                }
                ConnectServerAnswer::WrongPassword => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "Info: socket ({} AKA {}) was not connected, reason: wrong password, received password \"{}\".",
                        user_info.tcp_addr, &connect_packet.username, connect_packet.password
                    ));
                }
                ConnectServerAnswer::UsernameTaken => {
                    return HandleStateResult::UserNotConnectedReason(format!(
                        "Info: socket ({} AKA {}) was not connected, reason: username \"{}\" is not unique.",
                        user_info.tcp_addr, &connect_packet.username, connect_packet.username,
                    ));
                }
            }

            let user_connected_packet = ServerTcpMessage::UserConnected {
                username: connect_packet.username.clone(),
            };

            let binary_user_connected_packet = bincode::serialize(&user_connected_packet);
            if let Err(e) = binary_user_connected_packet {
                return HandleStateResult::HandleStateErr(format!(
                    "An error occurred while serializing, error: socket ({}) on state (NotConnected), error: {}, at [{}, {}]",
                    user_info.tcp_addr, e, file!(), line!()
                ));
            }

            let binary_user_connected_packet = binary_user_connected_packet.unwrap();

            // Send info about new user.
            {
                let mut rng = rand::thread_rng();
                let mut users_guard = users.lock().unwrap();
                for user in users_guard.iter_mut() {
                    // Encrypt packet.
                    let mut iv = vec![0u8; IV_LENGTH];
                    rng.fill_bytes(&mut iv);
                    let cipher = Aes256Cbc::new_from_slices(&user.secret_key, &iv).unwrap();
                    let mut encrypted_binary_user_connected_packet =
                        cipher.encrypt_vec(&binary_user_connected_packet);

                    // Check packet length.
                    if encrypted_binary_user_connected_packet.len() + IV_LENGTH
                        > TCP_PACKET_MAX_SIZE as usize
                    {
                        // should never happen
                        return HandleStateResult::HandleStateErr(format!(
                            "Error: the packet size ({}) exceeds the limit ({}), at [{}, {}]",
                            encrypted_binary_user_connected_packet.len(),
                            TCP_PACKET_MAX_SIZE,
                            file!(),
                            line!()
                        ));
                    }
                    let len = (encrypted_binary_user_connected_packet.len() + IV_LENGTH) as u16;
                    let mut len_buf = bincode::serialize(&len).unwrap();

                    // Send.
                    let mut send_buf: Vec<u8> = Vec::new();
                    send_buf.append(&mut len_buf);
                    send_buf.append(&mut iv);
                    send_buf.append(&mut encrypted_binary_user_connected_packet);

                    loop {
                        match self.write_to_socket(user, &mut send_buf) {
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

            // Add new connected user to our users list.
            user_info.username = connect_packet.username.clone();
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
        message: String,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> HandleStateResult {
        // Check spam protection.
        let time_diff = Local::now() - user_info.last_text_message_sent;
        if time_diff.num_seconds() < SPAM_PROTECTION_SEC as i64 {
            // can't happen with the default (unchanged) client version
            return HandleStateResult::HandleStateErr(format!(
                "the user \"{}\" tried sending text messages too quick (which should not happen with the default (unchanged) client version).",
                user_info.username
            ));
        }

        user_info.last_text_message_sent = Local::now();

        // use '.len' instead of '.chars().count()'
        // because we only care about byte length.
        if message.len() > MAX_MESSAGE_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "the user \"{}\" is sending text message that is too big ({}/{}) (which should not happen with the default (unchanged) client version).",
                user_info.username, message.len(), MAX_MESSAGE_SIZE
            ));
        }

        // Serialize packet.
        let packet = ServerTcpMessage::UserMessage {
            username: user_info.username.clone(),
            message,
        };

        let binary_packet = bincode::serialize(&packet);
        if let Err(e) = binary_packet {
            return HandleStateResult::HandleStateErr(format!(
                "bincode::serialize failed, error: {}, at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let binary_packet = binary_packet.unwrap();

        // Send to all.
        {
            let mut rng = rand::thread_rng();
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                if user.room_name == user_info.room_name {
                    // Encrypt with user key.
                    let mut iv = vec![0u8; IV_LENGTH];
                    rng.fill_bytes(&mut iv);
                    let cipher = Aes256Cbc::new_from_slices(&user.secret_key, &iv).unwrap();
                    let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

                    // Prepare message len buffer.
                    let encrypted_message_len = (encrypted_packet.len() + IV_LENGTH) as u16;
                    let encrypted_message_len_buf = bincode::serialize(&encrypted_message_len);
                    if let Err(e) = encrypted_message_len_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "bincode::serialize failed, error: {} at [{}, {}].",
                            e,
                            file!(),
                            line!()
                        ));
                    }
                    let mut encrypted_message_len_buf = encrypted_message_len_buf.unwrap();

                    encrypted_message_len_buf.append(&mut iv);
                    encrypted_message_len_buf.append(&mut encrypted_packet);

                    match self.write_to_socket(user, &mut encrypted_message_len_buf) {
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
        server_config: &ServerConfig,
        room_to_enter: String,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> HandleStateResult {
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

        // use '.len' instead of '.chars().count()'
        // because we only care about byte length.
        if room_to_enter.len() > MAX_USERNAME_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "the user \"{}\" is entering a room, with the name that is too big ({}/{}) (which should not happen with the default (unchanged) client version).",
                user_info.username, room_to_enter.len(), MAX_MESSAGE_SIZE
            ));
        }

        // Check if this room exists.
        let mut found_room = false;
        for room in server_config.rooms.iter() {
            if room.room_name == room_to_enter {
                found_room = true;
                break;
            }
        }
        if found_room == false {
            return HandleStateResult::HandleStateErr(format!(
                "the user \"{}\" is entering a room ({}) that does not exist (which should not happen with the default (unchanged) client version).",
                user_info.username, room_to_enter
            ));
        }

        // Change room for this user.
        {
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                if user.username == user_info.username {
                    user.room_name = room_to_enter.clone();
                    break;
                }
            }

            user_info.room_name = room_to_enter.clone();
        }

        // Serialize packet.
        let packet = ServerTcpMessage::UserEntersRoom {
            username: user_info.username.clone(),
            room_enters: room_to_enter,
        };

        let binary_packet = bincode::serialize(&packet);
        if let Err(e) = binary_packet {
            return HandleStateResult::HandleStateErr(format!(
                "bincode::serialize failed, error: {}, at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let binary_packet = binary_packet.unwrap();

        // Send to all.
        {
            let mut rng = rand::thread_rng();
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                // Encrypt with user key.
                let mut iv = vec![0u8; IV_LENGTH];
                rng.fill_bytes(&mut iv);
                let cipher = Aes256Cbc::new_from_slices(&user.secret_key, &iv).unwrap();
                let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

                // Prepare len buffer.
                let encrypted_len = (encrypted_packet.len() + IV_LENGTH) as u16;
                let encrypted_len_buf = bincode::serialize(&encrypted_len);
                if let Err(e) = encrypted_len_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "bincode::serialize failed, error: {} at [{}, {}].",
                        e,
                        file!(),
                        line!()
                    ));
                }
                let mut encrypted_len_buf = encrypted_len_buf.unwrap();

                encrypted_len_buf.append(&mut iv);
                encrypted_len_buf.append(&mut encrypted_packet);

                match self.write_to_socket(user, &mut encrypted_len_buf) {
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
        // Serialize packet.
        let packet = ServerTcpMessage::UserDisconnected {
            username: user_info.username.clone(),
        };

        let binary_packet = bincode::serialize(&packet);
        if let Err(e) = binary_packet {
            return HandleStateResult::HandleStateErr(format!(
                "bincode::serialize failed, error: {}, at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let binary_packet = binary_packet.unwrap();

        // Send to all.
        {
            let mut rng = rand::thread_rng();
            let mut users_guard = users.lock().unwrap();
            for user in users_guard.iter_mut() {
                // Encrypt with user key.
                let mut iv = vec![0u8; IV_LENGTH];
                rng.fill_bytes(&mut iv);
                let cipher = Aes256Cbc::new_from_slices(&user.secret_key, &iv).unwrap();
                let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

                // Prepare message len buffer.
                let encrypted_len = (encrypted_packet.len() + IV_LENGTH) as u16;
                let encrypted_len_buf = bincode::serialize(&encrypted_len);
                if let Err(e) = encrypted_len_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "bincode::serialize failed, error: {} at [{}, {}].",
                        e,
                        file!(),
                        line!()
                    ));
                }
                let mut encrypted_len_buf = encrypted_len_buf.unwrap();

                encrypted_len_buf.append(&mut iv);
                encrypted_len_buf.append(&mut encrypted_packet);

                match self.write_to_socket(user, &mut encrypted_len_buf) {
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
}
