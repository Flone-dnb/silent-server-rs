// External.
use bytevec::{ByteDecodable, ByteEncodable};
use chrono::prelude::*;
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use num_traits::cast::FromPrimitive;
use num_traits::cast::ToPrimitive;

// Std.
use std::collections::LinkedList;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
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
enum ServerMessage {
    UserConnected = 0,
    UserDisconnected = 1,
    UserMessage = 2,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum ClientMessage {
    UserMessage = 0,
}

pub enum IoResult {
    Ok(usize),
    WouldBlock,
    FIN,
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
}

impl UserTcpService {
    pub fn new() -> Self {
        UserTcpService {
            user_state: UserState::NotConnected,
        }
    }
    pub fn read_from_socket(&self, user_info: &mut UserInfo, buf: &mut [u8]) -> IoResult {
        if buf.len() == 0 {
            return IoResult::Err(format!(
                "An error occurred at UserTcpService::read_from_socket_tcp(), error: passed 'buf' has 0 len at [{}, {}]", file!(), line!()
            ));
        }

        let _io_guard = user_info.tcp_io_mutex.lock().unwrap();
        // (non-blocking)
        match user_info.tcp_socket.read(buf) {
            Ok(0) => {
                return IoResult::FIN;
            }
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
                return IoResult::FIN;
            }
            Ok(n) => {
                if n != buf.len() {
                    return IoResult::Err(format!(
                        "socket ({}) try_write() failed, error: failed to read 'buf' size (got: {}, expected: {})",
                        user_info.tcp_addr, n, buf.len()
                    ));
                }

                return IoResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return IoResult::WouldBlock;
            }
            Err(e) => {
                return IoResult::Err(String::from(format!(
                    "socket ({}) try_write() failed, error: {}",
                    user_info.tcp_addr, e
                )));
            }
        };
    }
    pub fn handle_user_state(
        &mut self,
        current_u16: u16,
        user_info: &mut UserInfo,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: &Arc<Mutex<Vec<BannedAddress>>>,
        user_enters_leaves_server_lock: &Arc<Mutex<()>>,
        logger: &Arc<Mutex<ServerLogger>>,
        server_password: &str,
    ) -> HandleStateResult {
        match self.user_state {
            UserState::NotConnected => {
                return self.handle_not_connected_state(
                    current_u16,
                    user_info,
                    users,
                    banned_addrs,
                    user_enters_leaves_server_lock,
                    logger,
                    server_password,
                );
            }
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
                    ClientMessage::UserMessage => {
                        return self.handle_user_message(user_info, users);
                    }
                }
            }
        }
    }
    fn handle_not_connected_state(
        &mut self,
        current_u16: u16,
        user_info: &mut UserInfo,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: &Arc<Mutex<Vec<BannedAddress>>>,
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

        // Get password string size.
        let mut password_size_buf = vec![0u8; std::mem::size_of::<u16>()];
        let mut _password_size = 0u16;
        loop {
            match self.read_from_socket(user_info, &mut password_size_buf) {
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&password_size_buf);
                    if let Err(e) = res {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::decode::<u16>() failed, error: socket ({}) failed to decode (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }

                    _password_size = res.unwrap();

                    break;
                }
                res => return HandleStateResult::IoErr(res),
            }
        }

        let mut _password = String::new();
        if _password_size != 0 {
            if _password_size as usize > MAX_PASSWORD_SIZE {
                return HandleStateResult::HandleStateErr(format!(
                    "An error occurred, error: socket ({}) on state (NotConnected) failed because the received password len is too big ({}) while the maximum is {}, at [{}, {}]",
                    user_info.tcp_addr, _password_size, MAX_PASSWORD_SIZE, file!(), line!()
                ));
            }

            // Get password string.
            let mut password_buf = vec![0u8; _password_size as usize];
            loop {
                match self.read_from_socket(user_info, &mut password_buf) {
                    IoResult::WouldBlock => {
                        thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                        continue;
                    }
                    IoResult::Ok(_bytes) => {
                        let res = std::str::from_utf8(&password_buf);
                        if let Err(e) = res {
                            return HandleStateResult::HandleStateErr(format!(
                                "std::str::from_utf8() failed, error: socket ({}) on state (NotConnected) failed (error: {}) at [{}, {}]",
                                user_info.tcp_addr, e, file!(), line!()
                            ));
                        }

                        _password = String::from(res.unwrap());

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
                    let mut found = false;
                    for banned_addr in banned_addrs_guard.iter() {
                        if banned_addr.addr == user_info.tcp_addr.ip() {
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        banned_addrs_guard.push(BannedAddress {
                            banned_at: Local::now(),
                            addr: user_info.tcp_addr.ip(),
                        });
                    }
                }
            }

            // Check if the client version is supported.
            if _client_version_string != SUPPORTED_CLIENT_VERSION {
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

            if name_is_unique == false {
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

            // Send usernames of other users.
            let mut info_out_buf: Vec<u8> = Vec::new();
            {
                let users_guard = users.lock().unwrap();

                let users_count = users_guard.len() as u64;
                let users_count_buf = u64::encode::<u64>(&users_count);
                if let Err(e) = users_count_buf {
                    return HandleStateResult::HandleStateErr(format!(
                        "u64::encode::<u64> failed, error: socket ({}) on state (NotConnected) failed on 'users_count' (error: {}) at [{}, {}]",
                        user_info.tcp_addr, e, file!(), line!()
                    ));
                }
                let mut users_count_buf = users_count_buf.unwrap();
                info_out_buf.append(&mut users_count_buf);

                for user in users_guard.iter() {
                    let username_len = user.username.len() as u16;
                    let user_name_len_buf = u16::encode::<u16>(&username_len);
                    if let Err(e) = user_name_len_buf {
                        return HandleStateResult::HandleStateErr(format!(
                            "u16::encode::<u16> failed, error: socket ({}) on state (NotConnected) failed on 'username_len' (error: {}) at [{}, {}]",
                            user_info.tcp_addr, e, file!(), line!()
                        ));
                    }
                    let mut user_name_len_buf = user_name_len_buf.unwrap();

                    info_out_buf.append(&mut user_name_len_buf);

                    let mut user_name_buf = Vec::from(user.username.as_bytes());

                    info_out_buf.append(&mut user_name_buf);
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

            let data_id = ServerMessage::UserConnected.to_u16();
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
        // (u16) - message.len()
        // (size) - message

        // use data ID = ServerMessage::UserMessage
        let data_id = ServerMessage::UserMessage.to_u16();
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

        // Read message len.
        let mut message_len_buf: Vec<u8> = vec![0u8; std::mem::size_of::<u16>()];
        loop {
            match self.read_from_socket(user_info, &mut message_len_buf) {
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
        let message_len = u16::decode::<u16>(&message_len_buf);
        if let Err(e) = message_len {
            return HandleStateResult::HandleStateErr(format!(
                "u16::decode::<u16>() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let message_len = message_len.unwrap();
        if message_len as usize > MAX_MESSAGE_SIZE {
            return HandleStateResult::HandleStateErr(format!(
                "An error occurred, error: socket ({}) on state (Connected) failed because the received message len is too big ({}) while the maximum is {}, at [{}, {}]",
                user_info.tcp_addr, message_len, MAX_MESSAGE_SIZE, file!(), line!()
            ));
        }

        // Read message.
        let mut message_buf: Vec<u8> = vec![0u8; message_len as usize];
        loop {
            match self.read_from_socket(user_info, &mut message_buf) {
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

        // Combine all to one buffer.
        let mut out_buf: Vec<u8> = Vec::new();
        out_buf.append(&mut data_id_buf);
        out_buf.append(&mut username_len_buf);
        out_buf.append(&mut username_buf);
        out_buf.append(&mut message_len_buf);
        out_buf.append(&mut message_buf);

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
        let data_id = ServerMessage::UserDisconnected.to_u16();
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
