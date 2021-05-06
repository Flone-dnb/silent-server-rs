use bytevec::{ByteDecodable, ByteEncodable};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use std::collections::LinkedList;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use num_traits::cast::ToPrimitive;

use super::net_service::*;
use crate::config_io::ServerLogger;
use crate::global_params::*;

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
}

pub enum IoResult {
    Ok(usize),
    WouldBlock,
    FIN,
    Err(String),
}

pub enum HandleStateResult {
    Ok,
    ReadErr(IoResult),
    HandleStateErr(String),
    ErrInfo(String), // not a critical error
}

pub struct UserNetService {
    pub user_state: UserState,
}

impl UserNetService {
    pub fn new() -> Self {
        UserNetService {
            user_state: UserState::NotConnected,
        }
    }
    pub async fn read_from_socket(
        &self,
        socket: &mut TcpStream,
        addr: &SocketAddr,
        buf: &mut [u8],
    ) -> IoResult {
        // Wait for the socket to be readable
        if socket.readable().await.is_err() {
            return IoResult::Err(String::from(format!("socket ({}) readable() failed", addr)));
        }

        // (non-blocking)
        match socket.try_read(buf) {
            Ok(0) => {
                return IoResult::FIN;
            }
            Ok(n) => {
                if n != buf.len() {
                    return IoResult::Err(String::from(format!(
                        "socket ({}) try_read() failed, error: failed to read 'buf_u16' size",
                        addr
                    )));
                }

                return IoResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return IoResult::WouldBlock;
            }
            Err(e) => {
                return IoResult::Err(String::from(format!(
                    "socket ({}) try_read() failed, error: {}",
                    addr, e
                )));
            }
        };
    }
    pub async fn write_to_socket(
        &self,
        socket: &mut TcpStream,
        addr: &SocketAddr,
        buf: &mut [u8],
    ) -> IoResult {
        // Wait for the socket to be writeable.
        if socket.writable().await.is_err() {
            return IoResult::Err(String::from(format!(
                "socket ({}) writeable() failed",
                addr
            )));
        }

        // (non-blocking)
        match socket.try_write(buf) {
            Ok(0) => {
                return IoResult::FIN;
            }
            Ok(n) => {
                if n != buf.len() {
                    return IoResult::Err(String::from(format!(
                        "socket ({}) try_write() failed, error: failed to read 'buf_u16' size",
                        addr
                    )));
                }

                return IoResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return IoResult::WouldBlock;
            }
            Err(e) => {
                return IoResult::Err(String::from(format!(
                    "socket ({}) try_write() failed, error: {}",
                    addr, e
                )));
            }
        };
    }
    pub async fn handle_user_state(
        &mut self,
        current_u16: u16,
        socket: &mut TcpStream,
        addr: &SocketAddr,
        user_info: &mut UserInfo,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        user_enters_server_lock: Arc<RwLock<()>>,
        logger: Arc<Mutex<ServerLogger>>,
    ) -> HandleStateResult {
        match self.user_state {
            UserState::NotConnected => {
                return self
                    .handle_not_connected_state(
                        current_u16,
                        socket,
                        addr,
                        user_info,
                        users,
                        user_enters_server_lock,
                        logger,
                    )
                    .await;
            }
            _ => HandleStateResult::Ok,
        }
    }
    async fn handle_not_connected_state(
        &mut self,
        current_u16: u16,
        socket: &mut TcpStream,
        addr: &SocketAddr,
        user_info: &mut UserInfo,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        user_enters_server_lock: Arc<RwLock<()>>,
        logger: Arc<Mutex<ServerLogger>>,
    ) -> HandleStateResult {
        if current_u16 as u32 > MAX_VERSION_STRING_LENGTH {
            return HandleStateResult::HandleStateErr(String::from(format!(
                "socket ({}) on state (NotConnected) failed, reason: version str len ({}) > {}",
                addr, current_u16, MAX_VERSION_STRING_LENGTH,
            )));
        }

        // Get version string.
        let mut client_version_buf = vec![0u8; current_u16 as usize];
        let mut client_version_string = String::new();
        loop {
            match self
                .read_from_socket(socket, addr, &mut client_version_buf)
                .await
            {
                IoResult::WouldBlock => continue, // try again
                IoResult::Ok(_bytes) => {
                    let res = std::str::from_utf8(&client_version_buf);
                    if res.is_err() {
                        return HandleStateResult::HandleStateErr(String::from(format!(
                            "socket ({}) on state (NotConnected) failed, reason: std::str::from_utf8() on client_version_buf failed",
                            addr,
                        )));
                    }

                    client_version_string = String::from(res.unwrap());

                    break;
                }
                res => return HandleStateResult::ReadErr(res),
            };
        }

        // Get name string size.
        let mut client_name_size_buf = [0u8; 2];
        let mut client_name_size = 0u16;
        loop {
            match self
                .read_from_socket(socket, &addr, &mut client_name_size_buf)
                .await
            {
                IoResult::WouldBlock => continue,
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&client_name_size_buf);
                    if res.is_err() {
                        return HandleStateResult::HandleStateErr(String::from(format!(
                            "socket ({}) decode(u16) failed",
                            addr
                        )));
                    }

                    client_name_size = res.unwrap();

                    break;
                }
                res => return HandleStateResult::ReadErr(res),
            }
        }

        // Get name string.
        let mut client_name_buf = vec![0u8; client_name_size as usize];
        let mut client_name_string = String::new();
        loop {
            match self
                .read_from_socket(socket, addr, &mut client_name_buf)
                .await
            {
                IoResult::WouldBlock => continue, // try again
                IoResult::Ok(_bytes) => {
                    let res = std::str::from_utf8(&client_name_buf);
                    if res.is_err() {
                        return HandleStateResult::HandleStateErr(String::from(format!(
                            "socket ({}) on state (NotConnected) failed, reason: std::str::from_utf8() on client_name_buf failed",
                            addr,
                        )));
                    }

                    client_name_string = String::from(res.unwrap());

                    break;
                }
                res => return HandleStateResult::ReadErr(res),
            };
        }

        let mut answer = ConnectServerAnswer::Ok;

        {
            user_enters_server_lock.write().await;

            // Check if the client version is supported.
            if client_version_string != SUPPORTED_CLIENT_VERSION {
                // Send error (wrong version).
                answer = ConnectServerAnswer::WrongVersion;
            }

            // Check if the name is unique.
            let mut name_is_unique = true;
            {
                let users_guard = users.lock().unwrap();
                for user in users_guard.iter() {
                    if user.username == client_name_string {
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
                return HandleStateResult::HandleStateErr(String::from(
                    "ToPrimitive::to_u16() failed.",
                ));
            }
            let answer_id = id.unwrap();
            let answer_buf = u16::encode::<u16>(&answer_id);
            if answer_buf.is_err() {
                return HandleStateResult::HandleStateErr(String::from(
                    "encode::<u16> (answer_buf) failed.",
                ));
            }
            let mut answer_buf = answer_buf.unwrap();
            loop {
                match self.write_to_socket(socket, &addr, &mut answer_buf).await {
                    IoResult::WouldBlock => continue, // try again
                    IoResult::Ok(_bytes) => {
                        break;
                    }
                    res => return HandleStateResult::ReadErr(res),
                }
            }

            if answer == ConnectServerAnswer::WrongVersion {
                // Also send correct version.
                // Write version string size.
                let supported_client_str_len = SUPPORTED_CLIENT_VERSION.len() as u16;
                let answer_buf = u16::encode::<u16>(&supported_client_str_len);
                if answer_buf.is_err() {
                    return HandleStateResult::HandleStateErr(String::from(
                        "encode::<u16> (supported_client_str_len) failed.",
                    ));
                }
                let mut answer_buf = answer_buf.unwrap();
                loop {
                    match self.write_to_socket(socket, &addr, &mut answer_buf).await {
                        IoResult::WouldBlock => continue, // try again
                        IoResult::Ok(_bytes) => {
                            break;
                        }
                        res => return HandleStateResult::ReadErr(res),
                    }
                }

                let mut supported_client_str = Vec::from(SUPPORTED_CLIENT_VERSION.as_bytes());
                loop {
                    match self
                        .write_to_socket(socket, &addr, &mut supported_client_str)
                        .await
                    {
                        IoResult::WouldBlock => continue, // try again
                        IoResult::Ok(_bytes) => {
                            break;
                        }
                        res => return HandleStateResult::ReadErr(res),
                    }
                }
            }

            match answer {
                ConnectServerAnswer::Ok => {}
                ConnectServerAnswer::WrongVersion => {
                    return HandleStateResult::ErrInfo(String::from(format!(
                        "client version ({}) is not supported.",
                        client_version_string
                    )));
                }
                ConnectServerAnswer::UsernameTaken => {
                    return HandleStateResult::ErrInfo(String::from(format!(
                        "username {} is not unique.",
                        client_name_string
                    )));
                }
            }

            // Send usernames of other users.
            let mut info_out_buf: Vec<u8> = Vec::new();
            {
                let users_guard = users.lock().unwrap();

                let users_count = users_guard.len() as u64;
                let users_count_buf = u64::encode::<u64>(&users_count);
                if users_count_buf.is_err() {
                    return HandleStateResult::HandleStateErr(String::from(
                        "encode::<u64> on users_count failed.",
                    ));
                }
                let mut users_count_buf = users_count_buf.unwrap();
                info_out_buf.append(&mut users_count_buf);

                for user in users_guard.iter() {
                    let username_len = user.username.len() as u16;
                    let user_name_len_buf = u16::encode::<u16>(&username_len);
                    if user_name_len_buf.is_err() {
                        return HandleStateResult::HandleStateErr(String::from(
                            "encode::<u16> on user_name_len failed.",
                        ));
                    }
                    let mut user_name_len_buf = user_name_len_buf.unwrap();

                    info_out_buf.append(&mut user_name_len_buf);

                    let mut user_name_buf = Vec::from(user.username.as_bytes());

                    info_out_buf.append(&mut user_name_buf);
                }
            }

            loop {
                match self.write_to_socket(socket, &addr, &mut info_out_buf).await {
                    IoResult::WouldBlock => continue, // try again
                    IoResult::Ok(_) => {
                        break;
                    }
                    res => return HandleStateResult::ReadErr(res),
                }
            }

            user_info.username = client_name_string;
            self.user_state = UserState::Connected;

            // New connected user.
            let mut _users_connected = 0;
            {
                let mut users_guard = users.lock().unwrap();
                users_guard.push_back(user_info.clone());
                _users_connected = users_guard.len();
            }

            let mut logger_guard = logger.lock().unwrap();
            if let Err(e) = logger_guard.println_and_log(&format!(
                "New connection from ({:?}) AKA ({}) [connected users: {}].",
                addr, user_info.username, _users_connected
            )) {
                println!("ServerLogger failed, error: {}", e);
            }
        }

        HandleStateResult::Ok
    }
}
