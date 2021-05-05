use bytevec::{ByteDecodable, ByteEncodable};
use tokio::net::TcpStream;

use std::collections::LinkedList;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use num_traits::cast::ToPrimitive;

use super::net_service::*;
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
    ) -> HandleStateResult {
        match self.user_state {
            UserState::NotConnected => {
                return self
                    .handle_not_connected_state(current_u16, socket, addr, user_info, users)
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
            drop(users_guard);
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

        user_info.username = client_name_string;
        self.user_state = UserState::Connected;

        HandleStateResult::Ok
    }
}
