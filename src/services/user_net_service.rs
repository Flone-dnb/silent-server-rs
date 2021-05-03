use bytevec::{ByteDecodable, ByteEncodable};
use tokio::net::TcpStream;

use std::net::SocketAddr;

use super::net_service::*;
use crate::global_params::*;

#[derive(PartialEq, Copy, Clone)]
pub enum UserState {
    NotConnected,
    Connected,
}

pub enum ReadResult {
    Ok(usize),
    WouldBlock,
    FIN,
    Err(String),
}

pub enum HandleStateResult {
    Ok,
    ReadErr(ReadResult),
    HandleStateErr(String),
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
    ) -> ReadResult {
        // Wait for the socket to be readable
        if socket.readable().await.is_err() {
            return ReadResult::Err(String::from(format!("socket ({}) readable() failed", addr)));
        }

        // (non-blocking)
        match socket.try_read(buf) {
            Ok(0) => {
                return ReadResult::FIN;
            }
            Ok(n) => {
                if n != buf.len() {
                    return ReadResult::Err(String::from(format!(
                        "socket ({}) try_read() failed, error: failed to read 'buf_u16' size",
                        addr
                    )));
                }

                return ReadResult::Ok(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return ReadResult::WouldBlock;
            }
            Err(e) => {
                return ReadResult::Err(String::from(format!(
                    "socket ({}) try_read() failed, error: {}",
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
    ) -> HandleStateResult {
        match self.user_state {
            UserState::NotConnected => {
                return self
                    .handle_not_connected_state(current_u16, socket, addr, user_info)
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
                ReadResult::WouldBlock => continue, // try again
                ReadResult::Ok(_bytes) => {
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

        // Get version string.
        let mut client_version_buf = vec![0u8; current_u16 as usize];
        let mut client_version_string = String::new();
        loop {
            match self
                .read_from_socket(socket, addr, &mut client_version_buf)
                .await
            {
                ReadResult::WouldBlock => continue, // try again
                ReadResult::Ok(_bytes) => {
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
                ReadResult::WouldBlock => continue,
                ReadResult::Ok(_bytes) => {
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
                ReadResult::WouldBlock => continue, // try again
                ReadResult::Ok(_bytes) => {
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

        user_info.username = client_name_string;
        self.user_state = UserState::Connected;

        HandleStateResult::Ok
    }
}
