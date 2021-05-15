// External.
use bytevec::ByteEncodable;
use chrono::prelude::*;
use num_traits::cast::ToPrimitive;

// Std.
use std::collections::LinkedList;
use std::io::ErrorKind;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
use super::net_service::UserInfo;
use super::user_tcp_service::ServerMessageTcp;
use crate::global_params::*;

#[derive(Debug)]
pub struct UserUdpService {}

impl UserUdpService {
    pub fn new() -> Self {
        UserUdpService {}
    }
    pub fn connect(&self, udp_socket: &UdpSocket) -> Result<u16, String> {
        // Send '0' to server to specify OK and wait for response.
        let mut ok_buf = vec![0u8; 1];

        let ping_start_time = Local::now();

        if let Err(msg) = self.send(udp_socket, &ok_buf) {
            return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
        }

        // Receive '0' as OK.
        if let Err(msg) = self.recv(&udp_socket, &mut ok_buf) {
            return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
        }

        if ok_buf[0] != 0 {
            return Err(format!(
                "UserUdpService::connect() failed, error: received value is not '0', at [{}, {}]",
                file!(),
                line!()
            ));
        }

        let ping_time = Local::now() - ping_start_time;
        let ping_ms = ping_time.num_milliseconds() as u16;

        // Write ping.
        let ping_ms_buf = u16::encode::<u16>(&ping_ms);
        if let Err(e) = ping_ms_buf {
            return Err(format!(
                "u16::encode::<u16>() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let mut ping_ms_buf = ping_ms_buf.unwrap();

        // Send ping.
        if let Err(msg) = self.send(&udp_socket, &mut ping_ms_buf) {
            return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
        }

        Ok(ping_ms)
    }
    pub fn wait_for_connection(
        &self,
        udp_socket: &UdpSocket,
        user_addr: SocketAddr,
        user_name: &str,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> Result<(), String> {
        let mut buf = vec![0u8; 2 + MAX_USERNAME_SIZE * 4];
        loop {
            buf.fill(0u8);
            match self.peek(&udp_socket, &mut buf) {
                Ok(src_addr) => {
                    if user_addr.ip() != src_addr.ip() {
                        // Not our data, don't touch.
                        thread::sleep(Duration::from_millis(INTERVAL_UDP_IDLE_MS));
                        continue;
                    }
                    // ip correct, check username
                    // packet:
                    // (u8) - value '0'
                    // (u8) - username size
                    // (size) - username
                    let username_len = buf[1] as usize;
                    let recv_username = String::from_utf8(Vec::from(&buf[2..2 + username_len]));
                    if let Err(e) = recv_username {
                        return Err(format!(
                            "String::from_utf8() failed, error: {}, at [{}, {}]",
                            e,
                            file!(),
                            line!()
                        ));
                    }
                    let recv_username = recv_username.unwrap();

                    if recv_username != user_name {
                        // Not our data, don't touch.
                        thread::sleep(Duration::from_millis(INTERVAL_UDP_IDLE_MS));
                        continue;
                    }

                    // Clear this packet from queue.
                    let mut recv_buf = vec![0u8; 2 + username_len];
                    if let Err(msg) = self.recv(udp_socket, &mut recv_buf) {
                        return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
                    }

                    if let Err(e) = udp_socket.connect(src_addr) {
                        return Err(format!(
                            "udp_socket.connect() failed, error: {}, at [{}, {}]",
                            e,
                            file!(),
                            line!()
                        ));
                    }

                    let socket_clone = udp_socket.try_clone();
                    if let Err(e) = socket_clone {
                        return Err(format!(
                            "udp_socket.try_clone() failed, error: {}, at [{}, {}]",
                            e,
                            file!(),
                            line!()
                        ));
                    }
                    let socket_clone = socket_clone.unwrap();

                    {
                        let mut users_guard = users.lock().unwrap();
                        for user in users_guard.iter_mut() {
                            if user.username == user_name {
                                user.udp_socket = Some(socket_clone);
                                break;
                            }
                        }
                    }

                    return Ok(());
                }
                Err(msg) => {
                    return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
                }
            }
        }
    }
    pub fn send(&self, udp_socket: &UdpSocket, buf: &[u8]) -> Result<(), String> {
        loop {
            match udp_socket.send(buf) {
                Ok(n) => {
                    if n != buf.len() {
                        return Err(format!("udp_socket.send() failed, error: sent only {} bytes out of {}, at [{}, {}]",
                        n, buf.len(), file!(), line!()));
                    } else {
                        break;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_UDP_MESSAGE_MS));
                    continue;
                }
                Err(e) => {
                    return Err(format!(
                        "udp_socket.send() failed, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    ));
                }
            }
        }

        Ok(())
    }
    pub fn peek(&self, udp_socket: &UdpSocket, buf: &mut [u8]) -> Result<SocketAddr, String> {
        loop {
            match udp_socket.peek_from(buf) {
                Ok((_, addr)) => {
                    return Ok(addr);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_UDP_MESSAGE_MS));
                    continue;
                }
                Err(e) => {
                    return Err(format!(
                        "udp_socket.peek_from() failed, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    ));
                }
            }
        }
    }
    pub fn prepare_ping_info_buf(&self, username: &str, buf: &mut Vec<u8>) -> Result<(), String> {
        // Data:
        // (u16) - data ID (User ping)
        // (u16) - username.len()
        // (size) - username
        // (u16) - ping (will be set outside of this function)

        // Prepare data ID.
        // use data ID = ServerMessage::UserMessage
        let data_id = ServerMessageTcp::UserPing.to_u16();
        if data_id.is_none() {
            return Err(format!(
                "ServerMessage::UserPing.to_u16() failed at [{}, {}]",
                file!(),
                line!()
            ));
        }
        let data_id = data_id.unwrap();
        let data_id_buf = u16::encode::<u16>(&data_id);
        if let Err(e) = data_id_buf {
            return Err(format!(
                "u16::encode::<u16>() failed on value {} (error: {}) at [{}, {}]",
                data_id,
                e,
                file!(),
                line!()
            ));
        }
        let mut data_id_buf = data_id_buf.unwrap();
        buf.append(&mut data_id_buf);

        // Prepare username.len()
        let username_len = username.len() as u16;
        let username_len_buf = u16::encode::<u16>(&username_len);
        if let Err(e) = username_len_buf {
            return Err(format!(
                "u16::encode::<u16>() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        let mut username_len_buf = username_len_buf.unwrap();
        buf.append(&mut username_len_buf);

        // Prepare username
        let mut username_buf = Vec::from(username.as_bytes());
        buf.append(&mut username_buf);

        Ok(())
    }
    pub fn recv(&self, udp_socket: &UdpSocket, buf: &mut [u8]) -> Result<(), String> {
        loop {
            match udp_socket.recv(buf) {
                Ok(n) => {
                    if n != buf.len() {
                        return Err(format!("udp_socket.recv() failed, error: received only {} bytes out of {}, at [{}, {}]",
                        n, buf.len(), file!(), line!()));
                    } else {
                        break;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_UDP_MESSAGE_MS));
                    continue;
                }
                Err(e) => {
                    return Err(format!(
                        "udp_socket.recv() failed, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    ));
                }
            }
        }

        Ok(())
    }
}
