// External.
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};
use chrono::prelude::*;
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
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
use super::udp_packets::*;
use crate::global_params::*;

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum ServerMessageUdp {
    UserPing = 0,
    PingCheck = 1,
    VoiceMessage = 2,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq)]
pub enum ClientMessageUdp {
    VoicePacket = 0,
    PingCheck = 1,
}

#[derive(Debug)]
pub struct UserUdpService {
    secret_key: Vec<u8>,
    username: String,
}

impl UserUdpService {
    pub fn new(secret_key: Vec<u8>, username: String) -> Self {
        UserUdpService {
            secret_key,
            username,
        }
    }
    pub fn do_first_ping_check(&self, udp_socket: &UdpSocket) -> Result<u16, String> {
        // Serialize packet.
        let packet = ServerUdpMessage::PingCheck {};

        let binary_packet = bincode::serialize(&packet);
        if let Err(e) = binary_packet {
            return Err(format!(
                "bincode::serialize failed, error: {:?}, at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let binary_packet = binary_packet.unwrap();

        // Encrypt with user key.
        type Aes128Ecb = Ecb<Aes128, Pkcs7>;
        let cipher = Aes128Ecb::new_from_slices(&self.secret_key, Default::default()).unwrap();
        let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

        // Prepare len buffer.
        let encrypted_len = encrypted_packet.len() as u16;
        let encrypted_len_buf = bincode::serialize(&encrypted_len);
        if let Err(e) = encrypted_len_buf {
            return Err(format!(
                "bincode::serialize failed, error: {:?} at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let mut encrypted_len_buf = encrypted_len_buf.unwrap();

        encrypted_len_buf.append(&mut encrypted_packet);

        // Start timer.
        let ping_start_time = Local::now();

        // Send.
        match self.send(udp_socket, &encrypted_len_buf) {
            Ok(()) => {}
            Err(msg) => return Err(format!("{}, at [{}, {}]", msg, file!(), line!())),
        }

        // Wait for answer.
        let mut recv_buffer = vec![0u8; UDP_PACKET_MAX_SIZE as usize];
        match self.recv(udp_socket, &mut recv_buffer) {
            Ok(byte_count) => {
                if byte_count < std::mem::size_of::<u16>() {
                    return Err(format!(
                        "received message is too small, at [{}, {}]",
                        file!(),
                        line!()
                    ));
                } else {
                    // Deserialize packet length.
                    let packet_len =
                        bincode::deserialize::<u16>(&recv_buffer[..std::mem::size_of::<u16>()]);
                    if let Err(e) = packet_len {
                        return Err(format!("{}, at [{}, {}]", e, file!(), line!()));
                    }
                    let packet_len = packet_len.unwrap();

                    // Check size.
                    if packet_len > UDP_PACKET_MAX_SIZE {
                        return Err(format!(
                            "received packet length is too big ({}/{}), at [{}, {}]",
                            packet_len,
                            UDP_PACKET_MAX_SIZE,
                            file!(),
                            line!()
                        ));
                    }

                    // Exclude size of the packet and trailing zeros.
                    recv_buffer = recv_buffer[std::mem::size_of::<u16>()..byte_count].to_vec();
                }
            }
            Err(msg) => {
                return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
            }
        }

        // Decrypt.
        let cipher = Aes128Ecb::new_from_slices(&self.secret_key, Default::default()).unwrap();
        let decrypted_packet = cipher.decrypt_vec(&recv_buffer);
        if let Err(e) = decrypted_packet {
            return Err(format!("{:?}, at [{}, {}]", e, file!(), line!()));
        }
        let decrypted_packet = decrypted_packet.unwrap();

        // Deserialize to ServerUdpMessage because the client just resends our data (our ServerUdpMessage).
        let packet_buf = bincode::deserialize::<ServerUdpMessage>(&decrypted_packet);
        if let Err(e) = packet_buf {
            return Err(format!("{:?}, at [{}, {}]", e, file!(), line!()));
        }
        let packet_buf = packet_buf.unwrap();

        match packet_buf {
            ServerUdpMessage::PingCheck => {}
            _ => {
                return Err(format!(
                    "unexpected packet type, at [{}, {}]",
                    file!(),
                    line!()
                ));
            }
        }

        let ping_time = Local::now() - ping_start_time;
        let ping_ms = ping_time.num_milliseconds() as u16;

        Ok(ping_ms)
    }
    pub fn send_user_ping_to_all(
        &self,
        ping_ms: u16,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
    ) -> Result<(), String> {
        // Serialize packet.
        let packet = ServerUdpMessage::UserPing {
            username: self.username.clone(),
            ping_ms,
        };

        let binary_packet = bincode::serialize(&packet);
        if let Err(e) = binary_packet {
            return Err(format!(
                "bincode::serialize failed, error: {:?}, at [{}, {}].",
                e,
                file!(),
                line!()
            ));
        }
        let binary_packet = binary_packet.unwrap();

        // Send ping to all + update user's ping in our list.
        let mut users_guard = users.lock().unwrap();
        for user in users_guard.iter_mut() {
            if user.username == self.username {
                user.last_ping = ping_ms; // update client's ping in our list.
            }
            if user.udp_socket.is_some() {
                // Encrypt with user key.
                type Aes128Ecb = Ecb<Aes128, Pkcs7>;
                let cipher =
                    Aes128Ecb::new_from_slices(&user.secret_key, Default::default()).unwrap();
                let mut encrypted_packet = cipher.encrypt_vec(&binary_packet);

                // Prepare len buffer.
                let encrypted_len = encrypted_packet.len() as u16;
                let encrypted_len_buf = bincode::serialize(&encrypted_len);
                if let Err(e) = encrypted_len_buf {
                    return Err(format!(
                        "bincode::serialize failed, error: {:?} at [{}, {}].",
                        e,
                        file!(),
                        line!()
                    ));
                }
                let mut encrypted_len_buf = encrypted_len_buf.unwrap();

                encrypted_len_buf.append(&mut encrypted_packet);

                match self.send(user.udp_socket.as_ref().unwrap(), &encrypted_len_buf) {
                    Ok(()) => {}
                    Err(msg) => {
                        return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
                    }
                }
            }
        }

        Ok(())
    }
    pub fn send_ping_check(&self, udp_socket: &UdpSocket) -> Result<(), String> {
        let mut buf = vec![0u8; 1];
        let data_id = ServerMessageUdp::PingCheck.to_u8();
        if data_id.is_none() {
            return Err(format!(
                "ServerMessageUdp::PingCheck.to_u8() failed, at [{}, {}]",
                file!(),
                line!()
            ));
        }
        buf[0] = data_id.unwrap();

        match self.send(udp_socket, &buf) {
            Ok(()) => Ok(()),
            Err(msg) => Err(format!("{}, at [{}, {}]", msg, file!(), line!())),
        }
    }
    pub fn wait_for_connection(
        &self,
        udp_socket: &UdpSocket,
        user_addr: SocketAddr,
        users: &Arc<Mutex<LinkedList<UserInfo>>>,
        user_connect_disconnect_server_lock: &Arc<Mutex<()>>,
    ) -> Result<(), String> {
        let mut packet_size = vec![0u8; std::mem::size_of::<u16>()];
        loop {
            packet_size.fill(0u8);
            match self.peek(udp_socket, &mut packet_size) {
                Ok((_size, src_addr)) => {
                    // only one thread should be here
                    let _connect_guard = user_connect_disconnect_server_lock.lock().unwrap();
                    if user_addr.ip() != src_addr.ip() {
                        // Not our data.
                        // see if this data belongs to our users
                        {
                            let mut found = false;
                            let users_guard = users.lock().unwrap();
                            for user in users_guard.iter() {
                                if user.tcp_addr.ip() == src_addr.ip() {
                                    found = true;
                                    break; // yes, belongs to our users
                                }
                            }

                            // do under mutex
                            if !found {
                                // data does not belong to any of our users, remove this from queue
                                let mut recv_buffer = vec![0u8; UDP_PACKET_MAX_SIZE as usize];
                                loop {
                                    match udp_socket.recv_from(&mut recv_buffer) {
                                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                            thread::sleep(Duration::from_millis(
                                                INTERVAL_UDP_MESSAGE_MS,
                                            ));
                                            continue;
                                        }
                                        Err(e) => {
                                            return Err(format!(
                                                "udp_socket.recv_from() failed, error: {}, at [{}, {}]",
                                                e,
                                                file!(),
                                                line!()
                                            ));
                                        }
                                        Ok((n, _recv_addr)) => {
                                            println!("info: received UDP packet not from our users with size: {} bytes, ignoring...", n);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        drop(_connect_guard);
                        thread::sleep(Duration::from_millis(INTERVAL_UDP_WAIT_FOR_CONNECTION_MS));
                        continue;
                    }

                    // IP is correct.
                    let mut recv_buffer = vec![0u8; UDP_PACKET_MAX_SIZE as usize];
                    match self.peek(udp_socket, &mut recv_buffer) {
                        Ok((byte_count, _addr)) => {
                            if byte_count < std::mem::size_of::<u16>() {
                                return Err(format!(
                                    "received message is too small, at [{}, {}]",
                                    file!(),
                                    line!()
                                ));
                            } else {
                                // Deserialize packet length.
                                let packet_len = bincode::deserialize::<u16>(
                                    &recv_buffer[..std::mem::size_of::<u16>()],
                                );
                                if let Err(e) = packet_len {
                                    return Err(format!("{}, at [{}, {}]", e, file!(), line!()));
                                }
                                let packet_len = packet_len.unwrap();

                                // Check size.
                                if packet_len > UDP_PACKET_MAX_SIZE {
                                    return Err(format!(
                                        "received packet length is too big ({}/{}), at [{}, {}]",
                                        packet_len,
                                        UDP_PACKET_MAX_SIZE,
                                        file!(),
                                        line!()
                                    ));
                                }

                                // Exclude size of the packet and trailing zeros.
                                recv_buffer =
                                    recv_buffer[std::mem::size_of::<u16>()..byte_count].to_vec();
                            }
                        }
                        Err(msg) => {
                            return Err(format!("{}, at [{}, {}]", msg, file!(), line!()));
                        }
                    }

                    // Deserialize.
                    let packet_buf = bincode::deserialize::<ClientUdpMessage>(&recv_buffer);
                    if let Err(e) = packet_buf {
                        return Err(format!("{:?}, at [{}, {}]", e, file!(), line!()));
                    }
                    let packet_buf = packet_buf.unwrap();

                    match packet_buf {
                        ClientUdpMessage::Connect { username } => {
                            if username != self.username {
                                // Not our data, don't touch.
                                thread::sleep(Duration::from_millis(
                                    INTERVAL_UDP_WAIT_FOR_CONNECTION_MS,
                                ));
                                continue;
                            }
                        }
                        _ => {
                            return Err(format!(
                                "received unexpected packet, at [{}, {}]",
                                file!(),
                                line!()
                            ));
                        }
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

                    // Remove this packet from queue.
                    recv_buffer = vec![0u8; UDP_PACKET_MAX_SIZE as usize];
                    if let Err(e) = self.recv(udp_socket, &mut recv_buffer) {
                        return Err(format!("{}, at [{}, {}]", e, file!(), line!()));
                    }

                    {
                        let mut users_guard = users.lock().unwrap();
                        for user in users_guard.iter_mut() {
                            if user.username == self.username {
                                println!("OK");
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
    pub fn peek(
        &self,
        udp_socket: &UdpSocket,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr), String> {
        loop {
            match udp_socket.peek_from(buf) {
                Ok((n, addr)) => {
                    return Ok((n, addr));
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
    pub fn recv(&self, udp_socket: &UdpSocket, buf: &mut [u8]) -> Result<usize, String> {
        loop {
            match udp_socket.recv(buf) {
                Ok(n) => return Ok(n),
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
    }
}
