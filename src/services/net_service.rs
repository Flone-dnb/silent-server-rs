// External.
use bytevec::{ByteDecodable, ByteEncodable};
use chrono::prelude::*;
use num_traits::{cast::ToPrimitive, FromPrimitive};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

// Std.
use std::collections::LinkedList;
use std::io::ErrorKind;
use std::net::*;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
use super::user_tcp_service::*;
use super::user_udp_service::*;
use crate::config_io::*;
use crate::global_params::*;

pub struct UserInfo {
    pub username: String,
    pub room_name: String,
    pub last_ping: u16,
    pub tcp_addr: SocketAddr,
    pub tcp_socket: TcpStream,
    pub udp_socket: Option<UdpSocket>,
    pub tcp_io_mutex: Arc<Mutex<()>>,
    pub last_text_message_sent: DateTime<Local>,
    pub last_time_entered_room: DateTime<Local>,
}
impl UserInfo {
    pub fn clone(&self) -> Result<UserInfo, String> {
        let tcp_socket_clone = self.tcp_socket.try_clone();
        if let Err(e) = tcp_socket_clone {
            return Err(format!(
                "UserInfo::clone() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        Ok(UserInfo {
            username: self.username.clone(),
            room_name: String::from(DEFAULT_ROOM_NAME),
            last_ping: 0,
            tcp_addr: self.tcp_addr.clone(),
            tcp_socket: tcp_socket_clone.unwrap(),
            udp_socket: None,
            tcp_io_mutex: Arc::clone(&self.tcp_io_mutex),
            last_text_message_sent: Local::now(),
            last_time_entered_room: Local::now(),
        })
    }
}

pub struct BannedAddress {
    pub banned_at: DateTime<Local>,
    pub addr: IpAddr,
}

pub struct NetService {
    pub server_config: ServerConfig,
    connected_users: Arc<Mutex<LinkedList<UserInfo>>>,
    logger: Arc<Mutex<ServerLogger>>,
    user_enters_leaves_server_lock: Arc<Mutex<()>>,
    banned_addrs: Arc<Mutex<Option<Vec<BannedAddress>>>>,
    is_running: bool,
}

impl NetService {
    pub fn new() -> Self {
        Self {
            server_config: ServerConfig::new().unwrap(),
            is_running: false,
            connected_users: Arc::new(Mutex::new(LinkedList::new())),
            user_enters_leaves_server_lock: Arc::new(Mutex::new(())),
            logger: Arc::new(Mutex::new(ServerLogger::new())),
            banned_addrs: Arc::new(Mutex::new(Some(Vec::new()))),
        }
    }

    pub fn start(&mut self) {
        if self.is_running {
            println!("\nAlready running...");
            return;
        }

        {
            let mut logger_guard = self.logger.lock().unwrap();

            if let Err(e) = logger_guard.open(&self.server_config.log_file_path) {
                println!("ServerLogger::open() failed, error: {}", e);
            }

            if let Err(e) = logger_guard.println_and_log("Starting...") {
                println!("ServerLogger failed, error: {}", e);
            }
        }

        self.is_running = true;

        let server_config_copy = self.server_config.clone();
        let logger_copy = Arc::clone(&self.logger);
        let users_copy = Arc::clone(&self.connected_users);
        let banned_addrs_copy = Arc::clone(&self.banned_addrs);
        let user_io_lock_copy = Arc::clone(&self.user_enters_leaves_server_lock);
        thread::spawn(move || {
            NetService::service(
                server_config_copy,
                logger_copy,
                users_copy,
                banned_addrs_copy,
                user_io_lock_copy,
            )
        });
    }

    fn service(
        server_config: ServerConfig,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: Arc<Mutex<Option<Vec<BannedAddress>>>>,
        user_enters_leaves_server_lock: Arc<Mutex<()>>,
    ) {
        let init_time = Local::now();

        let listener_socket = TcpListener::bind(format!("127.0.0.1:{}", server_config.server_port));

        if let Err(e) = listener_socket {
            println!(
                "listener_socket.accept() failed, error: {} at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return;
        }
        let listener_socket = listener_socket.unwrap();

        {
            let mut logger_guard = logger.lock().unwrap();

            if let Err(e) = logger_guard.println_and_log(&format!(
                "Ready. Listening on port {} for connection requests...",
                server_config.server_port
            )) {
                println!(
                    "ServerLogger.println_and_log() failed, error: {} at [{}, {}]",
                    e,
                    file!(),
                    line!()
                );
            }
        }

        loop {
            let accept_result = listener_socket.accept();

            if let Err(e) = accept_result {
                println!(
                    "listener_socket.accept() failed, error: {} at [{}, {}]",
                    e,
                    file!(),
                    line!()
                );
                continue;
            }

            let (socket, addr) = accept_result.unwrap();

            {
                let mut banned_addrs_guard = banned_addrs.lock().unwrap();

                // leave only banned in the vec
                // use 'Option' to move out of mutex
                *banned_addrs_guard = Some(
                    banned_addrs_guard
                        .take()
                        .unwrap()
                        .into_iter()
                        .filter(|banned_item| {
                            let time_diff = Local::now() - banned_item.banned_at;
                            time_diff.num_seconds() < PASSWORD_RETRY_DELAY_SEC as i64
                        })
                        .collect::<Vec<BannedAddress>>(),
                );

                // find addr
                let addr_entry = banned_addrs_guard
                    .as_ref()
                    .unwrap()
                    .iter()
                    .position(|banned_item| banned_item.addr == addr.ip());
                if addr_entry.is_some() {
                    continue; // still banned
                }
            }

            if let Err(e) = socket.set_nodelay(true) {
                println!(
                    "socket.set_nodelay() failed on addr ({}), error: {} at [{}, {}]",
                    addr,
                    e,
                    file!(),
                    line!()
                );
                continue;
            }
            if let Err(e) = socket.set_nonblocking(true) {
                println!(
                    "socket.set_nonblocking() failed on addr ({}), error: {} at [{}, {}]",
                    addr,
                    e,
                    file!(),
                    line!()
                );
                continue;
            }

            let logger_copy = Arc::clone(&logger);
            let users_copy = Arc::clone(&users);
            let config_copy = server_config.clone();
            let banned_addrs_copy = Arc::clone(&banned_addrs);
            let user_io_lock_copy = Arc::clone(&user_enters_leaves_server_lock);
            let server_password_copy = server_config.server_password.clone();
            thread::spawn(move || {
                NetService::handle_user(
                    socket,
                    addr,
                    config_copy,
                    logger_copy,
                    users_copy,
                    banned_addrs_copy,
                    user_io_lock_copy,
                    server_password_copy,
                    init_time,
                )
            });
        }
    }

    fn handle_user(
        socket: TcpStream,
        addr: SocketAddr,
        server_config: ServerConfig,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        banned_addrs: Arc<Mutex<Option<Vec<BannedAddress>>>>,
        user_enters_leaves_server_lock: Arc<Mutex<()>>,
        server_password: String,
        init_time: DateTime<Local>,
    ) {
        let mut buf_u16 = [0u8; 2];
        let mut _var_u16 = 0u16;
        let mut is_error = true;
        let mut user_net_service = UserTcpService::new();

        let mut user_info = UserInfo {
            username: String::from(""),
            room_name: String::from(DEFAULT_ROOM_NAME),
            last_ping: 0,
            tcp_addr: addr,
            tcp_socket: socket,
            udp_socket: None,
            tcp_io_mutex: Arc::new(Mutex::new(())),
            last_text_message_sent: init_time,
            last_time_entered_room: init_time,
        };

        let (s, r) = mpsc::channel();
        let r = Arc::new(Mutex::new(r));

        // Read data from the socket.
        loop {
            // Read 2 bytes.
            match user_net_service.read_from_socket(&mut user_info, &mut buf_u16) {
                IoResult::FIN => {
                    is_error = false;
                    break;
                }
                IoResult::WouldBlock => {
                    let time_diff = Local::now() - user_net_service.last_keep_alive_check_time;
                    if time_diff.num_seconds() > INTERVAL_KEEP_ALIVE_CHECK_SEC as i64 {
                        if user_net_service.sent_keep_alive {
                            // Already did that.
                            let time_diff = Local::now() - user_net_service.sent_keep_alive_time;
                            if time_diff.num_seconds() > TIME_TO_ANSWER_TO_KEEP_ALIVE_SEC as i64 {
                                // no answer was received
                                break; // close connection
                            }
                        } else {
                            // Send keep alive check.
                            let data_id = ServerMessageTcp::KeepAliveCheck.to_u16();
                            if data_id.is_none() {
                                println!(
                                    "ToPrimitive::to_u16() failed, error: socket ({}) at [{}, {}]",
                                    user_info.tcp_addr,
                                    file!(),
                                    line!()
                                );
                                break;
                            }
                            let data_id: u16 = data_id.unwrap();
                            let data_id_buf = u16::encode::<u16>(&data_id);
                            if let Err(e) = data_id_buf {
                                println!(
                                    "u16::encode::<u16> failed, error: socket ({}) (error: {}) at [{}, {}]",
                                    user_info.tcp_addr, e, file!(), line!()
                                );
                                break;
                            }
                            let mut data_id_buf = data_id_buf.unwrap();

                            let mut _is_fin = false;
                            loop {
                                match user_net_service
                                    .write_to_socket(&mut user_info, &mut data_id_buf)
                                {
                                    IoResult::FIN => {
                                        is_error = false;
                                        _is_fin = true;
                                        break;
                                    }
                                    IoResult::WouldBlock => {
                                        thread::sleep(Duration::from_millis(
                                            INTERVAL_TCP_MESSAGE_MS,
                                        ));
                                        continue;
                                    }
                                    IoResult::Err(msg) => {
                                        println!("{} at [{}, {}]", msg, file!(), line!());
                                        _is_fin = true;
                                        break;
                                    }
                                    IoResult::Ok(_) => break,
                                }
                            }

                            if _is_fin {
                                break;
                            }

                            user_net_service.sent_keep_alive = true;
                            user_net_service.sent_keep_alive_time = Local::now();
                        }
                    }

                    thread::sleep(Duration::from_millis(INTERVAL_TCP_IDLE_MS));
                    continue;
                }
                IoResult::Err(e) => {
                    println!("{} at [{}, {}]", e, file!(), line!());
                    break;
                }
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&buf_u16);
                    if let Err(e) = res {
                        println!("NetService::handle_user::read_from_socket_tcp() failed, error: socket ({}) decode(u16) failed with error: {} at [{}, {}]", addr, e, file!(), line!());
                        break;
                    }

                    _var_u16 = res.unwrap();
                }
            }

            user_net_service.last_keep_alive_check_time = Local::now();
            user_net_service.sent_keep_alive = false;

            let prev_state = user_net_service.user_state;

            // Using current state and these 2 bytes we know what to do.
            match user_net_service.handle_user_state(
                _var_u16,
                &mut user_info,
                &server_config,
                &users,
                &banned_addrs,
                &user_enters_leaves_server_lock,
                &logger,
                &server_password,
            ) {
                HandleStateResult::IoErr(read_e) => match read_e {
                    IoResult::FIN => {
                        is_error = false;
                        break;
                    }
                    IoResult::Err(e) => {
                        println!("{} at [{}, {}]", e, file!(), line!());
                        break;
                    }
                    _ => {}
                },
                HandleStateResult::HandleStateErr(msg) => {
                    println!("{} at [{}, {}]", msg, file!(), line!());
                    break;
                }
                HandleStateResult::UserNotConnectedReason(msg) => {
                    println!("{}", msg);
                    break;
                }
                HandleStateResult::Ok => {}
            };

            if prev_state == UserState::NotConnected
                && user_net_service.user_state == UserState::Connected
            {
                // Start UDP service.
                let username_copy = user_info.username.clone();
                let addr_copy = addr;
                let users_copy = Arc::clone(&users);
                let r_clone = Arc::clone(&r);
                thread::spawn(move || {
                    NetService::udp_service(username_copy, addr_copy, users_copy, r_clone)
                });
            }
        }

        // signal to udp that we are done
        if s.send(()).is_err() {
            // udp thread probably ended earlier due to error
        }

        let mut _out_str = String::from("");

        if user_net_service.user_state == UserState::Connected {
            let mut _users_connected = 0;
            {
                let _guard = user_enters_leaves_server_lock.lock().unwrap();

                // Erase from global users list.
                let mut users_guard = users.lock().unwrap();
                for (i, user) in users_guard.iter().enumerate() {
                    if user.username == user_info.username {
                        users_guard.remove(i);
                        _users_connected = users_guard.len();
                        break;
                    }
                }
            }

            if is_error {
                _out_str = format!(
                    "Closing connection with socket ({}) AKA ({}) due to error [connected users: {}].",
                    user_info.tcp_addr, user_info.username, _users_connected
                );
            } else {
                _out_str = format!(
                    "Closing connection with socket ({}) AKA ({}) in response to FIN [connected users: {}].",
                    user_info.tcp_addr, user_info.username, _users_connected
                );
            }

            match user_net_service.send_disconnected_notice(&mut user_info, users) {
                HandleStateResult::HandleStateErr(msg) => {
                    println!("{} at [{}, {}]", msg, file!(), line!());
                }
                _ => {}
            }
        } else {
            if is_error {
                _out_str = format!(
                    "Closing connection with socket ({}) due to error (this user was not connected).",
                    user_info.tcp_addr,
                );
            } else {
                _out_str = format!(
                    "Closing connection with socket ({}) AKA ({}) in response to FIN (this user was not connected).",
                    user_info.tcp_addr, user_info.username,
                );
            }
        }

        // Show output.
        let mut logger_guard = logger.lock().unwrap();
        if let Err(e) = logger_guard.println_and_log(&_out_str) {
            println!("{} at [{}, {}]", e, file!(), line!());
        }
    }
    fn udp_service(
        username: String,
        addr: SocketAddr,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        tcp_listen: Arc<Mutex<mpsc::Receiver<()>>>,
    ) {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP));
        if let Err(e) = socket {
            println!(
                "Socket::new() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return;
        }
        let socket = socket.unwrap();
        let sock_addr = SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            SERVER_DEFAULT_PORT,
        ));
        let res = socket.set_reuse_address(true);
        if let Err(e) = res {
            println!(
                "Socket::set_reuse_address() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return;
        }
        if let Err(e) = socket.bind(&sock_addr) {
            println!(
                "Socket::bind() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return;
        }

        let udp_socket: UdpSocket = socket.into();

        if let Err(e) = udp_socket.set_nonblocking(true) {
            println!(
                "udp_socket.set_nonblocking() failed, error: {}, at [{}, {}]",
                e,
                file!(),
                line!()
            );
            return;
        }

        let user_udp_service = UserUdpService::new();

        // Wait for "connection".
        match user_udp_service.wait_for_connection(&udp_socket, addr, &username, &users) {
            Ok(()) => {}
            Err(msg) => {
                println!("{} at [{}, {}]", msg, file!(), line!());
                return;
            }
        }

        // Prepare packet about user ping to all.
        let mut ping_info_buf = Vec::new();
        match user_udp_service.prepare_ping_info_buf(&username, &mut ping_info_buf) {
            Ok(()) => {}
            Err(msg) => {
                println!("{} at [{}, {}]", msg, file!(), line!());
                return;
            }
        }

        // Start first ping check.
        match user_udp_service.connect(&udp_socket) {
            Ok(ping_ms) => {
                // ping to buf
                let ping_buf = u16::encode::<u16>(&ping_ms);
                if let Err(e) = ping_buf {
                    println!(
                        "u16::encode::<u16>() failed, error: {} at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    );
                    return;
                }
                let mut ping_buf = ping_buf.unwrap();
                ping_info_buf.append(&mut ping_buf);

                // Send ping to all.
                let mut users_guard = users.lock().unwrap();
                for user in users_guard.iter_mut() {
                    if user.username == username {
                        user.last_ping = ping_ms;
                    }
                    if user.udp_socket.is_some() {
                        match user_udp_service
                            .send(user.udp_socket.as_ref().unwrap(), &ping_info_buf)
                        {
                            Ok(()) => {}
                            Err(msg) => {
                                println!("{} at [{}, {}]", msg, file!(), line!());
                                return;
                            }
                        }
                    }
                }
            }
            Err(msg) => {
                println!("{} at [{}, {}]", msg, file!(), line!());
                return;
            }
        }

        // Ready.
        let mut last_ping_check_time = Local::now();
        let mut in_buf = vec![0u8; IN_UDP_BUFFER_SIZE];
        loop {
            match udp_socket.recv(&mut in_buf) {
                Ok(_) => match FromPrimitive::from_u8(in_buf[0]) {
                    Some(ClientMessageUdp::PingCheck) => {
                        // Update user ping.
                        let time_diff = Local::now() - last_ping_check_time;
                        let user_ping_ms = time_diff.num_milliseconds() as u16;
                        last_ping_check_time = Local::now();

                        // Prepare packet about user ping to all.
                        let mut ping_info_buf = Vec::new();
                        match user_udp_service.prepare_ping_info_buf(&username, &mut ping_info_buf)
                        {
                            Ok(()) => {}
                            Err(msg) => {
                                println!("{} at [{}, {}]", msg, file!(), line!());
                                return;
                            }
                        }

                        // ping to buf
                        let ping_buf = u16::encode::<u16>(&user_ping_ms);
                        if let Err(e) = ping_buf {
                            println!(
                                "u16::encode::<u16>() failed, error: {} at [{}, {}]",
                                e,
                                file!(),
                                line!()
                            );
                            return;
                        }
                        let mut ping_buf = ping_buf.unwrap();
                        ping_info_buf.append(&mut ping_buf);

                        let mut users_guard = users.lock().unwrap();
                        for user in users_guard.iter_mut() {
                            if user.username == username {
                                user.last_ping = user_ping_ms;
                            }
                            if user.udp_socket.is_some() {
                                match user_udp_service
                                    .send(user.udp_socket.as_ref().unwrap(), &ping_info_buf)
                                {
                                    Ok(()) => {}
                                    Err(msg) => {
                                        println!("{} at [{}, {}]", msg, file!(), line!());
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Some(ClientMessageUdp::VoicePacket) => {
                        let mut read_index = 1usize;

                        let voice_data_len_buf = &in_buf[1..1 + std::mem::size_of::<u16>()];
                        read_index += std::mem::size_of::<u16>();
                        let voice_data_len = u16::decode::<u16>(&voice_data_len_buf);
                        if let Err(e) = voice_data_len {
                            println!(
                                "u16::decode::<u16>() failed, error: {} at [{}, {}]",
                                e,
                                file!(),
                                line!()
                            );
                            return;
                        }
                        let voice_data_len = voice_data_len.unwrap();

                        let voice_data = &in_buf[read_index..read_index + voice_data_len as usize];

                        // Prepare out packet:
                        // (u8) - id (ServerMessageUdp::VoiceMessage)
                        // (u8) - username len
                        // (size) - username
                        // (u16) - voice data len
                        // (size) - voice data
                        let packet_id = ServerMessageUdp::VoiceMessage.to_u8().unwrap();
                        let mut voice_data_len_buf = Vec::from(voice_data_len_buf);
                        let mut voice_data = Vec::from(voice_data);
                        let mut username_buf = Vec::from(username.as_bytes());
                        let username_len = username_buf.len() as u8;

                        let mut out_buf: Vec<u8> = Vec::new();
                        out_buf.push(packet_id);
                        out_buf.push(username_len);
                        out_buf.append(&mut username_buf);
                        out_buf.append(&mut voice_data_len_buf);
                        out_buf.append(&mut voice_data);

                        let mut users_guard = users.lock().unwrap();
                        for user in users_guard.iter_mut() {
                            if user.username != username && user.udp_socket.is_some() {
                                match user_udp_service
                                    .send(user.udp_socket.as_ref().unwrap(), &out_buf)
                                {
                                    Ok(()) => {}
                                    Err(msg) => {
                                        println!("{} at [{}, {}]", msg, file!(), line!());
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        println!(
                            "FromPrimitive::from_u8() failed with value {}, at [{}, {}]",
                            in_buf[0],
                            file!(),
                            line!()
                        );
                        return;
                    }
                },
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    {
                        if tcp_listen.lock().unwrap().try_recv().is_ok() {
                            // tcp thread ended, finish this thread
                            return;
                        }
                    }

                    let time_diff = Local::now() - last_ping_check_time;
                    if time_diff.num_seconds() > INTERVAL_PING_CHECK_SEC {
                        match user_udp_service.send_ping_check(&udp_socket) {
                            Ok(()) => last_ping_check_time = Local::now(),
                            Err(msg) => {
                                println!("{}, at [{}, {}]", msg, file!(), line!());
                                return;
                            }
                        }
                    }

                    thread::sleep(Duration::from_millis(INTERVAL_UDP_IDLE_MS));
                    continue;
                }
                Err(e) => {
                    println!(
                        "udp_socket.recv() failed, error: {}, at [{}, {}]",
                        e,
                        file!(),
                        line!()
                    );
                    return;
                }
            }
        }
    }
}
