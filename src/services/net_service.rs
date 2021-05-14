// External.
use bytevec::ByteDecodable;
use chrono::prelude::*;

// Std.
use std::collections::LinkedList;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Custom.
use super::user_tcp_service::*;
use crate::config_io::*;
use crate::global_params::*;

pub struct UserInfo {
    pub username: String,
    pub tcp_addr: SocketAddr,
    pub tcp_socket: TcpStream,
    pub tcp_io_mutex: Arc<Mutex<()>>,
    pub last_text_message_sent: DateTime<Local>,
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
            tcp_addr: self.tcp_addr.clone(),
            tcp_socket: tcp_socket_clone.unwrap(),
            tcp_io_mutex: Arc::clone(&self.tcp_io_mutex),
            last_text_message_sent: Local::now(),
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
            let banned_addrs_copy = Arc::clone(&banned_addrs);
            let user_io_lock_copy = Arc::clone(&user_enters_leaves_server_lock);
            let server_password_copy = server_config.server_password.clone();
            thread::spawn(move || {
                NetService::handle_user(
                    socket,
                    addr,
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
            tcp_addr: addr,
            tcp_socket: socket,
            tcp_io_mutex: Arc::new(Mutex::new(())),
            last_text_message_sent: init_time,
        };

        // Read data from the socket.
        loop {
            // Read 2 bytes.
            match user_net_service.read_from_socket(&mut user_info, &mut buf_u16) {
                IoResult::FIN => {
                    is_error = false;
                    break;
                }
                IoResult::WouldBlock => {
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

            // Using current state and these 2 bytes we know what to do.
            match user_net_service.handle_user_state(
                _var_u16,
                &mut user_info,
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
}
