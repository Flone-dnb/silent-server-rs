use bytevec::ByteDecodable;

use std::collections::LinkedList;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::user_net_service::*;
use crate::config_io::*;
use crate::global_params::*;

pub struct UserInfo {
    pub username: String,
    pub tcp_addr: SocketAddr,
}
impl UserInfo {
    pub fn clone(&self) -> UserInfo {
        UserInfo {
            username: self.username.clone(),
            tcp_addr: self.tcp_addr.clone(),
        }
    }
}

pub struct NetService {
    pub server_config: ServerConfig,
    connected_users: Arc<Mutex<LinkedList<UserInfo>>>,
    logger: Arc<Mutex<ServerLogger>>,
    user_enters_leaves_server_lock: Arc<Mutex<()>>,
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
        }
    }

    pub fn start(&mut self) {
        if self.is_running {
            println!("\nAlready running...");
            return;
        }

        let mut logger_guard = self.logger.lock().unwrap();

        if let Err(e) = logger_guard.open(&self.server_config.log_file_path) {
            println!("ServerLogger::open() failed, error: {}", e);
        }

        if let Err(e) = logger_guard.println_and_log(&format!(
            "Starting... Listening on port {} for connection requests...",
            self.server_config.server_port
        )) {
            println!("ServerLogger failed, error: {}", e);
        }

        self.is_running = true;

        let server_config_copy = self.server_config.clone();
        let logger_copy = Arc::clone(&self.logger);
        let users_copy = Arc::clone(&self.connected_users);
        let user_io_lock_copy = Arc::clone(&self.user_enters_leaves_server_lock);
        thread::spawn(move || {
            NetService::service(
                server_config_copy,
                logger_copy,
                users_copy,
                user_io_lock_copy,
            )
        });
    }

    fn service(
        server_config: ServerConfig,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        user_enters_leaves_server_lock: Arc<Mutex<()>>,
    ) {
        let listener_socket = TcpListener::bind(format!("127.0.0.1:{}", server_config.server_port));

        if listener_socket.is_err() {
            println!("listener_socket.accept() failed.");
            return;
        }
        let listener_socket = listener_socket.unwrap();

        loop {
            let accept_result = listener_socket.accept();

            if let Err(e) = accept_result {
                println!("listener_socket.accept() failed, err: {}", e);
                continue;
            }

            let (socket, addr) = accept_result.unwrap();
            if socket.set_nodelay(true).is_err() {
                println!("socket.set_nodelay() failed on addr ({}).", addr);
                continue;
            }
            if socket.set_nonblocking(true).is_err() {
                println!("socket.set_nonblocking() failed on addr ({}).", addr);
                continue;
            }

            let logger_copy = Arc::clone(&logger);
            let users_copy = Arc::clone(&users);
            let user_io_lock_copy = Arc::clone(&user_enters_leaves_server_lock);
            thread::spawn(move || {
                NetService::handle_user(socket, addr, logger_copy, users_copy, user_io_lock_copy)
            });
        }
    }

    fn handle_user(
        mut socket: TcpStream,
        addr: SocketAddr,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
        user_enters_leaves_server_lock: Arc<Mutex<()>>,
    ) {
        let mut buf_u16 = [0u8; 2];
        let mut _var_u16 = 0u16;
        let mut is_error = true;
        let mut user_net_service = UserNetService::new();
        let mut user_info = UserInfo {
            username: String::from(""),
            tcp_addr: addr,
        };

        // Read data from the socket.
        loop {
            // Read 2 bytes.
            match user_net_service.read_from_socket(&mut socket, &addr, &mut buf_u16) {
                IoResult::FIN => {
                    is_error = false;
                    break;
                }
                IoResult::WouldBlock => {
                    thread::sleep(Duration::from_millis(INTERVAL_TCP_MESSAGE_MS));
                    continue;
                }
                IoResult::Err(e) => {
                    println!("read_from_socket() failed, error: {}", e);
                    break;
                }
                IoResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&buf_u16);
                    if res.is_err() {
                        println!("socket ({}) decode(u16) failed", addr);
                        break;
                    }

                    _var_u16 = res.unwrap();
                }
            }

            // Using current state and these 2 bytes we know what to do.
            match user_net_service.handle_user_state(
                _var_u16,
                &mut socket,
                &addr,
                &mut user_info,
                Arc::clone(&users),
                Arc::clone(&user_enters_leaves_server_lock),
                Arc::clone(&logger),
            ) {
                HandleStateResult::ReadErr(read_e) => match read_e {
                    IoResult::FIN => {
                        is_error = false;
                        break;
                    }
                    IoResult::Err(e) => {
                        println!(
                            "handle_user_state().read_from_socket() failed, error: {}",
                            e
                        );
                        break;
                    }
                    _ => {}
                },
                HandleStateResult::HandleStateErr(msg) => {
                    println!("handle_user_state() failed, error: {}", msg);
                    break;
                }
                HandleStateResult::ErrInfo(msg) => {
                    println!(
                        "handle_user_state() returned status on socket ({}): {}",
                        addr, msg
                    );
                    break;
                }
                _ => {}
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
            println!("ServerLogger failed, error: {}", e);
        }
    }
}
