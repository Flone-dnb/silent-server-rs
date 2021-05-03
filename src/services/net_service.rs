use bytevec::{ByteDecodable, ByteEncodable};
use tokio::net::{TcpListener, TcpStream};

use std::collections::LinkedList;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::user_net_service::*;
use crate::config_io::*;

pub struct UserInfo {
    pub username: String,
    tcp_addr: SocketAddr,
}
impl UserInfo {
    fn clone(&self) -> UserInfo {
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
    tokio_runtime: tokio::runtime::Runtime,
    is_running: bool,
}

impl NetService {
    pub fn new() -> Self {
        let rt = tokio::runtime::Runtime::new();
        if rt.is_err() {
            println!("can't start Tokio runtime");
            panic!();
        }

        Self {
            tokio_runtime: rt.unwrap(),
            server_config: ServerConfig::new().unwrap(),
            is_running: false,
            connected_users: Arc::new(Mutex::new(LinkedList::new())),
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
            "\nStarting... Listening on port {} for connection requests...",
            self.server_config.server_port
        )) {
            println!("ServerLogger failed, error: {}", e);
        }

        self.is_running = true;
        self.tokio_runtime.spawn(NetService::service(
            self.server_config.clone(),
            Arc::clone(&self.logger),
            Arc::clone(&self.connected_users),
        ));
    }

    pub fn stop(self) {
        let mut logger_guard = self.logger.as_ref().lock().unwrap();
        if let Err(e) = logger_guard.println_and_log("\nStop requested...") {
            println!("ServerLogger failed, error: {}", e);
        }

        self.tokio_runtime.shutdown_timeout(Duration::from_secs(5));

        println!("\nStopped.");
    }

    async fn service(
        server_config: ServerConfig,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
    ) {
        let listener_socket = TcpListener::bind(format!("127.0.0.1:{}", server_config.server_port))
            .await
            .unwrap();

        loop {
            let accept_result = listener_socket.accept().await;

            println!("");

            if let Err(e) = accept_result {
                println!("listener_socket.accept() failed, err: {}", e);
                continue;
            }

            let (socket, addr) = accept_result.unwrap();

            tokio::spawn(NetService::handle_user(
                socket,
                addr,
                Arc::clone(&logger),
                Arc::clone(&users),
            ));
        }
    }

    async fn handle_user(
        mut socket: TcpStream,
        addr: SocketAddr,
        logger: Arc<Mutex<ServerLogger>>,
        users: Arc<Mutex<LinkedList<UserInfo>>>,
    ) {
        let mut buf_u16 = [0u8; 2];
        let mut _var_u16 = 0u16;
        let mut is_error = true;
        let mut user_net_service = UserNetService::new();
        let mut _prev_user_state = user_net_service.user_state;
        let mut user_info = UserInfo {
            username: String::from(""),
            tcp_addr: addr,
        };

        // Read data from the socket.
        loop {
            // Read 2 bytes.
            match user_net_service
                .read_from_socket(&mut socket, &addr, &mut buf_u16)
                .await
            {
                ReadResult::FIN => {
                    is_error = false;
                    break;
                }
                ReadResult::WouldBlock => continue,
                ReadResult::Err(e) => {
                    println!("read_from_socket() failed, error: {}", e);
                    break;
                }
                ReadResult::Ok(_bytes) => {
                    let res = u16::decode::<u16>(&buf_u16);
                    if res.is_err() {
                        println!("socket ({}) decode(u16) failed", addr);
                        break;
                    }

                    _var_u16 = res.unwrap();
                }
            }

            // Save current state.
            _prev_user_state = user_net_service.user_state;

            // Using current state and these 2 bytes we know what to do.
            match user_net_service
                .handle_user_state(_var_u16, &mut socket, &addr, &mut user_info)
                .await
            {
                HandleStateResult::ReadErr(read_e) => match read_e {
                    ReadResult::FIN => {
                        is_error = false;
                        break;
                    }
                    ReadResult::Err(e) => {
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
                _ => {}
            };

            // See if state is changed.
            if _prev_user_state != user_net_service.user_state {
                if _prev_user_state == UserState::NotConnected
                    && user_net_service.user_state == UserState::Connected
                {
                    // New connected user.
                    let mut users_guard = users.lock().unwrap();
                    users_guard.push_back(user_info.clone());
                    drop(users_guard);

                    let mut logger_guard = logger.lock().unwrap();
                    if let Err(e) = logger_guard.println_and_log(&format!(
                        "New connection from ({:?}) AKA ({}).",
                        addr, user_info.username
                    )) {
                        println!("ServerLogger failed, error: {}", e);
                    }
                }
            }
        }

        // Erase from global users list.
        let mut users_guard = users.lock().unwrap();
        for (i, user) in users_guard.iter().enumerate() {
            if user.username == user_info.username {
                users_guard.remove(i);
                break;
            }
        }
        drop(users_guard);

        // Show output.
        let mut _out_str = String::from("");

        if is_error {
            if user_info.username != "" {
                _out_str = format!(
                    "Closing connection with socket ({}) AKA ({}) due to error.",
                    user_info.tcp_addr, user_info.username
                );
            } else {
                _out_str = format!(
                    "Closing connection with socket ({}) due to error.",
                    user_info.tcp_addr
                );
            }
        } else {
            _out_str = format!(
                "Closing connection with socket ({}) AKA ({}) in response to FIN.",
                user_info.tcp_addr, user_info.username
            );
        }

        let mut logger_guard = logger.lock().unwrap();
        if let Err(e) = logger_guard.println_and_log(&_out_str) {
            println!("ServerLogger failed, error: {}", e);
        }
    }
}
