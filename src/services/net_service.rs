use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config_io::*;

pub struct NetService {
    pub server_config: ServerConfig,
    tokio_runtime: tokio::runtime::Runtime,
    is_running: bool,
    logger: Arc<Mutex<ServerLogger>>,
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

    async fn service(server_config: ServerConfig, logger: Arc<Mutex<ServerLogger>>) {
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

            let (mut socket, addr) = accept_result.unwrap();
            let mut logger_guard = logger.lock().unwrap();
            if let Err(e) = logger_guard.println_and_log(&format!("New connection from {:?}", addr))
            {
                println!("ServerLogger failed, error: {}", e);
            }

            tokio::spawn(async move {
                let mut buf = [0; 2];

                // Read data from the socket and write the data back.
                loop {
                    let n = match socket.read(&mut buf).await {
                        // socket closed
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(e) => {
                            println!("failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };

                    // Write the data back
                    if let Err(e) = socket.write_all(&buf[0..n]).await {
                        eprintln!("failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
    }
}
