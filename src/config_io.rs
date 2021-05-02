use bytevec::{ByteDecodable, ByteEncodable};
use platform_dirs::UserDirs;

use crate::global_params::*;
use chrono::prelude::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub struct ServerLogger {
    file_handle: Option<File>,
}

impl ServerLogger {
    pub fn new() -> Self {
        ServerLogger { file_handle: None }
    }
    pub fn open(&mut self, log_file_path: &String) -> Result<(), &'static str> {
        if Path::new(log_file_path).exists() {
            // Remove existing (old) config file.
            if std::fs::remove_file(log_file_path).is_err() {
                return Err("can't remove old config file to save a new config");
            }
        }

        let file = File::create(log_file_path);
        if file.is_err() {
            return Err("can't create log file");
        }
        self.file_handle = Some(file.unwrap());

        Ok(())
    }
    pub fn println_and_log(&mut self, info: &str) -> Result<(), &'static str> {
        println!("{}", info);

        if self.file_handle.is_some() {
            let now = Local::now();
            let mut hour: String = now.hour().to_string();
            let mut minute: String = now.minute().to_string();

            if hour.len() == 1 {
                hour = String::from("0") + &hour;
            }

            if minute.len() == 1 {
                minute = String::from("0") + &minute;
            }

            let file = self.file_handle.as_mut().unwrap();
            if file
                .write_all(format!("\n[{}:{}]", hour, minute).as_bytes())
                .is_err()
            {
                return Err("can't write time to log file");
            }
            if file.write_all(format!("{}\n", info).as_bytes()).is_err() {
                return Err("can't write info to log file");
            }

            Ok(())
        } else {
            Err("no log file, 'open()' log file first")
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    pub server_port: u16,
    pub server_password: String,
    pub config_file_path: String,
    pub log_file_path: String,
}

impl ServerConfig {
    pub fn new() -> Option<Self> {
        let config_file_path = ServerConfig::get_config_file_path();
        if config_file_path.is_none() {
            return None;
        }
        let config_file_path = config_file_path.unwrap();

        if Path::new(&config_file_path).exists() {
            //
            // Open existing config file.
            //
            let config_file = File::open(&config_file_path);
            if config_file.is_err() {
                format!("can't open config file '{}'", config_file_path,);
                return None;
            }
            let mut config_file = config_file.unwrap();

            let mut server_config = ServerConfig::default();
            //
            // Fill default config with data from file.
            //
            // Read server port.
            let mut buf = vec![0u8; 2];
            if config_file.read(&mut buf).is_err() {
                println!("can't read 'server_port' from config file");
                return None;
            }
            server_config.server_port = u16::decode::<u16>(&buf).unwrap();

            // Read server password size.
            let mut buf = vec![0u8; 4];
            let mut _password_byte_count = 0u32;
            if config_file.read(&mut buf).is_err() {
                println!("can't read server's password size from config file");
                return None;
            }
            _password_byte_count = u32::decode::<u32>(&buf).unwrap();

            // Read server password.
            let mut buf = vec![0u8; _password_byte_count as usize];
            if _password_byte_count > 0 {
                if config_file.read(&mut buf).is_err() {
                    println!("can't read 'server_password' from config file");
                    return None;
                }
                let server_pass = std::str::from_utf8(&buf);
                if server_pass.is_err() {
                    println!("can't convert raw bytes of 'server_password' to string");
                    return None;
                }
                server_config.server_password = String::from(server_pass.unwrap());
            }

            Some(server_config)
        } else {
            //
            // Create new config file with default settings.
            //
            let server_config = ServerConfig::default();
            if server_config.save_config().is_err() {
                return None;
            }

            Some(server_config)
        }
    }

    pub fn clone(&self) -> ServerConfig {
        ServerConfig {
            server_port: self.server_port,
            server_password: self.server_password.clone(),
            config_file_path: self.config_file_path.clone(),
            log_file_path: self.log_file_path.clone(),
        }
    }

    pub fn reset_config(&mut self) -> Self {
        ServerConfig::default()
    }

    pub fn save_config(&self) -> Result<(), ()> {
        let config_file_path = ServerConfig::get_config_file_path();
        if config_file_path.is_none() {
            return Err(());
        }
        let config_file_path = config_file_path.unwrap();

        if Path::new(&config_file_path).exists() {
            //
            // Remove existing (old) config file.
            //
            if std::fs::remove_file(&config_file_path).is_err() {
                println!("can't remove old config file to save a new config");
                return Err(());
            }
        }
        //
        // Create new config file.
        //
        let config_file = File::create(&config_file_path);
        if config_file.is_err() {
            format!("can't create new config file '{}'", config_file_path,);
            return Err(());
        }
        let mut config_file = config_file.unwrap();

        // Write server port.
        if config_file
            .write(&self.server_port.encode::<u16>().unwrap())
            .is_err()
        {
            println!("can't write 'server_port' to new config file");
            return Err(());
        }

        // Write server password size.
        let pass_size: u32 = self.server_password.len() as u32;
        if config_file
            .write(&pass_size.encode::<u32>().unwrap())
            .is_err()
        {
            println!("can't write server's password size to new config file");
            return Err(());
        }

        // Write server password.
        if self.server_password.len() > 0 {
            if config_file.write(self.server_password.as_bytes()).is_err() {
                println!("can't write 'server_password' to new config file");
                return Err(());
            }
        }

        Ok(())
    }

    fn default() -> Self {
        ServerConfig {
            server_port: SERVER_DEFAULT_PORT,
            server_password: String::from(""),
            config_file_path: ServerConfig::get_config_file_path().unwrap(),
            log_file_path: ServerConfig::get_config_file_dir().unwrap() + LOG_FILE_NAME,
        }
    }

    fn get_config_file_path() -> Option<String> {
        Some(ServerConfig::get_config_file_dir().unwrap() + CONFIG_FILE_NAME)
    }

    fn get_config_file_dir() -> Option<String> {
        let user_dirs = UserDirs::new();
        if user_dirs.is_none() {
            println!("can't read user dirs");
            return None;
        }
        let user_dirs = user_dirs.unwrap();

        let config_dir = String::from(user_dirs.document_dir.to_str().unwrap());

        let mut _config_file_path = config_dir;
        if !_config_file_path.ends_with("/") && !_config_file_path.ends_with("\\") {
            _config_file_path += "/";
        }

        Some(_config_file_path)
    }
}
