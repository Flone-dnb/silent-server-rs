use bytevec::{ByteDecodable, ByteEncodable};
use platform_dirs::UserDirs;

use crate::global_params::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[derive(Debug)]
pub struct ServerConfig {
    pub server_port: u16,
    pub server_password: String,
    pub config_file_path: String,
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
        }
    }

    fn get_config_file_path() -> Option<String> {
        let user_dirs = UserDirs::new();
        if user_dirs.is_none() {
            println!("can't read user dirs");
            return None;
        }
        let user_dirs = user_dirs.unwrap();

        let mut _config_file_path = String::new();
        if user_dirs.document_dir.ends_with("/") || user_dirs.document_dir.ends_with("\\") {
            _config_file_path =
                String::from(user_dirs.document_dir.to_str().unwrap()) + CONFIG_FILE_NAME;
        } else {
            _config_file_path =
                String::from(user_dirs.document_dir.to_str().unwrap()) + "/" + CONFIG_FILE_NAME;
        }

        Some(_config_file_path)
    }
}
