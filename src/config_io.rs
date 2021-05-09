// External.
use bytevec::{ByteDecodable, ByteEncodable};
use chrono::prelude::*;
use platform_dirs::UserDirs;

// Std.
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

// Custom.
use crate::global_params::*;

pub struct ServerLogger {
    file_handle: Option<File>,
}

impl ServerLogger {
    pub fn new() -> Self {
        ServerLogger { file_handle: None }
    }
    pub fn open(&mut self, log_file_path: &String) -> Result<(), String> {
        if Path::new(log_file_path).exists() {
            // Remove existing (old) config file.
            if std::fs::remove_file(log_file_path).is_err() {
                return Err(format!("std::fs::remove_file() failed, error: can't remove old config file to save a new one at [{}, {}]", file!(), line!()));
            }
        }

        let file = File::create(log_file_path);
        if file.is_err() {
            return Err(format!(
                "File::create() failed, error: can't create log file (location {}) at [{}, {}]",
                log_file_path,
                file!(),
                line!()
            ));
        }
        self.file_handle = Some(file.unwrap());

        Ok(())
    }
    pub fn println_and_log(&mut self, info: &str) -> Result<(), String> {
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
                return Err(format!(
                    "File::write_all() failed, error: can't write time to log file at [{}, {}]",
                    file!(),
                    line!()
                ));
            }
            if file.write_all(format!("{}\n", info).as_bytes()).is_err() {
                return Err(format!(
                    "File::write_all() failed, error: can't write info to log file at [{}, {}]",
                    file!(),
                    line!()
                ));
            }

            Ok(())
        } else {
            Err(format!(
                "An error occurred: no log file created, 'open()' log file first at [{}, {}]",
                file!(),
                line!()
            ))
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
    pub fn new() -> Result<Self, String> {
        let config_file_path = ServerConfig::get_config_file_path();
        if let Err(msg) = config_file_path {
            return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
        }
        let config_file_path = config_file_path.unwrap();

        if Path::new(&config_file_path).exists() {
            // Read existing config file.
            let mut server_config = ServerConfig::default();
            match server_config.read_config() {
                Ok(()) => Ok(server_config),
                Err(msg) => {
                    return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
                }
            }
        } else {
            // Create new config file with default settings.
            let server_config = ServerConfig::default();
            if let Err(msg) = server_config.save_config() {
                return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
            }

            Ok(server_config)
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

    pub fn read_config(&mut self) -> Result<(), String> {
        let config_file_path = ServerConfig::get_config_file_path();
        if let Err(msg) = config_file_path {
            return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
        }
        let config_file_path = config_file_path.unwrap();

        //
        // Open existing config file.
        //
        let config_file = File::open(&config_file_path);
        if config_file.is_err() {
            return Err(format!(
                "File::open() failed, error: can't open config file '{}' at [{}, {}]",
                config_file_path,
                file!(),
                line!()
            ));
        }
        let mut config_file = config_file.unwrap();

        // Read magic number.
        let mut buf = vec![0u8; std::mem::size_of::<u16>()];
        if config_file.read(&mut buf).is_err() {
            return Err(format!(
                "File::read() failed, error: can't read 'server_port' from config file at [{}, {}]",
                file!(),
                line!()
            ));
        }
        let magic_number = u16::decode::<u16>(&buf).unwrap();
        if magic_number != CONFIG_FILE_MAGIC_NUMBER {
            return Err(format!(
                "An error occurred: file magic number ({}) != config magic number ({}) at [{}, {}]",
                magic_number,
                CONFIG_FILE_MAGIC_NUMBER,
                file!(),
                line!(),
            ));
        }

        // Read config version.
        let mut buf = vec![0u8; std::mem::size_of::<u64>()];
        if config_file.read(&mut buf).is_err() {
            return Err(format!(
                "File::read() failed, error: can't read 'server_port' from config file at [{}, {}]",
                file!(),
                line!()
            ));
        }
        // use it to handle old config versions...
        let config_version = u64::decode::<u64>(&buf).unwrap();

        // Read server port.
        let mut buf = vec![0u8; 2];
        if config_file.read(&mut buf).is_err() {
            return Err(format!(
                "File::read() failed, error: can't read 'server_port' from config file at [{}, {}]",
                file!(),
                line!()
            ));
        }
        self.server_port = u16::decode::<u16>(&buf).unwrap();

        // Read server password size.
        let mut buf = vec![0u8; 4];
        let mut _password_byte_count = 0u32;
        if config_file.read(&mut buf).is_err() {
            return Err(format!("File::read() failed, error: can't read server's password size from config file at [{}, {}]",
            file!(),
            line!()));
        }
        _password_byte_count = u32::decode::<u32>(&buf).unwrap();

        // Read server password.
        let mut buf = vec![0u8; _password_byte_count as usize];
        if _password_byte_count > 0 {
            if config_file.read(&mut buf).is_err() {
                return Err(format!("File::read() failed, error: can't read 'server_password' from config file at [{}, {}]",
                file!(),
                line!()));
            }
            let server_pass = std::str::from_utf8(&buf);
            if server_pass.is_err() {
                return Err(format!("std::str::from_utf8() failed, error: can't convert raw bytes of 'server_password' to string at [{}, {}]",
                file!(),
                line!()));
            }
            self.server_password = String::from(server_pass.unwrap());
        }

        //
        // please use 'config_version' variable to handle old config versions...
        //

        Ok(())
    }

    pub fn save_config(&self) -> Result<(), String> {
        let config_file_path = ServerConfig::get_config_file_path();
        if let Err(msg) = config_file_path {
            return Err(format!("{} at [{}, {}]", msg, file!(), line!()));
        }
        let config_file_path = config_file_path.unwrap();

        if Path::new(&config_file_path).exists() {
            // Remove existing (old) config file.
            if std::fs::remove_file(&config_file_path).is_err() {
                return Err(
                format!("std::fs::remove_file() failed, error: can't remove old config file to save a new one (file exists at location: {}) at [{}, {}]",
                config_file_path,
                file!(),
                line!()));
            }
        }

        // Create new config file.
        let config_file = File::create(&config_file_path);
        if config_file.is_err() {
            format!("can't create new config file '{}'", config_file_path,);
            return Err(format!(
                "File::create() failed, error: can't create new config file at '{}' at [{}, {}]",
                config_file_path,
                file!(),
                line!()
            ));
        }
        let mut config_file = config_file.unwrap();

        // Write magic number.
        let magic_number = CONFIG_FILE_MAGIC_NUMBER;
        if config_file
            .write(&magic_number.encode::<u16>().unwrap())
            .is_err()
        {
            return Err(format!("File::write() failed, error: can't write 'magic_number' to new config file at [{}, {}]",
            file!(),
            line!()));
        }

        // Write config file version.
        let config_version = CONFIG_FILE_VERSION;
        if config_file
            .write(&config_version.encode::<u64>().unwrap())
            .is_err()
        {
            return Err(format!("File::write() failed, error: can't write 'config_version' to new config file at [{}, {}]",
            file!(),
            line!()));
        }

        // Write server port.
        if config_file
            .write(&self.server_port.encode::<u16>().unwrap())
            .is_err()
        {
            return Err(format!("File::write() failed, error: can't write 'server_port' to new config file at [{}, {}]",
            file!(),
            line!()));
        }

        // Write server password size.
        let pass_size: u32 = self.server_password.len() as u32;
        if config_file
            .write(&pass_size.encode::<u32>().unwrap())
            .is_err()
        {
            return Err(format!("File::write() failed, error: can't write server's password size to new config file at [{}, {}]",
            file!(),
            line!()));
        }

        // Write server password.
        if self.server_password.len() > 0 {
            if config_file.write(self.server_password.as_bytes()).is_err() {
                return Err(format!("File::write() failed, error: can't write 'server_password' to new config file at [{}, {}]",
                file!(),
                line!()));
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

    fn get_config_file_path() -> Result<String, String> {
        let res = ServerConfig::get_config_file_dir();
        match res {
            Ok(path) => return Ok(path + CONFIG_FILE_NAME),
            Err(msg) => return Err(msg),
        }
    }

    fn get_config_file_dir() -> Result<String, String> {
        let user_dirs = UserDirs::new();
        if user_dirs.is_none() {
            return Err(format!(
                "UserDirs::new() failed, error: can't read user dirs at [{}, {}]",
                file!(),
                line!(),
            ));
        }
        let user_dirs = user_dirs.unwrap();

        let config_dir = String::from(user_dirs.document_dir.to_str().unwrap());

        let mut _config_file_path = config_dir;
        if !_config_file_path.ends_with("/") && !_config_file_path.ends_with("\\") {
            _config_file_path += "/";
        }

        Ok(_config_file_path)
    }
}
