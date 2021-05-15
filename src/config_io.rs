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
            if let Err(e) = std::fs::remove_file(log_file_path) {
                return Err(format!("std::fs::remove_file() failed, error: can't remove old config file to save a new one (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
        }

        let file = File::create(log_file_path);
        if let Err(e) = file {
            return Err(format!(
                "File::create() failed, error: can't create log file (location {}) (error: {}) at [{}, {}]",
                log_file_path,
                e,
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
            if let Err(e) = file.write_all(format!("\n[{}:{}]", hour, minute).as_bytes()) {
                return Err(format!(
                    "File::write_all() failed, error: can't write time to log file (error: {}) at [{}, {}]",
                    e,
                    file!(),
                    line!()
                ));
            }
            if let Err(e) = file.write_all(format!("{}\n", info).as_bytes()) {
                return Err(format!(
                    "File::write_all() failed, error: can't write info to log file (error: {}) at [{}, {}]",
                    e,
                    file!(),
                    line!()
                ));
            }

            Ok(())
        } else {
            Err(format!(
                "An error occurred: no log file created, 'open()' log file first, at [{}, {}]",
                file!(),
                line!()
            ))
        }
    }
}

#[derive(Debug)]
pub struct RoomInfo {
    pub room_name: String,
}

impl Clone for RoomInfo {
    fn clone(&self) -> Self {
        RoomInfo {
            room_name: self.room_name.clone(),
        }
    }
}

impl RoomInfo {
    fn new(room_name: String) -> Self {
        RoomInfo { room_name }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    pub server_port: u16,
    pub server_password: String,
    pub rooms: Vec<RoomInfo>,
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
            rooms: self.rooms.clone(),
        }
    }

    pub fn clear_rooms(&mut self) {
        self.rooms.clear();
        self.rooms
            .push(RoomInfo::new(String::from(DEFAULT_ROOM_NAME)));
    }

    pub fn add_room(&mut self, room_name: String) -> Result<(), String> {
        if room_name.chars().count() > MAX_USERNAME_SIZE {
            return Err(format!(
                "room name is too long (max. len. is {})",
                MAX_USERNAME_SIZE
            ));
        }

        // find room with this name
        let room_entry = self
            .rooms
            .iter()
            .position(|room_info| room_info.room_name == room_name);
        if room_entry.is_some() {
            return Err(String::from("room name is not unique"));
        }

        self.rooms.push(RoomInfo::new(room_name));

        if self.rooms.len() == std::u16::MAX as usize {
            return Err(String::from("too many rooms created"));
        }

        Ok(())
    }

    pub fn remove_room(&mut self, room_name: String) -> Result<(), String> {
        let mut found = false;
        let mut found_at = 0usize;
        for (i, room) in self.rooms.iter().enumerate() {
            if room.room_name == room_name {
                found = true;
                found_at = i;
                break;
            }
        }

        if !found {
            return Err(format!("room ({}) not found", room_name));
        }

        if self.rooms.len() == 1 && self.rooms[0].room_name == DEFAULT_ROOM_NAME {
            return Err(String::from(
                "can't remove lobby room, it should always exist",
            ));
        }
        self.rooms.remove(found_at);

        Ok(())
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

        if !Path::new(&config_file_path).exists() {
            return Err(format!(
                "An error occurred, error: ServerConfig::read_config() failed: the file at ({}) does not exist at [{}, {}]",
                config_file_path,
                file!(),
                line!()
            ));
        }

        // Open existing config file.
        let config_file = File::open(&config_file_path);
        if let Err(e) = config_file {
            return Err(format!(
                "File::open() failed, error: can't open config file '{}' (error: {}) at [{}, {}]",
                e,
                config_file_path,
                file!(),
                line!()
            ));
        }
        let mut config_file = config_file.unwrap();

        // Read magic number.
        let mut buf = vec![0u8; std::mem::size_of::<u16>()];
        if let Err(e) = config_file.read(&mut buf) {
            return Err(format!(
                "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
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
        if let Err(e) = config_file.read(&mut buf) {
            return Err(format!(
                "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        // use it to handle old config versions...
        let config_version = u64::decode::<u64>(&buf).unwrap();

        // Read server port.
        let mut buf = vec![0u8; std::mem::size_of::<u16>()];
        if let Err(e) = config_file.read(&mut buf) {
            return Err(format!(
                "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        self.server_port = u16::decode::<u16>(&buf).unwrap();

        // Read server password size.
        let mut buf = vec![0u8; std::mem::size_of::<u32>()];
        let mut _password_byte_count = 0u32;
        if let Err(e) = config_file.read(&mut buf) {
            return Err(format!(
                "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        _password_byte_count = u32::decode::<u32>(&buf).unwrap();

        // Read server password.
        let mut buf = vec![0u8; _password_byte_count as usize];
        if _password_byte_count > 0 {
            if let Err(e) = config_file.read(&mut buf) {
                return Err(format!("File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
            let server_pass = std::str::from_utf8(&buf);
            if let Err(e) = server_pass {
                return Err(format!("std::str::from_utf8() failed, error: can't convert raw bytes to string (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
            self.server_password = String::from(server_pass.unwrap());
        }

        // Read room count.
        let mut buf = vec![0u8; std::mem::size_of::<u16>()];
        let mut _room_count = 0u16;
        if let Err(e) = config_file.read(&mut buf) {
            return Err(format!(
                "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()
            ));
        }
        _room_count = u16::decode::<u16>(&buf).unwrap();

        self.rooms.clear();

        for _ in 0.._room_count {
            // Read room name len.
            let mut buf = vec![0u8; std::mem::size_of::<u8>()];
            let mut _room_name_len = 0u8;
            if let Err(e) = config_file.read(&mut buf) {
                return Err(format!(
                    "File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                    e,
                    file!(),
                    line!()
                ));
            }
            _room_name_len = u8::decode::<u8>(&buf).unwrap();

            // Read room name.
            let mut buf = vec![0u8; _room_name_len as usize];
            if let Err(e) = config_file.read(&mut buf) {
                return Err(format!("File::read() failed, error: can't read from config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
            let room_name = std::str::from_utf8(&buf);
            if let Err(e) = room_name {
                return Err(format!("std::str::from_utf8() failed, error: can't convert raw bytes to string (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
            self.rooms
                .push(RoomInfo::new(String::from(room_name.unwrap())));
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
            if let Err(e) = std::fs::remove_file(&config_file_path) {
                return Err(
                format!("std::fs::remove_file() failed, error: can't remove old config file to save a new one (file exists at location: {}) (error: {}) at [{}, {}]",
                config_file_path,
                e,
                file!(),
                line!()));
            }
        }

        // Create new config file.
        let config_file = File::create(&config_file_path);
        if let Err(e) = config_file {
            format!("can't create new config file '{}'", config_file_path,);
            return Err(format!(
                "File::create() failed, error: can't create new config file at '{}' (error: {}) at [{}, {}]",
                config_file_path,
                e,
                file!(),
                line!()
            ));
        }
        let mut config_file = config_file.unwrap();

        // Write magic number.
        let magic_number = CONFIG_FILE_MAGIC_NUMBER;
        if let Err(e) = config_file.write(&magic_number.encode::<u16>().unwrap()) {
            return Err(
                format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
            e,
            file!(),
            line!()),
            );
        }

        // Write config file version.
        let config_version = CONFIG_FILE_VERSION;
        if let Err(e) = config_file.write(&config_version.encode::<u64>().unwrap()) {
            return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
            e,
            file!(),
            line!()));
        }

        // Write server port.
        if let Err(e) = config_file.write(&self.server_port.encode::<u16>().unwrap()) {
            return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
            e,
            file!(),
            line!()));
        }

        // Write server password size.
        let pass_size: u32 = self.server_password.len() as u32;
        if let Err(e) = config_file.write(&pass_size.encode::<u32>().unwrap()) {
            return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
            e,
            file!(),
            line!()));
        }

        // Write server password.
        if self.server_password.len() > 0 {
            if let Err(e) = config_file.write(self.server_password.as_bytes()) {
                return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
        }

        // Write room count.
        let room_count = self.rooms.len() as u16;
        if let Err(e) = config_file.write(&room_count.encode::<u16>().unwrap()) {
            return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
            e,
            file!(),
            line!()));
        }

        // Write rooms.
        for room in self.rooms.iter() {
            // Write room name len.
            let room_name_len = room.room_name.len() as u8;
            if let Err(e) = config_file.write(&room_name_len.encode::<u8>().unwrap()) {
                return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }

            // Write room name.
            if let Err(e) = config_file.write(room.room_name.as_bytes()) {
                return Err(format!("File::write() failed, error: can't write to new config file (error: {}) at [{}, {}]",
                e,
                file!(),
                line!()));
            }
        }

        Ok(())
    }

    fn default() -> Self {
        let default_rooms: Vec<RoomInfo> = vec![
            RoomInfo::new(String::from(DEFAULT_ROOM_NAME)),
            RoomInfo::new(String::from("Room 1")),
            RoomInfo::new(String::from("Room 2")),
            RoomInfo::new(String::from("Room 3")),
        ];
        ServerConfig {
            server_port: SERVER_DEFAULT_PORT,
            server_password: String::from(""),
            config_file_path: ServerConfig::get_config_file_path().unwrap(),
            log_file_path: ServerConfig::get_config_file_dir().unwrap() + LOG_FILE_NAME,
            rooms: default_rooms,
        }
    }

    fn get_config_file_path() -> Result<String, String> {
        let res = ServerConfig::get_config_file_dir();
        match res {
            Ok(path) => return Ok(path + CONFIG_FILE_NAME),
            Err(msg) => return Err(format!("{} at [{}, {}]", msg, file!(), line!())),
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
