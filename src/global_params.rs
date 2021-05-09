pub const CONFIG_FILE_NAME: &str = "silent_server.config";
pub const LOG_FILE_NAME: &str = "silent_server.log";
pub const CONFIG_FILE_MAGIC_NUMBER: u16 = 51338;
pub const CONFIG_FILE_VERSION: u64 = 0;

pub const SERVER_DEFAULT_PORT: u16 = 51337;
pub const SUPPORTED_CLIENT_VERSION: &str = "0.1.0";
pub const MAX_VERSION_STRING_LENGTH: u32 = 30;
pub const INTERVAL_TCP_MESSAGE_MS: u64 = 250;
pub const INTERVAL_TCP_MESSAGE_MS_UNDER_MUTEX: u64 = 10;
pub const INTERVAL_TCP_CONNECT_MS: u64 = 50;
