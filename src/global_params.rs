pub const CONFIG_FILE_NAME: &str = "silent_server.config";
pub const LOG_FILE_NAME: &str = "silent_server.log";
pub const CONFIG_FILE_MAGIC_NUMBER: u16 = 51338;
pub const CONFIG_FILE_VERSION: u64 = 0;

// these should be in sync with the client's global params
pub const MAX_MESSAGE_SIZE: usize = 500;
pub const MAX_USERNAME_SIZE: usize = 25;
pub const MAX_PASSWORD_SIZE: usize = 20;
pub const SPAM_PROTECTION_SEC: usize = 2; // client can send only 1 message per SPAM_PROTECTION_SEC
pub const PASSWORD_RETRY_DELAY_SEC: usize = 5;
pub const DEFAULT_ROOM_NAME: &str = "Lobby";

pub const SERVER_DEFAULT_PORT: u16 = 51337;

pub const SUPPORTED_CLIENT_VERSION: &str = "0.1.0";
pub const MAX_VERSION_STRING_LENGTH: u32 = 30;

pub const INTERVAL_TCP_IDLE_MS: u64 = 250;
pub const INTERVAL_TCP_MESSAGE_MS: u64 = 10;
