pub const CONFIG_FILE_NAME: &str = "silent_server.config";
pub const LOG_FILE_NAME: &str = "silent_server.log";
pub const CONFIG_DIR_NAME: &str = "SilentServer";
pub const CONFIG_FILE_MAGIC_NUMBER: u16 = 51338;
pub const CONFIG_FILE_VERSION: u64 = 0;

// these should be in sync with the client's global params
pub const MAX_MESSAGE_SIZE: usize = 500;
pub const MAX_USERNAME_SIZE: usize = 25;
pub const MAX_PASSWORD_SIZE: usize = 20;
pub const SPAM_PROTECTION_SEC: usize = 2; // client can send only 1 message per SPAM_PROTECTION_SEC and can enter only 1 room per SPAM_PROTECTION_SEC
pub const PASSWORD_RETRY_DELAY_SEC: usize = 5;
pub const DEFAULT_ROOM_NAME: &str = "Lobby";
pub const IV_LENGTH: usize = 16;
pub const CMAC_TAG_LENGTH: usize = 16;

pub const SERVER_DEFAULT_PORT: u16 = 51337;
pub const NETWORK_PROTOCOL_VERSION: u64 = 1; // client with the same version is considered compatible

pub const INTERVAL_TCP_IDLE_MS: u64 = 250;
pub const INTERVAL_TCP_MESSAGE_MS: u64 = 10;
pub const INTERVAL_KEEP_ALIVE_CHECK_SEC: u64 = 60; // if user was inactive (no messages from user)
pub const TIME_TO_ANSWER_TO_KEEP_ALIVE_SEC: u64 = 10; // after we send keep alive
pub const INTERVAL_PING_CHECK_SEC: i64 = 30; // update ping every 'INTERVAL_PING_CHECK_SEC' seconds

pub const INTERVAL_UDP_WAIT_FOR_CONNECTION_MS: u64 = 30;
pub const INTERVAL_UDP_IDLE_MS: u64 = 10;
pub const INTERVAL_UDP_MESSAGE_MS: u64 = 2;
