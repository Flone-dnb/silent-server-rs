// This file should be exactly like in the client.

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum ConnectServerAnswer {
    Ok,
    WrongProtocol,
    UsernameTaken,
    WrongPassword,
    ServerIsFull,
}

// there's no such thing as a packet in TCP (it's all just a stream)
// but the only thing that we receive unencrypted is the data size
// thus we check if this data has the size that we expect to handle
pub const TCP_PACKET_MAX_SIZE: u16 = 1400;
// this is an exception, the connect answer packet (from the server) contains
// a lot of data about rooms and users
// if you want to change this value to allow even more users
// you can easily do this here (change this value) + in the client's tcp_packets.rs
// that will be enough
pub const TCP_CONNECT_ANSWER_PACKET_MAX_SIZE: u64 = std::u16::MAX as u64;

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct ClientConnectPacket {
    pub net_protocol_version: u64,
    pub username: String,
    pub password: String,
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct ServerTcpConnectPacket {
    pub answer: ConnectServerAnswer,
    pub correct_net_protocol: Option<u64>, // will be some if the answer is WrongProtocol
    pub connected_info: Option<Vec<RoomNetInfo>>, // will be some if the answer is OK
}
#[derive(Serialize, Deserialize)]
pub struct RoomNetInfo {
    pub room_name: String,
    pub users: Vec<UserNetInfo>,
}
#[derive(Serialize, Deserialize)]
pub struct UserNetInfo {
    pub username: String,
    pub ping: u16,
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub enum ServerTcpMessage {
    UserConnected {
        username: String,
    },
    UserDisconnected {
        username: String,
    },
    UserMessage {
        username: String,
        message: String,
    },
    UserEntersRoom {
        username: String,
        room_enters: String,
    },
    KeepAliveCheck,
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub enum ClientTcpMessage {
    UserMessage { message: String },
    UserEnterRoom { room_name: String },
    KeepAliveCheck,
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
