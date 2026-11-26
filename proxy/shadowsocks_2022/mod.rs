pub mod client;
pub mod cipher;
pub mod config;
#[path = "config.pb.rs"]
pub mod config_pb;
pub mod inbound;
pub mod inbound_multi;
pub(crate) mod identity;
pub mod inbound_relay;
pub mod kdf;
pub mod outbound;
pub mod protocol;
pub mod replay;
pub mod server;
pub mod shadowsocks_2022;
pub mod stream;
pub mod validator;

#[cfg(test)]
pub mod config_test;

pub use client::Client;
pub use config::Shadowsocks2022Config;
pub use inbound::Shadowsocks2022Inbound;
pub use inbound_multi::Shadowsocks2022MultiInbound;
pub use inbound_relay::Shadowsocks2022RelayInbound;
pub use outbound::Shadowsocks2022Outbound;
pub use protocol::{HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, SessionHeader};
pub use server::Server;
pub use validator::CipherValidator;

pub mod multi_server;
pub mod relay_server;
pub mod packet;
pub mod udp_session;
mod native;

#[cfg(test)]
mod native_test;

#[cfg(test)]
mod extended_test;

#[cfg(test)]
mod go_peer_test;
