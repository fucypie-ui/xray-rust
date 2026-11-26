pub mod bind;
pub mod client;
pub mod config;
pub mod device;
mod datagram;
mod dns;
mod ipv6;
mod native;
pub mod gvisortun;
pub mod server;
mod stack;
pub mod tun;
pub mod tun_default;
pub mod tun_linux;
pub mod wireguard;

#[cfg(test)]
pub mod server_test;

pub use bind::WireGuardBind;
pub use client::Client;
pub use config::{WireGuardConfig, WireGuardPeer, parse_key};
pub use device::{WireGuardDevice, WireGuardStats};
pub use native::WireGuardInbound;
pub use server::{WireGuardInboundDatagram, WireGuardServer};
pub use stack::{WireGuardTcpStream, WireGuardUdpSocket};
pub use tun::WireGuardTunDevice;
pub use wireguard::{DEFAULT_MTU, PROTOCOL_NAME, create_ipc_request, parse_endpoints};
