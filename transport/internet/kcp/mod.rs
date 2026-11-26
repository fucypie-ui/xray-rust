pub mod config;
pub mod connection;
pub mod dialer;
pub mod io;
pub mod kcp;
pub mod listener;
pub mod output;
pub mod receiving;
pub mod segment;
pub mod sending;
pub mod runtime;
mod engine;
mod wire;

#[cfg(test)]
pub mod connection_test;
#[cfg(test)]
pub mod io_test;
#[cfg(test)]
pub mod kcp_test;
#[cfg(test)]
pub mod segment_test;

pub use config::KcpConfig;
pub use connection::KcpConnection;
pub use runtime::{ConnectionStats, DatagramCodec, KcpStream, LegacyPacketCodec, PlainPacketCodec};
pub use dialer::{ConfiguredKcpDialer, KcpDialer};
pub use io::KcpIoQueue;
pub use kcp::PROTOCOL_NAME;
pub use listener::{KcpListener, KcpListenerOptions};
pub use output::SegmentWriter;
pub use receiving::ReceivingWindow;
pub use segment::{AckSegment, DataSegment};
pub use sending::SendingWindow;
#[cfg(test)]
mod scen_kcp_test;
#[cfg(test)]
mod runtime_test;
