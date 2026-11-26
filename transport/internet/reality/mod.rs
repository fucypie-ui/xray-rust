pub mod config;
pub mod reality;
mod certificate;
mod hello;
mod hooks;
mod kx;
mod stream;

#[cfg(test)]
pub mod reality_test;

pub use config::RealityConfig;
pub use reality::{RealityAuthSession, RealityClient, RealityServer, derive_auth_key, open_session_id, seal_session_id};
#[cfg(test)]
mod scen_reality_test;
#[cfg(test)]
mod config_test;
#[cfg(test)]
mod go_peer_test;
