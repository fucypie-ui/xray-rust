use crate::common::errors::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksAccount {
    #[serde(default, rename = "user")]
    pub username: String,
    #[serde(default, rename = "pass")]
    pub password: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SocksServerConfig {
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub accounts: HashMap<String, String>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default, rename = "userLevel")]
    pub user_level: Option<u32>,
}

// Keep the public account map and accept the original Rust map format, while
// decoding Go's accounts/users lists with their exact precedence semantics.
impl<'de> Deserialize<'de> for SocksServerConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Accounts {
            List(Vec<SocksAccount>),
            Map(HashMap<String, String>),
        }

        #[derive(Default, Deserialize)]
        struct RawConfig {
            #[serde(default)]
            auth: Option<String>,
            #[serde(default)]
            accounts: Option<Accounts>,
            #[serde(default)]
            users: Option<Vec<SocksAccount>>,
            #[serde(default)]
            udp: bool,
            #[serde(default)]
            ip: Option<String>,
            #[serde(default, rename = "userLevel", alias = "user_level")]
            user_level: Option<u32>,
        }

        let raw = RawConfig::deserialize(deserializer)?;
        let accounts = match raw.accounts {
            Some(Accounts::Map(accounts)) => accounts,
            Some(Accounts::List(accounts)) => accounts.into_iter()
                .map(|account| (account.username, account.password)).collect(),
            None => raw.users.unwrap_or_default().into_iter()
                .map(|account| (account.username, account.password)).collect(),
        };
        Ok(Self { auth: raw.auth, accounts, udp: raw.udp, ip: raw.ip, user_level: raw.user_level })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksRemoteConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub users: Option<Vec<SocksAccount>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksClientConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: u16,
    #[serde(default, rename = "user")]
    pub username: String,
    #[serde(default, rename = "pass")]
    pub password: String,
    #[serde(default)]
    pub servers: Option<Vec<SocksRemoteConfig>>,
}

impl SocksClientConfig {
    pub fn into_server(self) -> Result<SocksRemoteConfig> {
        // Go's flat address takes precedence over the entire servers list. A
        // flat password alone does not opt in to password authentication.
        let mut servers = if let Some(address) = self.address {
            let users = if self.username.is_empty() {
                None
            } else {
                Some(vec![SocksAccount { username: self.username, password: self.password }])
            };
            vec![SocksRemoteConfig { address: Some(address), port: self.port, users }]
        } else {
            self.servers.unwrap_or_default()
        };
        if servers.len() != 1 {
            return Err(Error::Config(
                "SOCKS settings: servers should have one and only one member; use separate outbounds and a routing balancer for multiple endpoints".into(),
            ));
        }
        let server = servers.pop().expect("validated one SOCKS server");
        if server.users.as_ref().is_some_and(|users| users.len() > 1) {
            return Err(Error::Config(
                "SOCKS servers: users should have one member at most; use separate outbounds and a routing balancer for multiple accounts".into(),
            ));
        }
        Ok(server)
    }
}
