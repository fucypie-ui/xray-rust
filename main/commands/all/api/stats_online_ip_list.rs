use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_stats_online_ip_list() -> Command {
    Command::new("online-ip-list", "xray api online-ip-list [-s=server:port]", "List active IP addresses for user")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        client.unsupported("online-ip-list")
    })
}
