use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_stats_get() -> Command {
    Command::new("get-stats", "xray api get-stats [-s=server:port]", "Get traffic statistics for a name")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        client.unsupported("get-stats")
    })
}
