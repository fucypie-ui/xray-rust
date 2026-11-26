use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_stats_query() -> Command {
    Command::new("query-stats", "xray api query-stats [-s=server:port]", "Query patterned statistics")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        client.unsupported("query-stats")
    })
}
