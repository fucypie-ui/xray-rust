use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_rules_remove() -> Command {
    Command::new("remove-rules", "xray api remove-rules [-s=server:port]", "Remove routing rules dynamically")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        client.unsupported("remove-rules")
    })
}
