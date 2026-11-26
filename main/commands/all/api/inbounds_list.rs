use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_inbounds_list() -> Command {
    Command::new("list-inbounds", "xray api list-inbounds [-s=server:port]", "List active inbounds")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        client.unsupported("list-inbounds")
    })
}
