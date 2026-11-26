use super::config::load_config;
use super::xray::Instance;
use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::infra::conf::Config;
use crate::transport::Link;
use crate::transport::internet::udp::{DispatcherConn, LinkDispatcher};
use crate::transport::internet::udp::dispatcher::dial_dispatcher_with_cancellation;
use crate::transport::pipe::{PipeOption, new_pipe};
use std::sync::Arc;

pub fn create_object(_instance: Option<&Instance>, config: &Config) -> Result<Instance> {
    Instance::from_config(config.clone())
}

pub fn start_instance(config_format: &str, config_bytes: &[u8]) -> Result<Instance> {
    let config = load_config(config_format, config_bytes)?;
    Instance::from_config(config)
}

pub async fn dial(instance: &Instance, dest: &Destination) -> Result<BoxStream> {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let session = SessionContext::new("dial".to_string(), dest.clone());
    let dispatcher = instance.dispatcher.clone();
    let task = tokio::spawn(async move {
        let _ = dispatcher.dispatch(Box::pin(server_stream), session).await;
    });
    instance.own_tasks(std::slice::from_ref(&task))?;
    Ok(Box::pin(client_stream))
}

pub async fn dial_udp(instance: &Instance) -> Result<DispatcherConn> {
    let cancellation = instance.cancellation_token()?;
    let dispatcher: Arc<dyn LinkDispatcher> = Arc::new(|_dest: Destination| -> Result<Link> {
        let (reader, writer) = new_pipe(PipeOption::new());
        Ok(Link::new(reader, writer))
    });
    dial_dispatcher_with_cancellation(dispatcher, cancellation).await
}
