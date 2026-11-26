//! Feature-level entry points shared by stream, packet, and multiplex inbounds.
use super::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, datagram::BoxDatagram};
use crate::common::protocol::SessionContext;
use crate::features::inbound::InboundDispatcher;
use crate::features::outbound::OutboundHandler;
use async_trait::async_trait;
use std::sync::Arc;

impl DefaultDispatcher {
    pub(super) async fn packet_outbound(&self, session: &mut SessionContext) -> Result<Arc<dyn OutboundHandler>> {
        let tag = if let Some(tag) = &session.forced_outbound_tag { tag.clone() }
        else if let Some(router) = &self.router {
            router.pick_outbound(session).map(str::to_owned)
                .or_else(|| self.default_outbound_tag.clone())
                .ok_or_else(|| Error::NotFound("No matching outbound route found".into()))?
        } else {
            self.default_outbound_tag.clone().or_else(|| self.outbounds.keys().next().cloned())
                .ok_or_else(|| Error::NotFound("No outbound handlers configured".into()))?
        };
        let dynamic = match &self.outbound_manager {
            Some(manager) => manager.get_handler(&tag).await,
            None => None,
        };
        let handler = dynamic.or_else(|| self.outbounds.get(&tag).cloned())
            .ok_or_else(|| Error::NotFound(format!("Outbound handler '{tag}' not found")))?;
        session.outbound_tag = Some(tag);
        Ok(handler)
    }
}

#[async_trait]
impl InboundDispatcher for DefaultDispatcher {
    async fn dispatch_stream(&self, stream: BoxStream, session: SessionContext) -> Result<()> {
        self.dispatch(stream, session).await
    }
    async fn connect_stream(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut session = session.clone();
        let handler = self.packet_outbound(&mut session).await?;
        handler.connect(&session).await
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        super::datagram::dispatch(self, packets, session).await
    }
}
