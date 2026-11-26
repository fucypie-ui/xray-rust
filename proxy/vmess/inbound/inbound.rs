use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;
use crate::common::{errors::{Error, Result}, net::{BoxStream, Destination}, protocol::{RequestCommand, SessionContext, User}};
use crate::features::inbound::{InboundDispatcher, InboundHandler, InboundResult};
use crate::proxy::vmess::{encoding::{RequestHeader, VmessDatagram, VmessStream}, validator::MemoryValidator};

pub struct Server { tag: String, validator: Arc<MemoryValidator> }
impl Server {
    pub fn new(tag: impl Into<String>, users: Vec<Uuid>) -> Self {
        let validator=MemoryValidator::new();
        for user in users {let _=validator.add(User::new(user));}
        Self {tag:tag.into(),validator:Arc::new(validator)}
    }
    pub fn with_validator(tag: impl Into<String>, validator: Arc<MemoryValidator>) -> Self {Self {tag:tag.into(),validator}}
    pub fn validator(&self) -> &Arc<MemoryValidator> {&self.validator}
    /// Native integration point for a parent-owned Mux.Cool dispatcher.
    pub async fn accept_session(&self, mut stream: BoxStream) -> Result<(VmessStream, RequestHeader, User)> {
        let request=RequestHeader::decode(&mut stream,&self.validator).await?;
        let user=self.validator.get(&request.user_id).ok_or_else(|| Error::AuthFailed("VMess user was removed".into()))?;
        let authenticated=VmessStream::server(stream,request.clone())?;
        Ok((authenticated,request,user))
    }
}
#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str {&self.tag}
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let (stream,request,user)=self.accept_session(stream).await?;
        if request.command!=RequestCommand::Tcp {
            return Err(Error::Unsupported("VMess UDP and Mux require dispatch_connection".into()));
        }
        let mut session=SessionContext::new(&self.tag,request.destination);
        session.source=Some(remote_addr);session.user=Some(user);
        Ok(InboundResult {stream:stream.into_boxed(),session})
    }
    async fn dispatch_connection(&self, stream: BoxStream, remote_addr: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
        let (stream, request, user) = self.accept_session(stream).await?;
        let mut session = SessionContext::new(&self.tag, request.destination.clone());
        session.source = Some(remote_addr);
        session.user = Some(user);
        match request.command {
            RequestCommand::Tcp => dispatcher.dispatch_stream(stream.into_boxed(), session).await,
            RequestCommand::Udp => {
                let source = Destination::udp(remote_addr.ip().into(), remote_addr.port());
                let packets = VmessDatagram::inbound(stream, request.destination, Some(source))?;
                dispatcher.dispatch_datagrams(packets, session).await
            }
            RequestCommand::Mux => crate::common::mux::serve_mux(stream.into_boxed(), session, dispatcher).await,
            _ => Err(Error::Protocol("unsupported VMess dispatch command".into())),
        }
    }
}
pub use Server as VMessInboundServer;
