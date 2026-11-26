use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use crate::common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::BoxDatagram}, protocol::{RequestCommand, SessionContext}};
use crate::features::outbound::OutboundHandler;
use crate::proxy::vmess::encoding::{BodySecurity, RequestHeader, VmessDatagram, VmessStream, OPTION_CHUNK_STREAM, OPTION_CHUNK_MASKING, OPTION_GLOBAL_PADDING};
use crate::transport::internet::{TcpDialer, TlsClient};
use crate::transport::internet::dialer::Dialer;

pub struct Client {
    tag: String,
    server_addr: Destination,
    user_id: Uuid,
    tls_client: Option<Arc<TlsClient>>,
    tls_sni: Option<String>,
    dialer: Option<Arc<dyn Dialer>>,
    security: BodySecurity,
    options: u8,
    termination_signal: bool,
}
impl Client {
    pub fn new(tag: impl Into<String>, server_addr: Destination, user_id: Uuid, tls_client: Option<TlsClient>, tls_sni: Option<String>) -> Self {
        Self {tag:tag.into(),server_addr,user_id,tls_client:tls_client.map(Arc::new),tls_sni,dialer:None,
            security:BodySecurity::auto(),options:OPTION_CHUNK_STREAM|OPTION_CHUNK_MASKING|OPTION_GLOBAL_PADDING,termination_signal:true}
    }
    pub fn with_security(mut self, security: &str) -> Result<Self> {self.security=BodySecurity::from_name(security)?;Ok(self)}
    pub fn with_options(mut self, options: u8) -> Self {self.options=options;self}
    pub fn with_termination_signal(mut self, enabled: bool) -> Self {self.termination_signal=enabled;self}
    pub fn with_dialer(mut self, dialer: Arc<dyn Dialer>) -> Self {self.dialer=Some(dialer);self}
    async fn dial_transport(&self) -> Result<BoxStream> {
        let tcp = if let Some(dialer) = &self.dialer {
            dialer.dial(&self.server_addr).await?
        } else { TcpDialer::dial(&self.server_addr).await? };
        if let Some(tls) = &self.tls_client {
            let sni = self.tls_sni.as_deref().unwrap_or_else(|| match &self.server_addr.address {
                crate::common::net::Address::Domain(domain) => domain.as_str(), _ => "localhost",
            });
            tls.connect(sni, tcp).await
        } else { Ok(tcp) }
    }
    /// Use an already-established transport, including native multiplex lanes.
    pub async fn open_session(&self, mut stream: BoxStream, destination: Destination, command: RequestCommand) -> Result<VmessStream> {
        let mut request=RequestHeader::new(self.user_id,command,destination);
        request.security=self.security;request.options=self.options;
        request.encode(&mut stream).await?;
        Ok(VmessStream::client(stream,request)?.with_termination_signal(self.termination_signal))
    }
}
#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str {&self.tag}
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        if session.destination.network == Network::Udp {
            return Err(Error::Unsupported("VMess UDP requires connect_datagram".into()));
        }
        let stream = self.dial_transport().await?;
        Ok(self.open_session(stream,session.destination.clone(),RequestCommand::Tcp).await?.into_boxed())
    }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> {
        let mut destination = session.destination.clone();
        destination.network = Network::Udp;
        let stream = self.dial_transport().await?;
        let stream = self.open_session(stream, destination.clone(), RequestCommand::Udp).await?;
        VmessDatagram::outbound(stream, destination)
    }
}
pub use Client as VmessOutboundClient;
