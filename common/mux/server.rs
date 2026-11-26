use super::frame::{Frame, SessionStatus};
use super::session::{Session, SessionManager};
use crate::common::errors::{Error, Result};
use std::sync::Arc;

pub struct MuxServer {
    session_manager: Arc<SessionManager>,
}

impl MuxServer {
    pub fn new() -> Self { Self { session_manager: Arc::new(SessionManager::new()), } }
    pub async fn serve(&self, stream: crate::common::net::BoxStream, context: crate::common::protocol::SessionContext, dispatcher: Arc<dyn crate::features::inbound::InboundDispatcher>) -> Result<()> {
        super::runtime::serve_mux(stream, context, dispatcher).await
    }
    pub fn session_count(&self) -> usize { self.session_manager.size() }
    pub async fn dispatch_frame(&self, frame: Frame) -> Result<Option<Session>> {
        match frame.status {
            SessionStatus::New => {
                let target = frame.target.ok_or_else(|| Error::Protocol("mux New missing destination".into()))?;
                self.session_manager.remove(false, frame.session_id);
                let session = Session::with_channel(frame.session_id, target, 16);
                if !self.session_manager.add(&session) { return Err(Error::Closed); }
                if frame.option & super::frame::OPTION_DATA != 0 && let Some(sender) = &session.sender {
                    sender.send(frame.payload).await.map_err(|_| Error::Closed)?;
                }
                return Ok(Some(session));
            }
            SessionStatus::Keep => if let Some(s) = self.session_manager.get(frame.session_id) {
                if frame.option & super::frame::OPTION_DATA != 0 && let Some(ref sender) = s.sender { sender.send(frame.payload).await.map_err(|_| Error::Closed)?; }
                return Ok(Some(s));
            },
            SessionStatus::End => { self.session_manager.remove(false, frame.session_id); }
            _ => {}
        }
        Ok(None)
    }
    pub fn close(&self) { self.session_manager.close(); }
}

impl Default for MuxServer {
    fn default() -> Self { Self::new() }
}

pub type Server = MuxServer;
