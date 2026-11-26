//! Owned Mux.Cool carrier: one ordered writer, bounded queues, owned children.
use super::frame::{Frame, SessionStatus, OPTION_DATA, OPTION_ERROR, MAX_UDP_PAYLOAD};
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::net::datagram::{BoxDatagram, Datagram, datagram_pair};
use crate::common::protocol::SessionContext;
use crate::features::inbound::InboundDispatcher;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

#[derive(Clone, Debug)]
pub struct MuxLimits {
    pub max_sessions: usize,
    pub frame_queue: usize,
    pub session_queue: usize,
    pub stream_buffer: usize,
    pub keepalive: Duration,
}
impl Default for MuxLimits {
    fn default() -> Self {
        Self { max_sessions: 128, frame_queue: 32, session_queue: 16, stream_buffer: 65_536, keepalive: Duration::from_secs(30) }
    }
}
impl MuxLimits {
    fn validate(&self) -> Result<()> {
        if self.max_sessions == 0 || self.max_sessions > 65_536 || self.frame_queue == 0 || self.session_queue == 0 || self.stream_buffer == 0 || self.keepalive.is_zero() {
            return Err(Error::Config("mux limits must be positive and session count fit u16 identifiers".into()));
        }
        Ok(())
    }
}
struct CarrierOwner(JoinHandle<()>);
impl Drop for CarrierOwner { fn drop(&mut self) { self.0.abort(); } }

/// Dropping the last connection handle cancels the carrier and all child tasks.
#[derive(Clone)]
pub struct MuxConnection {
    commands: mpsc::Sender<Open>,
    owner: Arc<CarrierOwner>,
    limits: MuxLimits,
}
impl MuxConnection {
    pub fn new(stream: BoxStream, limits: MuxLimits) -> Result<Self> {
        limits.validate()?;
        let (commands, requests) = mpsc::channel(limits.frame_queue);
        let runtime_limits = limits.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run(stream, runtime_limits, Some(requests), None).await {
                tracing::debug!("mux client closed: {}", error);
            }
        });
        Ok(Self { commands, owner: Arc::new(CarrierOwner(task)), limits })
    }
    pub fn is_closed(&self) -> bool { self.owner.0.is_finished() }
    pub fn close(&self) { self.owner.0.abort(); }
    pub async fn open_stream(&self, target: Destination) -> Result<BoxStream> {
        if target.network != Network::Tcp { return Err(Error::Protocol("mux stream target must be TCP".into())); }
        let (application, bridge) = tokio::io::duplex(self.limits.stream_buffer);
        self.open(target, Endpoint::Stream(bridge)).await?;
        Ok(Box::pin(application))
    }
    pub async fn open_datagram(&self, target: Destination) -> Result<BoxDatagram> {
        self.open_datagram_with_global_id(target, [0; 8]).await
    }
    pub async fn open_datagram_with_global_id(&self, target: Destination, global_id: [u8; 8]) -> Result<BoxDatagram> {
        if target.network != Network::Udp { return Err(Error::Protocol("mux packet target must be UDP".into())); }
        let (application, bridge) = datagram_pair(self.limits.session_queue);
        self.open(target, Endpoint::Packets(bridge, global_id)).await?;
        Ok(application)
    }
    async fn open(&self, target: Destination, endpoint: Endpoint) -> Result<()> {
        let (accepted, result) = oneshot::channel();
        self.commands.send(Open { target, endpoint, accepted }).await.map_err(|_| Error::Closed)?;
        result.await.map_err(|_| Error::Closed)?
    }
}
enum Endpoint { Stream(DuplexStream), Packets(BoxDatagram, [u8; 8]) }
struct Open { target: Destination, endpoint: Endpoint, accepted: oneshot::Sender<Result<()>> }
struct Entry { sender: mpsc::Sender<Frame>, abort: AbortHandle, generation: u64 }
enum Completion { Session(u16, u64, Result<()>) }
type ServerContext = (SessionContext, Arc<dyn InboundDispatcher>);

pub async fn serve_mux(stream: BoxStream, context: SessionContext, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
    serve_mux_with_limits(stream, context, dispatcher, MuxLimits::default()).await
}
pub async fn serve_mux_with_limits(stream: BoxStream, context: SessionContext, dispatcher: Arc<dyn InboundDispatcher>, limits: MuxLimits) -> Result<()> {
    limits.validate()?;
    run(stream, limits, None, Some((context, dispatcher))).await
}

async fn run(stream: BoxStream, limits: MuxLimits, mut requests: Option<mpsc::Receiver<Open>>, server: Option<ServerContext>) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames, mut incoming) = mpsc::channel(limits.frame_queue);
    let (output, mut outgoing) = mpsc::channel::<Frame>(limits.frame_queue);
    let mut drivers = JoinSet::new();
    let mut children = JoinSet::new();
    let read = async move {
        loop {
            match Frame::decode(&mut reader).await {
                Ok(frame) => if frames.send(frame).await.is_err() { return Ok(()); },
                Err(Error::Eof) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    };
    let write = async move {
        while let Some(frame) = outgoing.recv().await { frame.encode(&mut writer).await?; }
        writer.shutdown().await?;
        Ok(())
    };
    drivers.spawn(async move {
        // Observe peer EOF before a simultaneously ready terminal write error.
        // Separate tasks can report BrokenPipe before noticing peer closure.
        // A live peer's write failures still propagate.
        tokio::select! {
            biased;
            result = read => result,
            result = write => result,
        }
    });
    let mut sessions: HashMap<u16, Entry> = HashMap::new();
    let mut next_id = 0u16;
    let mut generation = 0u64;
    let mut keepalive = tokio::time::interval(limits.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let process = async {
        loop {
            tokio::select! {
                completed = children.join_next(), if !children.is_empty() => {
                    match completed {
                        Some(Ok(Completion::Session(id, completed_generation, result))) => {
                            if !sessions.get(&id).is_some_and(|entry| entry.generation == completed_generation) { continue; }
                            sessions.remove(&id);
                            output.send(if result.is_err() { Frame::error(id) } else { Frame::end(id) }).await.map_err(|_| Error::Closed)?;
                        }
                        Some(Err(error)) if error.is_cancelled() => {}
                        Some(Err(error)) => return Err(Error::Other(format!("mux task failed: {error}"))),
                        None => return Ok(()),
                    }
                }
                _ = keepalive.tick() => { output.send(Frame::keepalive()).await.map_err(|_| Error::Closed)?; }
                request = async { match requests.as_mut() { Some(requests) => requests.recv().await, None => std::future::pending().await } } => {
                    let Some(request) = request else { return Ok(()); };
                    if sessions.len() >= limits.max_sessions { let _ = request.accepted.send(Err(Error::BufferOverflow)); continue; }
                    let id = (0..=u16::MAX).find_map(|_| {
                        next_id = next_id.wrapping_add(1);
                        (!sessions.contains_key(&next_id)).then_some(next_id)
                    }).ok_or(Error::BufferOverflow)?;
                    let (sender, receiver) = mpsc::channel(limits.session_queue);
                    generation = generation.wrapping_add(1);
                    let task_generation = generation;
                    let output = output.clone();
                    let abort = match request.endpoint {
                        Endpoint::Stream(stream) => {
                            output.send(Frame::new_session(id, request.target, Vec::new())).await.map_err(|_| Error::Closed)?;
                            children.spawn(async move { Completion::Session(id, task_generation, bridge_stream(stream, receiver, output, id).await) })
                        }
                        Endpoint::Packets(packets, global_id) => {
                            children.spawn(async move { Completion::Session(id, task_generation, bridge_packets(packets, receiver, output, id, request.target, global_id, false, None).await) })
                        }
                    };
                    sessions.insert(id, Entry { sender, abort, generation: task_generation });
                    let _ = request.accepted.send(Ok(()));
                }
                frame = incoming.recv() => {
                    let Some(frame) = frame else { return Ok(()); };
                    let id = frame.session_id;
                    match frame.status {
                        SessionStatus::KeepAlive => {}
                        SessionStatus::New => {
                            let Some((context, dispatcher)) = &server else { return Err(Error::Protocol("server attempted to open mux session".into())); };
                            if let Some(old) = sessions.remove(&id) { old.abort.abort(); }
                            if sessions.len() >= limits.max_sessions { output.send(Frame::error(id)).await.map_err(|_| Error::Closed)?; continue; }
                            let target = frame.target.clone().ok_or_else(|| Error::Protocol("mux New missing destination".into()))?;
                            if target.network == Network::Udp && frame.payload.len() > MAX_UDP_PAYLOAD { return Err(Error::BufferOverflow); }
                            let mut context = context.clone();
                            context.destination = target.clone();
                            context.original_destination = Some(target.clone());
                            context.route_target = None;
                            context.outbound_tag = None;
                            let dispatcher = dispatcher.clone();
                            generation = generation.wrapping_add(1);
                            let task_generation = generation;
                            let (sender, receiver) = mpsc::channel(limits.session_queue);
                            sender.send(frame).await.map_err(|_| Error::Closed)?;
                            let output = output.clone();
                            let buffer = limits.stream_buffer;
                            let queue = limits.session_queue;
                            let abort = children.spawn(async move {
                                let result = if target.network == Network::Tcp {
                                    let (application, bridge) = tokio::io::duplex(buffer);
                                    let dispatch = dispatcher.dispatch_stream(Box::pin(application), context);
                                    let bridge = bridge_stream(bridge, receiver, output, id);
                                    combine(dispatch, bridge).await
                                } else {
                                    let (application, bridge) = datagram_pair(queue);
                                    let source = context.source.map(|address| Destination::udp(address.ip().into(), address.port()));
                                    let dispatch = dispatcher.dispatch_datagrams(application, context);
                                    let bridge = bridge_packets(bridge, receiver, output, id, target, [0; 8], true, source);
                                    combine(dispatch, bridge).await
                                };
                                Completion::Session(id, task_generation, result)
                            });
                            sessions.insert(id, Entry { sender, abort, generation: task_generation });
                        }
                        SessionStatus::Keep | SessionStatus::End => {
                            if let Some(entry) = sessions.get(&id) {
                                if entry.sender.send(frame).await.is_err() { sessions.remove(&id); }
                            } else if frame.status == SessionStatus::Keep {
                                output.send(Frame::error(id)).await.map_err(|_| Error::Closed)?;
                            }
                        }
                    }
                }
            }
        }
    };
    // Supervise physical I/O even while admission or a child queue is blocked.
    let mut result = tokio::select! {
        biased;
        driver = drivers.join_next() => match driver {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(Error::Other(format!("mux I/O task failed: {error}"))),
            None => Ok(()),
        },
        result = process => result,
    };
    // Channel closure is an effect of driver termination, not its close cause.
    // On another worker it can be visible before the task result is joinable.
    if !drivers.is_empty() && matches!(result, Ok(()) | Err(Error::Closed))
        && (incoming.is_closed() || output.is_closed())
    {
        result = match drivers.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(Error::Other(format!("mux I/O task failed: {error}"))),
            None => result,
        };
    }
    drivers.abort_all();
    children.abort_all();
    while drivers.join_next().await.is_some() {}
    while children.join_next().await.is_some() {}
    result
}

async fn combine<A, B>(dispatch: A, bridge: B) -> Result<()>
where A: std::future::Future<Output = Result<()>>, B: std::future::Future<Output = Result<()>> {
    tokio::pin!(dispatch, bridge);
    tokio::select! {
        result = &mut dispatch => { result?; bridge.await }
        result = &mut bridge => { result?; dispatch.await }
    }
}
async fn bridge_stream(stream: DuplexStream, mut incoming: mpsc::Receiver<Frame>, output: mpsc::Sender<Frame>, id: u16) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let uplink = async {
        while let Some(frame) = incoming.recv().await {
            if frame.option & OPTION_ERROR != 0 { return Err(Error::Protocol("mux peer reset session".into())); }
            if frame.option & OPTION_DATA != 0 { writer.write_all(&frame.payload).await?; }
            if frame.status == SessionStatus::End { break; }
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let downlink = async {
        let mut buffer = vec![0; 8 * 1024];
        loop {
            let size = reader.read(&mut buffer).await?;
            if size == 0 { return Ok::<_, Error>(()); }
            output.send(Frame::data(id, buffer[..size].to_vec())).await.map_err(|_| Error::Closed)?;
        }
    };
    // Go END is full close, not a TCP half close. Either local EOF or peer END
    // seals this child; retaining the other copy loop would leak idle sessions.
    tokio::select! { result = uplink => result, result = downlink => result }
}
#[allow(clippy::too_many_arguments)]
async fn bridge_packets(packets: BoxDatagram, mut incoming: mpsc::Receiver<Frame>, output: mpsc::Sender<Frame>, id: u16, target: Destination, global_id: [u8; 8], server: bool, local: Option<Destination>) -> Result<()> {
    let local = std::sync::RwLock::new(local);
    let uplink = async {
        while let Some(frame) = incoming.recv().await {
            if frame.option & OPTION_ERROR != 0 { return Err(Error::Protocol("mux peer reset packet session".into())); }
            if frame.option & OPTION_DATA != 0 {
                if frame.payload.len() > MAX_UDP_PAYLOAD { return Err(Error::BufferOverflow); }
                let destination = frame.target.unwrap_or_else(|| target.clone());
                let local = local.read().map_err(|_| Error::Other("mux endpoint lock poisoned".into()))?.clone();
                let packet = if server {
                    Datagram { payload: frame.payload.into(), source: local, destination }
                } else {
                    Datagram { payload: frame.payload.into(), source: Some(destination), destination: local.unwrap_or_else(|| target.clone()) }
                };
                packets.send(packet).await?;
            }
            if frame.status == SessionStatus::End { return Ok(()); }
        }
        Ok::<_, Error>(())
    };
    let downlink = async {
        let mut first = !server;
        while let Some(packet) = packets.recv().await? {
            if packet.payload.len() > MAX_UDP_PAYLOAD { return Err(Error::BufferOverflow); }
            if !server {
                let mut local = local.write().map_err(|_| Error::Other("mux endpoint lock poisoned".into()))?;
                *local = packet.source.clone().or_else(|| local.clone());
            }
            let destination = if server { packet.source.unwrap_or_else(|| target.clone()) } else { packet.destination };
            if destination.network != Network::Udp { return Err(Error::Protocol("mux packet target must be UDP".into())); }
            let mut frame = if first { Frame::new_session(id, destination, packet.payload.to_vec()) }
                else { let mut frame = Frame::data(id, packet.payload.to_vec()); frame.target = Some(destination); frame };
            frame.option |= OPTION_DATA;
            frame.global_id = global_id;
            first = false;
            output.send(frame).await.map_err(|_| Error::Closed)?;
        }
        Ok::<_, Error>(())
    };
    let result = tokio::select! { result = uplink => result, result = downlink => result };
    let closed = packets.close().await;
    result.and(closed)
}
