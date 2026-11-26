//! Bounded, packet-preserving routing, including multi-destination associations.
use super::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::{Destination, Network};
use crate::common::net::datagram::{BoxDatagram, datagram_pair};
use crate::common::protocol::SessionContext;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

const MAX_ASSOCIATIONS: usize = 64;
const ASSOCIATION_QUEUE: usize = 8;
type FlowKey = (Option<Destination>, Destination);

pub(super) async fn dispatch(dispatcher: &DefaultDispatcher, inbound: BoxDatagram, context: SessionContext) -> Result<()> {
    let mut associations: HashMap<FlowKey, BoxDatagram> = HashMap::new();
    let mut children = JoinSet::new();
    let (activity, mut changed) = watch::channel(Instant::now());
    let idle = dispatcher.policy.as_ref().map_or(Duration::from_secs(300), |policy| {
        policy.for_level(context.user.as_ref().map_or(0, |user| user.level)).timeouts.connection_idle
    });
    let result = async {
        loop {
            let deadline = *changed.borrow_and_update() + idle;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return Err(Error::Timeout),
                _ = changed.changed() => {}
                completed = children.join_next(), if !children.is_empty() => {
                    if let Some(Ok((key, result))) = completed {
                        associations.remove(&key);
                        if let Err(error) = result { tracing::debug!("packet association ended: {}", error); }
                    }
                }
                packet = inbound.recv() => {
                    let Some(mut packet) = packet? else { return Ok(()); };
                    activity.send_replace(Instant::now());
                    if packet.destination.network != Network::Udp { return Err(Error::Protocol("non-UDP packet destination".into())); }
                    if packet.source.is_none() {
                        packet.source = context.source.map(|address| Destination::udp(address.ip().into(), address.port()));
                    }
                    let key = (packet.source.clone(), packet.destination.clone());
                    if let Some(flow) = associations.get(&key) {
                        match flow.send(packet.clone()).await {
                            Ok(()) => continue,
                            Err(Error::Closed) => { associations.remove(&key); }
                            Err(error) => return Err(error),
                        }
                    }
                    if associations.len() >= MAX_ASSOCIATIONS { return Err(Error::BufferOverflow); }
                    let mut session = context.clone();
                    session.destination = packet.destination.clone();
                    session.original_destination = Some(session.destination.clone());
                    session.route_target = None;
                    session.outbound_tag = None;
                    if let Some(source) = packet.source.as_ref().and_then(Destination::to_socket_addr) { session.source = Some(source); }
                    let handler = dispatcher.packet_outbound(&mut session).await?;
                    let outbound = handler.connect_datagram(&session).await?;
                    let counters = PacketCounters::new(dispatcher, &session);
                    let (input, receiver) = datagram_pair(ASSOCIATION_QUEUE);
                    input.send(packet).await?;
                    associations.insert(key.clone(), input);
                    let inbound = inbound.clone();
                    let activity = activity.clone();
                    children.spawn(async move {
                        let result = association(receiver, outbound, inbound, activity, counters).await;
                        (key, result)
                    });
                }
            }
        }
    }.await;
    children.abort_all();
    while children.join_next().await.is_some() {}
    let closed = inbound.close().await;
    result.and(closed)
}

async fn association(input: BoxDatagram, outbound: BoxDatagram, replies: BoxDatagram, activity: watch::Sender<Instant>, counters: PacketCounters) -> Result<()> {
    let uplink = async {
        while let Some(packet) = input.recv().await? {
            let length = packet.payload.len() as i64;
            outbound.send(packet).await?;
            counters.add(true, length);
            activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    let downlink = async {
        while let Some(packet) = outbound.recv().await? {
            let length = packet.payload.len() as i64;
            replies.send(packet).await?;
            counters.add(false, length);
            activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    let result = tokio::select! { result = uplink => result, result = downlink => result };
    let (a, b) = tokio::join!(input.close(), outbound.close());
    result.and(a).and(b)
}

struct PacketCounters {
    up: Vec<Arc<crate::features::stats::Counter>>,
    down: Vec<Arc<crate::features::stats::Counter>>,
    online: Option<(Arc<dyn crate::features::stats::OnlineMap>, String)>,
}
impl PacketCounters {
    fn new(dispatcher: &DefaultDispatcher, session: &SessionContext) -> Self {
        let mut counters = Self { up: Vec::new(), down: Vec::new(), online: None };
        let Some(stats) = &dispatcher.stats else { return counters; };
        let system = dispatcher.policy.as_ref().map(|policy| policy.for_system()).unwrap_or_default();
        if let Some(tag) = &session.outbound_tag {
            if system.stats.outbound_uplink { counters.up.push(stats.register_counter(&format!("outbound>>>{tag}>>>traffic>>>uplink"))); }
            if system.stats.outbound_downlink { counters.down.push(stats.register_counter(&format!("outbound>>>{tag}>>>traffic>>>downlink"))); }
        }
        if let (Some(user), Some(policy)) = (&session.user, &dispatcher.policy) {
            if user.email.is_empty() { return counters; }
            let policy = policy.for_level(user.level);
            if policy.stats.user_uplink { counters.up.push(stats.register_counter(&format!("user>>>{}>>>traffic>>>uplink", user.email))); }
            if policy.stats.user_downlink { counters.down.push(stats.register_counter(&format!("user>>>{}>>>traffic>>>downlink", user.email))); }
            if policy.stats.user_online && let Some(source) = session.source {
                let online = stats.register_online_map(&format!("user>>>{}>>>online", user.email));
                let ip = source.ip().to_string();
                online.add_ip(&ip);
                counters.online = Some((online, ip));
            }
        }
        counters
    }
    fn add(&self, uplink: bool, length: i64) {
        for counter in if uplink { &self.up } else { &self.down } { counter.add(length); }
    }
}
impl Drop for PacketCounters {
    fn drop(&mut self) { if let Some((online, ip)) = &self.online { online.remove_ip(ip); } }
}
