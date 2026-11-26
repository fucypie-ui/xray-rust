//! Bounded, packet-preserving routing, including multi-destination associations.
use super::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::{Destination, Network};
use crate::common::net::datagram::{BoxDatagram, datagram_pair};
use crate::common::protocol::SessionContext;
use std::collections::HashMap;
use std::time::Duration;
use tokio::task::JoinSet;

const MAX_ASSOCIATIONS: usize = 64;
const ASSOCIATION_QUEUE: usize = 8;
type FlowKey = (Option<Destination>, Destination);

pub(super) async fn dispatch(dispatcher: &DefaultDispatcher, inbound: BoxDatagram, context: SessionContext) -> Result<()> {
    let mut associations: HashMap<FlowKey, BoxDatagram> = HashMap::new();
    let mut children = JoinSet::new();
    let idle = dispatcher.policy.as_ref().map_or(Duration::from_secs(300), |policy| {
        policy.for_level(context.user.as_ref().map_or(0, |user| user.level)).timeouts.connection_idle
    });
    let result = async {
        loop {
            tokio::select! {
                completed = children.join_next(), if !children.is_empty() => {
                    if let Some(Ok((key, result))) = completed {
                        associations.remove(&key);
                        if let Err(error) = result { tracing::debug!("packet association ended: {}", error); }
                    }
                }
                packet = tokio::time::timeout(idle, inbound.recv()) => {
                    let Some(mut packet) = packet.map_err(|_| Error::Timeout)?? else { return Ok(()); };
                    if packet.destination.network != Network::Udp { return Err(Error::Protocol("non-UDP packet destination".into())); }
                    if packet.source.is_none() {
                        packet.source = context.source.map(|address| Destination::udp(address.ip().into(), address.port()));
                    }
                    let key = (packet.source.clone(), packet.destination.clone());
                    if let Some(flow) = associations.get(&key) {
                        flow.send(packet).await?;
                        continue;
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
                    let (input, receiver) = datagram_pair(ASSOCIATION_QUEUE);
                    input.send(packet).await?;
                    associations.insert(key.clone(), input);
                    let inbound = inbound.clone();
                    children.spawn(async move {
                        let result = association(receiver, outbound, inbound, idle).await;
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

async fn association(input: BoxDatagram, outbound: BoxDatagram, replies: BoxDatagram, idle: Duration) -> Result<()> {
    let result = async {
        loop {
            let activity = async {
                tokio::select! {
                    packet = input.recv() => {
                        let Some(packet) = packet? else { return Ok(false); };
                        outbound.send(packet).await?;
                    }
                    packet = outbound.recv() => {
                        let Some(packet) = packet? else { return Ok(false); };
                        replies.send(packet).await?;
                    }
                }
                Ok::<_, Error>(true)
            };
            if !tokio::time::timeout(idle, activity).await.map_err(|_| Error::Timeout)?? { return Ok(()); }
        }
    }.await;
    let (a, b) = tokio::join!(input.close(), outbound.close());
    result.and(a).and(b)
}
