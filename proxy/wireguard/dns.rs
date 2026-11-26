//! Destination DNS runs inside the authenticated tunnel, as Go's netstack does.
//! Only the outer peer endpoint is bootstrapped with the system resolver.
use std::{net::{IpAddr, SocketAddr}, time::Duration};
use hickory_proto::{op::{Message, MessageType, OpCode, Query, ResponseCode}, rr::{DNSClass, Name, RecordType}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::common::errors::{Error, Result};
use super::device::WireGuardDevice;

pub(super) async fn resolve(device: &WireGuardDevice, domain: &str) -> Result<Vec<IpAddr>> {
    let name = Name::from_ascii(if domain.ends_with('.') { domain.to_owned() } else { format!("{domain}.") })
        .map_err(|error| Error::Config(format!("invalid WireGuard DNS name: {error}")))?;
    let (v4, v6) = tokio::join!(query(device, &name, RecordType::A), query(device, &name, RecordType::AAAA));
    let mut addresses = Vec::new();
    if let Ok(v4) = v4 { addresses.extend(v4); }
    if let Ok(v6) = v6 { addresses.extend(v6); }
    if addresses.is_empty() { return Err(Error::NotFound(format!("WireGuard tunneled DNS returned no addresses for {domain}"))); }
    Ok(addresses)
}

async fn query(device: &WireGuardDevice, name: &Name, record_type: RecordType) -> Result<Vec<IpAddr>> {
    let mut request = Message::query();
    request.metadata.id = rand::random(); request.metadata.recursion_desired = true;
    request.add_query(Query::query(name.clone(), record_type));
    let wire = request.to_vec().map_err(|error| Error::Protocol(error.to_string()))?;
    for server in device.dns_servers().iter().copied().filter(|server| device.can_route(*server)) {
        let endpoint = SocketAddr::new(server, 53);
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let socket = device.connect_udp(endpoint)?;
            socket.send(&wire).await?;
            let mut buffer = vec![0; 65535];
            loop {
                let len = socket.recv(&mut buffer).await?;
                let response = &buffer[..len];
                if response.len() < 12 || response[..2] != wire[..2] || response[2] & 0x80 == 0 { continue; }
                if response[2] & 2 != 0 {
                    let mut tcp = device.connect_tcp(endpoint).await?;
                    tcp.write_u16(wire.len() as u16).await?; tcp.write_all(&wire).await?;
                    let size = tcp.read_u16().await? as usize;
                    let mut response = vec![0; size]; tcp.read_exact(&mut response).await?;
                    return decode(&request, &response, record_type);
                }
                match decode(&request, response, record_type) {
                    Ok(addresses) => return Ok(addresses),
                    Err(error @ Error::NotFound(_)) => return Err(error),
                    Err(_) => continue,
                }
            }
        }).await;
        if let Ok(Ok(addresses)) = response { return Ok(addresses); }
    }
    Err(Error::NotFound(format!("WireGuard tunneled DNS query failed: {name}")))
}

fn decode(request: &Message, wire: &[u8], record_type: RecordType) -> Result<Vec<IpAddr>> {
    let response = Message::from_vec(wire).map_err(|error| Error::Protocol(error.to_string()))?;
    if response.metadata.id != request.metadata.id || response.queries != request.queries
        || response.metadata.message_type != MessageType::Response || response.metadata.op_code != OpCode::Query
        || response.metadata.truncation {
        return Err(Error::Protocol("WireGuard DNS response does not match query".into()));
    }
    if response.metadata.response_code != ResponseCode::NoError {
        return Err(Error::NotFound("WireGuard DNS server returned a negative answer".into()));
    }
    let addresses = response.answers.iter().filter(|record| record.dns_class == DNSClass::IN && record.record_type() == record_type)
        .filter_map(|record| record.data.ip_addr()).collect::<Vec<_>>();
    Ok(addresses)
}
