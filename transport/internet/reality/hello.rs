//! Bounded TLS framing and target-flight admission. Adapted from Shoes (MIT).
use std::collections::HashSet;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "Invalid REALITY ClientHello") }

struct Reader<'a> { bytes: &'a [u8], position: usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.position.checked_add(n).ok_or_else(invalid)?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(invalid)?;
        self.position = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> io::Result<usize> { Ok(self.take(1)?[0] as usize) }
    fn u16(&mut self) -> io::Result<usize> { Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| invalid())?) as usize) }
    fn done(&self) -> bool { self.position == self.bytes.len() }
}

pub(super) struct ClientHello {
    pub(super) random: [u8; 32],
    pub(super) session: [u8; 32],
    pub(super) public: [u8; 32],
    pub(super) server_name: String,
    pub(super) aad: Vec<u8>,
}

pub(super) fn parse_client_hello(handshake: &[u8]) -> io::Result<ClientHello> {
    let mut hello = Reader::new(handshake);
    if hello.u8()? != 1 { return Err(invalid()); }
    let length = hello.take(3)?;
    let length = (length[0] as usize) << 16 | (length[1] as usize) << 8 | length[2] as usize;
    if length + 4 != handshake.len() || hello.u16()? != 0x0303 { return Err(invalid()); }
    let random = hello.take(32)?.try_into().map_err(|_| invalid())?;
    if hello.u8()? != 32 { return Err(invalid()); }
    let session = hello.take(32)?.try_into().map_err(|_| invalid())?;
    let suites = hello.u16()?;
    if suites == 0 || suites % 2 != 0 { return Err(invalid()); }
    hello.take(suites)?;
    let compression = hello.u8()?;
    if hello.take(compression)? != [0] { return Err(invalid()); }
    let length = hello.u16()?;
    let mut extensions = Reader::new(hello.take(length)?);
    if !hello.done() { return Err(invalid()); }
    let mut seen = HashSet::new();
    let (mut sni, mut public, mut tls13) = (String::new(), None, false);
    while !extensions.done() {
        let kind = extensions.u16()?;
        if !seen.insert(kind) { return Err(invalid()); }
        let length = extensions.u16()?;
        let mut data = Reader::new(extensions.take(length)?);
        match kind {
            0 => {
                let length = data.u16()?;
                let mut names = Reader::new(data.take(length)?);
                if !data.done() { return Err(invalid()); }
                let mut found = false;
                while !names.done() {
                    let kind = names.u8()?;
                    let length = names.u16()?;
                    let name = names.take(length)?;
                    if kind == 0 {
                        if found || name.is_empty() || name.ends_with(b".") { return Err(invalid()); }
                        sni = std::str::from_utf8(name).map_err(|_| invalid())?.to_owned();
                        found = true;
                    }
                }
            }
            43 => {
                let length = data.u8()?;
                let versions = data.take(length)?;
                if !data.done() || versions.len() % 2 != 0 { return Err(invalid()); }
                tls13 = versions.as_chunks::<2>().0.iter().any(|v| *v == [3, 4]);
            }
            51 => {
                let length = data.u16()?;
                let mut shares = Reader::new(data.take(length)?);
                if !data.done() { return Err(invalid()); }
                let mut hybrid = None;
                let mut selected = false;
                while !shares.done() {
                    let group = shares.u16()?;
                    let length = shares.u16()?;
                    let key = shares.take(length)?;
                    // Continue validating framing after selecting the optional
                    // standalone share; Go's TLS decoder does this before auth.
                    if selected { continue; }
                    if group == 0x11ec && length == 1216 {
                        if hybrid.is_some() { return Err(invalid()); }
                        hybrid = Some(key[1184..].try_into().map_err(|_| invalid())?);
                    } else if group == 0x001d && length == 32 {
                        // Pinned Go requires the hybrid share BEFORE X25519.
                        if hybrid.is_none() { return Err(invalid()); }
                        public = Some(key.try_into().map_err(|_| invalid())?);
                        selected = true;
                    }
                }
                public = public.or(hybrid);
                if public.is_none() { return Err(invalid()); }
            }
            _ => {}
        }
    }
    if !tls13 { return Err(invalid()); }
    let mut aad = handshake.to_vec();
    aad.get_mut(39..71).ok_or_else(invalid)?.fill(0);
    Ok(ClientHello { random, session, public: public.ok_or_else(invalid)?, server_name: sni, aad })
}

/// Mirror every preread byte to the already-open target, including malformed
/// headers. The returned wire bytes retain original TLS record fragmentation.
pub(super) async fn read_client_hello(
    client: &mut (impl AsyncRead + Unpin), target: &mut (impl AsyncWrite + Unpin),
) -> io::Result<(Vec<u8>, Option<ClientHello>)> {
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0; 5];
        client.read_exact(&mut header).await?;
        target.write_all(&header).await?;
        wire.extend_from_slice(&header);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22 || header[1] != 3 || length == 0 || length > 16384 || wire.len() + length > 128 * 1024 {
            target.flush().await?;
            return Ok((wire, None));
        }
        let mut record = vec![0; length];
        client.read_exact(&mut record).await?;
        target.write_all(&record).await?;
        target.flush().await?;
        wire.extend_from_slice(&record);
        handshake.extend_from_slice(&record);
        if handshake.len() >= 4 {
            let length = (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
            if handshake[0] != 1 || length > 65532 { return Ok((wire, None)); }
            if handshake.len() >= length + 4 {
                return Ok((wire, parse_client_hello(&handshake[..length + 4]).ok()));
            }
        }
    }
}

pub(super) struct TargetFlight {
    pub(super) raw: Vec<u8>,
    pub(super) records: Vec<Vec<u8>>,
}

pub(super) async fn read_target_flight(target: &mut (impl AsyncRead + Unpin)) -> io::Result<TargetFlight> {
    let mut flight = TargetFlight { raw: Vec::new(), records: Vec::new() };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut parsed = 0;
    loop {
        let mut buffer = [0; 8192];
        let n = match tokio::time::timeout_at(deadline, target.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(flight),
        };
        if n == 0 { return Ok(flight); }
        flight.raw.extend_from_slice(&buffer[..n]);
        if flight.raw.len() > 128 * 1024 { return Ok(flight); }
        while let Some(header) = flight.raw.get(parsed..parsed + 5) {
            let index = flight.records.len();
            let kind = if index == 0 { 22 } else if index == 1 { 20 } else { 23 };
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[0] != kind || header[1..3] != [3, 3] || length == 0 || length > 16401 || index > 6 { return Ok(flight); }
            let end = parsed + 5 + length;
            let Some(record) = flight.raw.get(parsed..end) else { break; };
            flight.records.push(record.to_vec());
            parsed = end;
        }
        let len = flight.records.len();
        if len >= 3 && flight.records[2].len() > 512 { return Ok(flight); }
        if len >= 6 && (parsed == flight.raw.len() || len == 7) { return Ok(flight); }
    }
}

pub(super) fn flight_plan(flight: &TargetFlight) -> io::Result<rustls::reality::FlightPlan> {
    let records = &flight.records;
    if !matches!(records.len(), 3 | 6 | 7) || records.iter().map(Vec::len).sum::<usize>() != flight.raw.len()
        || records[1] != [20, 3, 3, 0, 1, 1] || (records.len() == 3) != (records[2].len() > 512) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let end = if records.len() == 3 { 3 } else { 6 };
    let lengths: Vec<_> = records[2..end].iter().map(Vec::len).collect();
    rustls::reality::FlightPlan::new(&lengths, records.get(6).map(Vec::len))
        .map_err(|_| io::ErrorKind::Unsupported.into())
}

pub(super) fn verify_staged(wire: &[u8], target: &TargetFlight, hello: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    for (index, record) in target.records.iter().enumerate() {
        let staged = wire.get(offset..offset + record.len()).ok_or_else(invalid)?;
        if staged[..5] != record[..5] || (index == 0 && &staged[5..] != hello)
            || (index == 1 && staged != [20, 3, 3, 0, 1, 1]) { return Err(invalid()); }
        offset += record.len();
    }
    if offset != wire.len() { return Err(invalid()); }
    Ok(())
}
