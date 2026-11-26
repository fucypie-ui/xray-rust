//! SIP022 TCP framing around the official Rust cipher engine, matching Go stream.go.
//! The two directions have independent salts, session keys and nonce counters.
use crate::common::net::{Address, BoxStream, Destination, Network};
use rand::{RngExt, TryRng};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::cipher::{AEAD_TAG_SIZE, CipherMethod, CipherState, invalid_data};
use super::protocol::{HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER};
use super::replay::ReplayFilter;

pub const MAX_PACKET_SIZE: usize = 65_535;
pub const MAX_PADDING_LENGTH: usize = 900;
const REQUEST_FIXED_LENGTH: usize = 11;

pub(crate) fn unix_time() -> io::Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs()).map_err(io::Error::other)
}

pub(crate) fn validate_timestamp(timestamp: u64, now: u64) -> io::Result<()> {
    if timestamp.abs_diff(now) > 30 { return Err(invalid_data("SS2022 timestamp outside 30-second window")); }
    Ok(())
}

fn random_salt(method: CipherMethod) -> io::Result<Vec<u8>> {
    let mut salt = vec![0; method.key_length()];
    rand::rngs::SysRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;
    Ok(salt)
}

pub fn encode_address(destination: &Destination) -> io::Result<Vec<u8>> {
    if destination.network != Network::Tcp {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "SS2022 UDP is not implemented"));
    }
    let mut output = Vec::with_capacity(259);
    match &destination.address {
        Address::Ipv4(ip) => { output.push(1); output.extend_from_slice(&ip.octets()); }
        Address::Ipv6(ip) => { output.push(4); output.extend_from_slice(&ip.octets()); }
        Address::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| invalid_data("SS2022 domain exceeds 255 bytes"))?;
            output.extend_from_slice(&[3, length]);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

pub fn decode_address(input: &[u8]) -> io::Result<(Destination, usize)> {
    // The Go TCP reader calls packet.go ParseAddressPort, which checks the
    // complete type byte (unlike the masked addrParser used by its writer).
    let kind = *input.first().ok_or_else(|| invalid_data("missing SS2022 address"))?;
    let (address, offset) = match kind {
        1 => {
            let octets: [u8; 4] = input.get(1..5).ok_or_else(|| invalid_data("short SS2022 IPv4"))?.try_into().map_err(|_| invalid_data("short SS2022 IPv4"))?;
            (Address::Ipv4(Ipv4Addr::from(octets)), 5)
        }
        4 => {
            let octets: [u8; 16] = input.get(1..17).ok_or_else(|| invalid_data("short SS2022 IPv6"))?.try_into().map_err(|_| invalid_data("short SS2022 IPv6"))?;
            (Address::ipv6(Ipv6Addr::from(octets)), 17)
        }
        3 => {
            let length = usize::from(*input.get(1).ok_or_else(|| invalid_data("missing SS2022 domain length"))?);
            let domain = input.get(2..2 + length).ok_or_else(|| invalid_data("short SS2022 domain"))?;
            let domain = std::str::from_utf8(domain).map_err(|_| invalid_data("SS2022 domain is not UTF-8"))?;
            (Address::Domain(domain.to_owned()), 2 + length)
        }
        _ => return Err(invalid_data("unknown SS2022 SOCKS address type")),
    };
    let port = input.get(offset..offset + 2).ok_or_else(|| invalid_data("missing SS2022 port"))?;
    Ok((Destination::tcp(address, u16::from_be_bytes([port[0], port[1]])), offset + 2))
}

pub(crate) fn encode_request(
    method: CipherMethod, key: &[u8], salt: &[u8], destination: &Destination,
    padding: &[u8], early_data: &[u8], timestamp: u64,
) -> io::Result<(Vec<u8>, CipherState)> {
    if padding.is_empty() && early_data.is_empty() {
        return Err(invalid_data("SS2022 request requires padding or payload"));
    }
    let mut variable = encode_address(destination)?;
    let padding_length = u16::try_from(padding.len()).map_err(|_| invalid_data("SS2022 padding too large"))?;
    variable.extend_from_slice(&padding_length.to_be_bytes());
    variable.extend_from_slice(padding);
    variable.extend_from_slice(early_data);
    let variable_length = u16::try_from(variable.len()).map_err(|_| invalid_data("SS2022 request header too large"))?;
    let mut fixed = Vec::with_capacity(REQUEST_FIXED_LENGTH);
    fixed.push(HEADER_TYPE_CLIENT);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(&variable_length.to_be_bytes());
    let mut cipher = CipherState::new(method, key, salt)?;
    let mut output = salt.to_vec();
    output.extend_from_slice(&cipher.seal(&fixed)?);
    output.extend_from_slice(&cipher.seal(&variable)?);
    Ok((output, cipher))
}

pub(crate) struct Request {
    pub(crate) salt: Vec<u8>,
    pub(crate) destination: Destination,
    pub(crate) early_data: Vec<u8>,
    pub(crate) cipher: CipherState,
}

async fn read_request<R: AsyncRead + Unpin>(
    stream: &mut R, method: CipherMethod, key: &[u8], now: Option<u64>,
) -> io::Result<Request> {
    let mut salt = vec![0; method.key_length()];
    stream.read_exact(&mut salt).await?;
    read_request_with_salt(stream, method, key, salt, now).await
}

async fn read_request_with_salt<R: AsyncRead + Unpin>(
    stream: &mut R, method: CipherMethod, key: &[u8], salt: Vec<u8>, now: Option<u64>,
) -> io::Result<Request> {
    let mut cipher = CipherState::new(method, key, &salt)?;
    let mut fixed = vec![0; REQUEST_FIXED_LENGTH + AEAD_TAG_SIZE];
    stream.read_exact(&mut fixed).await?;
    let fixed = cipher.open(&fixed)?;
    if fixed[0] != HEADER_TYPE_CLIENT { return Err(invalid_data("SS2022 expected client header")); }
    let timestamp = u64::from_be_bytes(fixed[1..9].try_into().map_err(|_| invalid_data("short SS2022 timestamp"))?);
    // Use receipt time after authenticating the fixed header, not accept time.
    validate_timestamp(timestamp, match now { Some(now) => now, None => unix_time()? })?;
    let length = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if length == 0 { return Err(invalid_data("empty SS2022 variable header")); }
    let mut variable = vec![0; length + AEAD_TAG_SIZE];
    stream.read_exact(&mut variable).await?;
    let variable = cipher.open(&variable)?;
    let (destination, offset) = decode_address(&variable)?;
    let padding = variable.get(offset..offset + 2).ok_or_else(|| invalid_data("missing SS2022 padding length"))?;
    let padding_length = usize::from(u16::from_be_bytes([padding[0], padding[1]]));
    let early_data = variable.get(offset + 2 + padding_length..).ok_or_else(|| invalid_data("short SS2022 padding"))?.to_vec();
    if padding_length == 0 && early_data.is_empty() { return Err(invalid_data("SS2022 request requires padding or payload")); }
    Ok(Request { salt, destination, early_data, cipher })
}

#[cfg(test)]
pub(crate) async fn read_request_at<R: AsyncRead + Unpin>(
    stream: &mut R, method: CipherMethod, key: &[u8], now: u64,
) -> io::Result<Request> {
    read_request(stream, method, key, Some(now)).await
}

pub(crate) fn encode_response(
    method: CipherMethod, key: &[u8], salt: &[u8], client_salt: &[u8],
    initial_payload: &[u8], timestamp: u64,
) -> io::Result<(Vec<u8>, CipherState)> {
    if client_salt.len() != method.key_length() { return Err(invalid_data("invalid SS2022 request salt")); }
    let length = u16::try_from(initial_payload.len()).map_err(|_| invalid_data("SS2022 response payload too large"))?;
    let mut fixed = Vec::with_capacity(11 + method.key_length());
    fixed.push(HEADER_TYPE_SERVER);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(client_salt);
    fixed.extend_from_slice(&length.to_be_bytes());
    let mut cipher = CipherState::new(method, key, salt)?;
    let mut output = salt.to_vec();
    output.extend_from_slice(&cipher.seal(&fixed)?);
    if !initial_payload.is_empty() { output.extend_from_slice(&cipher.seal(initial_payload)?); }
    Ok((output, cipher))
}

pub(crate) fn decode_response_header(
    method: CipherMethod, key: &[u8], client_salt: &[u8], header: &[u8], now: u64,
) -> io::Result<(CipherState, usize)> {
    let salt_length = method.key_length();
    if header.len() != 2 * salt_length + 11 + AEAD_TAG_SIZE || client_salt.len() != salt_length {
        return Err(invalid_data("short SS2022 response header"));
    }
    let mut cipher = CipherState::new(method, key, &header[..salt_length])?;
    let fixed = cipher.open(&header[salt_length..])?;
    if fixed[0] != HEADER_TYPE_SERVER { return Err(invalid_data("SS2022 expected server header")); }
    let timestamp = u64::from_be_bytes(fixed[1..9].try_into().map_err(|_| invalid_data("short SS2022 timestamp"))?);
    validate_timestamp(timestamp, now)?;
    let difference = fixed[9..9 + salt_length].iter().zip(client_salt).fold(0u8, |diff, (a, b)| diff | (a ^ b));
    if difference != 0 { return Err(invalid_data("SS2022 response request-salt mismatch")); }
    let offset = 9 + salt_length;
    let length = usize::from(u16::from_be_bytes([fixed[offset], fixed[offset + 1]]));
    Ok((cipher, length))
}

pub async fn connect_tcp(stream: BoxStream, method: CipherMethod, key: Vec<u8>, destination: &Destination) -> io::Result<EncryptedStream> {
    connect_tcp_chain(stream, method, vec![key], destination).await
}

pub async fn connect_tcp_chain(mut stream: BoxStream, method: CipherMethod, psks: Vec<Vec<u8>>, destination: &Destination) -> io::Result<EncryptedStream> {
    super::identity::validate_psks(method, &psks)?;
    let key = psks.last().ok_or_else(|| invalid_data("empty SS2022 PSK chain"))?.clone();
    let salt = random_salt(method)?;
    let padding_length = rand::rng().random_range(1..=MAX_PADDING_LENGTH);
    let (request, writer) = encode_request(method, &key, &salt, destination, &vec![0; padding_length], &[], unix_time()?)?;
    let identities = super::identity::tcp_headers(method, &psks, &salt)?;
    let mut wire = Vec::with_capacity(request.len() + identities.len());
    wire.extend_from_slice(&salt);
    wire.extend(identities);
    wire.extend_from_slice(&request[salt.len()..]);
    stream.write_all(&wire).await?;
    stream.flush().await?;
    let response = ResponseContext { method, key, client_salt: salt };
    Ok(EncryptedStream::new(stream, None, Some(writer), ReadStage::ResponseHeader(response), Vec::new(), None))
}

fn finish_accept(stream: BoxStream, method: CipherMethod, key: Vec<u8>, request: Request, replay: &ReplayFilter) -> io::Result<(Destination, EncryptedStream)> {
    replay.check_and_insert(&request.salt)?;
    let response = ResponseContext { method, key, client_salt: request.salt };
    let encrypted = EncryptedStream::new(stream, Some(request.cipher), None, ReadStage::Length, request.early_data, Some(response));
    Ok((request.destination, encrypted))
}

pub async fn accept_tcp(mut stream: BoxStream, method: CipherMethod, key: Vec<u8>, replay: &ReplayFilter) -> io::Result<(Destination, EncryptedStream)> {
    let request = read_request(&mut stream, method, &key, None).await?;
    finish_accept(stream, method, key, request, replay)
}

pub(crate) async fn accept_tcp_with_salt(mut stream: BoxStream, method: CipherMethod, key: Vec<u8>, salt: Vec<u8>, replay: &ReplayFilter) -> io::Result<(Destination, EncryptedStream)> {
    let request = read_request_with_salt(&mut stream, method, &key, salt, None).await?;
    finish_accept(stream, method, key, request, replay)
}

struct ResponseContext {
    method: CipherMethod,
    key: Vec<u8>,
    client_salt: Vec<u8>,
}

enum ReadStage {
    ResponseHeader(ResponseContext),
    Length,
    Payload(usize),
}

impl ReadStage {
    fn wire_length(&self) -> usize {
        match self {
            Self::ResponseHeader(response) => 2 * response.method.key_length() + 11 + AEAD_TAG_SIZE,
            Self::Length => 2 + AEAD_TAG_SIZE,
            Self::Payload(length) => length + AEAD_TAG_SIZE,
        }
    }
}

/// Native async encrypted stream. Ciphertext buffering is bounded to one record
/// per direction; no background bridge tasks can swallow authentication errors.
pub struct EncryptedStream {
    inner: BoxStream,
    reader: Option<CipherState>,
    writer: Option<CipherState>,
    response_pending: Option<ResponseContext>,
    read_stage: ReadStage,
    read_wire: Vec<u8>,
    read_filled: usize,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    read_eof: bool,
    read_failed: bool,
    write_wire: Vec<u8>,
    write_offset: usize,
    write_waiter: Option<Waker>,
    write_failed: bool,
    write_shutdown: bool,
}

impl EncryptedStream {
    fn new(
        inner: BoxStream, reader: Option<CipherState>, writer: Option<CipherState>,
        read_stage: ReadStage, plaintext: Vec<u8>, response_pending: Option<ResponseContext>,
    ) -> Self {
        let read_wire = vec![0; read_stage.wire_length()];
        Self { inner, reader, writer, response_pending, read_stage, read_wire, read_filled: 0, plaintext, plaintext_offset: 0, read_eof: false, read_failed: false, write_wire: Vec::new(), write_offset: 0, write_waiter: None, write_failed: false, write_shutdown: false }
    }

    fn finish_read_unit(&mut self) -> io::Result<()> {
        let stage = std::mem::replace(&mut self.read_stage, ReadStage::Length);
        match stage {
            ReadStage::ResponseHeader(response) => {
                let (cipher, length) = decode_response_header(response.method, &response.key, &response.client_salt, &self.read_wire, unix_time()?)?;
                self.reader = Some(cipher);
                if length > 0 { self.read_stage = ReadStage::Payload(length); }
            }
            ReadStage::Length => {
                let cipher = self.reader.as_mut().ok_or_else(|| invalid_data("missing SS2022 read cipher"))?;
                let length = cipher.open(&self.read_wire)?;
                let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
                if length == 0 { return Err(invalid_data("zero SS2022 payload length")); }
                self.read_stage = ReadStage::Payload(length);
            }
            ReadStage::Payload(_) => {
                let cipher = self.reader.as_mut().ok_or_else(|| invalid_data("missing SS2022 read cipher"))?;
                self.plaintext = cipher.open(&self.read_wire)?;
                self.plaintext_offset = 0;
            }
        }
        self.read_filled = 0;
        self.read_wire.resize(self.read_stage.wire_length(), 0);
        Ok(())
    }

    fn queue_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        if let Some(response) = self.response_pending.take() {
            let salt = random_salt(response.method)?;
            let (wire, cipher) = encode_response(response.method, &response.key, &salt, &response.client_salt, payload, unix_time()?)?;
            self.write_wire = wire;
            self.writer = Some(cipher);
        } else if !payload.is_empty() {
            let cipher = self.writer.as_mut().ok_or_else(|| invalid_data("missing SS2022 write cipher"))?;
            let length = u16::try_from(payload.len()).map_err(|_| invalid_data("SS2022 payload too large"))?;
            self.write_wire = cipher.seal(&length.to_be_bytes())?;
            self.write_wire.extend_from_slice(&cipher.seal(payload)?);
        }
        self.write_offset = 0;
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "SS2022 write direction failed"))); }
        while self.write_offset < self.write_wire.len() {
            let result = ready!(self.inner.as_mut().poll_write(cx, &self.write_wire[self.write_offset..]));
            match result {
                Ok(0) => {
                    self.write_failed = true;
                    if let Some(waiter) = self.write_waiter.take() { waiter.wake(); }
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "SS2022 transport write returned zero")));
                }
                Ok(length) => self.write_offset += length,
                Err(error) => {
                    self.write_failed = true;
                    if let Some(waiter) = self.write_waiter.take() { waiter.wake(); }
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.write_wire.clear();
        self.write_offset = 0;
        // poll_read also drives this queue and may replace the transport's write
        // waker. Notify an independently spawned split writer when it can retry.
        if let Some(waiter) = self.write_waiter.take() { waiter.wake(); }
        Poll::Ready(Ok(()))
    }

    fn poll_drain_for_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.poll_drain(cx);
        if result.is_pending() { self.write_waiter = Some(cx.waker().clone()); }
        result
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        if this.read_failed { return Poll::Ready(Err(invalid_data("SS2022 read direction failed"))); }
        // Accepted plaintext may still have bounded ciphertext buffered. Drive
        // it on reads too, but do not block incoming reads on write backpressure:
        // both peers may be sending a full record at the same time.
        if !this.write_wire.is_empty()
            && let Poll::Ready(Err(error)) = this.poll_drain(cx)
        {
            this.read_failed = true;
            return Poll::Ready(Err(error));
        }
        loop {
            if this.plaintext_offset < this.plaintext.len() {
                let length = output.remaining().min(this.plaintext.len() - this.plaintext_offset);
                output.put_slice(&this.plaintext[this.plaintext_offset..this.plaintext_offset + length]);
                this.plaintext_offset += length;
                return Poll::Ready(Ok(()));
            }
            if this.read_eof { return Poll::Ready(Ok(())); }
            while this.read_filled < this.read_wire.len() {
                let mut buffer = ReadBuf::new(&mut this.read_wire[this.read_filled..]);
                if let Err(error) = ready!(this.inner.as_mut().poll_read(cx, &mut buffer)) {
                    this.read_failed = true;
                    return Poll::Ready(Err(error));
                }
                let length = buffer.filled().len();
                if length == 0 {
                    if this.read_filled == 0 && matches!(this.read_stage, ReadStage::Length) {
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.read_failed = true;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SS2022 authenticated record")));
                }
                this.read_filled += length;
            }
            if let Err(error) = this.finish_read_unit() {
                this.read_failed = true;
                return Poll::Ready(Err(error));
            }
        }
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_failed || this.write_shutdown { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "SS2022 write direction closed"))); }
        if input.is_empty() { return Poll::Ready(Ok(0)); }
        // Pending here has accepted none of this call's input. If the caller
        // cancels and retries with another buffer, its bytes/count stay intact.
        ready!(this.poll_drain_for_writer(cx))?;
        let length = input.len().min(MAX_PACKET_SIZE);
        if let Err(error) = this.queue_payload(&input[..length]) {
            this.write_failed = true;
            return Poll::Ready(Err(error));
        }
        // This record is now owned by the stream. Report its plaintext count
        // even if the eager transport drain would block, as a buffered writer.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) { return Poll::Ready(Err(error)); }
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_failed { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "SS2022 write direction failed"))); }
        ready!(this.poll_drain_for_writer(cx))?;
        this.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_pending.is_some() {
            // Go ServerStreamWriter.Close authenticates even an empty response.
            if let Err(error) = self.queue_payload(&[]) {
                self.write_failed = true;
                return Poll::Ready(Err(error));
            }
        }
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        ready!(this.inner.as_mut().poll_shutdown(cx))?;
        this.write_shutdown = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "stream_test.rs"]
mod tests;
