//! A bounded, directly polled bridge between AsyncRead/AsyncWrite and an h2
//! stream. No unbounded duplex pump or application-byte background queue exists.
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use super::encoding::encoding::{MAX_MESSAGE, WRITE_CHUNK, check_header, decode_hunk, encode_hunk};

/// Drop requests a bounded final driver poll so queued RST/END_STREAM/trailers
/// can reach the socket. A stalled peer cannot retain the client driver forever.
pub(crate) struct DriverGuard { pub(crate) _stop: oneshot::Sender<()> }

pub(crate) fn content_type(headers: &HeaderMap) -> bool {
    if headers.get_all("content-type").iter().count() != 1 { return false; }
    headers.get("content-type").and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(';').next())
        .is_some_and(|s| matches!(s.trim(), "application/grpc" | "application/grpc+proto"))
}

pub(crate) fn identity_encoding(headers: &HeaderMap) -> bool {
    headers.get_all("grpc-encoding").iter().count() <= 1 && headers.get("grpc-encoding")
        .is_none_or(|h| h == "identity")
}

pub(crate) fn status_trailers(code: u8, message: &str) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_str(&code.to_string()).unwrap());
    if !message.is_empty() {
        let mut encoded = String::new();
        for b in message.bytes() {
            if (0x20..=0x7e).contains(&b) && b != b'%' { encoded.push(b as char); }
            else {
                use std::fmt::Write;
                write!(encoded, "%{b:02X}").unwrap();
            }
        }
        trailers.insert("grpc-message", HeaderValue::from_str(&encoded).unwrap());
    }
    trailers
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn status(headers: &HeaderMap) -> io::Result<Option<u8>> {
    let mut values = headers.get_all("grpc-status").iter();
    let Some(value) = values.next() else { return Ok(None); };
    if values.next().is_some() { return Err(invalid("duplicate grpc-status")); }
    let text = value.to_str().map_err(|_| invalid("non-ASCII grpc-status"))?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid grpc-status"));
    }
    let code: u8 = text.parse().map_err(|_| invalid("invalid grpc-status"))?;
    if code > 16 { return Err(invalid("out-of-range grpc-status")); }
    if code != 0 {
        let mut values = headers.get_all("grpc-message").iter();
        let raw = values.next().map_or(&[][..], |v| v.as_bytes());
        if values.next().is_some() { return Err(invalid("duplicate grpc-message")); }
        let mut decoded = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                if i + 2 >= raw.len() { return Err(invalid("invalid grpc-message percent escape")); }
                let hi = (raw[i + 1] as char).to_digit(16).ok_or_else(|| invalid("invalid grpc-message escape"))?;
                let lo = (raw[i + 2] as char).to_digit(16).ok_or_else(|| invalid("invalid grpc-message escape"))?;
                decoded.push((hi * 16 + lo) as u8);
                i += 3;
            } else { decoded.push(raw[i]); i += 1; }
        }
        return Err(io::Error::other(format!("gRPC status {code}: {}", String::from_utf8_lossy(&decoded))));
    }
    Ok(Some(code))
}

pub(crate) struct GunStream {
    send: SendStream<Bytes>,
    recv: Option<RecvStream>,
    response: Option<h2::client::ResponseFuture>,
    server: bool,
    multi: bool,
    wire: BytesMut,
    decoded: VecDeque<Bytes>,
    data_ended: bool,
    initial_status: Option<u8>,
    read_eof: bool,
    write_closed: bool,
    failure: Option<(io::ErrorKind, String)>,
    _driver: Option<DriverGuard>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl GunStream {
    pub(crate) fn client(send: SendStream<Bytes>, response: h2::client::ResponseFuture, multi: bool, driver: DriverGuard) -> Self {
        Self::new(send, None, Some(response), false, multi, Some(driver), None)
    }

    pub(crate) fn server(send: SendStream<Bytes>, recv: RecvStream, multi: bool, permit: OwnedSemaphorePermit) -> Self {
        Self::new(send, Some(recv), None, true, multi, None, Some(permit))
    }

    fn new(send: SendStream<Bytes>, recv: Option<RecvStream>, response: Option<h2::client::ResponseFuture>,
        server: bool, multi: bool, driver: Option<DriverGuard>, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            send, recv, response, server, multi, wire: BytesMut::new(), decoded: VecDeque::new(),
            data_ended: false, initial_status: None,
            read_eof: false, write_closed: false, failure: None, _driver: driver, _permit: permit,
        }
    }

    fn saved_error(&self) -> Option<io::Error> {
        self.failure.as_ref().map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn fail(&mut self, error: io::Error) -> io::Error { self.fail_code(error, 13) }

    fn fail_code(&mut self, error: io::Error, code: u8) -> io::Error {
        if self.server && !self.write_closed {
            let _ = self.send.send_trailers(status_trailers(code, &error.to_string()));
            self.write_closed = true;
        } else {
            self.send.send_reset(h2::Reason::CANCEL);
        }
        self.failure = Some((error.kind(), error.to_string()));
        error
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(response) = self.response.as_mut() else { return Poll::Ready(Ok(())); };
        let response: Response<RecvStream> = match std::task::ready!(Pin::new(response).poll(cx)) {
            Ok(response) => response,
            Err(e) => return Poll::Ready(Err(self.fail(io::Error::other(format!("gRPC HTTP/2 response: {e}"))))),
        };
        self.response = None;
        let checked = (|| {
            if response.status() != StatusCode::OK {
                return Err(io::Error::other(format!("gRPC HTTP status {}", response.status())));
            }
            if !content_type(response.headers()) { return Err(invalid("gRPC response requires application/grpc protobuf content-type")); }
            if !identity_encoding(response.headers()) { return Err(invalid("gRPC response compression is unavailable")); }
            self.initial_status = status(response.headers())?;
            if self.initial_status.is_some() && !response.body().is_end_stream() {
                return Err(invalid("grpc-status in non-final response headers"));
            }
            Ok(())
        })();
        if let Err(e) = checked { return Poll::Ready(Err(self.fail(e))); }
        self.recv = Some(response.into_body());
        Poll::Ready(Ok(()))
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.saved_error() { return Poll::Ready(Err(e)); }
        if !self.write_closed {
            match self.send.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => return Poll::Ready(Err(self.fail(io::Error::other(format!("gRPC HTTP/2 reset: {reason:?}"))))),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(self.fail(io::Error::other(format!("gRPC HTTP/2 send: {e}"))))),
                Poll::Pending => {}
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GunStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        if let Some(e) = this.saved_error() { return Poll::Ready(Err(e)); }
        if this.read_eof { return Poll::Ready(Ok(())); }
        std::task::ready!(this.poll_response(cx))?;
        // Empty messages and zero-length DATA are legal, but cannot monopolize
        // one executor poll or masquerade as AsyncRead EOF.
        for _ in 0..32 {
            while let Some(mut chunk) = this.decoded.pop_front() {
                if chunk.is_empty() { continue; }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                chunk.advance(n);
                if !chunk.is_empty() { this.decoded.push_front(chunk); }
                return Poll::Ready(Ok(()));
            }
            if this.wire.len() >= 5 {
                let len = match check_header(&this.wire[..5]) {
                    Ok(len) => len,
                    Err(e) => {
                        let declared = u32::from_be_bytes(this.wire[1..5].try_into().unwrap()) as usize;
                        let code = if this.wire[0] == 0 && declared > MAX_MESSAGE { 8 } else { 13 };
                        return Poll::Ready(Err(this.fail_code(invalid(e.to_string()), code)));
                    }
                };
                if this.wire.len() >= 5 + len {
                    this.wire.advance(5);
                    let payload = this.wire.split_to(len).freeze();
                    match decode_hunk(payload, this.multi) {
                        Ok(chunks) => this.decoded.extend(chunks),
                        Err(e) => return Poll::Ready(Err(this.fail(invalid(e.to_string())))),
                    }
                    continue;
                }
            }
            if !this.data_ended {
                match std::task::ready!(this.recv.as_mut().unwrap().poll_data(cx)) {
                    Some(Ok(data)) => {
                        // At most one 4 MiB message plus one h2 DATA frame is
                        // retained here. Releasing copied bytes allows messages
                        // larger than the receive window to finish assembling.
                        this.wire.extend_from_slice(&data);
                        if let Err(e) = this.recv.as_mut().unwrap().flow_control().release_capacity(data.len()) {
                            return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC HTTP/2 receive flow control: {e}")))));
                        }
                        continue;
                    }
                    Some(Err(e)) => return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC HTTP/2 receive: {e}"))))),
                    None => this.data_ended = true,
                }
            }
            if !this.wire.is_empty() {
                return Poll::Ready(Err(this.fail(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated gRPC envelope/protobuf message"))));
            }
            let trailers = match std::task::ready!(this.recv.as_mut().unwrap().poll_trailers(cx)) {
                Ok(trailers) => trailers,
                Err(e) => return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC HTTP/2 trailers: {e}"))))),
            };
            if !this.server {
                let final_status = match trailers.as_ref().map(status).transpose() {
                    Ok(value) => value.flatten(),
                    Err(e) => return Poll::Ready(Err(this.fail(e))),
                };
                if final_status.is_some() && this.initial_status.is_some() {
                    return Poll::Ready(Err(this.fail(invalid("grpc-status supplied twice"))));
                }
                if final_status.or(this.initial_status) != Some(0) {
                    return Poll::Ready(Err(this.fail(invalid("gRPC response ended without grpc-status"))));
                }
            }
            this.read_eof = true;
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = this.saved_error() { return Poll::Ready(Err(e)); }
        if this.write_closed { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "gRPC write half closed"))); }
        std::task::ready!(this.poll_pending(cx))?;
        if data.is_empty() { return Poll::Ready(Ok(0)); }
        this.send.reserve_capacity(WRITE_CHUNK + 16);
        if this.send.capacity() == 0 {
            match std::task::ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {
                    if this.send.capacity() == 0 { cx.waker().wake_by_ref(); return Poll::Pending; }
                }
                Some(Err(e)) => return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC HTTP/2 capacity: {e}"))))),
                None => return Poll::Ready(Err(this.fail(io::Error::new(io::ErrorKind::BrokenPipe, "gRPC send stream closed")))),
            }
        }
        let capacity = this.send.capacity();
        let n = data.len().min(WRITE_CHUNK).min(capacity.saturating_sub(16).max(1));
        // Even a peer advertising a one-byte window must make progress. In that
        // case h2 retains at most one tiny envelope's overhead, then sends its
        // fragments as capacity arrives. Builder send buffering is also capped.
        // No accepted write waits for a later application flush/read to enqueue.
        if let Err(e) = this.send.send_data(encode_hunk(&data[..n], this.multi), false) {
            return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC HTTP/2 DATA: {e}")))));
        }
        // Return unused connection credit instead of hoarding it while this
        // application stream is idle. h2 retains credit needed for queued DATA.
        this.send.reserve_capacity(0);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_pending(cx))?;
        if !this.write_closed {
            let result = if this.server { this.send.send_trailers(status_trailers(0, "")) }
                else { this.send.send_data(Bytes::new(), true) };
            if let Err(e) = result { return Poll::Ready(Err(this.fail(io::Error::other(format!("gRPC shutdown: {e}"))))); }
            this.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for GunStream {
    fn drop(&mut self) {
        // Server shutdown completes the RPC even if the client request half
        // remains open. Preserve queued OK/error trailers when the handler drops.
        let finished = if self.server { self.write_closed } else { self.read_eof && self.write_closed };
        if !finished {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}
