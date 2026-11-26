//! Reuse h3-quinn's backend, diverting authenticated 0x401 streams before H3 parses them.
//! The peek buffer preserves partial varints and every already-received application byte.
use bytes::{Buf, Bytes, BytesMut};
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use std::{io, pin::Pin, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, task::{Context, Poll, ready}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::mpsc};
use crate::proxy::hysteria::protocol::{FRAME_TYPE_TCP_REQUEST, QuicVarint};

pub struct Backend {
    inner: h3_quinn::Connection,
    pending: FuturesUnordered<BoxFuture<'static, Result<(u64, ReplayBi), StreamErrorIncoming>>>,
    authenticated: Arc<AtomicBool>,
    proxy: mpsc::Sender<ProxyStream>,
}
impl Backend {
    pub fn new(connection: quinn::Connection, authenticated: Arc<AtomicBool>, proxy: mpsc::Sender<ProxyStream>) -> Self {
        Self { inner: h3_quinn::Connection::new(connection), pending: FuturesUnordered::new(), authenticated, proxy }
    }
}
pub struct Opener(h3_quinn::OpenStreams);
impl quic::OpenStreams<Bytes> for Opener {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type BidiStream = ReplayBi;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<ReplayBi, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.0, cx).map(|result| result.map(ReplayBi::new))
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> { quic::OpenStreams::<Bytes>::poll_open_send(&mut self.0, cx) }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) { quic::OpenStreams::<Bytes>::close(&mut self.0, code, reason); }
}
impl quic::OpenStreams<Bytes> for Backend {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type BidiStream = ReplayBi;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<ReplayBi, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx).map(|result| result.map(ReplayBi::new))
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> { quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx) }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) { quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason); }
}
impl quic::Connection<Bytes> for Backend {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener;
    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> { quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx) }
    fn opener(&self) -> Opener { Opener(quic::Connection::<Bytes>::opener(&self.inner)) }
    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<ReplayBi, ConnectionErrorIncoming>> {
        // A stalled first stream must not block a subsequent authentication stream.
        let mut full_batch = true;
        for _ in 0..32 {
            match quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx) {
                Poll::Ready(Ok(stream)) => self.pending.push(Box::pin(async move {
                    tokio::time::timeout(std::time::Duration::from_secs(10), classify(ReplayBi::new(stream))).await
                        .unwrap_or_else(|_| Err(StreamErrorIncoming::Unknown(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Hysteria stream type timeout")))))
                })),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => { full_batch = false; break; },
            }
        }
        while let Poll::Ready(Some(result)) = self.pending.poll_next_unpin(cx) {
            let Ok((kind, mut stream)) = result else { continue; };
            if kind == FRAME_TYPE_TCP_REQUEST {
                let (_, used) = QuicVarint::parse(&stream.prefix).expect("classified varint");
                stream.prefix.advance(used);
                if self.authenticated.load(Ordering::Acquire) {
                    // Full queues reset this stream instead of blocking all H3 traffic.
                    let _ = self.proxy.try_send(ProxyStream::new(stream));
                } else {
                    quic::SendStream::<Bytes>::reset(&mut stream, 0x101);
                    quic::RecvStream::stop_sending(&mut stream, 0x101);
                }
            } else {
                return Poll::Ready(Ok(stream));
            }
        }
        // If we consumed the bounded accept batch, ensure another poll drains it.
        if full_batch { cx.waker().wake_by_ref(); }
        Poll::Pending
    }
}
async fn classify(mut stream: ReplayBi) -> Result<(u64, ReplayBi), StreamErrorIncoming> {
    let mut prefix = BytesMut::new();
    loop {
        if let Ok((kind, _)) = QuicVarint::parse(&prefix) {
            stream.prefix = prefix.freeze();
            return Ok((kind, stream));
        }
        match std::future::poll_fn(|cx| quic::RecvStream::poll_data(&mut stream.inner, cx)).await? {
            Some(chunk) => prefix.extend_from_slice(&chunk),
            None => return Err(StreamErrorIncoming::Unknown(Box::new(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated Hysteria stream type")))),
        }
    }
}
pub struct ReplayBi { inner: h3_quinn::BidiStream<Bytes>, prefix: Bytes }
impl ReplayBi { fn new(inner: h3_quinn::BidiStream<Bytes>) -> Self { Self { inner, prefix: Bytes::new() } } }
pub struct ReplayRecv { inner: h3_quinn::RecvStream, prefix: Bytes }
impl quic::RecvStream for ReplayRecv {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if !self.prefix.is_empty() { return Poll::Ready(Ok(Some(self.prefix.split_to(self.prefix.len())))); }
        quic::RecvStream::poll_data(&mut self.inner, cx)
    }
    fn stop_sending(&mut self, code: u64) { quic::RecvStream::stop_sending(&mut self.inner, code); }
    fn recv_id(&self) -> StreamId { quic::RecvStream::recv_id(&self.inner) }
}
impl quic::RecvStream for ReplayBi {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if !self.prefix.is_empty() { return Poll::Ready(Ok(Some(self.prefix.split_to(self.prefix.len())))); }
        quic::RecvStream::poll_data(&mut self.inner, cx)
    }
    fn stop_sending(&mut self, code: u64) { quic::RecvStream::stop_sending(&mut self.inner, code); }
    fn recv_id(&self) -> StreamId { quic::RecvStream::recv_id(&self.inner) }
}
impl quic::SendStream<Bytes> for ReplayBi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> { quic::SendStream::poll_ready(&mut self.inner, cx) }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> { quic::SendStream::send_data(&mut self.inner, data) }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> { quic::SendStream::poll_finish(&mut self.inner, cx) }
    fn reset(&mut self, code: u64) { quic::SendStream::reset(&mut self.inner, code); }
    fn send_id(&self) -> StreamId { quic::SendStream::send_id(&self.inner) }
}
impl quic::BidiStream<Bytes> for ReplayBi {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = ReplayRecv;
    fn split(self) -> (Self::SendStream, ReplayRecv) {
        let (send, inner) = quic::BidiStream::split(self.inner);
        (send, ReplayRecv { inner, prefix: self.prefix })
    }
}
/// Exposes the hijacked QUIC stream to the existing BoxStream routing interface.
pub struct ProxyStream { inner: Mutex<ReplayBi>, buffered: Bytes }
impl ProxyStream { fn new(inner: ReplayBi) -> Self { Self { inner: Mutex::new(inner), buffered: Bytes::new() } } }
impl AsyncRead for ProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        if self.buffered.is_empty() {
            let next = { let stream = self.inner.get_mut().expect("stream mutex"); ready!(quic::RecvStream::poll_data(stream, cx)).map_err(io::Error::other)? };
            let Some(next) = next else { return Poll::Ready(Ok(())); };
            self.buffered = next;
        }
        let size = output.remaining().min(self.buffered.len());
        output.put_slice(&self.buffered.split_to(size));
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let stream = self.inner.get_mut().expect("stream mutex");
        let mut buffer = bytes;
        quic::SendStreamUnframed::poll_send(&mut stream.inner, cx, &mut buffer).map_err(io::Error::other)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { quic::SendStream::poll_ready(self.inner.get_mut().expect("stream mutex"), cx).map_err(io::Error::other) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { quic::SendStream::poll_finish(self.inner.get_mut().expect("stream mutex"), cx).map_err(io::Error::other) }
}
