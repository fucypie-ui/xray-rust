//! Bounded async driver for an already-created, authenticated rustls connection.
use crate::common::net::BoxStream;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct RealityStream {
    inner: BoxStream,
    connection: rustls::Connection,
    output: Vec<u8>,
    offset: usize,
    eof: bool,
    closing: bool,
}

impl RealityStream {
    pub(super) fn new(inner: BoxStream, mut connection: rustls::Connection) -> Self {
        connection.set_buffer_limit(Some(64 * 1024));
        Self { inner, connection, output: Vec::new(), offset: 0, eof: false, closing: false }
    }
    pub(super) fn with_output(inner: BoxStream, connection: rustls::Connection, output: Vec<u8>) -> Self {
        let mut stream = Self::new(inner, connection);
        stream.output = output;
        stream
    }
    pub(super) fn negotiated_h2(&self) -> bool { self.connection.alpn_protocol() == Some(b"h2") }
    pub(super) async fn handshake(mut self) -> io::Result<Self> {
        std::future::poll_fn(|cx| {
            loop {
                ready!(self.flush_tls(cx))?;
                if !self.connection.is_handshaking() { return Poll::Ready(Ok(())); }
                ready!(self.read_tls(cx))?;
                if self.eof { return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); }
            }
        }).await?;
        Ok(self)
    }
    fn flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.offset == self.output.len() {
                self.output.clear();
                self.offset = 0;
                if !self.connection.wants_write() { break; }
                self.connection.write_tls(&mut self.output)?;
                if self.output.is_empty() { return Poll::Ready(Err(io::ErrorKind::WriteZero.into())); }
            }
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.output[self.offset..]))?;
            if n == 0 { return Poll::Ready(Err(io::ErrorKind::WriteZero.into())); }
            self.offset += n;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut bytes = [0; 16 * 1024];
        let mut buf = ReadBuf::new(&mut bytes);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
        self.eof = buf.filled().is_empty();
        let mut input = io::Cursor::new(buf.filled());
        // rustls may read only part of the supplied socket chunk while growing
        // its deframer. Retain and consume the entire chunk before reading more.
        loop {
            let n = self.connection.read_tls(&mut input)?;
            self.connection.process_new_packets().map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if n == 0 || input.position() as usize == buf.filled().len() { break; }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        loop {
            match self.connection.reader().read(buf.initialize_unfilled()) {
                Ok(n) => { buf.advance(n); return Poll::Ready(Ok(())); }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
            ready!(self.flush_tls(cx))?;
            if self.eof { return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); }
            ready!(self.read_tls(cx))?;
        }
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.closing { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        ready!(self.flush_tls(cx))?;
        let n = self.connection.writer().write(&buf[..buf.len().min(16 * 1024)])?;
        // Try to send accepted plaintext immediately; any blocked output stays
        // buffered and is driven again by read, write, flush or shutdown.
        if let Poll::Ready(Err(error)) = self.flush_tls(cx) { return Poll::Ready(Err(error)); }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { self.flush_tls(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closing { self.connection.send_close_notify(); self.closing = true; }
        ready!(self.flush_tls(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
