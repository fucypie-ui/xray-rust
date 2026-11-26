//! Fixed-destination VMess command-2 datagrams over an authenticated session.
//! Independent halves provide bounded backpressure without bridge tasks or queues.
use super::VmessStream;
use crate::common::{
    errors::{Error, Result},
    net::{Destination, datagram::{BoxDatagram, Datagram, DatagramTransport, MAX_DATAGRAM_SIZE}},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{sync::{Arc, RwLock}, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, watch},
};

pub struct VmessDatagram {
    reader: Mutex<Option<ReadHalf<VmessStream>>>,
    writer: Mutex<Option<WriteHalf<VmessStream>>>,
    destination: Destination,
    source: Option<Destination>,
    enforce_destination: bool,
    local_source: RwLock<Option<Destination>>,
    closed: watch::Sender<bool>,
}
impl VmessDatagram {
    pub fn inbound(stream: VmessStream, destination: Destination, source: Option<Destination>) -> Result<BoxDatagram> {
        Self::new(stream, destination, source, false)
    }
    pub fn outbound(stream: VmessStream, destination: Destination) -> Result<BoxDatagram> {
        Self::new(stream, destination.clone(), Some(destination), true)
    }
    fn new(stream: VmessStream, destination: Destination, source: Option<Destination>, enforce_destination: bool) -> Result<BoxDatagram> {
        if !stream.is_packet() { return Err(Error::Protocol("VMess datagram adapter requires UDP command".into())); }
        let (reader, writer) = tokio::io::split(stream);
        let (closed, _) = watch::channel(false);
        Ok(Arc::new(Self {
            reader: Mutex::new(Some(reader)), writer: Mutex::new(Some(writer)),
            destination, source, enforce_destination, closed, local_source: RwLock::new(None),
        }))
    }
}
#[async_trait]
impl DatagramTransport for VmessDatagram {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Ok(None); }
        tokio::select! {
            biased;
            _ = closed.changed() => Ok(None),
            result = async {
                let mut guard = self.reader.lock().await;
                let Some(reader) = guard.as_mut() else { return Ok(None); };
                // A VMess frame has a uint16 size, including tag and padding.
                // VmessStream::poll_read returns at most one complete frame.
                let mut payload = vec![0u8; usize::from(u16::MAX)];
                let length = reader.read(&mut payload).await?;
                if length == 0 { return Ok(None); }
                if length > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
                payload.truncate(length);
                let destination = if self.enforce_destination {
                    self.local_source.read().map_err(|_| Error::Other("VMess datagram source lock poisoned".into()))?
                        .clone().unwrap_or_else(|| self.destination.clone())
                } else { self.destination.clone() };
                Ok(Some(Datagram {
                    payload: Bytes::from(payload), source: self.source.clone(),
                    destination,
                }))
            } => result,
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Err(Error::Closed); }
        if packet.payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        if self.enforce_destination && packet.destination != self.destination {
            return Err(Error::Protocol("VMess UDP command cannot change its fixed destination".into()));
        }
        if packet.payload.is_empty() { return Ok(()); }
        tokio::select! {
            biased;
            _ = closed.changed() => Err(Error::Closed),
            result = async {
                let mut guard = self.writer.lock().await;
                let writer = guard.as_mut().ok_or(Error::Closed)?;
                if self.enforce_destination {
                    *self.local_source.write().map_err(|_| Error::Other("VMess datagram source lock poisoned".into()))? = packet.source.clone();
                }
                // One write is one packet; an oversized packet fails atomically
                // before any packet bytes are accepted by the body writer.
                writer.write_all(&packet.payload).await?;
                writer.flush().await?;
                Ok(())
            } => result,
        }
    }
    async fn close(&self) -> Result<()> {
        self.closed.send_replace(true);
        // Active recv/send operations observe the watch and release both locks.
        let writer = self.writer.lock().await.take();
        drop(self.reader.lock().await.take());
        if let Some(mut writer) = writer {
            let result = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await
                .map_err(|_| Error::Timeout)?;
            if let Err(error) = result {
                if !matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
}
