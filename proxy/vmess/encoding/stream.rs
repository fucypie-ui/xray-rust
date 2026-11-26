//! Async authenticated stream with independent request/response codec state.
//! UDP writes are single datagrams and reads never merge frames. BoxStream has
//! no datagram API; use send_packet/recv_packet when boundaries are required.
use super::{BodyDecoder, BodyEncoder, Direction, FrameLength, RequestHeader, ResponseHeader};
use crate::common::{errors::{Error, Result}, net::BoxStream};
use std::{io, pin::Pin, task::{Context, Poll, ready}};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Clone, Copy)]
enum ReadState { ResponseLength, ResponsePayload, BodyLength, BodyPayload(FrameLength), Done }

pub struct VmessStream {
    inner: BoxStream,
    reader: BodyDecoder,
    writer: BodyEncoder,
    response: Option<RequestHeader>,
    read_state: ReadState,
    input: Vec<u8>,
    input_filled: usize,
    plain: Vec<u8>,
    plain_offset: usize,
    output: Vec<u8>,
    output_sent: usize,
    read_failed: bool,
    write_failed: bool,
    termination_signal: bool,
    termination_queued: bool,
}
impl VmessStream {
    pub fn client(inner: BoxStream, request: RequestHeader) -> Result<Self> {
        Self::new(inner, request, true)
    }
    pub fn server(inner: BoxStream, request: RequestHeader) -> Result<Self> {
        Self::new(inner, request, false)
    }
    fn new(inner: BoxStream, request: RequestHeader, client: bool) -> Result<Self> {
        let reader = BodyDecoder::new(&request, if client {Direction::Response} else {Direction::Request})?;
        let writer = BodyEncoder::new(&request, if client {Direction::Request} else {Direction::Response})?;
        let length_bytes = if client {18} else {reader.length_bytes()};
        let output = if client {Vec::new()} else {ResponseHeader::new(request.response_header_byte).encode_bytes(&request)?};
        Ok(Self {inner, reader, writer, response: client.then_some(request),
            read_state: if client {ReadState::ResponseLength} else {ReadState::BodyLength},
            input: vec![0u8;length_bytes], input_filled: 0, plain: Vec::new(), plain_offset: 0,
            output, output_sent: 0, read_failed: false, write_failed: false,
            termination_signal: true, termination_queued: false})
    }
    pub fn with_termination_signal(mut self, enabled: bool) -> Self {self.termination_signal=enabled;self}
    pub fn into_boxed(self) -> BoxStream {Box::pin(self)}
    pub fn is_packet(&self) -> bool {self.writer.is_packet()}
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if !self.writer.is_packet() {return Err(Error::Protocol("VMess session is not UDP".into()));}
        if packet.is_empty() {
            return Err(Error::Unsupported("VMess UDP cannot encode an empty datagram: an empty body frame signals EOF".into()));
        }
        self.write_all(packet).await?;self.flush().await?;Ok(())
    }
    pub async fn recv_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.writer.is_packet() {return Err(Error::Protocol("VMess session is not UDP".into()));}
        let mut packet=vec![0u8;u16::MAX as usize];
        let length=self.read(&mut packet).await?;
        if length==0 {Ok(None)} else {packet.truncate(length);Ok(Some(packet))}
    }
    fn set_read_state(&mut self, state: ReadState, size: usize) {
        self.read_state=state;self.input.resize(size,0);self.input_filled=0;
    }
    fn drain_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe,"VMess writer failed")));}
        while self.output_sent<self.output.len() {
            match self.inner.as_mut().poll_write(cx,&self.output[self.output_sent..]) {
                Poll::Pending=>return Poll::Pending,
                Poll::Ready(Ok(0))=>{self.write_failed=true;return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));}
                Poll::Ready(Ok(n))=>self.output_sent+=n,
                Poll::Ready(Err(error))=>{self.write_failed=true;return Poll::Ready(Err(error));}
            }
        }
        self.output.clear();self.output_sent=0;Poll::Ready(Ok(()))
    }
    fn read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining()==0 {return Poll::Ready(Ok(()));}
        if self.read_failed {return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,"VMess reader failed")));}
        // Drive buffered writes too: write_all followed directly by read must
        // work when the underlying transport applies backpressure.
        if let Poll::Ready(Err(error))=self.drain_output(cx) {return Poll::Ready(Err(error));}
        loop {
            if self.plain_offset<self.plain.len() {
                let size=buf.remaining().min(self.plain.len()-self.plain_offset);
                buf.put_slice(&self.plain[self.plain_offset..self.plain_offset+size]);self.plain_offset+=size;
                if self.plain_offset==self.plain.len(){self.plain.clear();self.plain_offset=0;}
                return Poll::Ready(Ok(()));
            }
            if matches!(self.read_state,ReadState::Done){return Poll::Ready(Ok(()));}
            while self.input_filled<self.input.len() {
                let mut incoming=ReadBuf::new(&mut self.input[self.input_filled..]);
                ready!(self.inner.as_mut().poll_read(cx,&mut incoming))?;
                let length=incoming.filled().len();
                if length==0 {
                    if self.input_filled==0 && matches!(self.read_state,ReadState::BodyLength) {
                        self.read_state=ReadState::Done;return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof,"truncated VMess authenticated frame")));
                }
                self.input_filled+=length;
            }
            match self.read_state {
                ReadState::ResponseLength=>{
                    let request=self.response.as_ref().ok_or_else(|| invalid("missing VMess response context"))?;
                    let length=ResponseHeader::decode_length(request,&self.input).map_err(protocol_error)?;
                    self.set_read_state(ReadState::ResponsePayload,length+16);
                }
                ReadState::ResponsePayload=>{
                    let request=self.response.as_ref().ok_or_else(|| invalid("missing VMess response context"))?;
                    ResponseHeader::decode_payload(request,&self.input).map_err(protocol_error)?;
                    self.response=None;
                    self.set_read_state(ReadState::BodyLength,self.reader.length_bytes());
                }
                ReadState::BodyLength=>{
                    let length=self.reader.decode_length(&self.input).map_err(protocol_error)?;
                    if length.is_terminal(){self.read_state=ReadState::Done;return Poll::Ready(Ok(()));}
                    self.set_read_state(ReadState::BodyPayload(length),length.size);
                }
                ReadState::BodyPayload(length)=>{
                    self.plain=self.reader.decode_frame(length,&self.input).map_err(protocol_error)?;
                    self.plain_offset=0;
                    if self.plain.is_empty(){self.read_state=ReadState::Done;return Poll::Ready(Ok(()));}
                    self.set_read_state(ReadState::BodyLength,self.reader.length_bytes());
                }
                ReadState::Done=>return Poll::Ready(Ok(())),
            }
        }
    }
}
fn invalid(message: &str) -> io::Error {io::Error::new(io::ErrorKind::InvalidData,message)}
fn protocol_error(error: Error) -> io::Error {io::Error::new(io::ErrorKind::InvalidData,error)}
impl AsyncRead for VmessStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this=self.get_mut();
        let result=this.read_inner(cx,buf);
        if matches!(result,Poll::Ready(Err(_))){this.read_failed=true;}
        result
    }
}
impl AsyncWrite for VmessStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this=self.get_mut();
        if this.termination_queued {return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe,"VMess write after shutdown")));}
        ready!(this.drain_output(cx))?;
        if buf.is_empty(){return Poll::Ready(Ok(0));}
        let length=if this.writer.is_packet(){buf.len()}else{buf.len().min(this.writer.max_stream_payload())};
        this.output=match this.writer.encode_frame(&buf[..length]){
            Ok(bytes)=>bytes,
            Err(error)=>{this.write_failed=true;return Poll::Ready(Err(protocol_error(error)));}
        };
        // The frame is accepted into this bounded buffer. Future writes,
        // flush, shutdown and reads all drive it to the underlying connection.
        if let Poll::Ready(Err(error))=this.drain_output(cx){return Poll::Ready(Err(error));}
        Poll::Ready(Ok(length))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this=self.get_mut();ready!(this.drain_output(cx))?;this.inner.as_mut().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this=self.get_mut();ready!(this.drain_output(cx))?;
        if !this.termination_queued {
            this.termination_queued=true;
            if this.termination_signal {
                this.output=this.writer.encode_frame(&[]).map_err(protocol_error)?;
            }
        }
        ready!(this.drain_output(cx))?;this.inner.as_mut().poll_shutdown(cx)
    }
}
