use bytes::{Buf, Bytes};
use prost::Message;
use crate::common::errors::{Error, Result};
use super::messages::{Hunk, MultiHunk};

/// grpc-go's default maximum received protobuf message, excluding the envelope.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
pub const WRITE_CHUNK: usize = 16 * 1024;
/// Prevent repeated empty bytes fields from amplifying a small wire message.
pub const MAX_HUNKS: usize = 4096;

pub fn encode_grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn decode_grpc_frame(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 5 { return Err(Error::Protocol("Incomplete gRPC frame header".into())); }
    check_header(&data[..5])?;
    let len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    if data.len() - 5 < len { return Err(Error::Protocol("Incomplete gRPC frame payload".into())); }
    Ok((&data[5..5 + len], &data[5 + len..]))
}

pub(crate) fn check_header(header: &[u8]) -> Result<usize> {
    if header[0] != 0 { return Err(Error::Unsupported("gRPC compressed/reserved message flag is unavailable".into())); }
    let len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE { return Err(Error::Protocol("gRPC message exceeds 4 MiB".into())); }
    Ok(len)
}

pub(crate) fn encode_hunk(data: &[u8], multi: bool) -> Bytes {
    let data = Bytes::copy_from_slice(data);
    let payload = if multi { MultiHunk { data: vec![data] }.encode_to_vec() }
        else { Hunk { data }.encode_to_vec() };
    Bytes::from(encode_grpc_frame(&payload))
}

pub(crate) fn decode_hunk(payload: Bytes, multi: bool) -> Result<Vec<Bytes>> {
    // Preflight field count before prost allocates the repeated vector. Unknown
    // fields retain normal protobuf semantics and prost's recursion limit.
    if multi {
        let mut input = payload.clone();
        let mut count = 0;
        while input.has_remaining() {
            let (tag, wire) = prost::encoding::decode_key(&mut input)
                .map_err(|e| Error::Protocol(format!("invalid MultiHunk: {e}")))?;
            if tag == 1 {
                count += 1;
                if count > MAX_HUNKS {
                    return Err(Error::Protocol("MultiHunk exceeds 4096 fields".into()));
                }
            }
            prost::encoding::skip_field(wire, tag, &mut input, Default::default())
                .map_err(|e| Error::Protocol(format!("invalid MultiHunk field: {e}")))?;
        }
        let message = MultiHunk::decode(payload)
            .map_err(|e| Error::Protocol(format!("invalid MultiHunk protobuf: {e}")))?;
        Ok(message.data)
    } else {
        let message = Hunk::decode(payload)
            .map_err(|e| Error::Protocol(format!("invalid Hunk protobuf: {e}")))?;
        Ok(vec![message.data])
    }
}
