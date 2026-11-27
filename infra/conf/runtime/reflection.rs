//! Commander reflection uses its own bidirectional stream, before unary dispatch.
//! The pool is global; only ListServices depends on this commander's registrations.
use std::{collections::{BTreeSet, HashSet, VecDeque}, future::poll_fn};
use bytes::{Buf, Bytes};
use prost::Message;
use prost_reflect::{DynamicMessage, FileDescriptor, Kind, MessageDescriptor, ReflectMessage, Value};
use crate::common::errors::{Error, Result};
use super::native;

// grpc-go v1.85.0 server.go's defaultServerMaxReceiveMessageSize counts payload,
// excluding the five-byte envelope. rpc_util.go checks length before payload flags.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const SEND_CHUNK: usize = 16 * 1024;
type Status = (u32, String);
type StreamResult<T> = std::result::Result<T, Status>;

pub(super) fn matches(path: &str) -> bool {
    matches!(path,
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" |
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
}

fn registered_services(enabled: &[String]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for service in enabled {
        let registration = match service.as_str() {
            "HandlerService" => Some(("xray.app.proxyman.command.HandlerService", Some("v2ray.core.app.proxyman.command.HandlerService"))),
            "LoggerService" => Some(("xray.app.log.command.LoggerService", Some("v2ray.core.app.log.command.LoggerService"))),
            "StatsService" => Some(("xray.app.stats.command.StatsService", Some("v2ray.core.app.stats.command.StatsService"))),
            "RoutingService" => Some(("xray.app.router.command.RoutingService", Some("v2ray.core.app.router.command.RoutingService"))),
            "ObservatoryService" => Some(("xray.core.app.observatory.command.ObservatoryService", None)),
            "ReflectionService" => Some(("grpc.reflection.v1.ServerReflection", Some("grpc.reflection.v1alpha.ServerReflection"))),
            _ => None,
        };
        if let Some((canonical, alias)) = registration {
            names.insert(canonical.to_owned());
            if let Some(alias) = alias { names.insert(alias.to_owned()); }
        }
    }
    names
}

/// FindDescriptorByName includes members, nested declarations and extensions.
fn symbol_file(name: &str) -> Option<FileDescriptor> {
    let pool = native::descriptors();
    if let Some(service) = pool.get_service_by_name(name) { return Some(service.parent_file()); }
    if let Some(message) = pool.get_message_by_name(name) { return Some(message.parent_file()); }
    if let Some(enumeration) = pool.get_enum_by_name(name) { return Some(enumeration.parent_file()); }
    if let Some(extension) = pool.get_extension_by_name(name) { return Some(extension.parent_file()); }
    for service in pool.services() {
        if service.methods().any(|method| method.full_name() == name) { return Some(service.parent_file()); }
    }
    for message in pool.all_messages() {
        if message.fields().any(|field| field.full_name() == name) || message.oneofs().any(|oneof| oneof.full_name() == name) {
            return Some(message.parent_file());
        }
    }
    for enumeration in pool.all_enums() {
        if enumeration.values().any(|value| value.full_name() == name) { return Some(enumeration.parent_file()); }
    }
    None
}

fn descriptor_closure(root: FileDescriptor, sent: &mut HashSet<String>) -> Vec<Value> {
    let mut visited = HashSet::from([root.name().to_owned()]);
    let mut queue = VecDeque::from([root]);
    let mut files = Vec::new();
    while let Some(file) = queue.pop_front() {
        let first_send = sent.insert(file.name().to_owned());
        if files.is_empty() || first_send {
            // Encoding the descriptor itself retains custom options/unknown fields,
            // unlike round-tripping the prost FileDescriptorProto representation.
            files.push(Value::Bytes(file.encode_to_vec().into()));
        }
        for dependency in file.dependencies() {
            if visited.insert(dependency.name().to_owned()) { queue.push_back(dependency); }
        }
    }
    files
}

fn message(package: &str, name: &str) -> DynamicMessage {
    DynamicMessage::new(native::descriptors().get_message_by_name(&format!("{}.{}", package, name)).expect("pinned reflection schema"))
}
fn string_field(input: &DynamicMessage, field: &str) -> String {
    input.get_field_by_name(field).and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()
}

fn answer(package: &str, input: DynamicMessage, enabled: &[String], sent: &mut HashSet<String>) -> StreamResult<DynamicMessage> {
    let mut output = message(package, "ServerReflectionResponse");
    output.set_field_by_name("valid_host", Value::String(string_field(&input, "host")));
    let (field, response) = if input.has_field_by_name("list_services") {
        let services = registered_services(enabled).into_iter().map(|name| {
            let mut service = message(package, "ServiceResponse");
            service.set_field_by_name("name", Value::String(name));
            Value::Message(service)
        }).collect();
        let mut response = message(package, "ListServiceResponse");
        response.set_field_by_name("service", Value::List(services));
        ("list_services_response", response)
    } else if input.has_field_by_name("all_extension_numbers_of_type") {
        let name = string_field(&input, "all_extension_numbers_of_type");
        // Go's fallback resolves any descriptor, including a service or field.
        if symbol_file(&name).is_none() {
            ("error_response", not_found(package))
        } else {
            let mut numbers: Vec<_> = native::descriptors().all_extensions()
                .filter(|extension| extension.containing_message().full_name() == name)
                .map(|extension| extension.number() as i32).collect();
            numbers.sort_unstable();
            let mut response = message(package, "ExtensionNumberResponse");
            response.set_field_by_name("base_type_name", Value::String(name));
            response.set_field_by_name("extension_number", Value::List(numbers.into_iter().map(Value::I32).collect()));
            ("all_extension_numbers_response", response)
        }
    } else {
        let root = if input.has_field_by_name("file_by_filename") {
            native::descriptors().get_file_by_name(&string_field(&input, "file_by_filename"))
        } else if input.has_field_by_name("file_containing_symbol") {
            symbol_file(&string_field(&input, "file_containing_symbol"))
        } else if input.has_field_by_name("file_containing_extension") {
            let extension = input.get_field_by_name("file_containing_extension").expect("present reflection extension");
            let extension = extension.as_message().expect("reflection extension message");
            let name = string_field(extension, "containing_type");
            let number = extension.get_field_by_name("extension_number").and_then(|value| value.as_i32()).unwrap_or_default();
            native::descriptors().all_extensions().find(|candidate| candidate.containing_message().full_name() == name && i64::from(candidate.number()) == i64::from(number))
                .map(|extension| extension.parent_file())
        } else { return Err((3, "invalid MessageRequest: <nil>".into())); };
        if let Some(root) = root {
            let mut response = message(package, "FileDescriptorResponse");
            response.set_field_by_name("file_descriptor_proto", Value::List(descriptor_closure(root, sent)));
            ("file_descriptor_response", response)
        } else { ("error_response", not_found(package)) }
    };
    output.set_field_by_name("original_request", Value::Message(input));
    output.set_field_by_name(field, Value::Message(response));
    Ok(output)
}
fn not_found(package: &str) -> DynamicMessage {
    let mut response = message(package, "ErrorResponse");
    response.set_field_by_name("error_code", Value::I32(5));
    response.set_field_by_name("error_message", Value::String("proto: not found".into()));
    response
}

// protobuf-go v1.36.12 internal/errors deliberately chooses ASCII space or
// NBSP after "proto:" using internal/detrand's hash of the Go binary. We emit
// ASCII. Only the complete NotFound lookup sentinel may be equated by peers;
// terminal diagnostics and metadata must retain their actual text/bytes.
fn invalid_wire() -> Status { unmarshal_error("proto: cannot parse invalid wire-format data") }
fn unmarshal_error(message: &str) -> Status {
    (13, format!("grpc: failed to unmarshal the received message: {}", message))
}
fn varint(input: &mut &[u8]) -> StreamResult<u64> {
    prost::encoding::decode_varint(input).map_err(|_| invalid_wire())
}
fn take<'a>(input: &mut &'a [u8], length: u64) -> StreamResult<&'a [u8]> {
    if length > input.len() as u64 { return Err(invalid_wire()); }
    let (value, rest) = input.split_at(length as usize); *input = rest; Ok(value)
}
fn scalar_wire_value<'a>(input: &mut &'a [u8], wire: u8) -> StreamResult<&'a [u8]> {
    let start = *input;
    match wire {
        0 => { varint(input)?; }
        1 => { take(input, 8)?; }
        2 => { let length = varint(input)?; return take(input, length); }
        5 => { take(input, 4)?; }
        _ => return Err(invalid_wire()),
    }
    Ok(&start[..start.len() - input.len()])
}
fn wire_value<'a>(input: &mut &'a [u8], number: u32, wire: u8) -> StreamResult<&'a [u8]> {
    if wire != 3 { return scalar_wire_value(input, wire); }
    let start = *input;
    // protowire.ConsumeFieldValue starts at depth 10000 and rejects a group
    // only below zero. Use a bounded explicit stack rather than Rust recursion.
    let mut groups = vec![number];
    while !groups.is_empty() {
        let tag = varint(input)?;
        // ConsumeTag inside unknown groups permits up to MaxInt32 (MessageSet);
        // the generated message decoder separately enforces the 29-bit limit.
        if tag >> 3 == 0 || tag >> 3 > i32::MAX as u64 { return Err(invalid_wire()); }
        let number = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        match wire {
            3 => {
                if groups.len() > 10000 { return Err(invalid_wire()); }
                groups.push(number);
            }
            4 => { if groups.pop() != Some(number) { return Err(invalid_wire()); } }
            _ => { scalar_wire_value(input, wire)?; }
        }
    }
    Ok(&start[..start.len() - input.len()])
}

// prost treats a known field with the wrong wire type as fatal. Go instead
// stores it as unknown, without selecting/clearing a oneof. Keep those bytes
// outside DynamicMessage, which cannot represent such colliding unknowns.
// These pinned schemas contain strings, int32 and one ExtensionRequest child.
// Keep that child solely in nested while merging: copying its accumulated
// value into the parent for every occurrence makes small continuations quadratic.
struct ReflectionMessage {
    value: DynamicMessage, unknown: Vec<u8>, nested: Option<(u32, Box<Self>)>,
}
impl ReflectionMessage {
    fn new(descriptor: MessageDescriptor) -> Self {
        Self { value: DynamicMessage::new(descriptor), unknown: Vec::new(), nested: None }
    }
    fn merge(&mut self, mut data: &[u8]) -> StreamResult<()> {
        let descriptor = self.value.descriptor();
        while !data.is_empty() {
            let tag = varint(&mut data)?;
            if tag >> 3 == 0 || tag >> 3 > (1 << 29) - 1 { return Err(invalid_wire()); }
            let number = (tag >> 3) as u32; let wire = (tag & 7) as u8;
            let start = data; let content = wire_value(&mut data, number, wire)?;
            if let Some(field) = descriptor.get_field(number) {
                match (field.kind(), wire) {
                    (Kind::String, 2) => {
                        let value = std::str::from_utf8(content).map_err(|_| unmarshal_error("string field contains invalid UTF-8"))?;
                        if field.containing_oneof().is_some() { self.nested = None; }
                        self.value.set_field(&field, Value::String(value.to_owned()));
                        continue;
                    }
                    (Kind::Int32, 0) => {
                        let mut content = content;
                        self.value.set_field(&field, Value::I32(varint(&mut content)? as i32));
                        continue;
                    }
                    (Kind::Message(child), 2) => {
                        if self.nested.as_ref().map(|(number, _)| *number) != Some(number) {
                            if let Some(oneof) = field.containing_oneof() {
                                for member in oneof.fields() { self.value.clear_field(&member); }
                            }
                            self.nested = Some((number, Box::new(Self::new(child))));
                        }
                        let nested = &mut self.nested.as_mut().expect("reflection ExtensionRequest").1;
                        nested.merge(content)?;
                        continue;
                    }
                    _ => {}
                }
            }
            // Generated Go canonicalizes an unknown tag, but appends its value
            // verbatim (including overlong varints, lengths and group contents).
            prost::encoding::encode_varint(tag, &mut self.unknown);
            self.unknown.extend_from_slice(&start[..start.len() - data.len()]);
        }
        Ok(())
    }
    fn echo(&self, preserve_unknown: bool) -> Vec<u8> {
        let mut encoded = self.value.encode_to_vec();
        if let Some((number, nested)) = &self.nested {
            append_message(*number, &nested.echo(preserve_unknown), &mut encoded);
        }
        // grpc-go's v1alpha adapter reconstructs both messages from known
        // fields; v1 returns the original, including every unknown wire record.
        if preserve_unknown { encoded.extend_from_slice(&self.unknown); }
        encoded
    }
    fn into_value(mut self) -> DynamicMessage {
        // Materialize each surviving child once, after all continuations and
        // oneof switches. Move its owned fields rather than cloning them.
        if let Some((number, nested)) = self.nested {
            self.value.set_field_by_number(number, Value::Message((*nested).into_value()));
        }
        self.value
    }
}
fn append_message(number: u32, data: &[u8], output: &mut Vec<u8>) {
    prost::encoding::encode_varint((u64::from(number) << 3) | 2, output);
    prost::encoding::encode_varint(data.len() as u64, output);
    output.extend_from_slice(data);
}

struct Receiver { body: h2::RecvStream, chunk: Bytes }
impl Receiver {
    async fn read_exact(&mut self, output: &mut [u8]) -> StreamResult<bool> {
        let mut copied = 0;
        while copied < output.len() {
            if self.chunk.is_empty() {
                let Some(chunk) = self.body.data().await else {
                    return if copied == 0 { Ok(false) } else { Err((13, "unexpected EOF".into())) };
                };
                let chunk = chunk.map_err(|error| (13, error.to_string()))?;
                // Credit is returned exactly once per acquired h2 DATA chunk.
                // Only one chunk is retained while waiting for response capacity.
                self.body.flow_control().release_capacity(chunk.len()).map_err(|error| (13, error.to_string()))?;
                self.chunk = chunk;
                if self.chunk.is_empty() { continue; }
            }
            let n = (output.len() - copied).min(self.chunk.len());
            output[copied..copied+n].copy_from_slice(&self.chunk[..n]);
            self.chunk.advance(n);
            copied += n;
        }
        Ok(true)
    }
    async fn next(&mut self) -> StreamResult<Option<Vec<u8>>> {
        let mut header = [0; 5];
        if !self.read_exact(&mut header).await? { return Ok(None); }
        let length = u32::from_be_bytes(header[1..5].try_into().expect("five-byte envelope")) as usize;
        if length > MAX_MESSAGE {
            return Err((8, format!("grpc: received message larger than max ({} vs. {})", length, MAX_MESSAGE)));
        }
        let mut data = vec![0; length];
        if !self.read_exact(&mut data).await? { return Err((13, "unexpected EOF".into())); }
        match header[0] {
            0 => Ok(Some(data)),
            1 => Err((13, "grpc: compressed flag set with identity or empty encoding".into())),
            flag => Err((13, format!("grpc: received unexpected payload format {}", flag))),
        }
    }
}

async fn send(stream: &mut h2::SendStream<Bytes>, data: Vec<u8>) -> StreamResult<()> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(0);
    frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
    frame.extend_from_slice(&data);
    let mut frame = Bytes::from(frame);
    while !frame.is_empty() {
        stream.reserve_capacity(frame.len().min(SEND_CHUNK));
        let capacity = if stream.capacity() > 0 { stream.capacity() } else {
            poll_fn(|cx| stream.poll_capacity(cx)).await
                .ok_or_else(|| (13, "reflection stream closed".into()))?
                .map_err(|error| (13, error.to_string()))?
        };
        let n = capacity.min(frame.len()).min(SEND_CHUNK);
        if n == 0 { continue; }
        stream.send_data(frame.split_to(n), false).map_err(|error| (13, error.to_string()))?;
    }
    Ok(())
}

pub(super) async fn serve(request: http::Request<h2::RecvStream>, mut response: h2::server::SendResponse<Bytes>, enabled: &[String]) -> Result<()> {
    let package = if request.uri().path().starts_with("/grpc.reflection.v1alpha.") { "grpc.reflection.v1alpha" } else { "grpc.reflection.v1" };
    let encoding = request.headers().get("grpc-encoding").and_then(|header| header.to_str().ok()).unwrap_or("").to_owned();
    let mut stream = None;
    let result: StreamResult<()> = async {
        if !enabled.iter().any(|service| service == "ReflectionService") {
            return Err((12, format!("unknown service {}.ServerReflection", package)));
        }
        // grpc-go rejects unregistered grpc-encoding before attempting RecvMsg,
        // even when the request has no messages or a zero compressed flag.
        if !encoding.is_empty() && encoding != "identity" {
            return Err((12, format!("grpc: Decompressor is not installed for grpc-encoding {:?}", encoding)));
        }
        let mut receiver = Receiver { body: request.into_body(), chunk: Bytes::new() };
        let descriptor = native::descriptors().get_message_by_name(&format!("{}.ServerReflectionRequest", package)).expect("pinned reflection request");
        let mut sent = HashSet::new();
        while let Some(data) = receiver.next().await? {
            let mut input = ReflectionMessage::new(descriptor.clone());
            input.merge(&data)?;
            let echo = input.echo(package == "grpc.reflection.v1");
            let mut output = answer(package, input.into_value(), enabled, &mut sent)?;
            output.clear_field_by_name("original_request");
            let mut encoded = output.encode_to_vec();
            append_message(2, &echo, &mut encoded);
            if stream.is_none() {
                let headers = http::Response::builder().status(200).header("content-type", "application/grpc").body(())
                    .expect("static reflection response headers");
                stream = Some(response.send_response(headers, false).map_err(|error| (13, error.to_string()))?);
            }
            // Do not read another request until this response passes flow control.
            send(stream.as_mut().expect("reflection headers sent"), encoded).await?;
        }
        Ok(())
    }.await;
    let (status, message) = result.err().unwrap_or_else(|| (0, String::new()));
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_str(&status.to_string()).map_err(protocol)?);
    let escaped: String = message.bytes().map(|byte| if (0x20..0x7f).contains(&byte) && byte != b'%' { (byte as char).to_string() } else { format!("%{:02X}", byte) }).collect();
    trailers.insert("grpc-message", http::HeaderValue::from_str(&escaped).map_err(protocol)?);
    if let Some(mut stream) = stream {
        stream.send_trailers(trailers).map_err(protocol)?;
    } else {
        // grpc-go v1.85.0 http2_server.go writeStatus: with no application
        // headers/message, a single END_STREAM HEADERS carries the trailers.
        let mut terminal = http::Response::builder().status(200).header("content-type", "application/grpc").body(()).map_err(protocol)?;
        terminal.headers_mut().extend(trailers);
        response.send_response(terminal, true).map_err(protocol)?;
    }
    Ok(())
}
fn protocol(error: impl std::fmt::Display) -> Error { Error::Protocol(error.to_string()) }

#[cfg(test)]
#[path = "reflection_test.rs"]
mod reflection_test;
#[cfg(test)]
#[path = "reflection_go_peer_test.rs"]
mod go_peer_test;
