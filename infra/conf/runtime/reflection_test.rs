//! Ordinary configured endpoint tests; no Go binary or generated fixtures required.
use super::*;
use crate::{
    common::{net::{BoxStream, Destination}, protocol::SessionContext},
    infra::conf::{BuiltConfig, Config},
};
use bytes::BytesMut;
use std::time::Duration;
use tokio::task::JoinHandle;

const LIMIT: Duration = Duration::from_secs(30);
const PACKAGES: [&str; 2] = ["grpc.reflection.v1", "grpc.reflection.v1alpha"];
const ALL: [&str; 6] = ["ReflectionService", "HandlerService", "LoggerService", "StatsService", "RoutingService", "ObservatoryService"];
const HANDLER: &str = "app/proxyman/command/command.proto";
const HANDLER_FILES: [&str; 4] = [HANDLER, "common/protocol/user.proto", "common/serial/typed_message.proto", "core/config.proto"];
const ALL_NAMES: [&str; 11] = [
    "grpc.reflection.v1.ServerReflection", "grpc.reflection.v1alpha.ServerReflection",
    "v2ray.core.app.log.command.LoggerService", "v2ray.core.app.proxyman.command.HandlerService",
    "v2ray.core.app.router.command.RoutingService", "v2ray.core.app.stats.command.StatsService",
    "xray.app.log.command.LoggerService", "xray.app.proxyman.command.HandlerService",
    "xray.app.router.command.RoutingService", "xray.app.stats.command.StatsService",
    "xray.core.app.observatory.command.ObservatoryService",
];

macro_rules! bounded_test {
    ($name:ident, $body:block) => {
        #[tokio::test]
        async fn $name() { tokio::time::timeout(LIMIT, async $body).await.expect(stringify!($name)); }
    };
}

struct Fixture {
    config: BuiltConfig,
    client: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
}
impl Fixture {
    async fn new(direct: bool, services: &[&str]) -> Self { Self::with_window(direct, services, 65535).await }
    async fn with_window(direct: bool, services: &[&str], window: u32) -> Self {
        let address = if direct {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().to_string()
        } else { String::new() };
        let config = serde_json::from_value::<Config>(serde_json::json!({
            "api":{"tag":"reflection-api", "listen":address, "services":services}, "stats":{}
        })).unwrap().build().unwrap();
        for feature in &config.features { if feature.feature_type() == "commander" { feature.start().unwrap(); } }
        let io: BoxStream = if direct {
            Box::pin(tokio::net::TcpStream::connect(&address).await.unwrap())
        } else {
            config.outbounds["reflection-api"].connect(&SessionContext::new("reflection-test", Destination::tcp(crate::common::net::parse_address("127.0.0.1"), 1))).await.unwrap()
        };
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(window).initial_connection_window_size(16 * 1024 * 1024);
        let (client, connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        Self { config, client, driver }
    }
    async fn open(&self, package: &str) -> Rpc {
        self.open_path(&format!("/{}.ServerReflection/ServerReflectionInfo", package), None, false).await
    }
    async fn open_path(&self, path: &str, encoding: Option<&str>, end: bool) -> Rpc {
        let mut client = self.client.clone().ready().await.unwrap();
        let mut request = http::Request::builder().method("POST").uri(format!("http://reflection.test{}", path)).header("content-type", "application/grpc").header("te", "trailers");
        if let Some(encoding) = encoding { request = request.header("grpc-encoding", encoding); }
        let (response, send) = client.send_request(request.body(()).unwrap(), end).unwrap();
        // Return the sender before waiting for headers: unary needs EOF, and
        // bare grpc-go reflection does not send headers until its first reply.
        Rpc { send, response: Some(response), headers: None, body: None,
            pending: BytesMut::new(), ended: end, reflection: matches(path) }
    }
    fn close(&self) {
        for feature in &self.config.features { if feature.feature_type() == "commander" { feature.close().unwrap(); } }
    }
}
impl Drop for Fixture { fn drop(&mut self) { self.close(); self.driver.abort(); } }

struct Rpc {
    send: h2::SendStream<Bytes>, response: Option<h2::client::ResponseFuture>,
    headers: Option<http::HeaderMap>, body: Option<h2::RecvStream>,
    pending: BytesMut, ended: bool, reflection: bool,
}
impl Rpc {
    async fn receive_headers(&mut self) {
        if let Some(response) = self.response.take() {
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "application/grpc");
            self.headers = Some(response.headers().clone());
            self.body = Some(response.into_body());
        }
    }
    async fn raw(&mut self, data: impl Into<Bytes>, end: bool) {
        let mut data = data.into();
        if data.is_empty() { self.send.send_data(data, end).unwrap(); }
        else {
            while !data.is_empty() {
                self.send.reserve_capacity(data.len().min(16384));
                let capacity = if self.send.capacity() > 0 { self.send.capacity() } else {
                    poll_fn(|cx| self.send.poll_capacity(cx)).await.unwrap().unwrap()
                };
                if capacity == 0 { continue; }
                let n = capacity.min(data.len()).min(16384);
                let last = n == data.len();
                self.send.send_data(data.split_to(n), end && last).unwrap();
            }
        }
        self.ended |= end;
    }
    async fn request(&mut self, input: &DynamicMessage) { self.raw(envelope(&input.encode_to_vec()), false).await; }
    async fn next_payload(&mut self) -> Option<Bytes> {
        self.receive_headers().await;
        loop {
            if self.pending.len() >= 5 {
                assert_eq!(self.pending[0], 0);
                let length = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
                assert!(length <= 16 * 1024 * 1024, "unexpected response allocation");
                if self.pending.len() >= 5 + length {
                    self.pending.advance(5);
                    return Some(self.pending.split_to(length).freeze());
                }
            }
            let body = self.body.as_mut().unwrap();
            match body.data().await {
                Some(chunk) => {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    self.pending.extend_from_slice(&chunk);
                }
                None => { assert!(self.pending.is_empty(), "partial response envelope"); return None; }
            }
        }
    }
    async fn response(&mut self, package: &str) -> DynamicMessage {
        let payload = self.next_payload().await.expect("reflection response before client half-close");
        DynamicMessage::decode(native::descriptors().get_message_by_name(&format!("{}.ServerReflectionResponse", package)).unwrap(), payload).unwrap()
    }
    async fn status(&mut self, expected: u32) -> http::HeaderMap {
        assert!(self.next_payload().await.is_none(), "unexpected additional response");
        let trailing = self.body.as_mut().unwrap().trailers().await.unwrap();
        let headers = self.headers.as_ref().unwrap();
        let trailers = if headers.contains_key("grpc-status") {
            assert!(trailing.is_none(), "trailers-only must be one END_STREAM HEADERS block");
            headers.clone()
        } else { trailing.expect("gRPC trailers") };
        assert_eq!(trailers["grpc-status"].to_str().unwrap(), expected.to_string());
        if self.reflection {
            assert!(trailers.contains_key("grpc-message"), "even OK has an empty grpc-message");
            if expected == 0 { assert_eq!(trailers["grpc-message"], ""); }
        }
        trailers
    }
    async fn finish(mut self, status: u32) {
        if !self.ended { self.raw(Bytes::new(), true).await; }
        self.status(status).await;
    }
}
fn status_description(metadata: &http::HeaderMap) -> String {
    let mut input = metadata["grpc-message"].as_bytes();
    let mut decoded = Vec::new();
    while let Some((&byte, remaining)) = input.split_first() {
        if byte == b'%' {
            assert!(remaining.len() >= 2);
            decoded.push(u8::from_str_radix(std::str::from_utf8(&remaining[..2]).unwrap(), 16).unwrap());
            input = &remaining[2..];
        } else { decoded.push(byte); input = remaining; }
    }
    String::from_utf8(decoded).unwrap()
}
async fn assert_terminal(rpc: &mut Rpc, code: u32, description: &str, trailers_only: bool) {
    let metadata = rpc.status(code).await;
    let headers = rpc.headers.as_ref().unwrap();
    assert_eq!(headers.contains_key("grpc-status"), trailers_only);
    assert_eq!(headers.contains_key("grpc-message"), trailers_only);
    assert_eq!(metadata.contains_key("content-type"), trailers_only);
    let actual = status_description(&metadata);
    if description == "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data" {
        // internal/errors + internal/detrand choose one of these complete
        // diagnostics depending on the Go binary. Validate exact alternatives;
        // never normalize terminal text, metadata, or arbitrary whitespace.
        assert!(matches!(actual.as_str(),
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data" |
            "grpc: failed to unmarshal the received message: proto:\u{a0}cannot parse invalid wire-format data"
        ), "unexpected terminal diagnostic: {:?}", actual);
    } else { assert_eq!(actual, description); }
}
fn bytes_field(number: u32, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    prost::encoding::encode_varint((u64::from(number) << 3) | 2, &mut output);
    prost::encoding::encode_varint(data.len() as u64, &mut output);
    output.extend_from_slice(data); output
}
// Parse raw records independently of the production decoder. A descriptor-based
// prost decode cannot inspect Go's echoed known-number/wrong-wire unknowns.
fn wire_record<'a>(input: &mut &'a [u8]) -> (u32, &'a [u8]) {
    let start = *input;
    let field = prost_reflect::UnknownField::decode(input, prost::encoding::DecodeContext::default()).unwrap();
    (field.number(), &start[..start.len() - input.len()])
}
fn raw_bytes_field(mut input: &[u8], number: u32) -> Vec<u8> {
    while !input.is_empty() {
        let (field, mut record) = wire_record(&mut input);
        if field == number {
            assert_eq!(prost::encoding::decode_key(&mut record).unwrap().1, prost::encoding::WireType::LengthDelimited);
            let length = prost::encoding::decode_varint(&mut record).unwrap() as usize;
            assert_eq!(record.len(), length); return record.to_vec();
        }
    }
    panic!("missing raw field {}", number);
}
fn without_original(package: &str, mut input: &[u8]) -> DynamicMessage {
    let mut output = Vec::new();
    while !input.is_empty() {
        let (field, record) = wire_record(&mut input);
        if field != 2 { output.extend_from_slice(record); }
    }
    DynamicMessage::decode(native::descriptors().get_message_by_name(&format!("{}.ServerReflectionResponse", package)).unwrap(), output.as_slice()).unwrap()
}
fn unknown_wire(number: u32, wire: u8) -> Vec<u8> {
    let mut output = Vec::new();
    prost::encoding::encode_varint((u64::from(number) << 3) | u64::from(wire), &mut output);
    match wire {
        0 => output.extend_from_slice(&[0x80, 0]), // valid overlong value: retain verbatim
        1 => output.extend_from_slice(&[0x55; 8]),
        2 => output.extend_from_slice(&[0x81, 0, 0xff]), // unknown bytes need not be UTF-8
        3 => {
            output.extend_from_slice(&[0x98, 6, 0x81, 0]);
            prost::encoding::encode_varint((u64::from(number) << 3) | 4, &mut output);
        }
        5 => output.extend_from_slice(&[0x55; 4]),
        _ => panic!("test wire type"),
    }
    output
}
fn envelope(data: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(0); frame.extend_from_slice(&(data.len() as u32).to_be_bytes()); frame.extend_from_slice(data); frame.into()
}
fn query(package: &str, field: &str, value: &str) -> DynamicMessage {
    let mut input = message(package, "ServerReflectionRequest");
    input.set_field_by_name("host", Value::String("reflection.example:443".into()));
    input.set_field_by_name(field, Value::String(value.into())); input
}
fn extension_query(package: &str, name: &str, number: i32) -> DynamicMessage {
    let mut extension = message(package, "ExtensionRequest");
    extension.set_field_by_name("containing_type", Value::String(name.into()));
    if number != 0 { extension.set_field_by_name("extension_number", Value::I32(number)); }
    let mut input = message(package, "ServerReflectionRequest");
    input.set_field_by_name("host", Value::String("reflection.example:443".into()));
    input.set_field_by_name("file_containing_extension", Value::Message(extension)); input
}
fn nested(input: &DynamicMessage, field: &str) -> DynamicMessage { input.get_field_by_name(field).unwrap().as_message().unwrap().clone() }
fn list(input: &DynamicMessage, field: &str) -> Vec<Value> { input.get_field_by_name(field).unwrap().as_list().unwrap().to_vec() }
fn services(input: &DynamicMessage) -> Vec<String> {
    assert!(input.has_field_by_name("list_services_response"));
    list(&nested(input, "list_services_response"), "service").iter().map(|service| string_field(service.as_message().unwrap(), "name")).collect()
}
fn files(input: &DynamicMessage) -> Vec<DynamicMessage> {
    assert!(input.has_field_by_name("file_descriptor_response"));
    list(&nested(input, "file_descriptor_response"), "file_descriptor_proto").iter().map(|file| {
        let bytes = file.as_bytes().unwrap();
        DynamicMessage::decode(native::descriptors().get_message_by_name("google.protobuf.FileDescriptorProto").unwrap(), bytes.as_ref()).unwrap()
    }).collect()
}
fn file_names(input: &DynamicMessage) -> Vec<String> { files(input).iter().map(|file| string_field(file, "name")).collect() }
fn assert_echo(output: &DynamicMessage, input: &DynamicMessage) {
    assert_eq!(string_field(output, "valid_host"), string_field(input, "host"));
    assert_eq!(nested(output, "original_request"), *input);
}
fn assert_missing(output: &DynamicMessage) {
    assert!(output.has_field_by_name("error_response"));
    assert_eq!(nested(output, "error_response").get_field_by_name("error_code").unwrap().as_i32(), Some(5));
    let diagnostic = string_field(&nested(output, "error_response"), "error_message");
    assert!(matches!(diagnostic.as_str(), "proto: not found" | "proto:\u{a0}not found"), "unexpected lookup diagnostic: {:?}", diagnostic);
}
async fn list_roundtrip(fixture: &Fixture, package: &str) {
    let mut rpc = fixture.open(package).await;
    let input = query(package, "list_services", "");
    rpc.request(&input).await;
    assert_echo(&rpc.response(package).await, &input);
    rpc.finish(0).await;
}

bounded_test!(configured_reflection_lists_sorted_actual_registrations, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &ALL).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            let input = query(package, "list_services", "ignored listing argument");
            rpc.request(&input).await;
            let response = rpc.response(package).await;
            assert_echo(&response, &input);
            assert_eq!(services(&response), ALL_NAMES);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_disabled_services_and_gun_are_absent, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["rEfLeCtIoNsErViCe", "StatsService", "not-a-service"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            rpc.request(&query(package, "list_services", "")).await;
            assert_eq!(services(&rpc.response(package).await), [ALL_NAMES[0], ALL_NAMES[1], ALL_NAMES[5], ALL_NAMES[9]]);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_disabled_endpoint_is_unimplemented, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["StatsService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open_path(&format!("/{}.ServerReflection/ServerReflectionInfo", package), None, true).await;
            assert_terminal(&mut rpc, 12, &format!("unknown service {}.ServerReflection", package), true).await;
        }
    }
});

bounded_test!(configured_reflection_all_five_variants_echo_host_and_original, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            for input in [
                query(package, "list_services", ""),
                query(package, "file_by_filename", HANDLER),
                query(package, "file_containing_symbol", "xray.app.proxyman.command.HandlerService"),
                extension_query(package, "google.protobuf.FeatureSet", 1002),
                query(package, "all_extension_numbers_of_type", "google.protobuf.FeatureSet"),
            ] {
                rpc.request(&input).await;
                let response = rpc.response(package).await;
                assert_echo(&response, &input);
                assert!(!response.has_field_by_name("error_response"));
                if input.has_field_by_name("all_extension_numbers_of_type") {
                    let response = nested(&response, "all_extension_numbers_response");
                    assert_eq!(string_field(&response, "base_type_name"), "google.protobuf.FeatureSet");
                    assert_eq!(list(&response, "extension_number"), vec![Value::I32(1002)]);
                }
            }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_descriptor_bfs_closure_repeat_root_and_fresh_rpc, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for _fresh_rpc in 0..2 {
                let mut rpc = fixture.open(package).await;
                rpc.request(&query(package, "file_containing_symbol", "xray.app.proxyman.command.HandlerService")).await;
                assert_eq!(file_names(&rpc.response(package).await), HANDLER_FILES);
                for root in [HANDLER, "core/config.proto", HANDLER] {
                    let mut input = query(package, "file_by_filename", root);
                    input.set_field_by_name("host", Value::String(format!("changed-host-{}", root)));
                    rpc.request(&input).await;
                    assert_eq!(file_names(&rpc.response(package).await), [root]);
                }
                rpc.finish(0).await;
            }
        }
    }
});

bounded_test!(configured_reflection_resolves_member_nested_enum_oneof_extension_symbols, {
    let symbols = [
        ("xray.app.proxyman.command.HandlerService.AddInbound", HANDLER),
        ("xray.common.protocol.User.email", "common/protocol/user.proto"),
        ("xray.common.geodata.Domain.Attribute", "common/geodata/geodat.proto"),
        ("xray.common.geodata.Domain.Type", "common/geodata/geodat.proto"),
        ("xray.common.geodata.Domain.Substr", "common/geodata/geodat.proto"),
        ("xray.common.net.TCP", "common/net/network.proto"),
        ("xray.common.net.IPOrDomain.address", "common/net/address.proto"),
        ("grpc.reflection.v1.ServerReflectionRequest.message_request", "grpc/reflection/v1/reflection.proto"),
        ("pb.go", "google/protobuf/go_features.proto"),
    ];
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            for (symbol, file) in symbols {
                rpc.request(&query(package, "file_containing_symbol", symbol)).await;
                assert_eq!(file_names(&rpc.response(package).await)[0], file, "{}", symbol);
            }
            // Registration aliases are not invented protobuf descriptor names.
            rpc.request(&query(package, "file_containing_symbol", "v2ray.core.app.proxyman.command.HandlerService")).await;
            assert_missing(&rpc.response(package).await);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_concurrent_streams_have_independent_descriptor_sets, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        let mut streams = Vec::new();
        for package in PACKAGES.into_iter().cycle().take(8) {
            let mut rpc = fixture.open(package).await;
            rpc.request(&query(package, "file_by_filename", HANDLER)).await;
            streams.push((package, rpc));
        }
        for (package, mut rpc) in streams {
            assert_eq!(file_names(&rpc.response(package).await), HANDLER_FILES);
            rpc.request(&query(package, "file_by_filename", HANDLER)).await;
            assert_eq!(file_names(&rpc.response(package).await), [HANDLER]);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_unknown_request_fields_follow_pinned_version_adapter, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let known = extension_query(package, "google.protobuf.FeatureSet", 1002);
            let mut input = known.clone();
            let mut extension = nested(&input, "file_containing_extension").encode_to_vec();
            extension.extend_from_slice(&[0x98, 0x06, 1]);
            input.set_field_by_name("file_containing_extension", Value::Message(DynamicMessage::decode(
                native::descriptors().get_message_by_name(&format!("{}.ExtensionRequest", package)).unwrap(), extension.as_slice()
            ).unwrap()));
            let mut encoded = input.encode_to_vec(); encoded.extend_from_slice(&[0x98, 0x06, 2]);
            let mut rpc = fixture.open(package).await; rpc.raw(envelope(&encoded), false).await;
            let output = rpc.response(package).await;
            assert_eq!(file_names(&output)[0], "google/protobuf/go_features.proto");
            let original = nested(&output, "original_request");
            if package == "grpc.reflection.v1alpha" { assert_echo(&output, &known); }
            else {
                assert_eq!(original.unknown_fields().count(), 1);
                assert_eq!(nested(&original, "file_containing_extension").unknown_fields().count(), 1);
            }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_wrong_wire_known_fields_are_preserved_as_unknown, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            let known = query(package, "list_services", "").encode_to_vec();
            let mut cases = vec![(vec![0x18, 0, 0x3a, 0], vec![0x3a, 0, 0x18, 0], vec![0x3a, 0]),
                // Go canonicalizes the unknown tag, but retains its value bytes.
                (vec![0x98, 0, 0x80, 0, 0x3a, 0], vec![0x3a, 0, 0x18, 0x80, 0], vec![0x3a, 0])];
            for number in [1, 2, 3, 4, 5, 6, 7, 100] {
                for wire in [0, 1, 2, 3, 5] {
                    if wire == 2 && number != 2 && number != 100 { continue; }
                    let unknown = unknown_wire(number, wire);
                    let mut input = unknown.clone(); input.extend_from_slice(&known); input.extend_from_slice(&unknown);
                    let mut echo = known.clone(); echo.extend_from_slice(&unknown); echo.extend_from_slice(&unknown);
                    cases.push((input, echo, known.clone()));
                }
            }
            for (input, expected_v1, expected_alpha) in cases {
                rpc.raw(envelope(&input), false).await;
                let payload = rpc.next_payload().await.unwrap();
                assert_eq!(services(&without_original(package, &payload)), &ALL_NAMES[..2]);
                let expected = if package == PACKAGES[0] { expected_v1 } else { expected_alpha };
                assert_eq!(raw_bytes_field(&payload, 2), expected, "{:02x?}", input);
            }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_unknown_groups_follow_go_depth_and_tag_limits, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for depth in [1, 101, 10001, 10002] {
                let mut unknown = vec![0x1b; depth];
                // ConsumeTag inside an unknown group permits a field number
                // above the message limit, through MaxInt32, like MessageSet.
                prost::encoding::encode_varint((i32::MAX as u64) << 3, &mut unknown);
                unknown.push(0); unknown.extend(std::iter::repeat_n(0x1c, depth));
                let mut input = unknown.clone(); input.extend_from_slice(&[0x3a, 0]);
                let mut rpc = fixture.open(package).await; rpc.raw(envelope(&input), true).await;
                if depth > 10001 {
                    assert_terminal(&mut rpc, 13, "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data", true).await;
                } else {
                    let payload = rpc.next_payload().await.unwrap();
                    assert_eq!(services(&without_original(package, &payload)), &ALL_NAMES[..2]);
                    let mut expected = vec![0x3a, 0];
                    if package == PACKAGES[0] { expected.extend_from_slice(&unknown); }
                    assert_eq!(raw_bytes_field(&payload, 2), expected);
                    assert_terminal(&mut rpc, 0, "", false).await;
                }
            }
        }
    }
});

bounded_test!(configured_reflection_nested_wrong_wire_unknowns_and_oneof_merges, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            let known = extension_query(package, "google.protobuf.FeatureSet", 1002);
            let extension = nested(&known, "file_containing_extension").encode_to_vec();
            for (number, wires) in [(1, &[0, 1, 3, 5][..]), (2, &[1, 2, 3, 5][..])] {
                for &wire in wires {
                    let unknown = unknown_wire(number, wire);
                    let mut inner = unknown.clone(); inner.extend_from_slice(&extension); inner.extend_from_slice(&unknown);
                    let input = bytes_field(5, &inner);
                    rpc.raw(envelope(&input), false).await;
                    let payload = rpc.next_payload().await.unwrap();
                    assert_eq!(file_names(&without_original(package, &payload))[0], "google/protobuf/go_features.proto");
                    let mut expected = extension.clone();
                    if package == PACKAGES[0] { expected.extend_from_slice(&unknown); expected.extend_from_slice(&unknown); }
                    assert_eq!(raw_bytes_field(&payload, 2), bytes_field(5, &expected));
                }
            }
            let mut first = message(package, "ExtensionRequest");
            first.set_field_by_name("containing_type", Value::String("google.protobuf.FeatureSet".into()));
            let mut second = message(package, "ExtensionRequest");
            second.set_field_by_name("extension_number", Value::I32(1002));
            let unknown = unknown_wire(2, 2);
            let mut first_bytes = first.encode_to_vec(); first_bytes.extend_from_slice(&unknown);
            for reset_oneof in [false, true] {
                let mut input = bytes_field(5, &first_bytes);
                if reset_oneof { input.extend_from_slice(&[0x3a, 0]); }
                // Wrong-wire siblings do not select a new oneof variant.
                input.extend_from_slice(&[0x18, 0]);
                input.extend_from_slice(&bytes_field(5, &second.encode_to_vec()));
                rpc.raw(envelope(&input), false).await;
                let payload = rpc.next_payload().await.unwrap();
                let output = without_original(package, &payload);
                if reset_oneof { assert_missing(&output); }
                else { assert_eq!(file_names(&output)[0], "google/protobuf/go_features.proto"); }
                let mut inner = if reset_oneof { second.encode_to_vec() } else { extension.clone() };
                if package == PACKAGES[0] && !reset_oneof { inner.extend_from_slice(&unknown); }
                let mut expected = bytes_field(5, &inner);
                if package == PACKAGES[0] { expected.extend_from_slice(&[0x18, 0]); }
                assert_eq!(raw_bytes_field(&payload, 2), expected);
            }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_million_empty_extensions_end_in_small_list_response, {
    let containing_type = vec![b'x'; 2 * 1024 * 1024];
    let mut input = bytes_field(5, &bytes_field(1, &containing_type));
    input.extend_from_slice(&[0x2a, 0].repeat(1_000_000));
    input.extend_from_slice(&[0x3a, 0]);
    assert_eq!(input.len(), 4_097_164);
    assert!(input.len() < MAX_MESSAGE);
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            rpc.raw(envelope(&input), false).await;
            let payload = rpc.next_payload().await.expect("large valid request responds before half-close");
            assert!(payload.len() < 512, "discarded ExtensionRequest leaked into response");
            let output = DynamicMessage::decode(
                native::descriptors().get_message_by_name(&format!("{}.ServerReflectionResponse", package)).unwrap(), payload
            ).unwrap();
            let mut expected = message(package, "ServerReflectionRequest");
            expected.set_field_by_name("list_services", Value::String(String::new()));
            assert_echo(&output, &expected);
            assert_eq!(services(&output), &ALL_NAMES[..2]);
            let next = extension_query(package, "google.protobuf.FeatureSet", 1002);
            rpc.request(&next).await;
            let output = rpc.response(package).await;
            assert_echo(&output, &next);
            assert_eq!(file_names(&output), ["google/protobuf/go_features.proto", "google/protobuf/descriptor.proto"]);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_many_nonempty_extensions_preserve_unknowns_and_oneof_state, {
    let containing_type = bytes_field(1, &vec![b'x'; 2 * 1024 * 1024]);
    let first_unknown = [0x98, 6, 0x80, 0];
    let nested_unknown = [0x12, 0x81, 0, 0xff];
    let root_unknown = [0x18, 0, 0x28, 0];
    let number = [0x10, 0xea, 7];
    let mut first = containing_type.clone(); first.extend_from_slice(&first_unknown);
    let mut continuation = number.to_vec(); continuation.extend_from_slice(&nested_unknown);
    let mut input = bytes_field(5, &first);
    input.extend_from_slice(&bytes_field(5, &continuation).repeat(200_000));
    // Wrong-wire siblings, including field 5 itself, must not select/reset the
    // oneof or discard the accumulated child and its verbatim unknown values.
    input.extend_from_slice(&root_unknown);
    assert_eq!(input.len(), 3_897_170);
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for reset in [false, true] {
                let mut request = input.clone();
                if reset {
                    request.extend_from_slice(&[0x3a, 0]);
                    request.extend_from_slice(&bytes_field(5, &number));
                }
                assert!(request.len() < MAX_MESSAGE);
                let mut rpc = fixture.open(package).await; rpc.raw(envelope(&request), false).await;
                let payload = rpc.next_payload().await.expect("nonempty continuations merge before half-close");
                assert_missing(&without_original(package, &payload));
                let mut extension = if reset { Vec::new() } else { containing_type.clone() };
                extension.extend_from_slice(&number);
                if package == PACKAGES[0] && !reset {
                    extension.extend_from_slice(&first_unknown);
                    extension.extend_from_slice(&nested_unknown.repeat(200_000));
                }
                let mut expected = bytes_field(5, &extension);
                if package == PACKAGES[0] { expected.extend_from_slice(&root_unknown); }
                assert_eq!(raw_bytes_field(&payload, 2), expected);
                if reset { assert!(payload.len() < 512, "oneof reset retained the old child"); }
                let next = extension_query(package, "google.protobuf.FeatureSet", 1002);
                rpc.request(&next).await;
                let output = rpc.response(package).await;
                assert_echo(&output, &next);
                assert_eq!(file_names(&output), ["google/protobuf/go_features.proto", "google/protobuf/descriptor.proto"]);
                rpc.finish(0).await;
            }
        }
    }
});

bounded_test!(configured_reflection_extension_1002_preserves_encoded_custom_options, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            rpc.request(&extension_query(package, "google.protobuf.FeatureSet", 1002)).await;
            let output = rpc.response(package).await;
            assert_eq!(file_names(&output), ["google/protobuf/go_features.proto", "google/protobuf/descriptor.proto"]);
            let encoded = list(&nested(&output, "file_descriptor_response"), "file_descriptor_proto");
            for file in &encoded {
                let data = file.as_bytes().unwrap();
                let decoded = DynamicMessage::decode(native::descriptors().get_message_by_name("google.protobuf.FileDescriptorProto").unwrap(), data.as_ref()).unwrap();
                let name = string_field(&decoded, "name");
                assert_eq!(data.as_ref(), native::descriptors().get_file_by_name(&name).unwrap().encode_to_vec());
            }
            let root = files(&output).remove(0);
            let extensions = list(&root, "extension");
            assert!(extensions.iter().any(|extension| extension.as_message().unwrap().get_field_by_name("number").unwrap().as_i32() == Some(1002)));
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_extension_numbers_known_empty_and_nonmessage_fallback, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            for name in ["xray.common.protocol.User", "xray.app.proxyman.command.HandlerService", "xray.common.protocol.User.email"] {
                rpc.request(&query(package, "all_extension_numbers_of_type", name)).await;
                let output = nested(&rpc.response(package).await, "all_extension_numbers_response");
                assert_eq!(string_field(&output, "base_type_name"), name);
                assert!(list(&output, "extension_number").is_empty());
            }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_missing_queries_recover_on_same_stream, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            for input in [
                query(package, "file_by_filename", "missing.proto"), query(package, "file_by_filename", ""),
                query(package, "file_containing_symbol", ".xray.common.protocol.User"),
                query(package, "file_containing_symbol", ".xray.app.proxyman.command.HandlerService"),
                query(package, "file_containing_symbol", ".xray.common.geodata.Domain.Type"),
                query(package, "file_containing_symbol", ".pb.go"),
                query(package, "file_containing_symbol", "missing.Symbol"),
                extension_query(package, "google.protobuf.FeatureSet", -1),
                extension_query(package, "google.protobuf.FeatureSet", 0),
                extension_query(package, "missing.Symbol", 1002),
                query(package, "all_extension_numbers_of_type", "missing.Symbol"),
                query(package, "all_extension_numbers_of_type", ".xray.common.protocol.User"),
            ] {
                rpc.request(&input).await;
                let output = rpc.response(package).await; assert_echo(&output, &input); assert_missing(&output);
                rpc.request(&query(package, "list_services", "")).await;
                assert_eq!(services(&rpc.response(package).await), &ALL_NAMES[..2]);
            }
            rpc.request(&query(package, "file_by_filename", HANDLER)).await;
            assert_eq!(file_names(&rpc.response(package).await), HANDLER_FILES);
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_missing_oneof_is_terminal_invalid_argument, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            let good = envelope(&query(package, "list_services", "").encode_to_vec());
            let missing = envelope(&message(package, "ServerReflectionRequest").encode_to_vec());
            let mut batch = Vec::new(); batch.extend_from_slice(&good); batch.extend_from_slice(&missing); batch.extend_from_slice(&good);
            rpc.raw(batch, true).await;
            assert_eq!(services(&rpc.response(package).await), &ALL_NAMES[..2]);
            assert_terminal(&mut rpc, 3, "invalid MessageRequest: <nil>", false).await;
            for payload in [vec![], vec![0x18, 0]] {
                let mut rpc = fixture.open(package).await;
                rpc.raw(envelope(&payload), true).await;
                assert_terminal(&mut rpc, 3, "invalid MessageRequest: <nil>", true).await;
            }
            list_roundtrip(&fixture, package).await;
        }
    }
});

bounded_test!(configured_reflection_empty_half_close_has_ok_trailers, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut closed = fixture.open_path(&format!("/{}.ServerReflection/ServerReflectionInfo", package), None, true).await;
            assert_terminal(&mut closed, 0, "", true).await;
            let mut rpc = fixture.open(package).await; rpc.raw(Bytes::new(), true).await;
            assert_terminal(&mut rpc, 0, "", true).await;
        }
    }
});

bounded_test!(configured_reflection_headers_wait_for_response_and_success_has_empty_message, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            assert!(tokio::time::timeout(Duration::from_millis(150), rpc.response.as_mut().unwrap()).await.is_err());
            rpc.request(&query(package, "list_services", "")).await;
            assert_eq!(services(&rpc.response(package).await), &ALL_NAMES[..2]);
            let headers = rpc.headers.as_ref().unwrap();
            assert!(!headers.contains_key("grpc-status")); assert!(!headers.contains_key("grpc-message"));
            rpc.raw(Bytes::new(), true).await;
            assert_terminal(&mut rpc, 0, "", false).await;
        }
    }
});

bounded_test!(configured_reflection_fragmentation_and_coalescing_before_half_close, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut rpc = fixture.open(package).await;
            let input = query(package, "list_services", "");
            let frame = envelope(&input.encode_to_vec());
            for byte in &frame { rpc.raw(vec![*byte], false).await; }
            assert_echo(&rpc.response(package).await, &input);
            let mut batch = Vec::new();
            for _ in 0..32 { batch.extend_from_slice(&frame); }
            rpc.raw(batch, true).await;
            for _ in 0..32 { assert_echo(&rpc.response(package).await, &input); }
            rpc.status(0).await;
        }
    }
});

bounded_test!(configured_reflection_wire_errors_have_pinned_terminal_statuses, {
    let mut cases = vec![
        (vec![0], 13), (vec![0, 0], 13), (vec![0, 0, 0], 13), (vec![0, 0, 0, 0], 13),
        (vec![0, 0, 0, 0, 3, 0x12], 13), (envelope(&[0xff]).to_vec(), 13),
        (envelope(&[0x12, 5, b'x']).to_vec(), 13),
        (vec![1, 0, 0, 0, 0], 13), (vec![2, 0, 0, 0, 0], 13), (vec![255, 0, 0, 0, 0], 13),
    ];
    let mut oversized = vec![0]; oversized.extend_from_slice(&((MAX_MESSAGE + 1) as u32).to_be_bytes()); cases.push((oversized, 8));
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for (frame, status) in &cases {
                let mut rpc = fixture.open(package).await; rpc.raw(frame.clone(), true).await; rpc.status(*status).await;
            }
            list_roundtrip(&fixture, package).await;
        }
    }
});

bounded_test!(configured_reflection_malformed_wire_diagnostics_match_pinned_go, {
    let malformed = [
        vec![0xff], vec![0], vec![0x0e], vec![0x0c], vec![0x0b],
        vec![0x0b, 0x14], vec![0x12, 5, b'x'], vec![0x2a, 1, 0x10],
        vec![0x18, 0x80], vec![0x19, 0], vec![0x1a, 0x80],
        vec![0x80; 11], vec![0x80, 0x80, 0x80, 0x80, 0x10, 0],
    ];
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for after_response in [false, true] {
                for data in &malformed {
                    let mut rpc = fixture.open(package).await;
                    if after_response {
                        rpc.request(&query(package, "list_services", "")).await;
                        assert_eq!(services(&rpc.response(package).await), &ALL_NAMES[..2]);
                    }
                    rpc.raw(envelope(data), true).await;
                    assert_terminal(&mut rpc, 13, "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data", !after_response).await;
                }
            }
            for data in [vec![0x0a, 1, 0xff, 0x3a, 0], vec![0x2a, 3, 0x0a, 1, 0xff]] {
                let mut rpc = fixture.open(package).await; rpc.raw(envelope(&data), true).await;
                assert_terminal(&mut rpc, 13, "grpc: failed to unmarshal the received message: string field contains invalid UTF-8", true).await;
            }
            list_roundtrip(&fixture, package).await;
        }
    }
});

bounded_test!(configured_reflection_oversize_header_fails_without_waiting_for_payload, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            for flag in [0, 1, 255] {
                let mut header = vec![flag]; header.extend_from_slice(&u32::MAX.to_be_bytes());
                let mut rpc = fixture.open(package).await; rpc.raw(header, false).await; rpc.status(8).await;
            }
        }
    }
});

bounded_test!(configured_reflection_compression_header_is_validated_before_receiving, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let path = format!("/{}.ServerReflection/ServerReflectionInfo", package);
            for encoding in ["not-installed", "gzip"] {
                for end in [false, true] {
                    let mut rpc = fixture.open_path(&path, Some(encoding), end).await;
                    assert_terminal(&mut rpc, 12, &format!("grpc: Decompressor is not installed for grpc-encoding {:?}", encoding), true).await;
                }
            }
            let mut rpc = fixture.open_path(&path, Some("identity"), false).await;
            rpc.request(&query(package, "list_services", "")).await;
            assert_eq!(services(&rpc.response(package).await), &ALL_NAMES[..2]); rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_exact_four_mib_payload_excludes_envelope, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let mut input = message(package, "ServerReflectionRequest");
            input.set_field_by_name("list_services", Value::String("x".repeat(MAX_MESSAGE - 5)));
            assert_eq!(input.encoded_len(), MAX_MESSAGE);
            let mut rpc = fixture.open(package).await; rpc.request(&input).await;
            let output = rpc.response(package).await; assert_echo(&output, &input);
            assert_eq!(services(&output), &ALL_NAMES[..2]); rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_four_mib_limit_is_per_message_not_per_rpc, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService"]).await;
        for package in PACKAGES {
            let input = query(package, "list_services", &"x".repeat(32768));
            let mut rpc = fixture.open(package).await;
            for _ in 0..129 { rpc.request(&input).await; assert_echo(&rpc.response(package).await, &input); }
            rpc.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_backpressure_and_cancel_isolate_concurrent_streams, {
    for direct in [false, true] {
        let fixture = Fixture::with_window(direct, &["ReflectionService", "StatsService"], 32).await;
        for package in PACKAGES {
            let mut blocked = fixture.open(package).await;
            let input = query(package, "file_by_filename", "google/protobuf/descriptor.proto");
            blocked.request(&input).await;
            // The first DATA exhausts this stream's tiny receive window. Withhold
            // its credit while proving another stream completes on the connection.
            blocked.receive_headers().await;
            let chunk = blocked.body.as_mut().unwrap().data().await.unwrap().unwrap(); assert_eq!(chunk.len(), 32);
            list_roundtrip(&fixture, package).await;
            // No application read-ahead while response capacity is blocked. h2's
            // bounded request window is exhausted by a second large input.
            let frame = envelope(&query(package, "list_services", &"x".repeat(256 * 1024)).encode_to_vec());
            assert!(tokio::time::timeout(Duration::from_millis(150), blocked.raw(frame, false)).await.is_err());
            blocked.send.send_reset(h2::Reason::CANCEL);
            blocked.body.as_mut().unwrap().flow_control().release_capacity(chunk.len()).unwrap();
            drop(blocked);
            list_roundtrip(&fixture, package).await;
            let mut independent = fixture.open(package).await;
            independent.request(&query(package, "file_by_filename", HANDLER)).await;
            assert_eq!(file_names(&independent.response(package).await), HANDLER_FILES);
            independent.finish(0).await;
        }
    }
});

bounded_test!(configured_reflection_cancellation_preserves_dynamic_unary_stats, {
    for direct in [false, true] {
        let fixture = Fixture::new(direct, &["ReflectionService", "StatsService"]).await;
        let counter = fixture.config.stats_manager.register_counter("reflection-live");
        for package in PACKAGES {
            let mut canceled = fixture.open(package).await;
            canceled.request(&query(package, "list_services", "")).await;
            assert!(!services(&canceled.response(package).await).is_empty());
            canceled.send.send_reset(h2::Reason::CANCEL); drop(canceled);
            let mut active = fixture.open(package).await;
            active.request(&query(package, "list_services", "")).await;
            assert_eq!(services(&active.response(package).await), [ALL_NAMES[0], ALL_NAMES[1], ALL_NAMES[5], ALL_NAMES[9]]);
            counter.add(7);
            let input = native::decode_message("xray.app.stats.command.QueryStatsRequest", &[]).unwrap();
            let mut unary = fixture.open_path("/xray.app.stats.command.StatsService/QueryStats", None, false).await;
            unary.raw(envelope(&input.encode_to_vec()), true).await;
            active.request(&query(package, "file_by_filename", HANDLER)).await;
            let output = native::decode_message("xray.app.stats.command.QueryStatsResponse", &unary.next_payload().await.unwrap()).unwrap();
            let stats = list(&output, "stat"); assert_eq!(stats.len(), 1);
            let stat = stats[0].as_message().unwrap();
            assert_eq!(string_field(stat, "name"), "reflection-live");
            assert_eq!(stat.get_field_by_name("value").unwrap().as_i64(), Some(counter.value()));
            unary.status(0).await;
            assert_eq!(file_names(&active.response(package).await), HANDLER_FILES);
            active.finish(0).await; list_roundtrip(&fixture, package).await;
        }
    }
});

bounded_test!(configured_reflection_root_close_terminates_idle_and_blocked_streams, {
    for direct in [false, true] {
        let fixture = Fixture::with_window(direct, &["ReflectionService"], 32).await;
        let mut idle = fixture.open(PACKAGES[0]).await;
        let mut blocked = fixture.open(PACKAGES[1]).await;
        blocked.request(&query(PACKAGES[1], "file_by_filename", "google/protobuf/descriptor.proto")).await;
        blocked.receive_headers().await;
        let chunk = blocked.body.as_mut().unwrap().data().await.unwrap().unwrap(); assert_eq!(chunk.len(), 32);
        let retained = fixture.config.outbounds["reflection-api"].clone();
        fixture.close();
        assert!(idle.response.take().unwrap().await.is_err());
        // Credit already handed to this test is still owned by the receive half;
        // dropping it must not delay connection shutdown or later close calls.
        drop(blocked);
        assert!(retained.connect(&SessionContext::new("closed", Destination::tcp(crate::common::net::parse_address("127.0.0.1"), 1))).await.is_err());
        fixture.close();
    }
});
