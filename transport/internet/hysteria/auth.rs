//! HTTP/3 authentication shared by the real endpoint and Go fixture tests.
use super::padding::padding::Padding;
use crate::{common::errors::{Error, Result}, proxy::hysteria::config::{HysteriaConfig, HysteriaUser}};
use http::{Method, Request, Response, StatusCode};

pub const STATUS_AUTH_OK: u16 = 233;
pub const HEADER_AUTH: &str = "hysteria-auth";
pub const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub const HEADER_UDP: &str = "hysteria-udp";
pub const HEADER_PADDING: &str = "hysteria-padding";

pub fn auth_request(config: &HysteriaConfig) -> Result<Request<()>> {
    Request::builder().method(Method::POST).uri("https://hysteria/auth")
        .header(HEADER_AUTH, config.auth_value()).header(HEADER_CC_RX, config.rx_bytes().to_string())
        .header(HEADER_PADDING, Padding::new(256, 2048).generate_string())
        .body(()).map_err(|error| Error::Config(error.to_string()))
}

/// None means masquerade. Some(None) is transport-auth; Some(Some(user)) is
/// proxy user authentication. Once authenticated, Go accepts repeated auth URLs.
pub fn authenticate(request: &Request<()>, config: &HysteriaConfig, active: bool) -> Option<Option<HysteriaUser>> {
    if request.method() != Method::POST || request.uri().authority().map(|value| value.as_str()) != Some("hysteria")
        || request.uri().path() != "/auth" { return None; }
    if active { return Some(None); }
    let supplied = request.headers().get(HEADER_AUTH)?.to_str().ok()?;
    if !config.users.is_empty() {
        return config.users.iter().find(|user| constant_time_eq(user.auth.as_bytes(), supplied.as_bytes())).cloned().map(Some);
    }
    (!config.auth_value().is_empty() && constant_time_eq(config.auth_value().as_bytes(), supplied.as_bytes())).then_some(None)
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() { return false; }
    left.iter().zip(right).fold(0u8, |difference, (left, right)| difference | (left ^ right)) == 0
}
pub fn auth_response(config: &HysteriaConfig, udp: bool) -> Result<Response<()>> {
    auth_response_values(config.rx_bytes(), udp)
}
pub fn auth_response_values(rx_bytes: u64, udp: bool) -> Result<Response<()>> {
    Response::builder().status(STATUS_AUTH_OK).header(HEADER_UDP, udp.to_string())
        .header(HEADER_CC_RX, rx_bytes.to_string())
        .header(HEADER_PADDING, Padding::new(256, 2048).generate_string())
        .body(()).map_err(|error| Error::Protocol(error.to_string()))
}
pub fn parse_response(response: &Response<()>) -> Result<bool> {
    if response.status().as_u16() != STATUS_AUTH_OK {
        return Err(Error::AuthFailed(format!("Hysteria HTTP/3 status {}", response.status())));
    }
    // Go does not require these optional headers. Missing/malformed UDP never
    // grants a capability; missing CC-RX behaves like zero in Go.
    Ok(response.headers().get(HEADER_UDP).and_then(|value| value.to_str().ok()).is_some_and(|value| value == "true" || value == "1" || value == "TRUE" || value == "True"))
}
pub fn masquerade(config: &HysteriaConfig) -> Result<(Response<()>, bytes::Bytes)> {
    let transport = &config.transport;
    if transport.masq_type.eq_ignore_ascii_case("string") {
        let mut response = Response::builder().status(if transport.masq_string_status_code == 0 { 200 } else { transport.masq_string_status_code });
        for (name, value) in &transport.masq_string_headers { response = response.header(name, value); }
        Ok((response.body(()).map_err(|error| Error::Config(error.to_string()))?, bytes::Bytes::copy_from_slice(transport.masq_string.as_bytes())))
    } else {
        Ok((Response::builder().status(StatusCode::NOT_FOUND).header("content-type", "text/plain; charset=utf-8").body(()).expect("static 404 response"), bytes::Bytes::from_static(b"404 page not found\n")))
    }
}
