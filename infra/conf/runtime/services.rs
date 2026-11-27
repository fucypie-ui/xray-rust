//! Small native gRPC/HTTP adapters over h2, httparse and prost-reflect.
//! Unsupported RPCs return UNIMPLEMENTED rather than acknowledging a no-op.
use std::{sync::{Arc, Mutex}, time::{Instant, UNIX_EPOCH}};
use async_trait::async_trait;
use bytes::Bytes;
use prost::Message;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use crate::{common::{errors::{Error, Result}, net::BoxStream, protocol::SessionContext}, features::{feature::Feature, outbound::OutboundHandler, stats::DefaultStatsManager}};
use super::super::{api::ApiConfig, metrics::MetricsConfig, native};

type RpcResult = std::result::Result<Value, (u32, String)>;

#[path = "reflection.rs"] mod reflection;

pub(super) struct RootServices {
    stats: Arc<DefaultStatsManager>,
    stats_enabled: bool,
    observation: Option<Arc<crate::app::observatory::Observatory>>,
    started: Instant,
}
impl RootServices {
    pub fn new(stats: Arc<DefaultStatsManager>, stats_enabled: bool, observation: Option<Arc<crate::app::observatory::Observatory>>) -> Self {
        Self { stats, stats_enabled, observation, started: Instant::now() }
    }
    fn counters(&self) -> Vec<(String, Arc<crate::features::stats::Counter>)> {
        if self.stats_enabled { self.stats.all_counters() } else { Vec::new() }
    }
    fn status(&self) -> Vec<Value> {
        let Some(observation) = &self.observation else { return Vec::new(); };
        let mut statuses = observation.all_statuses();
        statuses.sort_by(|a,b| a.outbound_tag.cmp(&b.outbound_tag));
        statuses.into_iter().map(|status| json!({
            "alive":status.alive, "delay":status.delay_ms.min(i64::MAX as u64),
            "lastErrorReason":status.last_error_reason.unwrap_or_default(), "outboundTag":status.outbound_tag,
            "lastSeenTime":status.last_seen_time, "lastTryTime":status.last_try_time,
        })).collect()
    }
    fn metrics(&self) -> Value {
        let mut stats = json!({"inbound":{},"outbound":{},"user":{}});
        for (name, counter) in self.counters() {
            let fields: Vec<_> = name.split(">>>").collect();
            if fields.len() >= 4 {
                if stats.get(fields[0]).is_none() { stats[fields[0]] = json!({}); }
                if stats[fields[0]].get(fields[1]).is_none() { stats[fields[0]][fields[1]] = json!({}); }
                stats[fields[0]][fields[1]][fields[3]] = json!(counter.value());
            }
        }
        let observations = if self.observation.is_some() {
            let mut statuses = serde_json::Map::new();
            for status in self.status() {
                let tag = status["outboundTag"].as_str().unwrap_or_default().to_string();
                statuses.insert(tag, status);
            }
            Value::Object(statuses)
        } else { Value::Null };
        json!({"stats":stats,"observatory":observations})
    }
    fn rpc(&self, service: &str, method: &str, input: &Value) -> RpcResult {
        let missing = |name: &str| (2,format!("{} not found.", name));
        let name = input["name"].as_str().unwrap_or_default();
        let reset = input["reset"].as_bool().unwrap_or(false);
        let counter_value = |counter: Arc<crate::features::stats::Counter>| if reset {counter.set(0)} else {counter.value()};
        match (service, method) {
            ("xray.app.stats.command.StatsService", "GetStats") => {
                let counter = self.stats_enabled.then(|| self.stats.get_counter(name)).flatten().ok_or_else(|| missing(name))?;
                Ok(json!({"stat":{"name":name,"value":counter_value(counter)}}))
            }
            ("xray.app.stats.command.StatsService", "QueryStats") => {
                let pattern = input["pattern"].as_str().unwrap_or_default();
                let mut stats = self.counters(); stats.sort_by(|a,b| a.0.cmp(&b.0));
                let stats: Vec<_> = stats.into_iter().filter(|(name,_)| name.contains(pattern)).map(|(name,counter)| json!({"name":name,"value":counter_value(counter)})).collect();
                Ok(json!({"stat":stats}))
            }
            ("xray.app.stats.command.StatsService", "GetStatsOnline") => {
                let online = self.stats_enabled.then(|| self.stats.get_online_map(name)).flatten().ok_or_else(|| missing(name))?;
                Ok(json!({"stat":{"name":name,"value":online.count()}}))
            }
            ("xray.app.stats.command.StatsService", "GetStatsOnlineIpList") => {
                let online = self.stats_enabled.then(|| self.stats.get_online_map(name)).flatten().ok_or_else(|| missing(name))?;
                let ips: serde_json::Map<_,_> = online.ip_time_map().into_iter().map(|(ip,time)| (ip,json!(time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()))).collect();
                Ok(json!({"name":name,"ips":ips}))
            }
            ("xray.app.stats.command.StatsService", "GetAllOnlineUsers") => {
                let users = if self.stats_enabled { self.stats.get_all_online_users().into_iter().filter_map(|name| name.strip_prefix("user>>>").and_then(|name| name.strip_suffix(">>>online")).map(str::to_owned)).collect::<Vec<_>>() } else {Vec::new()};
                Ok(json!({"users":users}))
            }
            ("xray.app.stats.command.StatsService", "GetUsersStats") => {
                let include_traffic = input["includeTraffic"].as_bool().unwrap_or(false);
                let mut users = std::collections::BTreeMap::<String,Value>::new();
                if self.stats_enabled {
                    for name in self.stats.get_all_online_users() {
                        let Some(email) = name.strip_prefix("user>>>").and_then(|name| name.strip_suffix(">>>online")) else {continue};
                        let ips = self.stats.get_online_map(&name).map(|map| map.ip_time_map().into_iter().map(|(ip,time)| json!({"ip":ip,"lastSeen":time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()})).collect::<Vec<_>>()).unwrap_or_default();
                        users.insert(email.into(),json!({"email":email,"ips":ips}));
                    }
                    if include_traffic {
                        for (name,counter) in self.counters() {
                            let fields: Vec<_> = name.split(">>>").collect();
                            if fields.len() != 4 || fields[0] != "user" || fields[2] != "traffic" || !matches!(fields[3], "uplink" | "downlink") {continue;}
                            let entry = users.entry(fields[1].into()).or_insert_with(|| json!({"email":fields[1],"ips":[]}));
                            if entry.get("traffic").is_none() {entry["traffic"] = json!({});}
                            entry["traffic"][fields[3]] = json!(counter_value(counter));
                        }
                    }
                }
                Ok(json!({"users":users.into_values().collect::<Vec<_>>()}))
            }
            ("xray.core.app.observatory.command.ObservatoryService", "GetOutboundStatus") => {
                if self.observation.is_none() {return Err((9,"observatory is not configured".into()));}
                Ok(json!({"status":{"status":self.status()}}))
            }
            // Go-runtime allocator/GC data has no equivalent in this runtime.
            ("xray.app.stats.command.StatsService", "GetSysStats") => Err((12,format!("Go runtime statistics are unavailable (uptime {}s)",self.started.elapsed().as_secs()))),
            _ => Err((12,format!("RPC {}.{} is not implemented", service, method))),
        }
    }
}

#[derive(Clone)]
enum Endpoint { Api(Vec<String>), Metrics }
struct EndpointState {
    services: Arc<RootServices>, endpoint: Endpoint, cancel: CancellationToken,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}
impl EndpointState {
    fn spawn(self: &Arc<Self>, stream: BoxStream) -> Result<()> {
        if self.cancel.is_cancelled() {return Err(Error::Closed);}
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error::Other(error.to_string()))?;
        let state = self.clone();
        let handle = runtime.spawn(async move {
            tokio::select! { _ = state.cancel.cancelled() => {}, _ = async {
                match &state.endpoint {
                    Endpoint::Api(services) => {let _ = grpc(stream, state.services.clone(), services.clone()).await;}
                    Endpoint::Metrics => {let _ = http_metrics(stream, &state.services).await;}
                }
            } => {} }
        }).abort_handle();
        let mut tasks = self.tasks.lock().map_err(|_| Error::Closed)?;
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
        Ok(())
    }
}
struct ServiceOutbound { tag: String, state: Arc<EndpointState> }
#[async_trait]
impl OutboundHandler for ServiceOutbound {
    fn tag(&self) -> &str {&self.tag}
    async fn connect(&self, _session: &SessionContext) -> Result<BoxStream> {
        let (client, server) = tokio::io::duplex(64*1024);
        self.state.spawn(Box::pin(server))?;
        Ok(Box::pin(client))
    }
}

pub(super) struct ServiceFeature { tag: String, listen: String, state: Arc<EndpointState>, listener: Mutex<Option<tokio::task::AbortHandle>> }
impl ServiceFeature {
    pub fn api(config: ApiConfig, services: Arc<RootServices>) -> Self {
        let enabled = config.enabled_services().into_iter().map(str::to_owned).collect();
        Self::new(config.tag, config.listen, services, Endpoint::Api(enabled))
    }
    pub fn metrics(config: MetricsConfig, services: Arc<RootServices>) -> Result<Self> {
        let config = config.build()?;
        Ok(Self::new(config.tag, config.listen, services, Endpoint::Metrics))
    }
    fn new(tag: String, listen: String, services: Arc<RootServices>, endpoint: Endpoint) -> Self {
        Self {tag, listen, state:Arc::new(EndpointState {services, endpoint, cancel:CancellationToken::new(), tasks:Mutex::new(Vec::new())}), listener:Mutex::new(None)}
    }
    pub fn tag(&self) -> &str {&self.tag}
    pub fn outbound(&self) -> Arc<dyn OutboundHandler> {Arc::new(ServiceOutbound {tag:self.tag.clone(),state:self.state.clone()})}
}
impl Feature for ServiceFeature {
    fn feature_type(&self) -> &'static str {match &self.state.endpoint {Endpoint::Api(_) => "commander",Endpoint::Metrics => "metrics"}}
    fn start(&self) -> Result<()> {
        if self.state.cancel.is_cancelled() {return Err(Error::Closed);}
        let mut task = self.listener.lock().map_err(|_| Error::Closed)?;
        if task.is_some() || self.listen.is_empty() {return Ok(());}
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error::Other(error.to_string()))?;
        let listener = std::net::TcpListener::bind(&self.listen)?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let state = self.state.clone();
        *task = Some(runtime.spawn(async move {
            loop { tokio::select! {
                _ = state.cancel.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream,_)) => {if state.spawn(Box::pin(stream)).is_err() {break;}}
                    Err(error) => {tracing::warn!("root service accept failed: {}",error);break;}
                }
            }}
        }).abort_handle());
        Ok(())
    }
    fn close(&self) -> Result<()> {
        self.state.cancel.cancel();
        if let Some(task) = self.listener.lock().map_err(|_| Error::Closed)?.take() {task.abort();}
        for task in self.state.tasks.lock().map_err(|_| Error::Closed)?.drain(..) {task.abort();}
        Ok(())
    }
}
impl Drop for ServiceFeature { fn drop(&mut self) {let _ = self.close();} }

async fn http_metrics(mut stream: BoxStream, services: &RootServices) -> Result<()> {
    let mut data = Vec::new();
    let (status,body) = loop {
        let mut buffer = [0u8;1024];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {return Ok(());}
        data.extend_from_slice(&buffer[..n]);
        let mut headers = [httparse::EMPTY_HEADER;64];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&data).map_err(|error| Error::Protocol(error.to_string()))? {
            httparse::Status::Complete(_) => {
                if request.path.map(|path| path.split('?').next().unwrap_or(path)) == Some("/debug/vars") {
                    break ("200 OK", services.metrics().to_string());
                } else if request.path.is_some_and(|path| path.starts_with("/debug/pprof/")) {
                    break ("501 Not Implemented", json!({"error":"Go pprof is unavailable in the Rust runtime"}).to_string());
                } else {break ("404 Not Found", "{}".into());}
            }
            httparse::Status::Partial if data.len() > 65536 => return Err(Error::Protocol("HTTP request headers too large".into())),
            _ => {}
        }
    };
    let response = format!("HTTP/1.1 {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",status,body.len(),body);
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn grpc(stream: BoxStream, services: Arc<RootServices>, enabled: Vec<String>) -> Result<()> {
    let mut connection = h2::server::handshake(stream).await.map_err(|error| Error::Protocol(error.to_string()))?;
    let mut jobs = tokio::task::JoinSet::new();
    while let Some(accepted) = connection.accept().await {
        let (request, response) = accepted.map_err(|error| Error::Protocol(error.to_string()))?;
        let (services, enabled) = (services.clone(),enabled.clone());
        jobs.spawn(async move {let _ = grpc_request(request,response,&services,&enabled).await;});
        while jobs.try_join_next().is_some() {}
    }
    while jobs.join_next().await.is_some() {}
    Ok(())
}

async fn grpc_request(request: http::Request<h2::RecvStream>, mut response: h2::server::SendResponse<Bytes>, services: &RootServices, enabled: &[String]) -> Result<()> {
    if reflection::matches(request.uri().path()) {
        return reflection::serve(request, response, enabled).await;
    }
    let path = request.uri().path().trim_start_matches('/').to_string();
    let result: std::result::Result<Vec<u8>,(u32,String)> = async {
        let (service,method) = path.rsplit_once('/').ok_or_else(|| (12,"unknown service".into()))?;
        let short = service.rsplit('.').next().unwrap_or(service);
        if !enabled.iter().any(|enabled| enabled == short) {return Err((12,format!("unknown service {}",service)));}
        let descriptor = native::descriptors().get_service_by_name(service).ok_or_else(|| (12,format!("unknown service {}",service)))?;
        let method_descriptor = descriptor.methods().find(|candidate| candidate.name() == method).ok_or_else(|| (12,"unknown method".into()))?;
        let mut body = request.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|error| (13,error.to_string()))?;
            body.flow_control().release_capacity(chunk.len()).map_err(|error| (13,error.to_string()))?;
            if data.len() + chunk.len() > 4*1024*1024 {return Err((8,"gRPC message exceeds 4 MiB".into()));}
            data.extend_from_slice(&chunk);
        }
        if data.len() < 5 || data[0] != 0 {return Err((3,"expected an uncompressed gRPC message".into()));}
        let length = u32::from_be_bytes(data[1..5].try_into().expect("checked frame length")) as usize;
        if length != data.len()-5 {return Err((3,"expected one complete gRPC message".into()));}
        let input = native::decode_message(method_descriptor.input().full_name(),&data[5..]).and_then(|message| native::message_json(&message)).map_err(|error| (3,error.to_string()))?;
        let output = services.rpc(service,method,&input)?;
        let text = output.to_string();
        let mut deserializer = serde_json::Deserializer::from_str(&text);
        let message = prost_reflect::DynamicMessage::deserialize(method_descriptor.output(),&mut deserializer).map_err(|error| (13,error.to_string()))?;
        Ok(message.encode_to_vec())
    }.await;
    let headers = http::Response::builder().status(200).header("content-type","application/grpc").body(()).map_err(|error| Error::Protocol(error.to_string()))?;
    let mut stream = response.send_response(headers,false).map_err(|error| Error::Protocol(error.to_string()))?;
    let (status,message) = match result {
        Ok(data) => {
            let mut frame = Vec::with_capacity(5+data.len());
            frame.push(0); frame.extend_from_slice(&(data.len() as u32).to_be_bytes()); frame.extend_from_slice(&data);
            stream.send_data(Bytes::from(frame),false).map_err(|error| Error::Protocol(error.to_string()))?;
            (0,String::new())
        }
        Err(error) => error,
    };
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status",http::HeaderValue::from_str(&status.to_string()).map_err(|error| Error::Protocol(error.to_string()))?);
    if !message.is_empty() {
        let escaped: String = message.bytes().map(|byte| if (0x20..0x7f).contains(&byte) && byte != b'%' { (byte as char).to_string() } else { format!("%{:02X}",byte) }).collect();
        trailers.insert("grpc-message",http::HeaderValue::from_str(&escaped).map_err(|error| Error::Protocol(error.to_string()))?);
    }
    stream.send_trailers(trailers).map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(())
}
