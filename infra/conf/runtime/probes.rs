use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use crate::{app::observatory::Observatory, common::{errors::{Error, Result}, net::Destination, protocol::SessionContext}, features::{feature::{Feature, TYPE_OBSERVATORY}, outbound::OutboundHandler}};
use super::super::observatory::{ObservatoryConfig, BurstObservatoryConfig, duration_ns};

type Handlers = HashMap<String, Arc<dyn OutboundHandler>>;

pub(super) struct ProbeFeature {
    pub state: Arc<Observatory>,
    handlers: Handlers,
    concurrent: bool,
    method: String,
    timeout: Duration,
    connectivity: String,
    samples: usize,
    cancel: CancellationToken,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}
impl ProbeFeature {
    pub fn observatory(config: ObservatoryConfig, handlers: Handlers) -> Result<Self> {
        let ns = duration_ns(config.probe_interval.as_deref())?;
        let interval = if ns == 0 { Duration::from_secs(10) } else { Duration::from_nanos(ns.max(0) as u64) };
        let url = config.probe_url.filter(|url| !url.is_empty()).unwrap_or_else(|| "https://www.google.com/generate_204".into());
        Ok(Self { state: Arc::new(Observatory::new(url, interval, config.subject_selectors)), handlers,
            concurrent: config.enable_concurrency.unwrap_or(false), method: "GET".into(), timeout: Duration::from_secs(30),
            connectivity: String::new(), samples: 1, cancel: CancellationToken::new(), task: Mutex::new(None) })
    }
    pub fn burst(config: BurstObservatoryConfig, handlers: Handlers) -> Result<Self> {
        config.validate()?;
        let ping = config.ping_config.expect("validated burst pingConfig");
        let ns = duration_ns(ping.interval.as_deref())?;
        let interval = if ns == 0 { Duration::from_secs(60) } else { Duration::from_nanos(ns.max(10_000_000_000) as u64) };
        let timeout = duration_ns(ping.timeout.as_deref())?;
        let timeout = if timeout <= 0 { Duration::from_secs(5) } else { Duration::from_nanos(timeout as u64) };
        let url: String = if ping.destination.trim().is_empty() { "https://connectivitycheck.gstatic.com/generate_204".into() } else { ping.destination.trim().into() };
        let method: String = if ping.http_method.is_empty() { "HEAD".into() } else { ping.http_method.trim().into() };
        http::Method::from_bytes(method.as_bytes()).map_err(|error| Error::Config(format!("invalid HTTP method: {}", error)))?;
        Ok(Self { state: Arc::new(Observatory::new(url, interval, config.subject_selectors)), handlers,
            concurrent: true, method, timeout, connectivity: ping.connectivity, samples: if ping.sampling <= 0 {10} else {ping.sampling as usize},
            cancel: CancellationToken::new(), task: Mutex::new(None) })
    }
}
impl Feature for ProbeFeature {
    fn feature_type(&self) -> &'static str { TYPE_OBSERVATORY }
    fn start(&self) -> Result<()> {
        let mut task = self.task.lock().map_err(|_| Error::Closed)?;
        if task.is_some() || self.state.subject_selectors().is_empty() { return Ok(()); }
        if self.cancel.is_cancelled() { return Err(Error::Closed); }
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error::Other(error.to_string()))?;
        let state = self.state.clone();
        let mut handlers: Vec<_> = self.handlers.iter().filter(|(tag,_)| state.subject_selectors().iter().any(|selector| tag.starts_with(selector))).map(|(tag, handler)| (tag.clone(), handler.clone())).collect();
        handlers.sort_by(|a,b| a.0.cmp(&b.0));
        let (method, timeout, concurrency, connectivity, samples) = (self.method.clone(), self.timeout, self.concurrent, self.connectivity.clone(), self.samples);
        let cancel = self.cancel.clone();
        let work = async move {
            let mut rounds = 0usize;
            loop {
                let mut jobs = tokio::task::JoinSet::new();
                for (tag, handler) in &handlers {
                    let (probe_state, tag, handler, method, connectivity) = (state.clone(), tag.clone(), handler.clone(), method.clone(), connectivity.clone());
                    let job = async move {
                        let result = probe(handler, probe_state.probe_url(), &method, timeout).await;
                        match result {
                            Ok(delay) => probe_state.record_result(&tag, delay, true, None),
                            Err(error) => {
                                // Go discards failed samples when direct connectivity is down.
                                if !connectivity.is_empty() {
                                    let direct = Arc::new(crate::proxy::freedom::Handler::new("connectivity"));
                                    if probe(direct, &connectivity, "HEAD", timeout).await.is_err() { return; }
                                }
                                probe_state.record_status(&tag, false, 99_999_999, Some(error.to_string()));
                            }
                        }
                    };
                    if concurrency { jobs.spawn(job); }
                    else { job.await; tokio::time::sleep(state.probe_interval()).await; }
                }
                while jobs.join_next().await.is_some() {}
                rounds = (rounds + 1) % samples;
                // Burst retains sampling-count-sized observation windows in Go;
                // stagger samples over the configured interval here.
                if concurrency || handlers.is_empty() {
                    tokio::time::sleep(state.probe_interval()).await;
                }
            }
        };
        *task = Some(runtime.spawn(async move { tokio::select! { _ = cancel.cancelled() => {}, _ = work => {} } }).abort_handle());
        Ok(())
    }
    fn close(&self) -> Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.lock().map_err(|_| Error::Closed)?.take() { task.abort(); }
        Ok(())
    }
}

async fn probe(handler: Arc<dyn OutboundHandler>, url: &str, method: &str, timeout: Duration) -> Result<Duration> {
    tokio::time::timeout(timeout, async {
        let uri: http::Uri = url.parse().map_err(|error| Error::Config(format!("invalid probe URL: {}", error)))?;
        let host = uri.host().ok_or_else(|| Error::Config("probe URL requires a host".into()))?;
        let tls = match uri.scheme_str() { Some("https") => true, Some("http") => false, _ => return Err(Error::Config("probe URL must use http or https".into())) };
        let port = uri.port_u16().unwrap_or(if tls {443} else {80});
        let destination = Destination::tcp(crate::common::net::parse_address(host.trim_matches(['[',']'])), port);
        let started = std::time::Instant::now();
        let mut stream = handler.connect(&SessionContext::new("observatory", destination)).await?;
        if tls { stream = crate::transport::internet::TlsClient::new(host, false, Vec::new())?.connect(host, stream).await?; }
        let target = uri.path_and_query().map(|path| path.as_str()).filter(|path| !path.is_empty()).unwrap_or("/");
        let authority = uri.authority().map(|authority| authority.as_str()).unwrap_or(host);
        let request = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", method, target, authority);
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut data = Vec::new();
        let mut buffer = [0u8;1024];
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 { return Err(Error::Protocol("incomplete probe HTTP response".into())); }
            data.extend_from_slice(&buffer[..n]);
            let mut headers = [httparse::EMPTY_HEADER;64];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&data).map_err(|error| Error::Protocol(error.to_string()))? {
                httparse::Status::Complete(_) => return Ok(started.elapsed()),
                httparse::Status::Partial if data.len() > 65536 => return Err(Error::Protocol("probe response headers too large".into())),
                _ => {}
            }
        }
    }).await.map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "probe timeout")))?
}
