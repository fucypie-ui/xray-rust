use super::ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig, TcpOptions};
use futures::{Stream, StreamExt};
use std::future::Future;
use std::sync::Arc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use super::config::TunConfig;
use super::routes;
use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;

pub struct TunRunner {
    pub cfg: TunConfig,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(cfg: TunConfig) -> Self {
        Self {
            cfg,
            cancellation_token: CancellationToken::new(),
        }
    }
    pub fn shutdown(&self) {
        info!("shutting down tun runner");
        let tun_name = if self.cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            self.cfg.name.clone()
        };
        let _ = routes::maybe_routes_clean_up(&self.cfg, &tun_name);
        self.cancellation_token.cancel();
    }
    pub async fn start(&self, dispatcher: Arc<DefaultDispatcher>) -> Result<JoinHandle<()>> {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return Ok(tokio::spawn(async {}));
        }
        let cfg = self.cfg.clone();
        let cancellation_token = self.cancellation_token.clone();
        let tun_name = if cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            cfg.name.clone()
        };
        let mtu = if cfg.mtu > 0 { cfg.mtu as u16 } else { 1500u16 };
        info!("initializing TUN device with native ipstack: {}", tun_name);
        #[cfg(target_os = "windows")]
        let device = {
            let guid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, tun_name.as_bytes()).as_u128();
            super::tun_windows::WintunAsyncDevice::create(&tun_name, guid, 0x800000)
                .map_err(|e| {
                    Error::Io(std::io::Error::other(format!(
                        "failed to create native wintun device {}: {}",
                        tun_name, e
                    )))
                })?
        };
        #[cfg(target_os = "android")]
        let device = { super::tun_android::AndroidTunDevice::from_env()? };
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        let device = {
            let mut tun_cfg = tun::Configuration::default();
            tun_cfg.tun_name(&tun_name).mtu(mtu);
            tun_cfg.address(cfg.gateway.addr()).netmask(cfg.gateway.netmask()).up();
            tun::create_as_async(&tun_cfg).map_err(|e| {
                Error::Io(std::io::Error::other(format!("failed to create tun device {}: {}", tun_name, e)))
            })?
        };
        // Arm cleanup before the first startup await, then transfer it into the
        // returned task. Drop also covers startup cancellation and task abort,
        // including an abort before the task has ever been polled.
        let cfg_clean = cfg.clone();
        let tun_name_clean = tun_name.clone();
        let cleanup = CleanupGuard::new(move || {
            let _ = routes::maybe_routes_clean_up(&cfg_clean, &tun_name_clean);
        });
        let sniffing = cfg.sniffing.clone();
        spawn_supervised_flows(
            async move {
                #[cfg(target_os = "windows")]
                for _ in 0..30 {
                    if let Some(iface) = super::net::get_interface_by_name(&tun_name) {
                        let _ = super::routes::add_address(&iface, cfg.gateway.into());
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                #[cfg(not(target_os = "android"))]
                if let Err(e) = routes::maybe_add_routes(&cfg, &tun_name) {
                    error!("failed to configure routes for {}: {}", tun_name, e);
                }
                let mut ipstack_cfg = IpStackConfig::default();
                let _ = ipstack_cfg.mtu(mtu);
                let mss = mtu.saturating_sub(40).max(536);
                let tcp_cfg = TcpConfig {
                    options: Some(vec![TcpOptions::MaximumSegmentSize(mss)]),
                    ..Default::default()
                };
                ipstack_cfg.with_tcp_config(tcp_cfg);
                let ip_stack = IpStack::new(ipstack_cfg, device);
                Ok(futures::stream::unfold(ip_stack, |mut ip_stack| async move {
                    let flow = ip_stack.accept().await;
                    Some((flow, ip_stack))
                }))
            },
            cancellation_token,
            move |stream| {
                let (network, local, peer, boxed, kind): (Network, _, _, crate::common::net::BoxStream, _) = match stream {
                    IpStackStream::Tcp(s) => (Network::Tcp, s.local_addr(), s.peer_addr(), Box::pin(s), "TCP"),
                    IpStackStream::Udp(s) => (Network::Udp, s.local_addr(), s.peer_addr(), Box::pin(s), "UDP"),
                    _ => return None,
                };
                if should_drop_tun_addr(local.ip(), peer.ip()) { return None; }
                let dest = Destination { network, address: Address::ip(peer.ip()), port: peer.port() };
                let mut session = SessionContext::new("tun-in", dest);
                session.inbound_tag = "tun".to_string();
                session.source = Some(local);
                session.sniffing_request = sniffing.clone();
                let dispatcher = dispatcher.clone();
                Some(async move {
                    if let Err(e) = dispatcher.dispatch(boxed, session).await {
                        debug!("tun {} dispatch error: {}", kind, e);
                    }
                })
            },
            cleanup,
        ).await
    }
}

struct CleanupGuard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> CleanupGuard<F> {
    fn new(cleanup: F) -> Self { Self(Some(cleanup)) }
}

impl<F: FnOnce()> Drop for CleanupGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() { cleanup(); }
    }
}

async fn spawn_supervised_flows<Flow, E, Task, Flows>(
    startup: impl Future<Output = Result<Flows>>,
    cancellation: CancellationToken,
    dispatch: impl FnMut(Flow) -> Option<Task> + Send + 'static,
    cleanup: CleanupGuard<impl FnOnce() + Send + 'static>,
) -> Result<JoinHandle<()>>
where
    Flow: Send + 'static,
    E: std::fmt::Display + Send + 'static,
    Task: Future + Send + 'static,
    Task::Output: Send + 'static,
    Flows: Stream<Item = std::result::Result<Flow, E>> + Send + 'static,
{
    let mut startup = Box::pin(startup);
    // On startup cancellation, clean routes while the device still exists.
    let route_cleanup = cleanup;
    let flows = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(Error::Closed),
        result = &mut startup => result?,
    };
    Ok(tokio::spawn(supervise_flows(flows, cancellation, dispatch, route_cleanup)))
}

// Keep the ownership loop independent of privileged TUN creation so lifecycle
// tests can inject real in-memory streams and a stalled outbound handshake.
async fn supervise_flows<Flow, E, Task>(
    flows: impl Stream<Item = std::result::Result<Flow, E>>,
    cancellation: CancellationToken,
    mut dispatch: impl FnMut(Flow) -> Option<Task>,
    cleanup: CleanupGuard<impl FnOnce()>,
) where
    E: std::fmt::Display,
    Task: Future + Send + 'static,
    Task::Output: Send + 'static,
{
    futures::pin_mut!(flows);
    // Drop cleanup before the flow source (and thus the TUN device).
    let _cleanup = cleanup;
    let mut children = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                info!("tun runner cancelled");
                break;
            }
            completed = children.join_next(), if !children.is_empty() => {
                if let Some(Err(error)) = completed {
                    debug!("tun dispatch task failed: {}", error);
                }
            }
            flow = flows.next() => match flow {
                Some(Ok(flow)) => {
                    if let Some(task) = dispatch(flow) { children.spawn(task); }
                }
                Some(Err(error)) => {
                    error!("ipstack accept error: {}", error);
                    break;
                }
                None => break,
            }
        }
    }
    // Graceful exit waits for dispatch futures to release their streams. An
    // abort/drop instead drops this JoinSet, which aborts every remaining child.
    children.shutdown().await;
    info!("tun runner exiting, cleaning up routes...");
}

fn should_drop_tun_addr(src: std::net::IpAddr, dst: std::net::IpAddr) -> bool {
    if src.is_loopback() || dst.is_loopback() || dst.is_unspecified() || src.is_multicast() || dst.is_multicast()
    { return true; }
    matches!(dst, std::net::IpAddr::V4(v4) if v4.is_broadcast())
}

#[cfg(test)]
#[path = "runner_test.rs"]
mod tests;
