use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use crate::app::dispatcher::DefaultDispatcher;
use crate::app::proxyman::InboundManager;
use crate::common::errors::{Error, MultiError, Result};
use crate::features::feature::Feature;
use crate::features::stats::DefaultStatsManager;
use crate::infra::conf::Config;
use crate::proxy::tun::WindowsTunDevice;

pub trait Server: Send + Sync {
    fn start(&self) -> Result<Vec<JoinHandle<()>>>;
    fn close(&self) -> Result<()>;
}

pub fn server_type() -> &'static str { "xray.core.Instance" }

type FeatureCallback = Box<dyn FnOnce(Vec<Arc<dyn Feature>>) -> Result<()> + Send + 'static>;

struct Resolution {
    types: Vec<String>,
    callback: FeatureCallback,
}

impl Resolution {
    fn resolve(&self, features: &[Arc<dyn Feature>]) -> Option<Vec<Arc<dyn Feature>>> {
        self.types.iter().map(|t| {
            features.iter().find(|f| f.feature_type() == t.as_str()).cloned()
        }).collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { New, Starting, Running, Closed }

struct State {
    phase: Phase,
    tasks: Vec<AbortHandle>,
    cancellation: CancellationToken,
}

struct Registry {
    closed: bool,
    features: Vec<Arc<dyn Feature>>,
    pending: Vec<Resolution>,
    optional: Vec<Resolution>,
}

pub struct Instance {
    pub dispatcher: Arc<DefaultDispatcher>,
    pub inbound_manager: InboundManager,
    pub tun_devices: Vec<Arc<WindowsTunDevice>>,
    pub stats_manager: Arc<DefaultStatsManager>,
    pub running: Arc<AtomicBool>,
    state: Mutex<State>,
    registry: Mutex<Registry>,
}

// Dropping a partially polled start future must release the same resources as an
// explicit startup error. In particular, dropping JoinHandles only detaches them.
struct Startup<'a> {
    instance: &'a Instance,
    committed: bool,
}

impl Drop for Startup<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.instance.close() {
                tracing::warn!("failed to clean up instance startup: {}", error);
            }
            // Close can race an asynchronous TUN initialization. Run its route
            // cleanup again after that initialization has returned or was dropped.
            for device in &self.instance.tun_devices { device.shutdown(); }
        }
    }
}

impl Instance {
    pub fn new(config: Config) -> Result<Self> { Self::from_config(config) }
    pub fn new_with_context(config: Config) -> Result<Self> { Self::from_config(config) }
    pub fn from_config(config: Config) -> Result<Self> {
        let built = config.build()?;
        let stats_manager = Arc::new(DefaultStatsManager::new());
        let dispatcher = Arc::new(
            DefaultDispatcher::new(built.outbounds, Arc::new(built.router)).with_stats(stats_manager.clone()),
        );
        let features: Vec<Arc<dyn Feature>> = vec![dispatcher.clone(), stats_manager.clone()];
        Ok(Self {
            dispatcher,
            inbound_manager: InboundManager::new(built.inbounds),
            tun_devices: built.tun_devices,
            stats_manager,
            running: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(State { phase: Phase::New, tasks: Vec::new(), cancellation: CancellationToken::new() }),
            registry: Mutex::new(Registry {
                closed: false, features, pending: Vec::new(), optional: Vec::new(),
            }),
        })
    }

    pub fn add_feature(&self, feature: Arc<dyn Feature>) -> Result<()> {
        let ready = {
            let state = self.state.lock().map_err(|_| Error::Other("instance lock".into()))?;
            match state.phase {
                Phase::Closed => return Err(Error::Closed),
                Phase::Starting => return Err(Error::Other("instance is starting".into())),
                Phase::Running => {
                    // Go's AddFeature starts but does not register late features,
                    // and logs their startup errors instead of returning them.
                    // Release the status lock first: Start may add another late
                    // feature or close the instance, just as it can in Go.
                    drop(state);
                    if let Err(error) = feature.start() {
                        tracing::info!("failed to start feature: {}", error);
                    }
                    return Ok(());
                }
                Phase::New => {}
            }
            // Preserve registration order, including duplicate types: Go's
            // GetFeature resolves the first registration of a type.
            let mut registry = self.registry.lock().map_err(|_| Error::Other("feature lock".into()))?;
            registry.features.push(feature);
            let features = registry.features.clone();
            let mut ready = Vec::new();
            let Registry { pending, optional, .. } = &mut *registry;
            for pending in [pending, optional] {
                let mut unresolved = Vec::new();
                for resolution in std::mem::take(pending) {
                    if let Some(arguments) = resolution.resolve(&features) {
                        ready.push((resolution.callback, arguments));
                    } else {
                        unresolved.push(resolution);
                    }
                }
                *pending = unresolved;
            }
            ready
        };
        // Callbacks may register more features or dependencies. Never invoke
        // them under the registry/lifecycle lock. Like Go, run every ready
        // callback and return the last callback's result.
        let mut result = Ok(());
        for (callback, arguments) in ready { result = callback(arguments); }
        result
    }

    pub fn get_feature(&self, feature_type: &str) -> Option<Arc<dyn Feature>> {
        self.registry.lock().ok()?.features.iter().find(|f| f.feature_type() == feature_type).cloned()
    }

    /// Invoke the callback once all requested types are registered. Unresolved
    /// callbacks are owned by the instance, hence the Send + 'static bounds.
    /// Capture a `Weak<Instance>` when referring back to the owner to avoid an `Arc` cycle.
    pub fn require_features<F>(&self, types: &[&str], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<Arc<dyn Feature>>) -> Result<()> + Send + 'static,
    {
        self.register_resolution(types, Box::new(callback), false)
    }

    /// Optional dependencies are deferred too, but do not prevent startup.
    /// The Option-shaped callback argument is retained for API compatibility;
    /// every entry is Some when the callback can be resolved.
    pub fn optional_features<F>(&self, types: &[&str], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<Option<Arc<dyn Feature>>>) -> Result<()> + Send + 'static,
    {
        self.register_resolution(types, Box::new(move |features| {
            callback(features.into_iter().map(Some).collect())
        }), true)
    }

    fn register_resolution(&self, types: &[&str], callback: FeatureCallback, optional: bool) -> Result<()> {
        let resolution = Resolution {
            types: types.iter().map(|t| (*t).to_owned()).collect(), callback,
        };
        let arguments = {
            let mut registry = self.registry.lock().map_err(|_| Error::Other("feature lock".into()))?;
            if registry.closed { return Err(Error::Closed); }
            match resolution.resolve(&registry.features) {
                Some(arguments) => arguments,
                None => {
                    if optional { registry.optional.push(resolution); }
                    else { registry.pending.push(resolution); }
                    return Ok(());
                }
            }
        };
        (resolution.callback)(arguments)
    }

    pub fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    pub fn r#type(&self) -> &'static str { server_type() }
    pub fn type_name(&self) -> &'static str { server_type() }

    // Connections receive child tokens so closing one connection cannot cancel
    // its instance or sibling connections. Serialize creation with Close.
    pub(super) fn cancellation_token(&self) -> Result<CancellationToken> {
        let state = self.state.lock().map_err(|_| Error::Other("instance lock".into()))?;
        if state.phase == Phase::Closed { return Err(Error::Closed); }
        Ok(state.cancellation.child_token())
    }

    // Retain cancellation rights independently of the JoinHandles returned to
    // callers. A concurrent Close must also cancel a just-created task.
    pub(super) fn own_tasks(&self, tasks: &[JoinHandle<()>]) -> Result<()> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                for task in tasks { task.abort(); }
                return Err(Error::Other("instance lock".into()));
            }
        };
        if state.phase == Phase::Closed {
            for task in tasks { task.abort(); }
            return Err(Error::Closed);
        }
        state.tasks.retain(|task| !task.is_finished());
        state.tasks.extend(tasks.iter().map(JoinHandle::abort_handle));
        Ok(())
    }

    pub async fn start(&self) -> Result<Vec<JoinHandle<()>>> {
        let features = {
            let mut state = self.state.lock().map_err(|_| Error::Other("instance lock".into()))?;
            match state.phase {
                Phase::Running => return Ok(Vec::new()),
                Phase::Closed => return Err(Error::Closed),
                Phase::Starting => return Err(Error::Other("instance is starting".into())),
                Phase::New => {}
            }
            let registry = self.registry.lock().map_err(|_| Error::Other("feature lock".into()))?;
            if !registry.pending.is_empty() {
                return Err(Error::Other("not all dependencies are resolved".into()));
            }
            state.phase = Phase::Starting;
            registry.features.clone()
        };
        let mut startup = Startup { instance: self, committed: false };
        for feature in features {
            // Serialize synchronous feature startup with Close. No guard is
            // held across an await, so the startup future remains Send.
            let state = self.state.lock().map_err(|_| Error::Other("instance lock".into()))?;
            if state.phase != Phase::Starting { return Err(Error::Closed); }
            feature.start()?;
        }
        crate::proxy::tun::init_net_config(None).await;
        let mut tasks = self.inbound_manager.start(self.dispatcher.clone()).await?;
        self.own_tasks(&tasks)?;
        for device in &self.tun_devices {
            let task = device.start(self.dispatcher.clone()).await?;
            self.own_tasks(std::slice::from_ref(&task))?;
            tasks.push(task);
        }
        #[cfg(debug_assertions)]
        if let Some(task) = crate::debug_panel::start_debug_server() {
            self.own_tasks(std::slice::from_ref(&task))?;
            tasks.push(task);
        }
        {
            let mut state = self.state.lock().map_err(|_| Error::Other("instance lock".into()))?;
            if state.phase != Phase::Starting { return Err(Error::Closed); }
            let registry = self.registry.lock().map_err(|_| Error::Other("feature lock".into()))?;
            if !registry.pending.is_empty() {
                return Err(Error::Other("not all dependencies are resolved".into()));
            }
            state.phase = Phase::Running;
            self.running.store(true, Ordering::SeqCst);
        }
        startup.committed = true;
        Ok(tasks)
    }

    pub fn close(&self) -> Result<()> {
        let (features, tasks, pending, optional) = {
            // Recover poisoned state during cleanup rather than leaking owned
            // tasks when a feature panics while holding the lifecycle lock.
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.phase == Phase::Closed { return Ok(()); }
            state.phase = Phase::Closed;
            self.running.store(false, Ordering::SeqCst);
            state.cancellation.cancel();
            let mut registry = self.registry.lock().unwrap_or_else(|error| error.into_inner());
            registry.closed = true;
            (registry.features.clone(), std::mem::take(&mut state.tasks),
                std::mem::take(&mut registry.pending), std::mem::take(&mut registry.optional))
        };
        let mut errors = MultiError::new();
        if let Err(error) = self.inbound_manager.close() { errors.add(error); }
        for device in &self.tun_devices { device.shutdown(); }
        for task in tasks { task.abort(); }
        for feature in features {
            if let Err(error) = feature.close() { errors.add(error); }
        }
        // Drop captures outside the lock too: they may themselves own resources
        // with destructors that call back into the instance.
        drop((pending, optional));
        errors.into_result()
    }
}

impl Drop for Instance {
    fn drop(&mut self) { let _ = self.close(); }
}

#[cfg(test)]
#[path = "lifecycle_test.rs"]
mod lifecycle_test;
