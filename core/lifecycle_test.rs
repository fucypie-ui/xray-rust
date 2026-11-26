use super::*;
use std::sync::Weak;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

type Events = Arc<Mutex<Vec<String>>>;

struct MockFeature {
    kind: &'static str,
    label: &'static str,
    events: Events,
    fail_start: bool,
    fail_close: bool,
}

impl MockFeature {
    fn new(kind: &'static str, events: &Events) -> Self {
        Self { kind, label: kind, events: events.clone(), fail_start: false, fail_close: false }
    }
}

impl Feature for MockFeature {
    fn feature_type(&self) -> &'static str { self.kind }
    fn start(&self) -> Result<()> {
        self.events.lock().unwrap().push(format!("start {}", self.label));
        if self.fail_start { return Err(Error::Other(format!("start {} failed", self.label))); }
        Ok(())
    }
    fn close(&self) -> Result<()> {
        self.events.lock().unwrap().push(format!("close {}", self.label));
        if self.fail_close { return Err(Error::Other(format!("close {} failed", self.label))); }
        Ok(())
    }
}

fn instance() -> Instance { Instance::from_config(Config::default()).unwrap() }
fn events() -> Events { Arc::new(Mutex::new(Vec::new())) }
fn recorded(events: &Events) -> Vec<String> { events.lock().unwrap().clone() }

async fn join_tasks(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        if let Err(error) = timeout(Duration::from_secs(5), task).await.expect("task did not terminate") {
            assert!(error.is_cancelled(), "owned task panicked: {error}");
        }
    }
}

struct StartupObserver {
    instance: Weak<Instance>,
}

impl Feature for StartupObserver {
    fn feature_type(&self) -> &'static str { "observer" }
    fn start(&self) -> Result<()> {
        let instance = self.instance.upgrade().unwrap();
        assert!(!instance.is_running(), "startup was published before all features started");
        assert!(instance.get_feature("first").is_some());
        // Feature callbacks can use the registry during startup. This catches
        // holding the dependency lock while calling arbitrary feature code.
        instance.require_features(&["first"], |features| {
            assert_eq!(features[0].feature_type(), "first");
            Ok(())
        })
    }
}

#[tokio::test]
async fn starts_every_feature_once_and_closes_in_registration_order() {
    let instance = Arc::new(instance());
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("first", &events))).unwrap();
    instance.add_feature(Arc::new(StartupObserver { instance: Arc::downgrade(&instance) })).unwrap();
    instance.add_feature(Arc::new(MockFeature::new("last", &events))).unwrap();
    assert!(recorded(&events).is_empty());
    let starter = instance.clone();
    // Spawning the real startup future also enforces its Send + 'static contract.
    let tasks = tokio::spawn(async move { starter.start().await }).await.unwrap().unwrap();
    assert!(instance.is_running());
    assert_eq!(recorded(&events), ["start first", "start last"]);
    assert!(instance.start().await.unwrap().is_empty());
    assert_eq!(recorded(&events), ["start first", "start last"]);
    instance.close().unwrap();
    assert!(!instance.is_running());
    assert_eq!(recorded(&events), ["start first", "start last", "close first", "close last"]);
    instance.close().unwrap();
    drop(instance);
    assert_eq!(recorded(&events), ["start first", "start last", "close first", "close last"]);
    join_tasks(tasks).await;
}

#[tokio::test]
async fn feature_start_failure_rolls_back_and_preserves_the_error() {
    let instance = instance();
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("first", &events))).unwrap();
    let mut broken = MockFeature::new("broken", &events);
    broken.fail_start = true;
    broken.fail_close = true;
    instance.add_feature(Arc::new(broken)).unwrap();
    instance.add_feature(Arc::new(MockFeature::new("unstarted", &events))).unwrap();
    let error = instance.start().await.unwrap_err();
    assert!(error.to_string().contains("start broken failed"));
    assert!(!instance.is_running());
    assert_eq!(recorded(&events), [
        "start first", "start broken", "close first", "close broken", "close unstarted",
    ]);
    assert!(matches!(instance.start().await, Err(Error::Closed)));
    instance.close().unwrap();
    assert_eq!(recorded(&events), [
        "start first", "start broken", "close first", "close broken", "close unstarted",
    ]);
}

#[test]
fn close_attempts_every_feature_aggregates_errors_and_is_idempotent() {
    let instance = instance();
    let events = events();
    for name in ["one", "two", "three"] {
        let mut feature = MockFeature::new(name, &events);
        feature.fail_close = name != "three";
        instance.add_feature(Arc::new(feature)).unwrap();
    }
    let error = instance.close().unwrap_err().to_string();
    assert!(error.contains("close one failed"), "{error}");
    assert!(error.contains("close two failed"), "{error}");
    assert_eq!(recorded(&events), ["close one", "close two", "close three"]);
    instance.close().unwrap();
    drop(instance);
    assert_eq!(recorded(&events), ["close one", "close two", "close three"]);
}

#[tokio::test]
async fn dropping_a_pending_start_future_rolls_back_started_features() {
    let instance = instance();
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("started", &events))).unwrap();
    // Pin startup at a real asynchronous boundary without sleeps, environment
    // changes, fake TUN devices, or privileged networking operations.
    let interface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.write().await;
    let mut startup = Box::pin(instance.start());
    assert!(futures::poll!(startup.as_mut()).is_pending());
    assert_eq!(recorded(&events), ["start started"]);
    assert!(!instance.is_running());
    drop(startup);
    drop(interface);
    assert_eq!(recorded(&events), ["start started", "close started"]);
    assert!(matches!(instance.start().await, Err(Error::Closed)));
}

#[tokio::test]
async fn close_during_pending_start_cannot_publish_running_or_start_listeners() {
    let instance = instance();
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("started", &events))).unwrap();
    let interface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.write().await;
    let mut startup = Box::pin(instance.start());
    assert!(futures::poll!(startup.as_mut()).is_pending());
    assert!(instance.add_feature(Arc::new(MockFeature::new("too-early", &events))).is_err());
    assert!(instance.start().await.is_err());
    instance.close().unwrap();
    drop(interface);
    assert!(matches!(startup.await, Err(Error::Closed)));
    assert!(!instance.is_running());
    assert_eq!(recorded(&events), ["start started", "close started"]);
    assert!(instance.inbound_manager.listen_addresses().is_empty());
}

#[tokio::test]
async fn late_features_follow_go_start_without_registration_and_log_failure_contract() {
    let instance = instance();
    let events = events();
    let tasks = instance.start().await.unwrap();
    for name in ["late", "failed-late"] {
        let mut feature = MockFeature::new(name, &events);
        feature.fail_start = name == "failed-late";
        instance.add_feature(Arc::new(feature)).unwrap();
        assert!(instance.get_feature(name).is_none());
    }
    assert_eq!(recorded(&events), ["start late", "start failed-late"]);
    instance.close().unwrap();
    // Like Go, unregistered late features are not part of Close's feature set.
    assert_eq!(recorded(&events), ["start late", "start failed-late"]);
    assert!(matches!(instance.add_feature(Arc::new(MockFeature::new("closed", &events))), Err(Error::Closed)));
    join_tasks(tasks).await;
}

struct ReentrantLateFeature {
    instance: Weak<Instance>,
    events: Events,
}

impl Feature for ReentrantLateFeature {
    fn feature_type(&self) -> &'static str { "late-outer" }
    fn start(&self) -> Result<()> {
        let instance = self.instance.upgrade().unwrap();
        self.events.lock().unwrap().push("start outer".into());
        let mut nested = MockFeature::new("late-inner", &self.events);
        nested.fail_start = true;
        instance.add_feature(Arc::new(nested))?;
        instance.close()?;
        self.events.lock().unwrap().push("outer resumed after close".into());
        Err(Error::Other("outer late startup failure".into()))
    }
}

#[tokio::test]
async fn late_feature_start_can_add_another_late_feature_and_close_the_instance() {
    let instance = Arc::new(instance());
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("registered", &events))).unwrap();
    let tasks = instance.start().await.unwrap();
    let feature = Arc::new(ReentrantLateFeature { instance: Arc::downgrade(&instance), events: events.clone() });
    let caller = instance.clone();
    let (done_tx, done_rx) = oneshot::channel();
    // A regression must time out rather than block this test's async runtime.
    // The OS thread is joined on success and detaches if the old deadlock recurs.
    let thread = std::thread::spawn(move || { let _ = done_tx.send(caller.add_feature(feature)); });
    timeout(Duration::from_secs(5), done_rx).await.expect("late feature startup deadlocked").unwrap().unwrap();
    thread.join().unwrap();
    assert_eq!(recorded(&events), [
        "start registered", "start outer", "start late-inner", "close registered", "outer resumed after close",
    ]);
    assert!(!instance.is_running());
    assert!(instance.get_feature("late-outer").is_none());
    assert!(instance.get_feature("late-inner").is_none());
    join_tasks(tasks).await;
}

#[test]
fn resolves_deferred_dependencies_once_in_argument_order_and_keeps_first_registration() {
    let instance = instance();
    let events = events();
    let first: Arc<dyn Feature> = Arc::new(MockFeature::new("alpha", &events));
    let second: Arc<dyn Feature> = Arc::new(MockFeature::new("beta", &events));
    let expected = [second.clone(), first.clone(), second.clone()];
    let callback_events = events.clone();
    let beta = String::from("beta");
    instance.require_features(&[&beta, "alpha", &beta], move |resolved| {
        assert_eq!(resolved.len(), expected.len());
        for (actual, expected) in resolved.iter().zip(expected.iter()) { assert!(Arc::ptr_eq(actual, expected)); }
        callback_events.lock().unwrap().push("resolved".into());
        Ok(())
    }).unwrap();
    drop(beta);
    instance.add_feature(first.clone()).unwrap();
    let mut duplicate = MockFeature::new("alpha", &events);
    duplicate.label = "duplicate-alpha";
    instance.add_feature(Arc::new(duplicate)).unwrap();
    assert!(recorded(&events).is_empty());
    assert!(Arc::ptr_eq(&instance.get_feature("alpha").unwrap(), &first));
    instance.add_feature(second).unwrap();
    instance.add_feature(Arc::new(MockFeature::new("unrelated", &events))).unwrap();
    assert_eq!(recorded(&events), ["resolved"]);
    // Zero dependencies resolve immediately too.
    let callback_events = events.clone();
    instance.require_features(&[], move |resolved| {
        assert!(resolved.is_empty());
        callback_events.lock().unwrap().push("empty".into());
        Ok(())
    }).unwrap();
    assert_eq!(recorded(&events), ["resolved", "empty"]);
}

#[test]
fn dependency_callbacks_can_register_and_resolve_more_dependencies() {
    let instance = Arc::new(instance());
    let events = events();
    let callback_instance = Arc::downgrade(&instance);
    let callback_events = events.clone();
    instance.require_features(&["alpha"], move |_| {
        let instance = callback_instance.upgrade().unwrap();
        let nested_events = callback_events.clone();
        instance.require_features(&["beta"], move |resolved| {
            assert_eq!(resolved[0].feature_type(), "beta");
            nested_events.lock().unwrap().push("nested".into());
            Ok(())
        })?;
        instance.add_feature(Arc::new(MockFeature::new("beta", &callback_events)))
    }).unwrap();
    instance.add_feature(Arc::new(MockFeature::new("alpha", &events))).unwrap();
    assert_eq!(recorded(&events), ["nested"]);
}

#[test]
fn ready_callbacks_all_run_and_return_the_last_result_like_go() {
    let instance = instance();
    let events = events();
    for name in ["first", "second"] {
        let callback_events = events.clone();
        instance.require_features(&["dependency"], move |_| {
            callback_events.lock().unwrap().push(name.into());
            Err(Error::Other(name.into()))
        }).unwrap();
    }
    let callback_events = events.clone();
    instance.optional_features(&["dependency"], move |resolved| {
        assert!(resolved[0].is_some());
        callback_events.lock().unwrap().push("optional".into());
        Err(Error::Other("last optional error".into()))
    }).unwrap();
    let error = instance.add_feature(Arc::new(MockFeature::new("dependency", &events))).unwrap_err();
    assert!(error.to_string().contains("last optional error"));
    assert_eq!(recorded(&events), ["first", "second", "optional"]);
    instance.add_feature(Arc::new(MockFeature::new("dependency", &events))).unwrap();
    assert_eq!(recorded(&events), ["first", "second", "optional"]);
    let error = instance.require_features(&["dependency"], |_| Err(Error::Other("immediate".into()))).unwrap_err();
    assert!(error.to_string().contains("immediate"));
}

#[tokio::test]
async fn required_dependencies_block_start_until_resolved_but_optional_ones_do_not() {
    let instance = instance();
    let events = events();
    let callback_events = events.clone();
    instance.require_features(&["required"], move |_| {
        callback_events.lock().unwrap().push("required resolved".into());
        Ok(())
    }).unwrap();
    let capture = Arc::new(());
    let weak_capture = Arc::downgrade(&capture);
    instance.optional_features(&["never-registered"], move |_| {
        drop(capture);
        panic!("unresolved optional callback must not run");
    }).unwrap();
    assert!(weak_capture.upgrade().is_some());
    let error = instance.start().await.unwrap_err();
    assert!(error.to_string().contains("not all dependencies"));
    assert!(!instance.is_running());
    instance.add_feature(Arc::new(MockFeature::new("required", &events))).unwrap();
    let tasks = instance.start().await.unwrap();
    assert!(instance.is_running());
    assert_eq!(recorded(&events), ["required resolved", "start required"]);
    instance.close().unwrap();
    assert!(weak_capture.upgrade().is_none(), "Close must drop unresolved callback captures");
    assert!(matches!(instance.require_features(&[], |_| Ok(())), Err(Error::Closed)));
    assert!(matches!(instance.optional_features(&[], |_| Ok(())), Err(Error::Closed)));
    join_tasks(tasks).await;
}

struct NotifyOnDrop(Option<oneshot::Sender<()>>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() { let _ = sender.send(()); }
    }
}

fn pending_task() -> (JoinHandle<()>, oneshot::Receiver<()>, oneshot::Receiver<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = NotifyOnDrop(Some(done_tx));
        let _ = ready_tx.send(());
        std::future::pending::<()>().await;
    });
    (task, ready_rx, done_rx)
}

#[tokio::test]
async fn close_and_drop_cancel_owned_tasks_even_if_callers_drop_handles() {
    let instance = instance();
    let (task, ready, done) = pending_task();
    let (detached, detached_ready, detached_done) = pending_task();
    instance.own_tasks(std::slice::from_ref(&task)).unwrap();
    instance.own_tasks(std::slice::from_ref(&detached)).unwrap();
    ready.await.unwrap();
    detached_ready.await.unwrap();
    drop(detached);
    let (release, wait) = oneshot::channel();
    let external = tokio::spawn(async move { wait.await.unwrap(); 73 });
    drop(instance);
    timeout(Duration::from_secs(5), done).await.unwrap().unwrap();
    timeout(Duration::from_secs(5), detached_done).await.unwrap().unwrap();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!external.is_finished(), "instance cleanup touched an external task");
    release.send(()).unwrap();
    assert_eq!(external.await.unwrap(), 73);
}

#[tokio::test]
async fn tasks_created_after_close_are_cancelled_instead_of_detached() {
    let instance = instance();
    instance.close().unwrap();
    let (task, ready, done) = pending_task();
    ready.await.unwrap();
    assert!(matches!(instance.own_tasks(std::slice::from_ref(&task)), Err(Error::Closed)));
    timeout(Duration::from_secs(5), done).await.unwrap().unwrap();
    assert!(task.await.unwrap_err().is_cancelled());
}

struct StalledInbound {
    accepted: mpsc::UnboundedSender<()>,
    dropped: mpsc::UnboundedSender<()>,
}

struct ConnectionDrop(mpsc::UnboundedSender<()>);
impl Drop for ConnectionDrop {
    fn drop(&mut self) { let _ = self.0.send(()); }
}

#[async_trait::async_trait]
impl crate::features::inbound::InboundHandler for StalledInbound {
    fn tag(&self) -> &str { "stalled" }
    async fn handle_connection(&self, stream: crate::common::net::BoxStream, _remote: std::net::SocketAddr) -> Result<crate::features::inbound::InboundResult> {
        let _guard = ConnectionDrop(self.dropped.clone());
        self.accepted.send(()).unwrap();
        let result = std::future::pending().await;
        drop(stream);
        result
    }
}

#[tokio::test]
async fn instance_close_releases_loopback_listener_and_active_inbound_connection() {
    use tokio::io::AsyncReadExt;
    let mut instance = instance();
    let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
    let (dropped_tx, mut dropped) = mpsc::unbounded_channel();
    instance.inbound_manager = InboundManager::new(vec![(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(StalledInbound { accepted: accepted_tx, dropped: dropped_tx }),
    )]);
    let tasks = instance.start().await.unwrap();
    let address = instance.inbound_manager.listen_addresses()[0];
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(5), accepted.recv()).await.unwrap().unwrap();
    instance.close().unwrap();
    join_tasks(tasks).await;
    timeout(Duration::from_secs(5), dropped.recv()).await.unwrap().unwrap();
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(5), stream.read(&mut byte)).await.unwrap().unwrap(), 0);
    assert!(tokio::net::TcpStream::connect(address).await.is_err(), "Close left the listening socket open");
    assert!(instance.inbound_manager.listen_addresses().is_empty());
}

#[tokio::test]
async fn inbound_bind_error_closes_started_features_and_keeps_running_false() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap();
    let (accepted, _accepted_rx) = mpsc::unbounded_channel();
    let (dropped, _dropped_rx) = mpsc::unbounded_channel();
    let handler = Arc::new(StalledInbound { accepted, dropped });
    let mut instance = instance();
    let events = events();
    instance.add_feature(Arc::new(MockFeature::new("feature", &events))).unwrap();
    instance.inbound_manager = InboundManager::new(vec![
        ("127.0.0.1:0".parse().unwrap(), handler.clone()),
        (address, handler),
    ]);
    let error = instance.start().await.unwrap_err().to_string();
    assert!(error.contains("stalled"), "{error}");
    assert!(error.contains(&address.to_string()), "{error}");
    assert_eq!(recorded(&events), ["start feature", "close feature"]);
    assert!(!instance.is_running());
    assert!(instance.inbound_manager.listen_addresses().is_empty());
    drop(occupied);
    let rebound = std::net::TcpListener::bind(address).unwrap();
    drop(rebound);
}

#[tokio::test]
async fn close_cancels_a_dispatched_inbound_after_a_real_loopback_roundtrip() {
    use crate::common::net::{Address, Destination, Network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
        assert_eq!(stream.read(&mut payload).await.unwrap(), 0, "inbound dispatch survived instance Close");
    });
    let config: Config = serde_json::from_str(r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
    let mut instance = Instance::from_config(config).unwrap();
    instance.inbound_manager = InboundManager::new(vec![(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(crate::proxy::dokodemo::Server::new(
            "roundtrip",
            Destination::tcp(Address::ip(target_address.ip()), target_address.port()),
            Network::Tcp,
        )),
    )]);
    let tasks = instance.start().await.unwrap();
    let mut client = tokio::net::TcpStream::connect(instance.inbound_manager.listen_addresses()[0]).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut payload = [0; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut payload)).await.unwrap().unwrap();
    assert_eq!(&payload, b"pong");
    instance.close().unwrap();
    join_tasks(tasks).await;
    assert_eq!(timeout(Duration::from_secs(5), client.read(&mut payload)).await.unwrap().unwrap(), 0);
    // This task is external to the instance and must complete normally, rather
    // than being caught by blanket runtime cancellation.
    timeout(Duration::from_secs(5), peer).await.unwrap().unwrap();
}
