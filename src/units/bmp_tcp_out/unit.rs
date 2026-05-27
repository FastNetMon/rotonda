use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures::{future::select, pin_mut};
use log::{debug, error, warn};
use non_empty_vec::NonEmpty;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, RwLock},
    time::sleep,
};
use uuid::Uuid;

use crate::{
    comms::{
        AnyDirectUpdate, DirectLink, DirectUpdate, Gate, GateStatus,
        Terminated,
    },
    http_ng,
    ingress::register::Register,
    manager::{Component, WaitPoint},
    payload::Update,
    units::bgp_tcp_in::peer_config::PrefixOrExact,
    units::Unit,
};

use super::{
    bmp_builder, client_handler,
    client_state::{BufferUpdateResult, ClientPhase, ClientState},
    metrics::BmpTcpOutMetrics,
    status_reporter::BmpTcpOutStatusReporter,
    tls,
};

//-------- BmpTcpOut config --------------------------------------------------

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct BmpTcpOut {
    /// Listen address for BMP client connections.
    #[serde_as(as = "Arc<DisplayFromStr>")]
    pub listen: Arc<SocketAddr>,

    /// Sources to receive updates from (upstream gates).
    pub sources: NonEmpty<DirectLink>,

    /// Name of the RIB unit to read initial state from.
    #[serde(default = "BmpTcpOut::default_rib_unit")]
    pub rib_unit: String,

    /// HTTP API path for client listing.
    #[serde(default = "BmpTcpOut::default_http_api_path")]
    http_api_path: Arc<String>,

    /// BMP Initiation sysName TLV.
    #[serde(default = "BmpTcpOut::default_sys_name")]
    pub sys_name: String,

    /// BMP Initiation sysDescr TLV.
    #[serde(default = "BmpTcpOut::default_sys_descr")]
    pub sys_descr: String,

    /// Maximum buffered updates per client during dump phase (entry count).
    /// Hard cap — clients that overflow are disconnected (they reconnect for
    /// a fresh dump). No dynamic growth.
    #[serde(default = "BmpTcpOut::default_max_client_buffer")]
    pub max_client_buffer: usize,

    /// Maximum buffered bytes per client during dump phase. Counts the
    /// shallow heap footprint of buffered `Update`s (excluding Arc-shared
    /// PaMap bytes). Hard cap — clients that overflow are disconnected.
    #[serde(default = "BmpTcpOut::default_max_client_buffer_bytes")]
    pub max_client_buffer_bytes: usize,

    /// ACL: list of allowed IP prefixes/addresses (required).
    /// Only IPs matching at least one entry are allowed to connect.
    /// Supports exact IPs and CIDR prefixes, both IPv4 and IPv6.
    /// Use "0.0.0.0/0" and/or "::/0" as wildcards to allow all.
    /// Examples:
    ///   acl = ["0.0.0.0/0", "::/0"]              # allow all
    ///   acl = ["10.0.0.0/8", "2001:db8::/32"]     # restrict to specific ranges
    ///   acl = ["192.168.1.1", "fd00::1"]           # restrict to exact IPs
    pub acl: Vec<PrefixOrExact>,

    /// Include upstream router identity (sysName/sysDescr) as a JSON Admin
    /// Label TLV (type 4, RFC 9736) in Peer Up messages. Default: true.
    #[serde(default = "BmpTcpOut::default_forward_router_info")]
    pub forward_router_info: bool,

    /// Enable TLS encryption for client connections. Default: false.
    #[serde(default)]
    pub tls: bool,

    /// Path to PEM certificate file. If omitted with tls=true, a self-signed cert is generated.
    #[serde(default)]
    pub tls_cert: Option<String>,

    /// Path to PEM private key file. Required if tls_cert is set.
    #[serde(default)]
    pub tls_key: Option<String>,
}

impl BmpTcpOut {
    pub async fn run(
        self,
        mut component: Component,
        gate: Gate,
        mut waitpoint: WaitPoint,
    ) -> Result<(), Terminated> {
        // Validate TLS configuration
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            log::error!(
                "BmpTcpOut: tls_cert and tls_key must both be set or both be omitted"
            );
            return Err(Terminated);
        }
        if !self.tls && (self.tls_cert.is_some() || self.tls_key.is_some()) {
            log::error!(
                "BmpTcpOut: tls_cert/tls_key are set but tls is not enabled"
            );
            return Err(Terminated);
        }

        let unit_name = component.name().clone();

        // Setup metrics
        let metrics = Arc::new(BmpTcpOutMetrics::new(&gate));
        component.register_metrics(metrics.clone());

        // Setup status reporter
        let status_reporter = Arc::new(BmpTcpOutStatusReporter::new(
            &unit_name,
            metrics.clone(),
        ));

        let ingress_register = component.ingresses();

        // Keep a shared reference to the HTTP API which holds the RIB.
        // The RibUnit calls Api::set_rib() at startup, which may happen
        // before or after this unit starts. By keeping the shared Api
        // reference, we can resolve the RIB lazily when a client connects,
        // avoiding a race where a cloned OnceLock stays empty forever.
        let http_ng_api = component.http_ng_api_arc();

        // Wait for other components to be ready
        gate.process_until(waitpoint.ready()).await?;
        waitpoint.running().await;

        BmpTcpOutRunner::new(
            gate,
            self.listen,
            self.sys_name,
            self.sys_descr,
            self.max_client_buffer,
            self.max_client_buffer_bytes,
            self.forward_router_info,
            self.acl,
            self.tls,
            self.tls_cert,
            self.tls_key,
            http_ng_api,
            ingress_register,
            metrics,
            status_reporter,
        )
        .run(self.sources)
        .await
    }

    fn default_http_api_path() -> Arc<String> {
        Arc::new("/bmp-out/".to_string())
    }

    fn default_rib_unit() -> String {
        "rib".to_string()
    }

    fn default_sys_name() -> String {
        "rotonda-bmp-out".to_string()
    }

    fn default_sys_descr() -> String {
        "Rotonda BMP restreamer".to_string()
    }

    /// 5 million Updates. Multi-minute dumps on busy systems (thousands
    /// of peers, sustained churn) generate millions of live Updates that
    /// must buffer until the walk finishes. The old 100k cap filled in
    /// seconds and caused immediate disconnect. The byte cap is the
    /// load-bearing limit; this exists as a safety rail.
    fn default_max_client_buffer() -> usize {
        5_000_000
    }

    /// 1 GiB. Sized to absorb large bursts (peer flaps, full-table
    /// reannouncements) and multi-minute dump windows without OOMing the
    /// process. Operators with many concurrent BMP consumers should set
    /// this lower to bound aggregate dump memory; operators with very
    /// long dumps may need to raise it (or accept disconnect+reconnect).
    fn default_max_client_buffer_bytes() -> usize {
        1024 * 1024 * 1024
    }

    fn default_forward_router_info() -> bool {
        true
    }
}

//-------- BmpTcpOutRunner ---------------------------------------------------

/// Type alias for a boxed async writer (plain TCP or TLS).
type BoxedAsyncWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

struct BmpTcpOutRunner {
    gate: Arc<Gate>,
    listen: Arc<SocketAddr>,
    sys_name: String,
    sys_descr: String,
    max_client_buffer: usize,
    max_client_buffer_bytes: usize,
    forward_router_info: bool,
    acl: Vec<PrefixOrExact>,
    tls: bool,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    http_ng_api: Arc<Mutex<http_ng::Api>>,
    ingress_register: Arc<Register>,
    metrics: Arc<BmpTcpOutMetrics>,
    status_reporter: Arc<BmpTcpOutStatusReporter>,
    clients: Arc<RwLock<HashMap<Uuid, Arc<ClientState>>>>,
}

#[async_trait]
impl DirectUpdate for BmpTcpOutRunner {
    async fn direct_update(&self, update: Update) {
        self.metrics
            .updates_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Snapshot client Arcs and drop the RwLock guard before any await
        // that can park. Holding `clients.read()` across
        // `buffer_update_if_dumping().await` deadlocks the writer task's
        // cleanup path, which needs `clients.write()` after a disconnect.
        let snapshot: Vec<Arc<ClientState>> = {
            let clients = self.clients.read().await;
            clients.values().cloned().collect()
        };
        for client in &snapshot {
            // Skip clients that have already been marked for disconnect.
            // Without this short-circuit, every upstream Update during the
            // window between "overflow detected" and "writer task removes
            // the client from the map" generated a fresh "Buffer overflow"
            // log line and another empty-Vec push — under sustained
            // upstream churn that produces hundreds of identical log
            // lines per second and stalls direct_update on a full writer
            // queue.
            if client
                .disconnect_pending
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                continue;
            }
            match client.buffer_update_if_dumping(update.clone()).await {
                BufferUpdateResult::Buffered => {}
                BufferUpdateResult::Overflow => {
                    // First overflow wins: compare-and-swap claims the
                    // disconnect, suppresses duplicate logs from races.
                    if !client
                        .disconnect_pending
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        self.status_reporter
                            .buffer_overflow(client.remote_addr);
                        // try_send: if the writer's mpsc is already full
                        // of dump messages, the disconnect signal will
                        // ride the queue naturally — we don't want to
                        // stall direct_update (and therefore the whole
                        // upstream pipeline) waiting for a slot. If the
                        // queue is so full that try_send fails, the
                        // writer is already overloaded and will exit on
                        // the next write_all error anyway.
                        let _ = client.tx.try_send(Vec::new());
                    }
                }
                BufferUpdateResult::NotDumping => {
                    // Live phase — send directly
                    if !client_handler::send_update_to_client(
                        client,
                        &update,
                        &self.ingress_register,
                        self.forward_router_info,
                    )
                    .await
                    {
                        debug!(
                            "Failed to send update to client {}, will be cleaned up",
                            client.remote_addr
                        );
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for BmpTcpOutRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BmpTcpOutRunner").finish()
    }
}

impl AnyDirectUpdate for BmpTcpOutRunner {}

impl BmpTcpOutRunner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        gate: Gate,
        listen: Arc<SocketAddr>,
        sys_name: String,
        sys_descr: String,
        max_client_buffer: usize,
        max_client_buffer_bytes: usize,
        forward_router_info: bool,
        acl: Vec<PrefixOrExact>,
        tls: bool,
        tls_cert: Option<String>,
        tls_key: Option<String>,
        http_ng_api: Arc<Mutex<http_ng::Api>>,
        ingress_register: Arc<Register>,
        metrics: Arc<BmpTcpOutMetrics>,
        status_reporter: Arc<BmpTcpOutStatusReporter>,
    ) -> Self {
        Self {
            gate: Arc::new(gate),
            listen,
            sys_name,
            sys_descr,
            max_client_buffer,
            max_client_buffer_bytes,
            forward_router_info,
            acl,
            tls,
            tls_cert,
            tls_key,
            http_ng_api,
            ingress_register,
            metrics,
            status_reporter,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn run(
        self,
        mut sources: NonEmpty<DirectLink>,
    ) -> Result<(), Terminated> {
        let arc_self = Arc::new(self);

        // Register as a direct update receiver with the linked gates.
        for link in sources.iter_mut() {
            link.connect(arc_self.clone(), false).await.unwrap();
        }

        let listen_addr = arc_self.listen.clone();
        let status_reporter = arc_self.status_reporter.clone();

        // Bind TCP listener with backoff
        let listener = loop {
            match TcpListener::bind(listen_addr.as_ref()).await {
                Ok(listener) => break listener,
                Err(err) => {
                    let msg = format!("{err}: Will retry in 5 seconds.");
                    status_reporter
                        .bind_error(&listen_addr.to_string(), &msg);
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        status_reporter.listener_listening(&listen_addr.to_string());

        // Build TLS acceptor if TLS is enabled
        let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = if arc_self.tls
        {
            let is_self_signed = arc_self.tls_cert.is_none();
            match tls::build_tls_acceptor(
                arc_self.tls_cert.as_deref(),
                arc_self.tls_key.as_deref(),
                &listen_addr,
            ) {
                Ok(acceptor) => {
                    status_reporter.tls_enabled(
                        &listen_addr.to_string(),
                        is_self_signed,
                    );
                    Some(acceptor)
                }
                Err(e) => {
                    error!("Failed to initialize TLS: {}", e);
                    return Err(Terminated);
                }
            }
        } else {
            None
        };

        // Main accept loop
        loop {
            let process_fut = arc_self.gate.process();
            let accept_fut = listener.accept();
            pin_mut!(process_fut);
            pin_mut!(accept_fut);

            match select(process_fut, accept_fut).await {
                futures::future::Either::Left((gate_result, _)) => {
                    match gate_result {
                        Ok(status) => match status {
                            GateStatus::Reconfiguring {
                                new_config:
                                    Unit::BmpTcpOut(BmpTcpOut {
                                        sources: new_sources,
                                        ..
                                    }),
                            } => {
                                debug!("BmpTcpOut reconfiguring");
                                sources = new_sources;
                                for link in sources.iter_mut() {
                                    link.connect(arc_self.clone(), false)
                                        .await
                                        .unwrap();
                                }
                            }
                            GateStatus::ReportLinks { report } => {
                                report.set_sources(&sources);
                                report.set_graph_status(
                                    arc_self.metrics.clone(),
                                );
                            }
                            _ => { /* Nothing to do */ }
                        },
                        Err(Terminated) => {
                            // Send termination to all clients
                            let term_msg =
                                bmp_builder::build_termination_message();
                            let clients = arc_self.clients.read().await;
                            for (_, client) in clients.iter() {
                                let _ = client
                                    .send_message(term_msg.clone())
                                    .await;
                            }
                            return Err(Terminated);
                        }
                    }
                }
                futures::future::Either::Right((accept_result, _)) => {
                    match accept_result {
                        Ok((tcp_stream, client_addr)) => {
                            let ip = client_addr.ip();
                            if !arc_self
                                .acl
                                .iter()
                                .any(|entry| entry.contains(ip))
                            {
                                warn!(
                                    "ACL rejected connection from {}",
                                    client_addr
                                );
                                status_reporter.acl_rejected(client_addr);
                                drop(tcp_stream);
                                continue;
                            }

                            if let Some(ref acceptor) = tls_acceptor {
                                // Spawn TLS handshake off the accept loop so a
                                // slow/stalled client cannot block new accepts or
                                // gate processing.
                                let acceptor = acceptor.clone();
                                let arc_self = arc_self.clone();
                                let status_reporter = status_reporter.clone();
                                crate::tokio::spawn(
                                    &format!(
                                        "bmp-out-tls-handshake[{}]",
                                        client_addr
                                    ),
                                    async move {
                                        match tokio::time::timeout(
                                            Duration::from_secs(10),
                                            acceptor.accept(tcp_stream),
                                        )
                                        .await
                                        {
                                            Ok(Ok(tls_stream)) => {
                                                let (_reader, writer) =
                                                    tokio::io::split(
                                                        tls_stream,
                                                    );
                                                let writer: BoxedAsyncWrite =
                                                    Box::new(writer);
                                                arc_self
                                                    .handle_new_client(
                                                        writer,
                                                        client_addr,
                                                    )
                                                    .await;
                                            }
                                            Ok(Err(e)) => {
                                                status_reporter
                                                    .tls_handshake_error(
                                                        client_addr,
                                                        e,
                                                    );
                                            }
                                            Err(_) => {
                                                status_reporter
                                                    .tls_handshake_error(
                                                    client_addr,
                                                    "handshake timeout (10s)",
                                                );
                                            }
                                        }
                                    },
                                );
                            } else {
                                let (_reader, writer) =
                                    tcp_stream.into_split();
                                let writer: BoxedAsyncWrite =
                                    Box::new(writer);
                                arc_self
                                    .handle_new_client(writer, client_addr)
                                    .await;
                            };
                        }
                        Err(err) => {
                            status_reporter.listener_io_error(err);
                        }
                    }
                }
            }
        }
    }

    /// Handle a newly connected BMP client.
    async fn handle_new_client(
        self: &Arc<Self>,
        writer: BoxedAsyncWrite,
        client_addr: SocketAddr,
    ) {
        self.status_reporter.client_connected(client_addr);

        // Create channel for sending messages to this client
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        let client = Arc::new(ClientState::new(
            client_addr,
            tx,
            self.max_client_buffer,
            self.max_client_buffer_bytes,
        ));

        let client_id = client.id;

        // Store client before starting dump/writer tasks to avoid missing
        // direct_update events during initial dump setup.
        {
            let mut clients = self.clients.write().await;
            clients.insert(client_id, client.clone());
        }

        // Spawn writer task
        let status_reporter = self.status_reporter.clone();
        let clients_for_writer = self.clients.clone();

        let mut writer = writer;

        crate::tokio::spawn(
            &format!("bmp-out-writer[{}]", client_addr),
            async move {
                while let Some(msg) = rx.recv().await {
                    if msg.is_empty() {
                        // Empty message signals disconnect
                        break;
                    }
                    if writer.write_all(&msg).await.is_err() {
                        break;
                    }
                }

                // Clean up client on disconnect
                clients_for_writer.write().await.remove(&client_id);
                status_reporter.client_disconnected(client_addr);
            },
        );

        // Spawn dump task — resolve the RIB lazily so that late
        // RibUnit initialization is visible.
        let http_ng_api = self.http_ng_api.clone();
        let ingress_register = self.ingress_register.clone();
        let sys_name = self.sys_name.clone();
        let sys_descr = self.sys_descr.clone();
        let forward_router_info = self.forward_router_info;
        let metrics_for_dump = self.metrics.clone();
        let status_reporter_for_dump = self.status_reporter.clone();

        crate::tokio::spawn(
            &format!("bmp-out-dump[{}]", client_addr),
            async move {
                // Resolve the RIB from the shared API at dump time,
                // not at unit startup.
                let rib = match http_ng_api.lock() {
                    Ok(api) => {
                        let state = api.cloned_api_state();
                        let r = state.store.load_full();
                        if r.is_none() {
                            warn!(
                                "RIB not set for client {} dump",
                                client_addr
                            );
                        }
                        r
                    }
                    Err(e) => {
                        warn!(
                            "http_ng_api mutex poisoned for client {} dump: {}",
                            client_addr, e
                        );
                        None
                    }
                };
                if let Some(rib) = rib {
                    let success = client_handler::perform_initial_dump(
                        &client,
                        &rib,
                        &ingress_register,
                        &sys_name,
                        &sys_descr,
                        forward_router_info,
                        &metrics_for_dump,
                        &status_reporter_for_dump,
                    )
                    .await;

                    if !success {
                        warn!(
                            "Initial dump failed for client {}",
                            client_addr
                        );
                    }
                } else {
                    // No RIB available yet - just send initiation and go live
                    warn!("No RIB available for initial dump, sending initiation only");
                    let init_msg = bmp_builder::build_initiation_message(
                        &sys_name, &sys_descr,
                    );
                    client.send_message(init_msg).await;

                    let mut phase = client.phase.write().await;
                    let buffered = client.take_buffered_updates().await;
                    for update in buffered {
                        if !client_handler::send_update_to_client(
                            &client,
                            &update,
                            &ingress_register,
                            forward_router_info,
                        )
                        .await
                        {
                            warn!(
                                "Failed to drain buffered update for client {}",
                                client_addr
                            );
                            break;
                        }
                    }
                    *phase = ClientPhase::Live;
                }
            },
        );
    }
}
