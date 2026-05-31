use std::{
    fmt::Display,
    net::SocketAddr,
    sync::{atomic::Ordering::SeqCst, Arc},
};

use log::{debug, error, info, warn};

use crate::common::status_reporter::{
    sr_log, AnyStatusReporter, Chainable, Named, UnitStatusReporter,
};

use super::metrics::BmpTcpOutMetrics;

#[derive(Debug, Default)]
pub struct BmpTcpOutStatusReporter {
    name: String,
    metrics: Arc<BmpTcpOutMetrics>,
}

impl BmpTcpOutStatusReporter {
    pub fn new<T: Display>(name: T, metrics: Arc<BmpTcpOutMetrics>) -> Self {
        Self {
            name: format!("{}", name),
            metrics,
        }
    }

    pub fn bind_error<T: Display>(&self, listen_addr: &str, err: T) {
        sr_log!(warn: self, "Error while listening for connections on {}: {}", listen_addr, err);
    }

    pub fn listener_listening(&self, server_uri: &str) {
        sr_log!(info: self, "Listening for BMP client connections on {}", server_uri);
        self.metrics.listener_bound_count.fetch_add(1, SeqCst);
    }

    pub fn client_connected(&self, client_addr: SocketAddr) {
        sr_log!(info: self, "BMP client connected from {}", client_addr);
        self.metrics.clients_connected.fetch_add(1, SeqCst);
    }

    pub fn client_disconnected(&self, client_addr: SocketAddr) {
        sr_log!(info: self, "BMP client disconnected: {}", client_addr);
        self.metrics.clients_disconnected.fetch_add(1, SeqCst);
    }

    pub fn dump_started(&self, client_addr: SocketAddr) {
        sr_log!(info: self, "Initial table dump started for client {}", client_addr);
        self.metrics.active_dumps.fetch_add(1, SeqCst);
    }

    pub fn dump_completed(&self, client_addr: SocketAddr) {
        sr_log!(info: self, "Initial table dump completed for client {}", client_addr);
        self.metrics.active_dumps.fetch_sub(1, SeqCst);
    }

    pub fn buffer_overflow(&self, client_addr: SocketAddr) {
        sr_log!(warn: self, "Buffer overflow for client {}, disconnecting", client_addr);
        self.metrics.buffer_overflows.fetch_add(1, SeqCst);
    }

    pub fn acl_rejected(&self, client_addr: SocketAddr) {
        sr_log!(warn: self, "ACL rejected connection from {}", client_addr);
        self.metrics.acl_rejected.fetch_add(1, SeqCst);
    }

    pub fn listener_io_error<T: Display>(&self, err: T) {
        sr_log!(warn: self, "Error while listening for connections: {}", err);
    }

    #[allow(dead_code)]
    pub fn internal_error<T: Display>(&self, err: T) {
        sr_log!(error: self, "Internal error: {}", err);
    }

    pub fn tls_handshake_error<T: Display>(
        &self,
        client_addr: SocketAddr,
        err: T,
    ) {
        sr_log!(warn: self, "TLS handshake failed for {}: {}", client_addr, err);
        self.metrics.tls_handshake_failures.fetch_add(1, SeqCst);
    }

    pub fn tls_enabled(&self, listen_addr: &str, is_self_signed: bool) {
        if is_self_signed {
            sr_log!(info: self, "TLS enabled on {} with auto-generated self-signed certificate", listen_addr);
        } else {
            sr_log!(info: self, "TLS enabled on {} with user-provided certificate", listen_addr);
        }
    }
}

impl UnitStatusReporter for BmpTcpOutStatusReporter {}

impl AnyStatusReporter for BmpTcpOutStatusReporter {
    fn metrics(&self) -> Option<Arc<dyn crate::metrics::Source>> {
        Some(self.metrics.clone())
    }
}

impl Chainable for BmpTcpOutStatusReporter {
    fn add_child<T: Display>(&self, child_name: T) -> Self {
        Self::new(self.link_names(child_name), self.metrics.clone())
    }
}

impl Named for BmpTcpOutStatusReporter {
    fn name(&self) -> &str {
        &self.name
    }
}
