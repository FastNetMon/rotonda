use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::ingress::IngressId;
use crate::payload::Update;

/// Phase of a connected BMP client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPhase {
    /// Initial table dump is in progress.
    Dumping,
    /// Client is receiving live updates.
    Live,
}

/// Result of trying to buffer an update for a dumping client.
pub enum BufferUpdateResult {
    Buffered,
    NotDumping,
    Overflow,
}

/// State for a single connected BMP consumer client.
pub struct ClientState {
    /// Unique identifier for this client connection.
    pub id: Uuid,

    /// Remote address of the connected client.
    pub remote_addr: SocketAddr,

    /// Current phase (Dumping or Live).
    pub phase: RwLock<ClientPhase>,

    /// Channel sender to the client's writer task.
    pub tx: mpsc::Sender<Vec<u8>>,

    /// Buffer for updates received during the initial dump phase.
    pub dump_buffer: tokio::sync::Mutex<Vec<Update>>,

    /// Set of peer IngressIds that this client knows about (has received Peer Up for).
    pub known_peers: RwLock<HashSet<IngressId>>,

    /// When this client connected.
    pub connected_at: DateTime<Utc>,

    /// Number of BMP messages sent to this client.
    pub messages_sent: AtomicUsize,

    /// Number of bytes sent to this client.
    pub bytes_sent: AtomicUsize,

    /// Maximum buffer size during dump phase (grows dynamically based on available RAM).
    pub max_buffer: AtomicUsize,
}

const BUFFER_GROWTH_STEP: usize = 50_000;
const MIN_FREE_RAM_BYTES: u64 = 512 * 1024 * 1024;

fn available_ram_bytes() -> u64 {
    unsafe {
        let mut info: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut info) == 0 {
            (info.freeram as u64) * (info.mem_unit as u64)
        } else {
            0
        }
    }
}

impl ClientState {
    pub fn new(
        remote_addr: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
        max_buffer: usize,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            phase: RwLock::new(ClientPhase::Dumping),
            tx,
            dump_buffer: tokio::sync::Mutex::new(Vec::new()),
            known_peers: RwLock::new(HashSet::new()),
            connected_at: Utc::now(),
            messages_sent: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            max_buffer: AtomicUsize::new(max_buffer),
        }
    }

    /// Buffer an update only if the client is still in dump phase.
    pub async fn buffer_update_if_dumping(
        &self,
        update: Update,
    ) -> BufferUpdateResult {
        let phase = self.phase.read().await;
        if *phase != ClientPhase::Dumping {
            return BufferUpdateResult::NotDumping;
        }

        let mut buf = self.dump_buffer.lock().await;
        let current_limit = self.max_buffer.load(Ordering::Relaxed);
        if buf.len() >= current_limit {
            if available_ram_bytes() < MIN_FREE_RAM_BYTES {
                return BufferUpdateResult::Overflow;
            }
            self.max_buffer
                .store(current_limit + BUFFER_GROWTH_STEP, Ordering::Relaxed);
        }
        buf.push(update);
        BufferUpdateResult::Buffered
    }

    /// Take all buffered updates (drain the buffer).
    pub async fn take_buffered_updates(&self) -> Vec<Update> {
        let mut buf = self.dump_buffer.lock().await;
        std::mem::take(&mut *buf)
    }

    /// Send a BMP message to this client.
    pub async fn send_message(&self, msg: Vec<u8>) -> bool {
        let len = msg.len();
        if self.tx.send(msg).await.is_ok() {
            self.messages_sent.fetch_add(1, Ordering::Relaxed);
            self.bytes_sent.fetch_add(len, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Add a peer to the known peers set.
    pub async fn add_known_peer(&self, ingress_id: IngressId) {
        self.known_peers.write().await.insert(ingress_id);
    }

    /// Mark peer as known and return true if it was not known before.
    pub async fn register_known_peer_if_absent(
        &self,
        ingress_id: IngressId,
    ) -> bool {
        self.known_peers.write().await.insert(ingress_id)
    }

    /// Remove a peer from the known peers set.
    pub async fn remove_known_peer(&self, ingress_id: IngressId) -> bool {
        self.known_peers.write().await.remove(&ingress_id)
    }

    /// Check if a peer is known to this client.
    pub async fn has_known_peer(&self, ingress_id: IngressId) -> bool {
        self.known_peers.read().await.contains(&ingress_id)
    }
}

impl std::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientState")
            .field("id", &self.id)
            .field("remote_addr", &self.remote_addr)
            .field("connected_at", &self.connected_at)
            .field(
                "messages_sent",
                &self.messages_sent.load(Ordering::Relaxed),
            )
            .finish()
    }
}
