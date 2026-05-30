use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, Notify, RwLock};
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

    /// Hard cap on buffered entries during dump phase. Fixed at construction.
    pub max_buffer_entries: usize,

    /// Hard cap on buffered `Update::shallow_bytes()` during dump phase.
    /// Fixed at construction.
    pub max_buffer_bytes: usize,

    /// Running sum of `Update::shallow_bytes()` for entries currently in
    /// `dump_buffer`. Read by progress logging and by the overflow check.
    pub buffered_bytes: AtomicUsize,

    /// Set once a buffer overflow (or any other terminal failure) has been
    /// observed for this client. `direct_update` uses this to skip further
    /// work for clients that are already on their way out — without it,
    /// every subsequent upstream Update produced a redundant "Buffer
    /// overflow" log line and queued another empty-Vec disconnect signal
    /// behind the still-draining dump messages.
    pub disconnect_pending: AtomicBool,

    /// Out-of-band shutdown signal for the writer task. Used because the
    /// in-band empty-Vec marker rides the same mpsc as dump messages — at
    /// the moment of overflow that channel is full, so a `try_send` of
    /// the empty Vec returns `Err` and the signal is silently dropped. A
    /// `Notify` permit, by contrast, is held until consumed, so the
    /// writer is guaranteed to observe it.
    pub disconnect_notify: Arc<Notify>,
}

impl ClientState {
    pub fn new(
        remote_addr: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
        max_buffer_entries: usize,
        max_buffer_bytes: usize,
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
            max_buffer_entries,
            max_buffer_bytes,
            buffered_bytes: AtomicUsize::new(0),
            disconnect_pending: AtomicBool::new(false),
            disconnect_notify: Arc::new(Notify::new()),
        }
    }

    /// Buffer an update only if the client is still in dump phase.
    ///
    /// Returns `Overflow` if either the entry cap or the byte cap would be
    /// exceeded. The caller is expected to disconnect the client in that
    /// case — there is no dynamic growth, by design: relying on the
    /// kernel's free-RAM reading let bmp-out OOM the whole process on
    /// large dumps (RSS climbed faster than glibc returned pages, so
    /// freeram-based growth never tripped its safety net until far too
    /// late).
    pub async fn buffer_update_if_dumping(
        &self,
        update: Update,
    ) -> BufferUpdateResult {
        let phase = self.phase.read().await;
        if *phase != ClientPhase::Dumping {
            return BufferUpdateResult::NotDumping;
        }

        let upd_bytes = update.shallow_bytes();
        let mut buf = self.dump_buffer.lock().await;
        if buf.len() >= self.max_buffer_entries {
            return BufferUpdateResult::Overflow;
        }
        let current_bytes = self.buffered_bytes.load(Ordering::Relaxed);
        if current_bytes.saturating_add(upd_bytes) > self.max_buffer_bytes {
            return BufferUpdateResult::Overflow;
        }
        buf.push(update);
        self.buffered_bytes
            .fetch_add(upd_bytes, Ordering::Relaxed);
        BufferUpdateResult::Buffered
    }

    /// Take all buffered updates (drain the buffer).
    pub async fn take_buffered_updates(&self) -> Vec<Update> {
        let mut buf = self.dump_buffer.lock().await;
        self.buffered_bytes.store(0, Ordering::Relaxed);
        std::mem::take(&mut *buf)
    }

    /// Send a BMP message to this client's writer task.
    ///
    /// `blocking` selects the backpressure policy:
    ///
    /// * `true` — used by the per-client dump and buffered-replay paths, which
    ///   run on the client's own task: awaiting the bounded channel applies
    ///   natural backpressure to just that task.
    /// * `false` — used by the shared live `direct_update` path. That path
    ///   runs inline on the ingest pipeline (the gate awaits it, and the RIB
    ///   and bmp-in await the gate in turn), so it must never park on one slow
    ///   consumer's TCP throughput — doing so head-of-line-blocks every other
    ///   client and freezes route ingestion process-wide. On a full queue the
    ///   client is flagged for disconnect (the same policy as a dump-phase
    ///   buffer overflow) and the message is dropped; the client will
    ///   reconnect and re-dump.
    pub async fn send_message_mode(
        &self,
        msg: Vec<u8>,
        blocking: bool,
    ) -> bool {
        let len = msg.len();
        let sent = if blocking {
            self.tx.send(msg).await.is_ok()
        } else {
            match self.tx.try_send(msg) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.request_disconnect();
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        };
        if sent {
            self.messages_sent.fetch_add(1, Ordering::Relaxed);
            self.bytes_sent.fetch_add(len, Ordering::Relaxed);
        }
        sent
    }

    /// Blocking send, for per-client tasks (dump / buffered replay). See
    /// [`send_message_mode`](Self::send_message_mode).
    pub async fn send_message(&self, msg: Vec<u8>) -> bool {
        self.send_message_mode(msg, true).await
    }

    /// Flag this client for disconnect and wake its writer task. Idempotent:
    /// the first caller wins the CAS and fires the notify exactly once, so
    /// concurrent overflow / live-backpressure events don't double-signal.
    pub fn request_disconnect(&self) {
        if !self.disconnect_pending.swap(true, Ordering::SeqCst) {
            self.disconnect_notify.notify_one();
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
