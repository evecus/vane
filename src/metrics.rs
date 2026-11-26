//! 轻量运行时指标（纯原子计数，供 /api/metrics 与压测前后对比采集）。

use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

pub static PROXY_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static TLS_HANDSHAKES: AtomicU64 = AtomicU64::new(0);
pub static TLS_CONFIG_REBUILDS: AtomicU64 = AtomicU64::new(0);
pub static TCP_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
pub static UDP_PACKETS: AtomicU64 = AtomicU64::new(0);
pub static UDP_SESSIONS: AtomicU64 = AtomicU64::new(0);
pub static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static SESSION_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub static SESSION_DB_FALLBACKS: AtomicU64 = AtomicU64::new(0);
pub static DB_OPS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn inc(c: &'static AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn snapshot() -> serde_json::Value {
    let get = |c: &'static AtomicU64| c.load(Ordering::Relaxed);
    json!({
        "proxy_requests": get(&PROXY_REQUESTS),
        "tls_handshakes": get(&TLS_HANDSHAKES),
        "tls_config_rebuilds": get(&TLS_CONFIG_REBUILDS),
        "tcp_connections": get(&TCP_CONNECTIONS),
        "udp_packets": get(&UDP_PACKETS),
        "udp_sessions": get(&UDP_SESSIONS),
        "log_dropped": get(&LOG_DROPPED),
        "session_cache_hits": get(&SESSION_CACHE_HITS),
        "session_db_fallbacks": get(&SESSION_DB_FALLBACKS),
        "db_ops": get(&DB_OPS),
    })
}
