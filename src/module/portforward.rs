use crate::config::{Config, PortForwardRule};
use crate::metrics;
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::{error, info, warn};

// ─── Tuning ───────────────────────────────────────────────────────────────────

const TCP_BUF_SIZE: usize = 64 * 1024;
const MAX_TCP_CONNS: usize = 4096;
const UDP_BUF_SIZE: usize = 65535;
const UDP_SESSION_IDLE_SECS: u64 = 60;
const MAX_UDP_SESSIONS: usize = 4096;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─── Stats ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct StatSnapshot {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub conns: i64,
    pub time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Default)]
struct Stats {
    bytes_in: std::sync::atomic::AtomicI64,
    bytes_out: std::sync::atomic::AtomicI64,
    conns: std::sync::atomic::AtomicI64,
}

impl Stats {
    fn snapshot(&self) -> StatSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        StatSnapshot {
            bytes_in: self.bytes_in.load(Relaxed),
            bytes_out: self.bytes_out.load(Relaxed),
            conns: self.conns.load(Relaxed),
            time: chrono::Utc::now(),
        }
    }
}

/// 连接数上限的 RAII 计数（防止连接风暴打爆 fd / 任务数）。
struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ─── Manager ──────────────────────────────────────────────────────────────────

type StopTx = watch::Sender<bool>;

struct WorkerEntry {
    stop: Vec<StopTx>,
    stats: Arc<Stats>,
}

pub struct Manager {
    cfg: Config,
    inner: Mutex<ManagerInner>,
}

#[derive(Default)]
struct ManagerInner {
    workers: HashMap<String, WorkerEntry>,
    history: HashMap<String, Vec<StatSnapshot>>,
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: Mutex::new(ManagerInner::default()),
        })
    }

    pub fn start_all(self: &Arc<Self>) {
        let rules: Vec<PortForwardRule> = {
            let cfg = self.cfg.read();
            cfg.port_forwards
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect()
        };
        for rule in rules {
            if let Err(e) = self.start(&rule.id) {
                error!("[portforward] start {} error: {}", rule.id, e);
            }
        }
        let mgr = Arc::clone(self);
        tokio::spawn(async move { mgr.collect_stats().await });
    }

    pub fn start(self: &Arc<Self>, id: &str) -> anyhow::Result<()> {
        let rule = {
            let cfg = self.cfg.read();
            cfg.port_forwards.iter().find(|r| r.id == id).cloned()
        };
        let rule = rule.ok_or_else(|| anyhow::anyhow!("rule {} not found", id))?;

        // Stop existing
        self.stop(id);

        let stats = Arc::new(Stats::default());
        let mut stops = Vec::new();

        let protocols: Vec<&str> = match rule.protocol.as_str() {
            "both" => vec!["tcp", "udp"],
            "udp" => vec!["udp"],
            _ => vec!["tcp"],
        };

        for proto in protocols {
            let (tx, rx) = watch::channel(false);
            stops.push(tx);
            let r = rule.clone();
            let st = Arc::clone(&stats);
            let cfg = self.cfg.clone();
            let p = proto.to_string();
            tokio::spawn(async move {
                if p == "udp" {
                    run_udp(r, st, rx, cfg).await;
                } else {
                    run_tcp(r, st, rx, cfg).await;
                }
            });
        }

        let mut inner = self.inner.lock().unwrap();
        inner
            .workers
            .insert(id.to_string(), WorkerEntry { stop: stops, stats });
        Ok(())
    }

    pub fn stop(&self, id: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.workers.remove(id) {
            for tx in entry.stop {
                let _ = tx.send(true);
            }
        }
    }

    pub fn get_stats(&self, id: &str) -> Option<StatSnapshot> {
        let inner = self.inner.lock().unwrap();
        inner.workers.get(id).map(|e| e.stats.snapshot())
    }

    pub fn get_history(&self, id: &str) -> Vec<StatSnapshot> {
        let inner = self.inner.lock().unwrap();
        inner.history.get(id).cloned().unwrap_or_default()
    }

    async fn collect_stats(&self) {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let mut inner = self.inner.lock().unwrap();
            let ids: Vec<String> = inner.workers.keys().cloned().collect();
            for id in ids {
                if let Some(entry) = inner.workers.get(&id) {
                    let snap = entry.stats.snapshot();
                    let h = inner.history.entry(id).or_default();
                    h.push(snap);
                    if h.len() > 360 {
                        let drain_to = h.len() - 360;
                        h.drain(0..drain_to);
                    }
                }
            }
        }
    }
}

// ─── TCP worker ───────────────────────────────────────────────────────────────

async fn run_tcp(
    rule: PortForwardRule,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
    cfg: Config,
) {
    let addr = format!("[::]:{}", rule.listen_port);
    let listener = match crate::net::bind_tcp(rule.listen_port).await {
        Ok(l) => l,
        Err(e) => {
            error!("[portforward] TCP listen {} error: {}", addr, e);
            return;
        }
    };
    info!(
        "[portforward] TCP {} → {}",
        addr,
        crate::net::host_port(&rule.target_ip, rule.target_port)
    );

    let active = Arc::new(AtomicUsize::new(0));
    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { break; } }
            res = listener.accept() => {
                match res {
                    Ok((conn, peer)) => {
                        let client_ip = crate::net::ip_string(peer.ip());
                        if !cfg.check_ip_allowed_addr(
                            "portforward",
                            &rule.id,
                            crate::net::canonical_ip(peer.ip()),
                        ) {
                            warn!("[portforward] TCP blocked {} → port {}", client_ip, rule.listen_port);
                            continue;
                        }
                        if active.load(Ordering::Relaxed) >= MAX_TCP_CONNS {
                            warn!("[portforward] TCP connection limit reached on port {}", rule.listen_port);
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let guard = ConnGuard(Arc::clone(&active));
                        let target = crate::net::host_port(&rule.target_ip, rule.target_port);
                        let st = Arc::clone(&stats);
                        tokio::spawn(async move {
                            let _guard = guard;
                            handle_tcp(conn, target, st).await;
                        });
                    }
                    Err(e) => { error!("[portforward] TCP accept error: {}", e); }
                }
            }
        }
    }
}

async fn handle_tcp(src: TcpStream, target: String, stats: Arc<Stats>) {
    use std::sync::atomic::Ordering::Relaxed;
    stats.conns.fetch_add(1, Relaxed);
    metrics::inc(&metrics::TCP_CONNECTIONS);
    let st_guard = Arc::clone(&stats);
    scopeguard::defer! { st_guard.conns.fetch_sub(1, Relaxed); }

    let dst = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&target)).await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            error!("[portforward] TCP dial {} error: {}", target, e);
            return;
        }
        Err(_) => {
            error!("[portforward] TCP dial {} timeout", target);
            return;
        }
    };

    // 转发场景关闭 Nagle，避免小包被 delayed-ACK 拖出 40ms 延迟。
    let _ = src.set_nodelay(true);
    let _ = dst.set_nodelay(true);

    // 单任务双向转发（原实现 3 个 task：handle + 两个 io::copy），
    // 并用 64KB BufReader 降低读侧 syscall 次数。
    let mut a = io::BufReader::with_capacity(TCP_BUF_SIZE, src);
    let mut b = io::BufReader::with_capacity(TCP_BUF_SIZE, dst);
    let (n_in, n_out) = match io::copy_bidirectional(&mut a, &mut b).await {
        Ok((x, y)) => (x, y),
        Err(_) => (0, 0),
    };
    stats.bytes_in.fetch_add(n_in as i64, Relaxed);
    stats.bytes_out.fetch_add(n_out as i64, Relaxed);
}

// ─── UDP worker（会话化） ─────────────────────────────────────────────────────

struct UdpSession {
    outbound: Arc<UdpSocket>,
    last_used: Arc<std::sync::atomic::AtomicI64>,
}

async fn run_udp(
    rule: PortForwardRule,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
    cfg: Config,
) {
    let addr = format!("[::]:{}", rule.listen_port);
    let sock = match crate::net::bind_udp(rule.listen_port) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("[portforward] UDP bind {} error: {}", addr, e);
            return;
        }
    };
    info!(
        "[portforward] UDP {} → {}",
        addr,
        crate::net::host_port(&rule.target_ip, rule.target_port)
    );

    let target = crate::net::host_port(&rule.target_ip, rule.target_port);
    let legacy = std::env::var("VANE_UDP_LEGACY")
        .map(|v| v == "1")
        .unwrap_or(false);

    // 目标地址启动时解析一次；之后每 60s 刷新以应对 DNS 变更，
    // 不再每个数据报都做 lookup_host（原实现会打满 blocking 线程池）。
    let mut target_addr = tokio::net::lookup_host(&target)
        .await
        .ok()
        .and_then(|mut it| it.next());
    let mut resolver = tokio::time::interval(Duration::from_secs(60));
    resolver.tick().await; // skip the immediate first tick

    let sessions: Arc<DashMap<SocketAddr, Arc<UdpSession>>> = Arc::new(DashMap::new());
    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { break; } }
            _ = resolver.tick() => {
                if let Ok(mut it) = tokio::net::lookup_host(&target).await {
                    if let Some(a) = it.next() { target_addr = Some(a); }
                }
            }
            res = sock.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => { error!("[portforward] UDP recv error: {}", e); continue; }
                };
                if !cfg.check_ip_allowed_addr(
                    "portforward",
                    &rule.id,
                    crate::net::canonical_ip(peer.ip()),
                ) {
                    continue;
                }
                metrics::inc(&metrics::UDP_PACKETS);
                use std::sync::atomic::Ordering::Relaxed;
                stats.bytes_in.fetch_add(n as i64, Relaxed);
                let data = buf[..n].to_vec();

                if legacy {
                    let src = Arc::clone(&sock);
                    let tgt = target.clone();
                    let st = Arc::clone(&stats);
                    tokio::spawn(async move {
                        handle_udp_legacy(src, peer, tgt, data, st).await;
                    });
                    continue;
                }

                let Some(addr) = target_addr else { continue };
                let Some(session) =
                    get_or_create_session(&sessions, &sock, peer, addr, &stats).await
                else {
                    continue;
                };
                session.last_used.store(now_secs(), Relaxed);
                if let Err(e) = session.outbound.send_to(&data, addr).await {
                    warn!("[portforward] UDP send error: {}", e);
                }
            }
        }
    }
}

/// 按 client 地址复用出站 socket；首次建会话时起一个常驻响应转发任务，
/// 支持一个会话内的多个响应包（原实现「一问一答」只回第一个）。
async fn get_or_create_session(
    sessions: &Arc<DashMap<SocketAddr, Arc<UdpSession>>>,
    listener: &Arc<UdpSocket>,
    client: SocketAddr,
    target: SocketAddr,
    stats: &Arc<Stats>,
) -> Option<Arc<UdpSession>> {
    if let Some(s) = sessions.get(&client) {
        return Some(Arc::clone(s.value()));
    }
    if sessions.len() >= MAX_UDP_SESSIONS {
        warn!("[portforward] UDP session limit reached, dropping packet");
        return None;
    }
    let dst = match crate::net::bind_udp_for(&target).await {
        Ok(s) => Arc::new(s),
        Err(_) => return None,
    };
    let last_used = Arc::new(std::sync::atomic::AtomicI64::new(now_secs()));
    let session = Arc::new(UdpSession {
        outbound: Arc::clone(&dst),
        last_used: Arc::clone(&last_used),
    });
    sessions.insert(client, Arc::clone(&session));
    metrics::UDP_SESSIONS.fetch_add(1, Ordering::Relaxed);

    let sessions2 = Arc::clone(sessions);
    let listener2 = Arc::clone(listener);
    let st = Arc::clone(stats);
    tokio::spawn(async move {
        let mut resp = vec![0u8; UDP_BUF_SIZE];
        loop {
            match tokio::time::timeout(
                Duration::from_secs(UDP_SESSION_IDLE_SECS),
                dst.recv_from(&mut resp),
            )
            .await
            {
                Ok(Ok((m, _))) => {
                    st.bytes_out
                        .fetch_add(m as i64, std::sync::atomic::Ordering::Relaxed);
                    let _ = listener2.send_to(&resp[..m], client).await;
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    // 只有整个超时窗口内都没有新包才回收，避免误删仍活跃的会话
                    // （客户端持续发包但后端暂时无响应时，会话必须保留）。
                    let idle_for =
                        now_secs() - last_used.load(std::sync::atomic::Ordering::Relaxed);
                    if idle_for < UDP_SESSION_IDLE_SECS as i64 {
                        continue;
                    }
                    if sessions2.remove(&client).is_some() {
                        metrics::UDP_SESSIONS.fetch_sub(1, Ordering::Relaxed);
                    }
                    break;
                }
            }
        }
    });
    Some(session)
}

/// 旧路径（每包 DNS + 每包新 socket），保留作 `VANE_UDP_LEGACY=1` 回退。
async fn handle_udp_legacy(
    src: Arc<UdpSocket>,
    client: SocketAddr,
    target: String,
    data: Vec<u8>,
    stats: Arc<Stats>,
) {
    let target_addr = match tokio::net::lookup_host(&target).await {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return,
        },
        Err(_) => return,
    };
    let dst = match crate::net::bind_udp_for(&target_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if dst.send_to(&data, target_addr).await.is_err() {
        return;
    }
    let mut resp = vec![0u8; UDP_BUF_SIZE];
    let _ = tokio::time::timeout(Duration::from_secs(5), dst.recv(&mut resp))
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|n| {
            use std::sync::atomic::Ordering::Relaxed;
            stats.bytes_out.fetch_add(n as i64, Relaxed);
            let data = resp[..n].to_vec();
            tokio::spawn(async move {
                let _ = src.send_to(&data, client).await;
            });
        });
}
