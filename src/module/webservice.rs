use crate::config::{Config, DataDir, TlsCert, WebRoute, WebService};
use crate::metrics;
use anyhow::{anyhow, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use bytes::Buf;
use once_cell::sync::Lazy;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// body 错误类型用 Box<dyn Error>：h3 入口的请求体流可以携带自己的错误
/// （客户端 reset / 读取失败），hyper::Error 无法从外部构造。
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

fn box_body<B>(b: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    b.map_err(|e| e.into()).boxed()
}

fn full_body(s: impl Into<Bytes>) -> BoxBody {
    Full::new(s.into()).map_err(|e| match e {}).boxed()
}

/// h3 请求体：由读取任务经有界通道喂入，实现流式转发（带背压），
/// 读取出错（客户端 reset 等）以 Err 传给 hyper client，从而中止向后端的请求，
/// 不会把截断的 body 当成完整请求。
struct ChanBody {
    rx: mpsc::Receiver<std::result::Result<Bytes, BoxError>>,
    /// 请求声明的 Content-Length（已知时让 hyper 按定长而非 chunked 转发）。
    len: Option<u64>,
}

impl hyper::body::Body for ChanBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, BoxError>>> {
        self.rx.poll_recv(cx).map(|o| {
            o.map(|r| r.map(hyper::body::Frame::data))
        })
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self.len {
            Some(n) => hyper::body::SizeHint::with_exact(n),
            None => hyper::body::SizeHint::default(),
        }
    }
}

/// 全局反向代理客户端：连接池 + DNS 缓存。原实现每个请求都 `build_http()`，
/// 等于每个请求重新 DNS 解析 + TCP 三次握手，是吞吐量的头号瓶颈。
/// body 统一为 BoxBody，兼容 h1/h2/h3 三种入口的请求体。
static PROXY_CLIENT: Lazy<Client<HttpConnector, BoxBody>> = Lazy::new(|| {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(10)));
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build(connector)
});

// ─── Access log ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, serde::Serialize)]
pub struct AccessLog {
    pub service_id: String,
    pub route_id: String,
    pub route_name: String,
    pub domain: String,
    pub client_ip: String,
    pub user_agent: String,
    pub time: String,
}

#[derive(Default)]
pub(crate) struct LogStore {
    logs: VecDeque<AccessLog>,
    dedup: HashMap<String, ()>,
    dedup_day: u64,
}

impl LogStore {
    /// O(1) 追加：原实现每请求都 `retain` 全量扫描（≤2000 条），
    /// 且 `dedup` 只增不减，长期运行会无限吃内存。
    fn add(&mut self, log: AccessLog) {
        const LOG_CAP: usize = 2000;
        const DEDUP_CAP: usize = 10_000;

        let day = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86400;

        // 按 UTC 日轮转，杜绝 dedup 无限增长。
        if day != self.dedup_day {
            self.dedup.clear();
            self.dedup_day = day;
        }

        let key = format!(
            "{}\x00{}\x00{}\x00{}",
            day, log.route_id, log.client_ip, log.user_agent
        );
        if self.dedup.contains_key(&key) {
            return;
        }
        if self.dedup.len() >= DEDUP_CAP {
            self.dedup.clear();
        }
        self.dedup.insert(key, ());

        if self.logs.len() >= LOG_CAP {
            self.logs.pop_front();
        }
        self.logs.push_back(log);
    }

    fn list(&self, service_id: &str, limit: usize) -> Vec<AccessLog> {
        self.logs
            .iter()
            .rev()
            .filter(|l| service_id.is_empty() || l.service_id == service_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

#[allow(dead_code)]
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simple approximation from unix days
    let y400 = days / 146097;
    let d = days % 146097;
    let y100 = (d / 36524).min(3);
    let d = d - y100 * 36524;
    let y4 = d / 1461;
    let d = d % 1461;
    let y1 = (d / 365).min(3);
    let d = d - y1 * 365;
    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1970;
    let month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    let mut rem = d;
    for &md in &month_days {
        if rem < md {
            break;
        }
        rem -= md;
        month += 1;
    }
    (year, month, rem + 1)
}

// ─── Manager ──────────────────────────────────────────────────────────────────

struct ServiceHandle {
    stop: watch::Sender<bool>,
}

pub struct Manager {
    cfg: Config,
    handles: Mutex<HashMap<String, ServiceHandle>>,
    pub logs: Arc<Mutex<LogStore>>,
    dd: Option<std::sync::Arc<DataDir>>,
    /// TLS ServerConfig 缓存：(svc_id, 协议档) → (配置版本, config)。
    /// 不同协议档对应不同 ALPN 集合，因此按档位各存一份；
    /// 配置版本由 Config 写 guard 自动递增，证书/路由变更会自动失效。
    tls_configs: Mutex<HashMap<(String, String), (u64, Arc<ServerConfig>)>>,
    /// 访问日志写入通道（有界），请求路径不持锁。
    log_tx: mpsc::Sender<AccessLog>,
    /// 当前 QUIC endpoint 在运行的服务 id；用于决定是否向 h1/h2 响应通告 Alt-Svc。
    h3_active: Mutex<std::collections::HashSet<String>>,
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        let dd = cfg.read().data_dir.clone();
        let logs = Arc::new(Mutex::new(LogStore::default()));
        let (log_tx, mut log_rx) = mpsc::channel::<AccessLog>(4096);
        {
            let sink = Arc::clone(&logs);
            tokio::spawn(async move {
                while let Some(log) = log_rx.recv().await {
                    sink.lock().unwrap().add(log);
                }
            });
        }
        Arc::new(Self {
            cfg,
            handles: Mutex::new(HashMap::new()),
            logs,
            dd,
            tls_configs: Mutex::new(HashMap::new()),
            log_tx,
            h3_active: Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// Drain all in-memory logs into the DB and trim to `keep` total rows.
    /// Called by the periodic flush task in main.rs.
    pub fn flush_logs_to_db(&self, keep: usize) {
        let Some(ref dd) = self.dd else {
            return;
        };
        let batch: Vec<AccessLog> = {
            let mut store = self.logs.lock().unwrap();
            // Take a snapshot of what's accumulated, leave memory empty so
            // the next window starts fresh (avoids double-writing on next flush).
            store.logs.drain(..).collect()
        };
        if let Err(e) = crate::config::db::flush_access_logs(dd, &batch, keep) {
            tracing::warn!("[webservice] flush_logs_to_db error: {}", e);
        }
    }

    pub fn start_all(self: &Arc<Self>) {
        let svcs: Vec<WebService> = {
            let cfg = self.cfg.read();
            cfg.web_services
                .iter()
                .filter(|s| s.enabled)
                .cloned()
                .collect()
        };
        for svc in svcs {
            if let Err(e) = self.start(&svc.id) {
                error!("[webservice] start {} error: {}", svc.id, e);
            }
        }
    }

    pub fn start(self: &Arc<Self>, id: &str) -> Result<()> {
        let svc = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().find(|s| s.id == id).cloned()
        };
        let svc = svc.ok_or_else(|| anyhow!("service {} not found", id))?;
        self.stop(id);

        let (tx, rx) = watch::channel(false);
        let mgr = Arc::clone(self);
        let svc_id = id.to_string();
        tokio::spawn(async move {
            mgr.run_service(svc, rx, svc_id).await;
        });
        self.handles
            .lock()
            .unwrap()
            .insert(id.to_string(), ServiceHandle { stop: tx });
        Ok(())
    }

    pub fn stop(&self, id: &str) {
        if let Some(h) = self.handles.lock().unwrap().remove(id) {
            let _ = h.stop.send(true);
        }
    }

    pub fn get_logs(&self, service_id: &str, limit: usize) -> Vec<AccessLog> {
        // Merge persisted logs (older) + in-memory logs (newer), newest-first.
        let mut mem: Vec<AccessLog> = self.logs.lock().unwrap().list(service_id, limit);
        if let Some(ref dd) = self.dd {
            if let Ok(mut db_logs) = crate::config::db::load_access_logs(dd, service_id, limit) {
                // db_logs are already newest-first; append mem (also newest-first)
                // then dedup on time+route_id+client_ip and take `limit`.
                db_logs.append(&mut mem);
                let mut seen = std::collections::HashSet::new();
                db_logs.retain(|l| {
                    let k = format!("{}|{}|{}", l.time, l.route_id, l.client_ip);
                    seen.insert(k)
                });
                db_logs.truncate(limit);
                return db_logs;
            }
        }
        mem
    }

    async fn run_service(
        self: Arc<Self>,
        svc: WebService,
        mut stop: watch::Receiver<bool>,
        svc_id: String,
    ) {
        let addr = format!("[::]:{}", svc.listen_port);
        let listener = match crate::net::bind_tcp(svc.listen_port).await {
            Ok(l) => l,
            Err(e) => {
                error!("[webservice] bind {} error: {}", addr, e);
                return;
            }
        };
        info!(
            "[webservice] listening on {} (https={})",
            addr, svc.enable_https
        );

        // HTTPS 服务同时开 QUIC (h3) 通道：UDP 端口与 TCP 相同号。
        // 端口被占用（另一个 svc / portforward UDP）时降级为仅 TCP，不影响 h1/h2。
        if svc.enable_https {
            // 服务重启（配置保存）时，旧 QUIC endpoint 是异步 close 的，UDP 端口释放
            // 有延迟；这里最多重试约 3 秒，避免误判为"端口被占用"而永久退化为仅 TCP。
            let mut bound = crate::net::bind_udp(svc.listen_port);
            for _ in 0..10 {
                if bound.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                bound = crate::net::bind_udp(svc.listen_port);
            }
            match bound {
                Ok(sock) => match sock.into_std() {
                    Ok(std_sock) => {
                        info!(
                            "[webservice] h3 (QUIC) on udp/{} for svc {}",
                            svc.listen_port, svc_id
                        );
                        tokio::spawn(Self::run_h3_endpoint(
                            Arc::clone(&self),
                            svc_id.clone(),
                            std_sock,
                            stop.clone(),
                        ));
                    }
                    Err(e) => {
                        warn!("[webservice] h3 udp/{} into_std failed: {}", svc.listen_port, e)
                    }
                },
                Err(e) => {
                    warn!(
                        "[webservice] h3 udp/{} unavailable (port busy): {} — falling back to TCP only",
                        svc.listen_port, e
                    )
                }
            }
        }

        // When HTTPS is enabled on port 443, also bind port 80 to redirect HTTP → HTTPS
        if svc.enable_https && svc.listen_port == 443 {
            let ln80 = match crate::net::bind_tcp(80).await {
                Ok(l) => {
                    info!(
                        "[webservice] :80 redirect listener started for svc {}",
                        svc_id
                    );
                    l
                }
                Err(e) => {
                    warn!("[webservice] :80 redirect unavailable (port busy): {}", e);
                    // Fall through without a :80 listener
                    let mgr = Arc::clone(&self);
                    let mut stop2 = stop.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = stop2.changed() => { if *stop2.borrow() { break; } }
                                res = listener.accept() => {
                                    match res {
                                        Ok((stream, peer)) => {
                                            let mgr2 = Arc::clone(&mgr);
                                            let id = svc_id.clone();
                                            tokio::spawn(async move {
                                                mgr2.handle_conn(stream, peer, &id).await;
                                            });
                                        }
                                        Err(e) => { error!("[webservice] accept error: {}", e); }
                                    }
                                }
                            }
                        }
                    });
                    return;
                }
            };

            let mgr80 = Arc::clone(&self);
            let mut stop80 = stop.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop80.changed() => { if *stop80.borrow() { break; } }
                        res = ln80.accept() => {
                            match res {
                                Ok((stream, _peer)) => {
                                    let mgr = Arc::clone(&mgr80);
                                    tokio::spawn(async move {
                                        mgr.serve_redirect(stream, 443).await;
                                    });
                                }
                                Err(e) => { error!("[webservice] :80 accept error: {}", e); }
                            }
                        }
                    }
                }
            });
        }

        loop {
            tokio::select! {
                _ = stop.changed() => { if *stop.borrow() { break; } }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let mgr = Arc::clone(&self);
                            let id = svc_id.clone();
                            tokio::spawn(async move {
                                mgr.handle_conn(stream, peer, &id).await;
                            });
                        }
                        Err(e) => { error!("[webservice] accept error: {}", e); }
                    }
                }
            }
        }
    }

    // ── HTTP/3 (QUIC) ─────────────────────────────────────────────────────

    /// QUIC endpoint 循环：UDP socket → quinn → 按 SNI 分发 h3 连接。
    /// ALPN 固定 h3；auto/h3 档域名放行，h1/h2 档域名握手后直接关闭。
    async fn run_h3_endpoint(
        self: Arc<Self>,
        svc_id: String,
        socket: std::net::UdpSocket,
        mut stop: watch::Receiver<bool>,
    ) {
        // 服务/路由/证书可能在 svc 启动后才配置完成，循环等待直到 TLS 配置就绪。
        let tls = loop {
            if let Some(t) = self.build_tls_config(&svc_id, "h3") {
                break t;
            }
            tokio::select! {
                _ = stop.changed() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        };
        // 证书解析器换成动态的：每次握手都取最新配置（缓存随配置版本自动失效），
        // 证书续期 / 新增域名无需重启 QUIC endpoint。
        let mut tls_cfg = (*tls).clone();
        tls_cfg.cert_resolver = Arc::new(DynH3Resolver {
            mgr: Arc::downgrade(&self),
            svc_id: svc_id.clone(),
        });
        let quic_crypto = match quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg) {
            Ok(c) => c,
            Err(e) => {
                warn!("[webservice] h3: build quic server config failed: {}", e);
                return;
            }
        };
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(256u32.into());
        transport.max_concurrent_uni_streams(32u32.into());
        if let Ok(idle) = Duration::from_secs(60).try_into() {
            transport.max_idle_timeout(Some(idle));
        }
        transport.keep_alive_interval(Some(Duration::from_secs(20)));
        server_config.transport_config(Arc::new(transport));

        let endpoint = match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!("[webservice] h3: endpoint init failed: {}", e);
                return;
            }
        };
        self.h3_active.lock().unwrap().insert(svc_id.clone());

        loop {
            let incoming = tokio::select! {
                _ = stop.changed() => { if *stop.borrow() { break; } else { continue; } },
                conn = endpoint.accept() => match conn {
                    Some(i) => i,
                    None => break,
                },
            };
            let mgr = Arc::clone(&self);
            let id = svc_id.clone();
            tokio::spawn(async move {
                mgr.handle_h3_conn(incoming, id).await;
            });
        }
        self.h3_active.lock().unwrap().remove(&svc_id);
        // 仅 drop endpoint 句柄不会关闭已建立的连接，socket 也不会释放（重启同端口会
        // 与旧 socket 并存、UDP 包被分流）。必须显式 close。
        endpoint.close(quinn::VarInt::from_u32(0), b"service stopped");
    }

    /// 单个 QUIC 连接：校验 SNI 协议档后进入 h3 请求循环。
    async fn handle_h3_conn(self: &Arc<Self>, incoming: quinn::Incoming, svc_id: String) {
        use quinn::crypto::rustls::HandshakeData;

        let conn = match incoming.await {
            Ok(c) => c,
            Err(_) => return,
        };

        // QUIC 的 TLS 握手内含 ClientHello：连接完全建立后取 SNI 与 ALPN。
        // 块作用域内完成 downcast，避免非 Send 的 Box<dyn Any> 跨 await。
        let (sni, alpn_ok) = {
            let hs = match conn.handshake_data() {
                Some(d) => d,
                None => return,
            };
            match hs.downcast_ref::<HandshakeData>() {
                Some(hd) => (
                    hd.server_name
                        .as_deref()
                        .map(|s| s.trim_end_matches('.').to_lowercase()),
                    hd.protocol.as_deref() == Some(b"h3"),
                ),
                None => (None, false),
            }
        };

        // 协议档：auto/h3 放行；h1/h2 档域名与无 SNI 的异常连接直接关闭。
        let profile = sni
            .as_deref()
            .map(|host| {
                self.cfg
                    .runtime()
                    .route(&svc_id, host)
                    .map(|r| r.http_version.clone())
                    .unwrap_or_else(|| "auto".to_string())
            })
            .unwrap_or_else(|| "h1".to_string());
        if !alpn_ok || !matches!(profile.as_str(), "auto" | "h3") {
            conn.close(quinn::VarInt::from_u32(0x1001), b"protocol not allowed");
            return;
        }

        let client_ip = crate::net::ip_string(conn.remote_address().ip());
        // enable_extended_connect：声明 SETTINGS_ENABLE_CONNECT_PROTOCOL（RFC 9220），
        // 浏览器只有看到该设置才会在 h3 上发 WebSocket。
        let mut h3 = match h3::server::builder()
            .enable_extended_connect(true)
            .max_field_section_size(64 * 1024)
            .build(h3_quinn::Connection::new(conn))
            .await
        {
            Ok(h) => h,
            Err(e) => {
                warn!("[webservice] h3 connection error: {}", e);
                return;
            }
        };

        loop {
            match h3.accept().await {
                Ok(Some(resolver)) => {
                    let mgr = Arc::clone(&self);
                    let cip = client_ip.clone();
                    let sid = svc_id.clone();
                    let sni = sni.clone();
                    tokio::spawn(async move {
                        mgr.handle_h3_request(resolver, cip, sid, sni).await;
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("[webservice] h3 accept error: {}", e);
                    break;
                }
            }
        }
    }

    /// 单个 h3 请求：请求体流式转发 → 复用 handle_request 代理链路 → 流式回写响应。
    async fn handle_h3_request(
        self: &Arc<Self>,
        resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
        client_ip: String,
        svc_id: String,
        sni: Option<String>,
    ) {
        use h3::error::Code;

        let (req, mut stream) = match resolver.resolve_request().await {
            Ok(v) => v,
            Err(e) => {
                warn!("[webservice] h3 resolve error: {}", e);
                return;
            }
        };
        // RFC 9220: WebSocket over HTTP/3 —— CONNECT + :protocol=websocket，
        // 数据走该双向 QUIC 流，不走普通请求/响应链路。
        if req.method() == Method::CONNECT {
            let is_ws = req
                .extensions()
                .get::<h3::ext::Protocol>()
                .map(|p| p.as_str())
                == Some("websocket");
            if is_ws {
                return self.handle_h3_ws(req, stream, client_ip, svc_id, sni).await;
            }
            // 其他 CONNECT（隧道代理）不支持。
            return deny_h3(&mut stream, StatusCode::METHOD_NOT_ALLOWED, "CONNECT not supported")
                .await;
        }

        let (mut send, mut recv) = stream.split();

        // 请求体：无 body 的请求（Content-Length: 0，或无 CL 的 GET/HEAD 等）直接用空体，
        // 避免 hyper client 对无界 body 的 GET 发 chunked；其余经有界通道流式转发。
        let content_length = req
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let bodyless = content_length == Some(0)
            || (content_length.is_none()
                && matches!(
                    *req.method(),
                    Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE | Method::TRACE
                ));
        let body: BoxBody = if bodyless {
            full_body(Bytes::new())
        } else {
            let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, BoxError>>(8);
            tokio::spawn(async move {
                loop {
                    match recv.recv_data().await {
                        Ok(Some(mut buf)) => {
                            let chunk = buf.copy_to_bytes(buf.remaining());
                            if tx.send(Ok(chunk)).await.is_err() {
                                // 代理侧已不再读取（后端出错 / 已应答）。
                                recv.stop_sending(Code::H3_NO_ERROR);
                                return;
                            }
                        }
                        Ok(None) => return, // 正常结束：drop tx 即 EOF
                        Err(e) => {
                            // 客户端 reset / 传输错误：必须让后端请求失败，
                            // 不能把截断的 body 当成完整请求。
                            let _ = tx
                                .send(Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    e.to_string(),
                                ))))
                                .await;
                            return;
                        }
                    }
                }
            });
            box_body(ChanBody { rx, len: content_length })
        };

        let request = req.map(|_| body);
        let resp = self
            .handle_request(request, client_ip, svc_id, true, sni, None)
            .await
            .unwrap_or_else(|e| match e {});

        let (mut parts, mut resp_body) = resp.into_parts();
        strip_connection_headers(&mut parts.headers);
        if send
            .send_response(hyper::Response::from_parts(parts, ()))
            .await
            .is_err()
        {
            return;
        }
        // 逐帧转发响应体。中途出错必须 reset 流：若正常 FIN，客户端会把截断响应当成完整的。
        loop {
            match resp_body.frame().await {
                None => break,
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if send.send_data(data).await.is_err() {
                            return;
                        }
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            let _ = send.send_trailers(trailers).await;
                            let _ = send.finish().await;
                            return;
                        }
                    }
                },
                Some(Err(e)) => {
                    warn!("[webservice] h3 upstream body error: {}", e);
                    send.stop_stream(Code::H3_INTERNAL_ERROR);
                    return;
                }
            }
        }
        let _ = send.finish().await;
    }

    /// WebSocket over HTTP/3（RFC 9220 extended CONNECT）。
    ///
    /// 与 h2 同构：CONNECT + :protocol=websocket 的双向 QUIC 流 ↔ 后端 h1 升级
    /// 连接。复用 route 匹配 / IP 过滤 / cookie auth / 后端握手逻辑。
    async fn handle_h3_ws(
        self: &Arc<Self>,
        req: Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        client_ip: String,
        svc_id: String,
        sni: Option<String>,
    ) {
        let host = req
            .uri()
            .host()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        metrics::inc(&metrics::PROXY_REQUESTS);

        // :authority 必须与连接的 SNI 一致，否则让客户端换连接（421），
        // 防止借 A 域名的连接绕过 B 域名的协议档。
        if sni_mismatch(sni.as_deref(), &host) {
            return deny_h3(&mut stream, StatusCode::MISDIRECTED_REQUEST, "Misdirected Request")
                .await;
        }

        let Some(route) = self.cfg.runtime().route(&svc_id, &host) else {
            self.log_access(&svc_id, "", "", &host, &client_ip, &parse_browser(&ua));
            return deny_h3(&mut stream, StatusCode::BAD_GATEWAY, "No matching route").await;
        };

        // IP filter
        let allowed = match client_ip.parse::<std::net::IpAddr>().ok().map(crate::net::canonical_ip) {
            Some(ip) => self.cfg.check_ip_allowed_addr("webservice", &route.id, ip),
            None => self.cfg.check_ip_allowed("webservice", &route.id, &client_ip),
        };
        if !allowed {
            return deny_h3(&mut stream, StatusCode::FORBIDDEN, "Forbidden").await;
        }

        // Auth（WS 无法渲染登录页，无有效 cookie 直接拒绝）
        if route.auth_enabled && !route.auth_pass_hash.is_empty() {
            let cookie_name = format!("vane_auth_{}", &route.id[..8.min(route.id.len())]);
            let session_token = auth_session_token(&route.id, &route.auth_pass_hash);
            let has_valid_cookie = merged_cookie(req.headers()).map(|cookies| {
                    cookies
                        .split(';')
                        .any(|c| c.trim() == format!("{}={}", cookie_name, session_token))
                })
                .unwrap_or(false);
            if !has_valid_cookie {
                self.log_access(&svc_id, &route.id, &route.name, &host, &client_ip, &parse_browser(&ua));
                return deny_h3(&mut stream, StatusCode::UNAUTHORIZED, "Unauthorized").await;
            }
        }

        self.log_access(&svc_id, &route.id, &route.name, &host, &client_ip, &parse_browser(&ua));

        let authority = req
            .uri()
            .host()
            .map(|h| {
                if let Some(p) = req.uri().port_u16() {
                    format!("{}:{}", h.trim_matches(|c| c == '[' || c == ']'), p)
                } else {
                    h.to_string()
                }
            })
            .unwrap_or_else(|| host.clone());
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string();

        let tunnel = match connect_backend_ws(
            &route.backend_url,
            &authority,
            &path_and_query,
            req.headers(),
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                error!("[webservice] h3 websocket backend error: {}", e);
                return deny_h3(&mut stream, StatusCode::BAD_GATEWAY, "Bad Gateway").await;
            }
        };

        match tunnel {
            BackendWsHandshake::Rejected(status, headers) => {
                let (parts, _) = Response::builder()
                    .status(status)
                    .body(())
                    .unwrap()
                    .into_parts();
                let mut parts = parts;
                for (n, v) in headers {
                    parts.headers.insert(n, v);
                }
                let _ = stream.send_response(hyper::Response::from_parts(parts, ())).await;
                let _ = stream.finish().await;
            }
            BackendWsHandshake::Upgraded(backend_stream, headers) => {
                // RFC 9220：h3 CONNECT 隧道以空 200 开场。
                let mut builder = hyper::Response::builder().status(StatusCode::OK);
                for (n, v) in &headers {
                    builder = builder.header(n, v);
                }
                let response = builder.body(()).unwrap();
                if stream.send_response(response).await.is_err() {
                    return;
                }

                // 双向转发：QUIC 流 ↔ 后端 TCP。split 后两个方向各占一个任务。
                let (mut send_half, mut recv_half) = stream.split();
                let (mut br, mut bw) = tokio::io::split(backend_stream);

                // 方向 1：客户端 → 后端
                tokio::spawn(async move {
                    while let Ok(Some(mut buf)) = recv_half.recv_data().await {
                        let bytes = buf.copy_to_bytes(buf.remaining());
                        if bw.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    // 客户端半关（发完）→ 通知后端写半结束
                    let _ = bw.shutdown().await;
                });

                // 方向 2：后端 → 客户端
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match br.read(&mut buf).await {
                            Ok(0) => break,
                            Err(_) => {
                                // 后端异常断开：reset 而不是正常 FIN，让客户端感知为异常关闭。
                                send_half.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                                return;
                            }
                            Ok(n) => {
                                if send_half
                                    .send_data(Bytes::copy_from_slice(&buf[..n]))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = send_half.finish().await;
                });
            }
        }
    }

    async fn handle_conn(self: &Arc<Self>, mut stream: TcpStream, peer: SocketAddr, svc_id: &str) {
        let client_ip = crate::net::ip_string(peer.ip());
        let svc = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().find(|s| s.id == svc_id).cloned()
        };
        let Some(svc) = svc else { return };

        if !svc.enable_https {
            // 明文服务：没有 ALPN 可协商，固定 HTTP/1.1。
            self.serve_http(
                hyper_util::rt::TokioIo::new(stream),
                &client_ip,
                svc_id,
                false,
                "h1",
                None,
                None,
            )
            .await;
            return;
        }

        // 读取首个 TLS 记录（通常即完整 ClientHello），解析 SNI 以决定该域名的协议档。
        let hello = match tokio::time::timeout(
            Duration::from_secs(10),
            read_client_hello(&mut stream),
        )
        .await
        {
            Ok(Ok(v)) => v,
            _ => return,
        };

        if !hello.is_tls {
            // 明文请求打到 HTTPS 端口 → 301 跳转（预读字节原样喂回）。
            let stream = PrefixedStream::new(hello.bytes, stream);
            self.serve_redirect(stream, svc.listen_port).await;
            return;
        }

        metrics::inc(&metrics::TLS_HANDSHAKES);
        // 按 SNI 查 route 的协议档；未启用/未匹配的域名回退 auto。
        let profile = match hello.sni.as_deref() {
            Some(host) => self
                .cfg
                .runtime()
                .route(svc_id, host)
                .map(|r| r.http_version.clone())
                .unwrap_or_else(|| "auto".to_string()),
            None => "auto".to_string(),
        };
        // h3 独占域名：真正的内容只走 UDP QUIC。TCP 侧不再直接断连，而是完成握手后
        // 回一个带 Alt-Svc 的引导页（426），浏览器没有 HTTPS 记录也能借此切到 h3。
        let h3_only = profile == "h3";
        // "h3-tcp" 不是协议档，仅用于取 ALPN = h2 + http/1.1 的 TCP 侧配置。
        let tls_profile = if h3_only { "h3-tcp" } else { profile.as_str() };

        let tls_config = match self.build_tls_config(svc_id, tls_profile) {
            Some(c) => c,
            None => {
                warn!("[webservice] no TLS config for {}", svc_id);
                return;
            }
        };
        let acceptor = TlsAcceptor::from(tls_config);
        let stream = PrefixedStream::new(hello.bytes, stream);
        let accepted = match tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream))
            .await
        {
            Ok(r) => r,
            Err(_) => return, // 握手超时（slowloris）
        };
        match accepted {
            Ok(tls_stream) => {
                let (_, conn) = tls_stream.get_ref();
                let alpn = conn.alpn_protocol().map(|p| p.to_vec());
                if h3_only {
                    self.serve_h3_bootstrap(
                        hyper_util::rt::TokioIo::new(tls_stream),
                        alpn.as_deref() == Some(b"h2"),
                        svc_id,
                    )
                    .await;
                    return;
                }
                // 强制档二次校验：rustls 不拒绝"未提供 ALPN"的客户端，
                // 因此 h2 档必须确认协商出的就是 h2，否则断开。
                if profile == "h2" && alpn.as_deref() != Some(b"h2") {
                    return;
                }
                self.serve_http(
                    hyper_util::rt::TokioIo::new(tls_stream),
                    &client_ip,
                    svc_id,
                    true,
                    &profile,
                    alpn.as_deref(),
                    hello.sni.clone(),
                )
                .await;
            }
            Err(e) => {
                warn!("[webservice] TLS accept error from {}: {}", client_ip, e);
            }
        }
    }

    fn build_tls_config(&self, svc_id: &str, profile: &str) -> Option<Arc<ServerConfig>> {
        let version = self.cfg.runtime().version();
        let key = (svc_id.to_string(), profile.to_string());
        if let Some((v, config)) = self.tls_configs.lock().unwrap().get(&key) {
            if *v == version {
                return Some(Arc::clone(config));
            }
        }
        let built = self.build_tls_config_uncached(svc_id, profile)?;
        metrics::inc(&metrics::TLS_CONFIG_REBUILDS);
        self.tls_configs
            .lock()
            .unwrap()
            .insert(key, (version, Arc::clone(&built)));
        Some(built)
    }

    /// 仅在配置版本变化时执行：解析 PEM、构造 CertifiedKey 与 ServerConfig。
    /// profile 决定 ALPN 白名单：h1/h2 为强制档，auto 同时声明 h2 + http/1.1。
    fn build_tls_config_uncached(&self, svc_id: &str, profile: &str) -> Option<Arc<ServerConfig>> {
        let cfg = self.cfg.read();
        let svc = cfg.web_services.iter().find(|s| s.id == svc_id)?;
        let mut cert_map: HashMap<String, Arc<rustls::sign::CertifiedKey>> = HashMap::new();

        for route in &svc.routes {
            if !route.enabled || route.matched_cert_id.is_empty() {
                continue;
            }
            if let Some(tls_cert) = cfg.tls_certs.iter().find(|c| c.id == route.matched_cert_id) {
                if tls_cert.cert_pem.is_empty() || tls_cert.key_pem.is_empty() {
                    continue;
                }
                if let Ok((certs, key)) = load_pem_pair(&tls_cert.cert_pem, &tls_cert.key_pem) {
                    // 私钥解析 / CertifiedKey 构造只在配置变更时做一次。
                    if let Some(ck) = make_certified_key(&certs, &key) {
                        cert_map.insert(route.domain.to_lowercase(), ck);
                    }
                }
            }
        }
        if cert_map.is_empty() {
            return None;
        }

        let resolver = Arc::new(SniResolver { certs: cert_map });
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        // ALPN 白名单：h1/h2 为强制档（客户端不匹配则协商失败或握手后被断开）；
        // rustls 对"客户端未提供 ALPN"不强制，因此 h1 档兼容无 ALPN 的老客户端。
        config.alpn_protocols = match profile {
            "h1" => vec![b"http/1.1".to_vec()],
            "h2" => vec![b"h2".to_vec()],
            "h3" => vec![b"h3".to_vec()],
            _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        Some(Arc::new(config))
    }

    async fn serve_redirect<S>(&self, mut stream: S, https_port: u16)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
        {
            Ok(Ok(n)) => n,
            _ => return,
        };
        let req_str = String::from_utf8_lossy(&buf[..n]);
        let resp = match redirect_location(&req_str, https_port) {
            // 308：永久跳转且保留请求方法（POST 不会被降级成 GET）。
            Some(loc) => format!(
                "HTTP/1.1 308 Permanent Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                loc
            ),
            None => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        };
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    /// h3 独占域名的 TCP 侧：对任何请求回 426 引导页，并通告 Alt-Svc。
    async fn serve_h3_bootstrap<S>(&self, io: hyper_util::rt::TokioIo<S>, is_h2: bool, svc_id: &str)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let port = if self.h3_active.lock().unwrap().contains(svc_id) {
            self.cfg
                .read()
                .web_services
                .iter()
                .find(|s| s.id == svc_id)
                .map(|s| s.listen_port)
        } else {
            None
        };
        let svc = hyper::service::service_fn(move |_req: Request<Incoming>| async move {
            Ok::<_, std::convert::Infallible>(h3_bootstrap_response(port))
        });
        let _ = if is_h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(hyper_util::rt::TokioTimer::new())
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(20))
                .max_concurrent_streams(64)
                .serve_connection(io, svc)
                .await
        } else {
            hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(io, svc)
                .await
        };
    }

    async fn serve_http<S>(
        self: &Arc<Self>,
        io: hyper_util::rt::TokioIo<S>,
        client_ip: &str,
        svc_id: &str,
        is_https: bool,
        profile: &str,
        alpn: Option<&[u8]>,
        sni: Option<String>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mgr = Arc::clone(self);
        let client_ip = client_ip.to_string();
        let svc_id = svc_id.to_string();

        let is_h2 = profile == "h2" || (profile != "h1" && alpn == Some(b"h2"));

        // QUIC endpoint 在运行时，向 h1/h2 响应通告 Alt-Svc，浏览器才会升级到 h3。
        let h3_port = if is_https && self.h3_active.lock().unwrap().contains(&svc_id) {
            self.cfg
                .read()
                .web_services
                .iter()
                .find(|s| s.id == svc_id)
                .map(|s| s.listen_port)
        } else {
            None
        };
        // h2 连接可被浏览器合并复用到其他域名：校验 :authority 与 SNI 一致（h1 有 Host，不查）。
        let sni = if is_h2 { sni } else { None };

        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let mgr = Arc::clone(&mgr);
            let cip = client_ip.clone();
            let sid = svc_id.clone();
            let sni = sni.clone();
            async move {
                mgr.handle_request(req.map(box_body), cip, sid, is_https, sni, h3_port)
                    .await
            }
        });

        // 协议选择：h1/h2 档强制；auto 档跟随 TLS ALPN 协商结果。
        // h2 连接开启 extended CONNECT（RFC 8441）：浏览器可直接在这条 h2 连接上
        // 建 WebSocket（:protocol=websocket），由 proxy_upgrade_h2 建立隧道。
        let _ = if is_h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(hyper_util::rt::TokioTimer::new())
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(20))
                .max_concurrent_streams(256)
                .max_header_list_size(64 * 1024)
                .enable_connect_protocol()
                .serve_connection(io, svc)
                .await
        } else {
            hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(60))
                .serve_connection(io, svc)
                .with_upgrades()
                .await
        };
    }

    async fn handle_request(
        self: &Arc<Self>,
        req: Request<BoxBody>,
        client_ip: String,
        svc_id: String,
        is_https: bool,
        conn_sni: Option<String>,
        h3_port: Option<u16>,
    ) -> Result<Response<BoxBody>, std::convert::Infallible> {
        // h2 用 :authority 伪头（hyper 放进 uri.authority），h1 用 Host 头；两者取其一。
        let host = req
            .uri()
            .host()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string())
            })
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or("")
            .to_lowercase();

        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        metrics::inc(&metrics::PROXY_REQUESTS);
        // h2/h3：:authority 与连接 SNI 不一致 → 421，让客户端用正确的连接重试。
        if sni_mismatch(conn_sni.as_deref(), &host) {
            return Ok(error_resp(
                StatusCode::MISDIRECTED_REQUEST,
                "Misdirected Request".into(),
            ));
        }
        // O(1) 索引查找：配置写操作会自动重建该索引，无需每请求遍历。
        let matched = self.cfg.runtime().route(&svc_id, &host);

        let route = match matched {
            Some(r) => r,
            None => {
                self.log_access(&svc_id, "", "", &host, &client_ip, &parse_browser(&ua));
                return Ok(error_resp(
                    StatusCode::BAD_GATEWAY,
                    format!("No matching route for host: {}", host),
                ));
            }
        };

        // IP filter（无锁快照；传已解析的 IpAddr 省一次字符串解析）
        let client_addr = client_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(crate::net::canonical_ip);
        let allowed = match client_addr {
            Some(ip) => self
                .cfg
                .check_ip_allowed_addr("webservice", &route.id, ip),
            None => self
                .cfg
                .check_ip_allowed("webservice", &route.id, &client_ip),
        };
        if !allowed {
            return Ok(error_resp(StatusCode::FORBIDDEN, "Forbidden".into()));
        }

        // Auth
        if route.auth_enabled && !route.auth_pass_hash.is_empty() {
            let cookie_name = format!("vane_auth_{}", &route.id[..8.min(route.id.len())]);
            let session_token = auth_session_token(&route.id, &route.auth_pass_hash);

            let has_valid_cookie = merged_cookie(req.headers()).map(|cookies| {
                    cookies
                        .split(';')
                        .any(|c| c.trim() == format!("{}={}", cookie_name, session_token))
                })
                .unwrap_or(false);

            if !has_valid_cookie {
                // Handle POST login
                if req.method() == hyper::Method::POST && req.uri().path() == "/__vane_login__" {
                    return self
                        .handle_login(req, &route, &cookie_name, &session_token, is_https)
                        .await;
                }
                let next = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
                    .to_string();
                let body = build_login_page(&next, "", &route.domain);
                self.log_access(
                    &svc_id,
                    &route.id,
                    &route.name,
                    &host,
                    &client_ip,
                    &parse_browser(&ua),
                );
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(full_body(body))
                    .unwrap());
            }
        }

        self.log_access(
            &svc_id,
            &route.id,
            &route.name,
            &host,
            &client_ip,
            &parse_browser(&ua),
        );
        // WebSocket over HTTP/2（RFC 8441 extended CONNECT）：
        // h2 请求没有 Upgrade/Connection 头，改用 CONNECT + :protocol=websocket 表达，
        // hyper 通过请求扩展 hyper::ext::Protocol 暴露给 service。
        if req.method() == Method::CONNECT
            && req
                .extensions()
                .get::<hyper::ext::Protocol>()
                .map(|p| p.as_str())
                == Some("websocket")
        {
            return match proxy_upgrade_h2(req, &route.backend_url).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!("[webservice] h2 websocket proxy error: {}", e);
                    Ok(error_resp(StatusCode::BAD_GATEWAY, "Bad Gateway".into()))
                }
            };
        }

        if is_upgrade_request(&req) {
            return match proxy_upgrade(req, &route.backend_url).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!("[webservice] websocket proxy error: {}", e);
                    Ok(error_resp(StatusCode::BAD_GATEWAY, "Bad Gateway".into()))
                }
            };
        }

        match proxy_request(req, &route.backend_url, &client_ip, is_https).await {
            Ok(mut resp) => {
                if is_https && !resp.headers().contains_key("alt-svc") {
                    let wants_h3 = matches!(route.http_version.as_str(), "auto" | "h3");
                    if let (true, Some(port)) = (wants_h3, h3_port) {
                        if let Ok(v) = format!("h3=\":{}\"; ma=86400", port).parse() {
                            resp.headers_mut().insert("alt-svc", v);
                        }
                    } else {
                        // h1/h2 强制档，或 QUIC 未启动（UDP 端口被占用）：清除浏览器此前缓存的
                        // h3 通告，否则浏览器最长 24h 仍会走 UDP，打到别的进程或被关闭，表现为随机失败。
                        resp.headers_mut()
                            .insert("alt-svc", hyper::header::HeaderValue::from_static("clear"));
                    }
                }
                Ok(resp)
            }
            Err(e) => {
                error!("[webservice] proxy error: {}", e);
                Ok(error_resp(StatusCode::BAD_GATEWAY, "Bad Gateway".into()))
            }
        }
    }

    async fn handle_login(
        &self,
        req: Request<BoxBody>,
        route: &WebRoute,
        cookie_name: &str,
        session_token: &str,
        is_https: bool,
    ) -> Result<Response<BoxBody>, std::convert::Infallible> {
        let body_bytes = match req.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Ok(error_resp(StatusCode::BAD_REQUEST, "Bad Request".into())),
        };

        let form: HashMap<String, String> = url::form_urlencoded::parse(&body_bytes)
            .into_owned()
            .collect();
        let username = form.get("username").map(|s| s.as_str()).unwrap_or("");
        let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
        let next = form
            .get("next")
            .map(|s| s.as_str())
            .unwrap_or("/")
            .to_string();

        let auth_user = route.auth_user.clone();
        let pass_hash = route.auth_pass_hash.clone();
        let pw = password.to_string();
        let verified = tokio::task::spawn_blocking(move || {
            bcrypt::verify(&pw, &pass_hash).unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if username == auth_user && verified {
            let cookie = format!(
                "{}={}; Path=/; Max-Age=86400; HttpOnly{}; SameSite=Lax",
                cookie_name,
                session_token,
                if is_https { "; Secure" } else { "" }
            );
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", next)
                .header("set-cookie", cookie)
                .body(full_body(""))
                .unwrap());
        }

        let body = build_login_page(&next, "用户名或密码错误", &route.domain);
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html; charset=utf-8")
            .body(full_body(body))
            .unwrap())
    }

    fn log_access(
        &self,
        svc_id: &str,
        route_id: &str,
        route_name: &str,
        domain: &str,
        client_ip: &str,
        ua: &str,
    ) {
        let log = AccessLog {
            service_id: svc_id.to_string(),
            route_id: route_id.to_string(),
            route_name: route_name.to_string(),
            domain: domain.to_string(),
            client_ip: client_ip.to_string(),
            user_agent: ua.to_string(),
            time: crate::config::types::now_rfc3339(),
        };
        // 有界通道：请求热路径完全不持有日志锁；队列满时丢弃并计数。
        if self.log_tx.try_send(log).is_err() {
            metrics::inc(&metrics::LOG_DROPPED);
        }
    }

    /// 纯计算：为一条 route 选出最佳证书，不触碰任何锁或缓存。
    fn pick_cert(certs: &[TlsCert], domain: &str) -> (String, String) {
        let mut best_id = String::new();
        let mut best_status = "no_cert".to_string();

        for cert in certs {
            if cert.cert_pem.is_empty() || cert.key_pem.is_empty() {
                continue;
            }
            let cert_domains: Vec<&str> = cert
                .domains
                .iter()
                .map(|s| s.as_str())
                .chain(if cert.domain.is_empty() {
                    None
                } else {
                    Some(cert.domain.as_str())
                })
                .collect();
            if !cert_domains
                .iter()
                .any(|cd| cert_domain_matches(cd, domain))
            {
                continue;
            }
            if cert.status == "active" {
                best_id = cert.id.clone();
                best_status = "ok".to_string();
                break;
            } else if best_id.is_empty() {
                best_id = cert.id.clone();
                best_status = "cert_inactive".to_string();
            }
        }
        (best_id, best_status)
    }

    pub fn match_route_cert(&self, svc_id: &str, route: &mut WebRoute) {
        let certs: Vec<TlsCert> = self.cfg.read().tls_certs.clone();
        let (best_id, best_status) = Self::pick_cert(&certs, &route.domain);
        route.matched_cert_id = best_id.clone();
        route.cert_status = best_status.clone();

        // 部分调用方（如 toggle）只持有一条 clone 出来的 route，依赖这里把
        // 重算结果同步回内存配置，因此保留这一次写回。
        let mut cfg = self.cfg.write();
        for svc in cfg.web_services.iter_mut() {
            if svc.id != svc_id {
                continue;
            }
            for r in svc.routes.iter_mut() {
                if r.id == route.id {
                    r.matched_cert_id = best_id.clone();
                    r.cert_status = best_status.clone();
                    break;
                }
            }
            break;
        }
    }

    pub fn rematch_all_routes(&self) {
        // 一次读 + 一次写：原先逐条调用 match_route_cert，每条 route 都会
        // 触发一次 ConfigWriteGuard 快照重建（N 条 → N×O(N)）。这里改成
        // 批量计算后单次写回，只重建一次派生快照。
        let updates: HashMap<(String, String), (String, String)> = {
            let cfg = self.cfg.read();
            let certs = &cfg.tls_certs;
            cfg.web_services
                .iter()
                .flat_map(|svc| {
                    svc.routes.iter().map(move |r| {
                        (
                            (svc.id.clone(), r.id.clone()),
                            Self::pick_cert(certs, &r.domain),
                        )
                    })
                })
                .collect()
        };
        let mut cfg = self.cfg.write();
        for svc in cfg.web_services.iter_mut() {
            for r in svc.routes.iter_mut() {
                let key = (svc.id.clone(), r.id.clone());
                if let Some((id, status)) = updates.get(&key) {
                    r.matched_cert_id = id.clone();
                    r.cert_status = status.clone();
                }
            }
        }
    }
}

/// QUIC 专用证书解析器：每次握手向 Manager 取当前（带版本缓存的）TLS 配置并委托其解析器，
/// 使 h3 与 TCP 路径一样能立即用上续期/新增的证书。
struct DynH3Resolver {
    mgr: std::sync::Weak<Manager>,
    svc_id: String,
}

impl std::fmt::Debug for DynH3Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynH3Resolver({})", self.svc_id)
    }
}

impl rustls::server::ResolvesServerCert for DynH3Resolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mgr = self.mgr.upgrade()?;
        let cfg = mgr.build_tls_config(&self.svc_id, "h3")?;
        cfg.cert_resolver.resolve(hello)
    }
}

// ─── SNI cert resolver ────────────────────────────────────────────────────────

struct SniResolver {
    certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SniResolver({:?})",
            self.certs.keys().collect::<Vec<_>>()
        )
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?.to_lowercase();
        if let Some(ck) = self.certs.get(&name) {
            return Some(Arc::clone(ck));
        }
        if let Some(rest) = name.split_once('.').map(|x| x.1) {
            let wildcard = format!("*.{}", rest);
            if let Some(ck) = self.certs.get(&wildcard) {
                return Some(Arc::clone(ck));
            }
        }
        // 兜底：返回第一张证书
        self.certs.values().next().cloned()
    }
}

/// 只在构建/重建 TLS 配置时调用一次，缓存 Arc<CertifiedKey>；
/// 原实现在每次握手的 resolve 里都重新解析私钥并 clone 整条证书链。
fn make_certified_key(
    certs: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(key).ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(
        certs.to_vec(),
        signing_key,
    )))
}

fn load_pem_pair(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    let certs: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_pem.as_bytes())).collect::<std::result::Result<_, _>>()?;
    let key = private_key(&mut BufReader::new(key_pem.as_bytes()))?
        .ok_or_else(|| anyhow!("no private key"))?;
    Ok((certs, key))
}

// ─── Reverse proxy ────────────────────────────────────────────────────────────

/// Returns true if the request is an HTTP Upgrade request (e.g. WebSocket
/// handshake): `Connection: Upgrade` + `Upgrade: <protocol>`.
fn is_upgrade_request(req: &Request<BoxBody>) -> bool {
    let has_upgrade_header = req.headers().get("upgrade").is_some();
    let connection_has_upgrade = req
        .headers()
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);
    has_upgrade_header && connection_has_upgrade
}

/// Proxies an HTTP Upgrade request (WebSocket, etc.) end-to-end.
///
/// The regular `proxy_request` path uses the hyper_util legacy `Client`,
/// which only understands the normal request/response model and cannot
/// hand off a raw, bidirectional byte stream once the backend answers with
/// `101 Switching Protocols`. WebSocket connections rely on exactly that
/// hand-off, so they need a separate code path:
///
/// 1. Open a raw TCP connection to the backend ourselves.
/// 2. Replay the client's handshake request to the backend over that raw
///    connection (headers untouched, including `Upgrade`/`Connection`).
/// 3. If the backend answers `101 Switching Protocols`, take over the
///    client connection via `hyper::upgrade::on(&mut req)` as well, and
///    splice the two raw streams together bidirectionally.
async fn proxy_upgrade(
    mut req: Request<BoxBody>,
    backend_url: &str,
) -> Result<Response<BoxBody>> {
    // IMPORTANT: hyper requires the upgrade intent to be registered via
    // `hyper::upgrade::on()` *before* the response is handed back to the
    // connection driver — not afterwards, and not from inside a detached
    // task created near the end of the handler. Registering it late (or
    // via the "low level" call path hyper detects when this ordering is
    // violated) fails with "upgrade expected but low level API in use".
    // So we grab the upgrade future FIRST, before doing anything else
    // (including talking to the backend), and only `.await` it later.
    let on_upgrade = hyper::upgrade::on(&mut req);

    let backend = backend_url
        .parse::<hyper::Uri>()
        .map_err(|e| anyhow!("{}", e))?;
    let host = backend
        .host()
        .ok_or_else(|| anyhow!("backend url has no host"))?
        .to_string();
    let port = backend
        .port_u16()
        .unwrap_or(if backend.scheme_str() == Some("https") {
            443
        } else {
            80
        });

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let backend_path = backend.path().trim_end_matches('/');
    let full_path = format!("{}{}", backend_path, path_and_query);

    // Only plain-HTTP backends are supported for the raw-socket hand-off
    // (this mirrors proxy_request, which also always connects to the
    // backend over HTTP).
    // hyper keeps the brackets of IPv6 literals in host(); strip them for connect().
    let connect_host = host.trim_start_matches('[').trim_end_matches(']');
    let mut backend_stream = TcpStream::connect((connect_host, port))
        .await
        .map_err(|e| anyhow!("connecting to backend {}:{}: {}", host, port, e))?;

    // Build the raw HTTP/1.1 handshake request to replay to the backend,
    // preserving all original headers (Upgrade, Connection, Sec-WebSocket-*,
    // cookies, auth, etc.) untouched.
    let method = req.method().clone();
    let version_str = "HTTP/1.1";
    let mut raw_req = format!("{} {} {}\r\n", method, full_path, version_str);
    let mut has_host = false;
    for (name, value) in req.headers().iter() {
        if name.as_str().eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if let Ok(v) = value.to_str() {
            raw_req.push_str(name.as_str());
            raw_req.push_str(": ");
            raw_req.push_str(v);
            raw_req.push_str("\r\n");
        }
    }
    if !has_host {
        raw_req.push_str(&format!("Host: {}\r\n", host));
    }
    raw_req.push_str("\r\n");

    backend_stream
        .write_all(raw_req.as_bytes())
        .await
        .map_err(|e| anyhow!("writing handshake to backend: {}", e))?;

    // Read the backend's handshake response headers (until the blank line).
    let backend_head = read_http_head(&mut backend_stream).await?;
    let backend_status = parse_status_line(&backend_head)?;

    if backend_status != 101 {
        // Backend declined the upgrade; relay its response as-is so the
        // client sees the real status/body instead of a generic 502.
        // We never `.await` on_upgrade in this branch, so hyper simply
        // treats the connection as a normal, non-upgraded response.
        // （原实现把响应头原文当 body 返回，且丢了所有头。）
        let mut resp = Response::builder()
            .status(backend_status)
            .body(full_body(Bytes::new()))
            .unwrap();
        for line in backend_head.split("\r\n").skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                let n = name.trim().to_ascii_lowercase();
                if matches!(
                    n.as_str(),
                    "connection" | "transfer-encoding" | "keep-alive" | "content-length"
                ) {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    hyper::header::HeaderName::try_from(n.as_str()),
                    hyper::header::HeaderValue::from_str(value.trim()),
                ) {
                    resp.headers_mut().append(name, value);
                }
            }
        }
        return Ok(resp);
    }

    // Backend agreed to upgrade. Build the 101 response to send back to
    // the client, then spawn the relay task that waits on the
    // already-registered `on_upgrade` future.
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(full_body(Bytes::new()))
        .unwrap();
    for line in backend_head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(name), Ok(value)) = (
                hyper::header::HeaderName::try_from(name.trim()),
                hyper::header::HeaderValue::from_str(value.trim()),
            ) {
                response.headers_mut().insert(name, value);
            }
        }
    }

    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                if let Err(e) =
                    tokio::io::copy_bidirectional(&mut client_io, &mut backend_stream).await
                {
                    warn!("[webservice] websocket relay ended: {}", e);
                }
            }
            Err(e) => {
                error!("[webservice] client upgrade failed: {}", e);
            }
        }
    });

    Ok(response)
}

type H3RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// h3 隧道拒绝：回错误响应并结束流。
async fn deny_h3(stream: &mut H3RequestStream, status: StatusCode, msg: &str) {
    let resp = error_resp(status, msg.to_string());
    let _ = stream
        .send_response(hyper::Response::from_parts(resp.into_parts().0, ()))
        .await;
    let _ = stream.finish().await;
}

/// 与后端建立 h1 WebSocket 升级连接（h2 RFC 8441 与 h3 RFC 9220 隧道共用）。
///
/// 把客户端的 WS 握手要素（:authority、路径、普通头）翻译成 h1 升级请求发给后端。
/// 后端答 101 → `Upgraded`（TCP 流 + 应回给客户端的响应头）；否则 `Rejected`
/// （状态码 + 头，交由各入口按自身协议语义透传）。
async fn connect_backend_ws(
    backend_url: &str,
    authority: &str,
    path_and_query: &str,
    headers: &hyper::HeaderMap,
) -> Result<BackendWsHandshake> {
    let backend = backend_url
        .parse::<hyper::Uri>()
        .map_err(|e| anyhow!("{}", e))?;
    let host = backend
        .host()
        .ok_or_else(|| anyhow!("backend url has no host"))?
        .to_string();
    let port = backend
        .port_u16()
        .unwrap_or(if backend.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let backend_path = backend.path().trim_end_matches('/');
    let full_path = format!("{}{}", backend_path, path_and_query);

    // 构造 h1 升级请求：h2/h3 中 Connection 类头非法（hyper/h3 已剥离），全部手工重建。
    let mut raw_req = format!("GET {} HTTP/1.1\r\n", full_path);
    raw_req.push_str(&format!("Host: {}\r\n", authority));
    raw_req.push_str("Upgrade: websocket\r\n");
    raw_req.push_str("Connection: Upgrade\r\n");
    // RFC 8441 §5 / RFC 9220 §3：h2/h3 上的 WebSocket 不携带 Sec-WebSocket-Key/Accept，
    // 但 h1 后端按 RFC 6455 必须收到 key，否则 400。客户端没给就由代理生成。
    let client_key = headers.contains_key("sec-websocket-key");
    if !client_key {
        use base64::Engine;
        let k: [u8; 16] = rand::random();
        raw_req.push_str(&format!(
            "Sec-WebSocket-Key: {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(k)
        ));
    }
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if matches!(
            n,
            "connection" | "upgrade" | "transfer-encoding" | "keep-alive" | "te"
                | "proxy-connection" | "host" | "content-length"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            raw_req.push_str(&format!("{}: {}\r\n", n, v));
        }
    }
    raw_req.push_str("\r\n");

    // hyper 保留 IPv6 字面量的方括号，connect() 前去掉。
    let connect_host = host.trim_start_matches('[').trim_end_matches(']');
    let mut backend_stream = TcpStream::connect((connect_host, port))
        .await
        .map_err(|e| anyhow!("connecting to backend {}:{}: {}", host, port, e))?;
    backend_stream
        .write_all(raw_req.as_bytes())
        .await
        .map_err(|e| anyhow!("writing handshake to backend: {}", e))?;

    let backend_head = read_http_head(&mut backend_stream).await?;
    let backend_status = parse_status_line(&backend_head)?;

    // 提取响应头（跳过 h2/h3 不允许的 Connection 类头）。
    // 非 101 时 body 不转发，Content-Length 也要去掉，否则 h2/h3 客户端判定响应长度不符。
    let mut resp_headers = Vec::new();
    for line in backend_head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let n = name.trim();
            let ln = n.to_ascii_lowercase();
            if matches!(
                ln.as_str(),
                "connection" | "upgrade" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            if backend_status != 101 && ln == "content-length" {
                continue;
            }
            // 客户端自己没发 key 时，Accept 对 h2/h3 客户端无意义，不回传。
            if !client_key && ln == "sec-websocket-accept" {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                hyper::header::HeaderName::try_from(n),
                hyper::header::HeaderValue::from_str(value.trim()),
            ) {
                resp_headers.push((name, value));
            }
        }
    }

    if backend_status != 101 {
        return Ok(BackendWsHandshake::Rejected(backend_status, resp_headers));
    }
    Ok(BackendWsHandshake::Upgraded(backend_stream, resp_headers))
}

enum BackendWsHandshake {
    /// 后端接受升级：TCP 流 + 需回给客户端的响应头（Sec-WebSocket-* 等）。
    Upgraded(
        TcpStream,
        Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    ),
    /// 后端拒绝升级：状态码 + 头，透传给客户端。
    Rejected(
        hyper::StatusCode,
        Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    ),
}

/// Proxies a WebSocket-over-HTTP/2 request (RFC 8441 extended CONNECT).
///
/// h2 客户端用 `CONNECT + :protocol=websocket` 建立双向流，语义上等价于
/// h1 的 `GET + Upgrade: websocket`。桥接：后端 101 后，对客户端回一个空
/// 200（h2 的 CONNECT 隧道以 2xx 响应开场，hyper 随即完成 upgrade 握手），
/// 然后在 h2 流与后端 TCP 流之间做双向字节转发。
async fn proxy_upgrade_h2(
    mut req: Request<BoxBody>,
    backend_url: &str,
) -> Result<Response<BoxBody>> {
    let on_upgrade = hyper::upgrade::on(&mut req);

    // h2 请求中 :authority 由 hyper 放进 uri.authority；路径取 :path。
    let authority = req
        .uri()
        .host()
        .map(|h| {
            if let Some(p) = req.uri().port_u16() {
                format!("{}:{}", h.trim_matches(|c| c == '[' || c == ']'), p)
            } else {
                h.to_string()
            }
        })
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    match connect_backend_ws(backend_url, &authority, &path_and_query, req.headers()).await? {
        BackendWsHandshake::Rejected(status, headers) => {
            let mut builder = hyper::Response::builder().status(status);
            for (n, v) in headers {
                builder = builder.header(n, v);
            }
            builder
                .body(full_body(Bytes::new()))
                .map_err(|e| anyhow!("{}", e))
        }
        BackendWsHandshake::Upgraded(mut backend_stream, headers) => {
            // RFC 8441：h2 CONNECT 隧道以空 200 开场（禁带 body/Content-Length）。
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .body(full_body(Bytes::new()))
                .unwrap();
            for (n, v) in headers {
                response.headers_mut().insert(n, v);
            }
            tokio::spawn(async move {
                match on_upgrade.await {
                    Ok(upgraded) => {
                        let mut client_io = TokioIo::new(upgraded);
                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut client_io, &mut backend_stream)
                                .await
                        {
                            warn!("[webservice] h2 websocket relay ended: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("[webservice] h2 client upgrade failed: {}", e);
                    }
                }
            });
            Ok(response)
        }
    }
}
async fn read_http_head(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| anyhow!("reading backend handshake: {}", e))?;
        if n == 0 {
            return Err(anyhow!("backend closed connection during handshake"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_terminator(&buf) {
            buf.truncate(pos);
            return String::from_utf8(buf).map_err(|e| anyhow!("invalid handshake utf8: {}", e));
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("backend handshake headers too large"));
        }
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(head: &str) -> Result<StatusCode> {
    let first_line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty backend response"))?;
    let code_str = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("malformed status line: {}", first_line))?;
    let code: u16 = code_str
        .parse()
        .map_err(|_| anyhow!("malformed status code: {}", code_str))?;
    StatusCode::from_u16(code).map_err(|e| anyhow!("invalid status code {}: {}", code, e))
}

async fn proxy_request(
    req: Request<BoxBody>,
    backend_url: &str,
    client_ip: &str,
    is_https: bool,
) -> Result<Response<BoxBody>> {
    let backend = backend_url
        .parse::<hyper::Uri>()
        .map_err(|e| anyhow!("{}", e))?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let backend_path = backend.path().trim_end_matches('/');
    let new_uri = format!(
        "{}://{}{}{}",
        backend.scheme_str().unwrap_or("http"),
        backend.authority().ok_or_else(|| anyhow!("no authority"))?,
        backend_path,
        path_and_query,
    )
    .parse::<hyper::Uri>()?;

    let (mut parts, body) = req.into_parts();
    // h2/h3 没有 Host 头，域名在 :authority（uri.authority）里；改写 URI 之前先保存，
    // 否则 hyper client 会把 Host 补成后端地址，导致后端虚拟主机/CSRF/OAuth 回调出错。
    let orig_host: Option<hyper::header::HeaderValue> = parts
        .headers
        .get(hyper::header::HOST)
        .cloned()
        .or_else(|| {
            parts
                .uri
                .authority()
                .and_then(|a| hyper::header::HeaderValue::from_str(a.as_str()).ok())
        });
    parts.uri = new_uri;
    if let Some(h) = orig_host {
        parts.headers.insert(hyper::header::HOST, h);
    }
    // 出向连接固定 HTTP/1.1（HttpConnector）：入口可能是 h2，版本标记必须降级，
    // 否则 hyper client 对 version=2 的请求直接报 UnsupportedVersion。
    parts.version = hyper::Version::HTTP_11;

    // Set proxy headers
    let prior = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let forwarded_for = match prior {
        Some(p) => format!("{}, {}", p, client_ip),
        None => client_ip.to_string(),
    };
    parts
        .headers
        .insert("x-forwarded-for", forwarded_for.parse().unwrap());
    parts
        .headers
        .insert("x-real-ip", client_ip.parse().unwrap());
    parts.headers.insert(
        "x-forwarded-proto",
        if is_https { "https" } else { "http" }.parse().unwrap(),
    );
    parts.headers.remove("te");
    parts.headers.remove("trailers");
    // h2/h3 的多条 Cookie 头合并成一条再发给 h1 后端（多数后端只认第一条）。
    if parts.headers.get_all(hyper::header::COOKIE).iter().count() > 1 {
        if let Some(m) = merged_cookie(&parts.headers) {
            if let Ok(v) = m.parse() {
                parts.headers.remove(hyper::header::COOKIE);
                parts.headers.insert(hyper::header::COOKIE, v);
            }
        }
    }

    let new_req = Request::from_parts(parts, body);

    // 复用全局连接池，避免每请求新建 Client 带来的 DNS + TCP 握手。
    let client = PROXY_CLIENT.clone();
    let resp = client
        .request(new_req)
        .await
        .map_err(|e| anyhow!("proxy: {}", e))?;
    Ok(resp.map(box_body))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// 握手探测结果：从流里预读出的字节 + 是否 TLS + SNI。
struct ClientHelloProbe {
    /// 已从流中读出的全部字节，必须通过 PrefixedStream 原样喂回。
    bytes: Vec<u8>,
    is_tls: bool,
    sni: Option<String>,
}

/// 读取首个 TLS 记录并解析 SNI。明文首字节直接短路返回（交给 redirect）。
/// ClientHello 极少跨 record 分片；跨片时按已收字节尽力解析，失败回退 auto 档。
async fn read_client_hello(stream: &mut TcpStream) -> std::io::Result<ClientHelloProbe> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut is_tls = false;
    loop {
        if buf.is_empty() {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            is_tls = buf[0] == 0x16;
            if !is_tls {
                break;
            }
        }
        if buf.len() < 5 {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            continue;
        }
        // TLS record: type(1) version(2) length(2)。记录体含完整握手即可停。
        let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
        if buf.len() >= 5 + rec_len {
            break;
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        // 上限保护：TLS 记录上限 16KB + 余量。
        if buf.len() > 65536 {
            break;
        }
    }
    let sni = if is_tls { parse_client_hello_sni(&buf) } else { None };
    Ok(ClientHelloProbe { bytes: buf, is_tls, sni })
}

/// 从首个 TLS 记录中提取 ClientHello 的 SNI（server_name 扩展，type=0x0000）。
/// 只处理单 record 内完整的 ClientHello，解析失败一律返回 None（回退 auto 档）。
fn parse_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
    let end = (5 + rec_len).min(buf.len());
    let hs = &buf[5..end];
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let body_len =
        ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let b = &hs[4..(4 + body_len).min(hs.len())];
    // ClientHello: version(2) + random(32) + session_id(1+len)
    //            + cipher_suites(2+len) + compression(1+len) + extensions(2+len)
    let mut i = 34usize;
    if b.len() <= i {
        return None;
    }
    let sid = b[i] as usize;
    i += 1 + sid;
    if b.len() <= i + 1 {
        return None;
    }
    let cs = ((b[i] as usize) << 8) | b[i + 1] as usize;
    i += 2 + cs;
    if b.len() <= i {
        return None;
    }
    let comp = b[i] as usize;
    i += 1 + comp;
    if b.len() <= i + 1 {
        return None;
    }
    let ext_total = ((b[i] as usize) << 8) | b[i + 1] as usize;
    i += 2;
    let ext_end = (i + ext_total).min(b.len());
    while i + 4 <= ext_end {
        let etype = ((b[i] as usize) << 8) | b[i + 1] as usize;
        let elen = ((b[i + 2] as usize) << 8) | b[i + 3] as usize;
        let data_start = i + 4;
        if data_start + elen > ext_end {
            break;
        }
        if etype == 0x0000 && elen >= 5 {
            let e = &b[data_start..data_start + elen];
            // server_name_list: list_len(2) + entry(name_type(1)=0, name_len(2), name)
            if e[2] == 0x00 {
                let nlen = ((e[3] as usize) << 8) | e[4] as usize;
                if nlen > 0 && e.len() >= 5 + nlen {
                    if let Ok(name) = std::str::from_utf8(&e[5..5 + nlen]) {
                        return Some(name.to_lowercase());
                    }
                }
            }
        }
        i = data_start + elen;
    }
    None
}

/// 把探测阶段预读的字节重新接到流头部，确保 TLS 握手 / redirect 读到完整原始流。
struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let chunk = &this.prefix[this.pos..];
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            this.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 由明文请求构造 https 跳转地址：保留路径与查询串；Host 非法时返回 None。
fn redirect_location(req: &str, https_port: u16) -> Option<String> {
    let mut lines = req.split("\r\n");
    let first = lines.next().unwrap_or("");
    // 请求目标必须是 origin-form（以 / 开头）且只含可见 ASCII，否则退回 "/"。
    let path = first
        .split(' ')
        .nth(1)
        .filter(|p| p.starts_with('/') && p.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        .unwrap_or("/");
    let raw = lines
        .find(|l| l.len() > 5 && l[..5].eq_ignore_ascii_case("host:"))
        .map(|l| l[5..].trim())?;
    // 去掉端口；IPv6 字面量保留方括号。
    let host = if raw.starts_with('[') {
        raw.find(']').map(|i| &raw[..=i])?
    } else {
        raw.split(':').next().unwrap_or("")
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return None;
    }
    Some(if https_port == 443 {
        format!("https://{}{}", host, path)
    } else {
        format!("https://{}:{}{}", host, https_port, path)
    })
}

/// h3 独占域名在 TCP 侧的引导响应。
fn h3_bootstrap_response(port: Option<u16>) -> Response<BoxBody> {
    let (note, script) = match port {
        Some(_) => (
            "正在切换到 HTTP/3……若长时间无响应，请确认网络放行了对应的 UDP 端口，并使用支持 HTTP/3 的浏览器。",
            // 最多自动重试 3 次，避免 UDP 被封时无限刷新。
            "<script>try{var k='vane_h3_try',n=+sessionStorage.getItem(k)||0;if(n<3){sessionStorage.setItem(k,n+1);setTimeout(function(){location.reload()},800)}}catch(e){}</script>",
        ),
        None => ("此站点仅支持 HTTP/3，但服务端的 QUIC (UDP) 通道当前不可用。", ""),
    };
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>需要 HTTP/3</title>\
<body style=\"font-family:-apple-system,sans-serif;max-width:520px;margin:15vh auto;padding:0 16px;color:#334155\">\
<h1 style=\"font-size:20px\">此站点仅支持 HTTP/3</h1><p>{}</p>{}</body>",
        note, script
    );
    let mut b = Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store");
    if let Some(p) = port {
        b = b.header("alt-svc", format!("h3=\":{}\"; ma=86400", p));
    }
    b.body(full_body(body)).unwrap()
}

/// h2/h3 连接的 SNI 与请求 :authority 主机不一致 → 需要 421。SNI 缺失不检查。
fn sni_mismatch(sni: Option<&str>, host: &str) -> bool {
    match sni {
        Some(s) => !s.trim_end_matches('.').eq_ignore_ascii_case(host.trim_end_matches('.')),
        None => false,
    }
}

/// h2/h3 允许客户端把 Cookie 拆成多个头字段（RFC 9113 §8.2.3 / RFC 9114 §4.2.1），
/// 浏览器也确实这么做；必须按 "; " 合并后再解析/转发。
fn merged_cookie(headers: &hyper::HeaderMap) -> Option<String> {
    let mut it = headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok());
    let mut out = it.next()?.to_string();
    for v in it {
        out.push_str("; ");
        out.push_str(v);
    }
    Some(out)
}

/// 剥离 h2/h3 不允许的 connection-specific 头（RFC 9110 §7.6.1）。
/// h1 代理透传后端响应时这些头合法，但 h2/h3 头字段禁止出现，
/// 必须在出口剔除，否则严格实现的客户端（如 aioquic/浏览器）会判 malformed。
fn strip_connection_headers(headers: &mut hyper::HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
    ] {
        while headers.remove(name).is_some() {}
    }
}

fn error_resp(status: StatusCode, body: String) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(body))
        .unwrap()
}

fn cert_domain_matches(cert_domain: &str, req_domain: &str) -> bool {
    let cd = cert_domain.to_lowercase();
    let rd = req_domain.to_lowercase();
    if cd == rd {
        return true;
    }
    if let Some(suffix) = cd.strip_prefix("*.") {
        if rd.ends_with(&format!(".{}", suffix)) {
            let host = &rd[..rd.len() - suffix.len() - 1];
            return !host.contains('.');
        }
    }
    false
}

fn auth_session_token(route_id: &str, pass_hash: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(pass_hash.as_bytes()).unwrap();
    mac.update(route_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn parse_browser(ua: &str) -> String {
    let ua = ua.to_lowercase();
    if ua.contains("edg/") {
        return "Edge".into();
    }
    if ua.contains("chrome") && ua.contains("mobile") {
        return "Chrome/Android".into();
    }
    if ua.contains("chrome") {
        return "Chrome".into();
    }
    if ua.contains("firefox") {
        return "Firefox".into();
    }
    if ua.contains("safari") && ua.contains("mobile") {
        return "Safari/iOS".into();
    }
    if ua.contains("safari") {
        return "Safari".into();
    }
    if ua.contains("curl") {
        return "curl".into();
    }
    if ua.is_empty() {
        return "—".into();
    }
    "Other".into()
}

fn build_login_page(next: &str, err_msg: &str, domain: &str) -> String {
    let err_html = if err_msg.is_empty() {
        String::new()
    } else {
        format!("<div class=\"error\">{}</div>", err_msg)
    };
    format!(
        r#"<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;font-family:-apple-system,sans-serif}}
.card{{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 36px;width:100%;max-width:380px}}
h1{{font-size:20px;font-weight:700;color:#1e293b;margin-bottom:6px;text-align:center}}
p{{font-size:13px;color:#94a3b8;text-align:center;margin-bottom:28px}}
label{{display:block;font-size:13px;font-weight:600;color:#64748b;margin-bottom:6px}}
input{{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:15px;outline:none}}
input:focus{{border-color:#6366f1}}
.field{{margin-bottom:18px}}
button{{width:100%;padding:12px;border:none;border-radius:10px;background:#6366f1;color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}}
.error{{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:18px;text-align:center}}
</style></head><body>
<div class="card">
  <h1>{domain}</h1><p>请登录以继续访问</p>
  {err_html}
  <form method="POST" action="/__vane_login__">
    <input type="hidden" name="next" value="{next}">
    <div class="field"><label>用户名</label><input type="text" name="username" autofocus required></div>
    <div class="field"><label>密码</label><input type="password" name="password" required></div>
    <button type="submit">登录 →</button>
  </form>
</div></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小但结构完整的 TLS ClientHello（单 record，含 SNI 扩展）。
    fn client_hello_with_sni(domain: &str) -> Vec<u8> {
        let sni = domain.as_bytes();
        let mut entry = vec![0x00u8]; // name_type = host_name
        entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        entry.extend_from_slice(sni);

        let mut ext_data = (entry.len() as u16).to_be_bytes().to_vec();
        ext_data.extend_from_slice(&entry);

        let mut sni_ext = 0x0000u16.to_be_bytes().to_vec(); // server_name
        sni_ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&ext_data);

        let mut body = vec![0x03, 0x03]; // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len = 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // compression len
        body.push(0x00); // null
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);

        let mut hs = vec![0x01u8]; // handshake type = ClientHello
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3 字节长度
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01]; // record: handshake, TLS 1.0
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parse_sni_from_client_hello() {
        let ch = client_hello_with_sni("a.com");
        assert_eq!(parse_client_hello_sni(&ch).as_deref(), Some("a.com"));

        let ch = client_hello_with_sni("Example.ROOT");
        // 解析结果统一小写
        assert_eq!(parse_client_hello_sni(&ch).as_deref(), Some("example.root"));
    }

    #[test]
    fn cookie_headers_are_merged() {
        let mut h = hyper::HeaderMap::new();
        h.append("cookie", "a=1".parse().unwrap());
        h.append("cookie", "b=2".parse().unwrap());
        assert_eq!(merged_cookie(&h).as_deref(), Some("a=1; b=2"));
        assert_eq!(merged_cookie(&hyper::HeaderMap::new()), None);
    }

    #[test]
    fn redirect_keeps_path_and_query() {
        let r = "GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: Example.com:8080\r\nUser-Agent: t\r\n\r\n";
        assert_eq!(redirect_location(r, 443).as_deref(), Some("https://Example.com/a/b?x=1&y=2"));
        assert_eq!(redirect_location(r, 8443).as_deref(), Some("https://Example.com:8443/a/b?x=1&y=2"));
        let v6 = "GET / HTTP/1.1\r\nhost: [::1]:80\r\n\r\n";
        assert_eq!(redirect_location(v6, 443).as_deref(), Some("https://[::1]/"));
        // 无 Host / Host 含非法字符 → None；异常请求目标退回 "/"
        assert_eq!(redirect_location("GET / HTTP/1.1\r\n\r\n", 443), None);
        assert_eq!(redirect_location("GET / HTTP/1.1\r\nHost: a.com/evil\r\n\r\n", 443), None);
        assert_eq!(
            redirect_location("GET http://x/ HTTP/1.1\r\nHost: a.com\r\n\r\n", 443).as_deref(),
            Some("https://a.com/")
        );
    }

    #[test]
    fn sni_authority_check() {
        assert!(!sni_mismatch(None, "a.com"));
        assert!(!sni_mismatch(Some("a.com"), "A.com"));
        assert!(sni_mismatch(Some("a.com"), "b.com"));
    }

    #[test]
    fn parse_sni_absent_or_malformed() {
        assert_eq!(parse_client_hello_sni(&[]), None);
        // 非 handshake record
        assert_eq!(parse_client_hello_sni(&[0x17, 0x03, 0x03, 0, 1, 0]), None);
        // 明文 HTTP 首字节
        assert_eq!(parse_client_hello_sni(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"), None);
    }
}
