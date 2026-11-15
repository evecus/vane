use crate::config::{Config, DataDir, TlsCert, WebRoute, WebService};
use crate::metrics;
use anyhow::{anyhow, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
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

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn box_body<B>(b: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<hyper::Error>,
{
    b.map_err(|e| e.into()).boxed()
}

fn full_body(s: impl Into<Bytes>) -> BoxBody {
    Full::new(s.into()).map_err(|_| unreachable!()).boxed()
}

/// 全局反向代理客户端：连接池 + DNS 缓存。原实现每个请求都 `build_http()`，
/// 等于每个请求重新 DNS 解析 + TCP 三次握手，是吞吐量的头号瓶颈。
static PROXY_CLIENT: Lazy<Client<HttpConnector, Incoming>> = Lazy::new(|| {
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
    /// TLS ServerConfig 缓存：svc_id → (配置版本, config)。
    /// 配置版本由 Config 写 guard 自动递增，证书/路由变更会自动失效。
    tls_configs: Mutex<HashMap<String, (u64, Arc<ServerConfig>)>>,
    /// 访问日志写入通道（有界），请求路径不持锁。
    log_tx: mpsc::Sender<AccessLog>,
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

    async fn handle_conn(self: &Arc<Self>, stream: TcpStream, peer: SocketAddr, svc_id: &str) {
        let client_ip = crate::net::ip_string(peer.ip());
        let svc = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().find(|s| s.id == svc_id).cloned()
        };
        let Some(svc) = svc else { return };

        if svc.enable_https {
            let mut peek_buf = [0u8; 1];
            if stream.peek(&mut peek_buf).await.is_err() {
                return;
            }

            if peek_buf[0] == 0x16 {
                metrics::inc(&metrics::TLS_HANDSHAKES);
                let tls_config = self.build_tls_config(svc_id);
                match tls_config {
                    Some(config) => {
                        let acceptor = TlsAcceptor::from(config);
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                self.serve_http(
                                    hyper_util::rt::TokioIo::new(tls_stream),
                                    &client_ip,
                                    svc_id,
                                    true,
                                )
                                .await;
                            }
                            Err(e) => {
                                warn!("[webservice] TLS accept error from {}: {}", client_ip, e);
                            }
                        }
                    }
                    None => {
                        warn!("[webservice] no TLS config for {}", svc_id);
                    }
                }
            } else {
                self.serve_redirect(stream, svc.listen_port).await;
            }
        } else {
            self.serve_http(
                hyper_util::rt::TokioIo::new(stream),
                &client_ip,
                svc_id,
                false,
            )
            .await;
        }
    }

    fn build_tls_config(&self, svc_id: &str) -> Option<Arc<ServerConfig>> {
        let version = self.cfg.runtime().version();
        if let Some((v, config)) = self.tls_configs.lock().unwrap().get(svc_id) {
            if *v == version {
                return Some(Arc::clone(config));
            }
        }
        let built = self.build_tls_config_uncached(svc_id)?;
        metrics::inc(&metrics::TLS_CONFIG_REBUILDS);
        self.tls_configs
            .lock()
            .unwrap()
            .insert(svc_id.to_string(), (version, Arc::clone(&built)));
        Some(built)
    }

    /// 仅在配置版本变化时执行：解析 PEM、构造 CertifiedKey 与 ServerConfig。
    fn build_tls_config_uncached(&self, svc_id: &str) -> Option<Arc<ServerConfig>> {
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
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        Some(Arc::new(config))
    }

    async fn serve_redirect(&self, stream: TcpStream, https_port: u16) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
        {
            Ok(Ok(n)) => n,
            _ => return,
        };
        let req_str = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let host = req_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().to_string())
            .unwrap_or_default();
        let host = host.split(':').next().unwrap_or("").to_string();
        let target = if https_port == 443 {
            format!("https://{}/", host)
        } else {
            format!("https://{}:{}/", host, https_port)
        };
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            target
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    async fn serve_http<S>(
        self: &Arc<Self>,
        io: hyper_util::rt::TokioIo<S>,
        client_ip: &str,
        svc_id: &str,
        is_https: bool,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mgr = Arc::clone(self);
        let client_ip = client_ip.to_string();
        let svc_id = svc_id.to_string();

        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let mgr = Arc::clone(&mgr);
            let cip = client_ip.clone();
            let sid = svc_id.clone();
            async move { mgr.handle_request(req, cip, sid, is_https).await }
        });

        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await;
    }

    async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
        client_ip: String,
        svc_id: String,
        is_https: bool,
    ) -> Result<Response<BoxBody>, std::convert::Infallible> {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
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

            let has_valid_cookie = req
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(|cookies| {
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
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!("[webservice] proxy error: {}", e);
                Ok(error_resp(StatusCode::BAD_GATEWAY, "Bad Gateway".into()))
            }
        }
    }

    async fn handle_login(
        &self,
        req: Request<Incoming>,
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
fn is_upgrade_request(req: &Request<Incoming>) -> bool {
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
    mut req: Request<Incoming>,
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
        let resp = Response::builder()
            .status(backend_status)
            .body(full_body(backend_head))
            .unwrap();
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

/// Reads raw bytes from `stream` until the `\r\n\r\n` header terminator and
/// returns the head (status line + headers) as a UTF-8 string. Any bytes
/// read past the terminator (e.g. buffered body data) are intentionally
/// not supported here since WebSocket upgrade responses have no body.
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
    req: Request<Incoming>,
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
    parts.uri = new_uri;

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
