use crate::api::AppState;
use crate::config::{db, types::now_rfc3339};
use crate::metrics;
use crate::net::canonical_ip;
use ipnetwork::IpNetwork;
use std::sync::Arc;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, RwLock};

// ─── Admin login log ──────────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct AdminLoginRecord {
    pub ip: String,
    pub success: bool,
    pub time: String,
}

/// In-memory buffer: keeps the latest 200 entries between flushes.
const ADMIN_LOG_MEM_CAP: usize = 200;

static ADMIN_LOGS: Lazy<Mutex<Vec<AdminLoginRecord>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn log_admin(ip: &str, success: bool) {
    let mut logs = ADMIN_LOGS.lock().unwrap();
    logs.push(AdminLoginRecord {
        ip: ip.to_string(),
        success,
        time: now_rfc3339(),
    });
    // Trim in-memory buffer; persisted rows are kept separately in DB.
    if logs.len() > ADMIN_LOG_MEM_CAP {
        let len = logs.len();
        logs.drain(0..len - ADMIN_LOG_MEM_CAP);
    }
}

pub async fn get_admin_logs(State(state): State<AppState>) -> impl IntoResponse {
    // Merge DB (older, newest-first) + in-memory buffer (newer).
    let mem: Vec<AdminLoginRecord> = ADMIN_LOGS.lock().unwrap().clone();
    let mut all: Vec<AdminLoginRecord> = if let Some(dd) = state.cfg.read().data_dir.clone() {
        crate::config::db::load_admin_login_logs(&dd, 200).unwrap_or_default()
    } else {
        Vec::new()
    };
    // mem is oldest-first; reverse so newest-first, then extend DB results
    let mut mem_rev: Vec<_> = mem.into_iter().rev().collect();
    mem_rev.truncate(200);
    // Merge: mem_rev (newest) already covers what's not yet flushed
    all.extend(mem_rev);
    // Sort newest-first by time string (RFC3339 sorts lexicographically)
    all.sort_unstable_by(|a, b| b.time.cmp(&a.time));
    all.dedup_by(|a, b| a.time == b.time && a.ip == b.ip);
    all.truncate(200);
    Json(all)
}

/// Drain in-memory admin logs to DB, keep latest `keep` rows in DB.
pub fn flush_admin_logs_to_db(dd: &crate::config::DataDir, keep: usize) {
    let batch: Vec<AdminLoginRecord> = {
        let mut logs = ADMIN_LOGS.lock().unwrap();
        std::mem::take(&mut *logs)
    };
    if let Err(e) = crate::config::db::flush_admin_login_logs(dd, &batch, keep) {
        tracing::warn!("[auth] flush_admin_logs_to_db error: {}", e);
    }
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

struct LoginAttempt {
    count: u32,
    window_at: chrono::DateTime<Utc>,
}

const MAX_LOGIN_ATTEMPTS: u32 = 10;
const LOGIN_WINDOW_SECS: i64 = 600; // 10 minutes
const GC_INTERVAL_SECS: u64 = 1800; // 30 minutes

static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, LoginAttempt>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn check_rate_limit(ip: &str) -> bool {
    let mut map = LOGIN_ATTEMPTS.lock().unwrap();
    let now = Utc::now();
    if let Some(a) = map.get_mut(ip) {
        if (now - a.window_at).num_seconds() > LOGIN_WINDOW_SECS {
            // Window expired — reset and allow this attempt
            a.count = 1;
            a.window_at = now;
            return true;
        }
        // Increment BEFORE the check: attempt #10 is the last allowed.
        // The old code checked then incremented, so attempt #11 was the first
        // rejected — an off-by-one that gave attackers one extra free try.
        a.count += 1;
        a.count <= MAX_LOGIN_ATTEMPTS
    } else {
        map.insert(
            ip.to_string(),
            LoginAttempt {
                count: 1,
                window_at: now,
            },
        );
        true
    }
}

fn clear_rate_limit(ip: &str) {
    LOGIN_ATTEMPTS.lock().unwrap().remove(ip);
}

/// Periodically remove stale rate-limit entries to prevent unbounded memory
/// growth when hit by many source IPs (distributed brute-force scan).
/// Mirrors the Go version's init() cleanup goroutine.
pub async fn purge_rate_limit_loop() {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(GC_INTERVAL_SECS));
    loop {
        ticker.tick().await;
        let now = Utc::now();
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        map.retain(|_, a| (now - a.window_at).num_seconds() <= LOGIN_WINDOW_SECS * 2);
    }
}

// ─── Session cache (memory-first, DB-backed) ─────────────────────────────────

static SESSIONS: Lazy<RwLock<HashMap<String, i64>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static SESSION_DIRTY: Lazy<Mutex<HashMap<String, i64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 设为 `0` / `false` 可回退到「每请求直查 SQLite」的旧行为。
fn session_memory_enabled() -> bool {
    static ENABLED: Lazy<bool> = Lazy::new(|| {
        std::env::var("VANE_SESSION_MEMORY")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
    });
    *ENABLED
}

/// 内存优先；未命中时回退查一次 DB 并回填（进程重启后会话仍可恢复）。
async fn session_expiry(dd: &Arc<crate::config::DataDir>, token: &str) -> Option<i64> {
    if session_memory_enabled() {
        if let Some(exp) = SESSIONS.read().unwrap().get(token).copied() {
            metrics::inc(&metrics::SESSION_CACHE_HITS);
            return Some(exp);
        }
    }
    metrics::inc(&metrics::SESSION_DB_FALLBACKS);
    metrics::inc(&metrics::DB_OPS);
    let dd = Arc::clone(dd);
    let t = token.to_string();
    let res = tokio::task::spawn_blocking(move || db::session_get(&dd, &t))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten();
    if let Some(exp) = res {
        if session_memory_enabled() {
            SESSIONS.write().unwrap().insert(token.to_string(), exp);
        }
    }
    res
}

fn session_put(token: &str, exp: i64) {
    if session_memory_enabled() {
        SESSIONS.write().unwrap().insert(token.to_string(), exp);
        SESSION_DIRTY.lock().unwrap().insert(token.to_string(), exp);
    }
}

fn session_remove(token: &str) {
    if session_memory_enabled() {
        SESSIONS.write().unwrap().remove(token);
        SESSION_DIRTY.lock().unwrap().remove(token);
    }
}

/// 后台把内存中的滑动续期批量写回 SQLite（默认每 60s）。
pub async fn session_flush_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        ticker.tick().await;
        if !session_memory_enabled() {
            continue;
        }
        let dirty: Vec<(String, i64)> = {
            let mut m = SESSION_DIRTY.lock().unwrap();
            m.drain().collect()
        };
        if dirty.is_empty() {
            continue;
        }
        let dd_opt = state.cfg.read().data_dir.clone();
        let Some(dd) = dd_opt else { continue };
        let _ = tokio::task::spawn_blocking(move || {
            for (t, e) in dirty {
                let _ = db::session_set(&dd, &t, e);
            }
        })
        .await;
    }
}

// ─── Login / Logout ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<LoginReq>,
) -> impl IntoResponse {
    let socket_ip = connect_info.map(|c| crate::net::ip_string(c.0.ip()));
    let ip = extract_client_ip(&headers, socket_ip.as_deref());

    // Apply admin IP filter to the login endpoint too.
    // auth_middleware only covers protected routes; without this check the
    // login endpoint is reachable from any IP even when a whitelist is configured.
    if !state.cfg.check_ip_allowed("admin", "", &ip) {
        log_admin(&ip, false);
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Forbidden"})),
        )
            .into_response();
    }

    if !check_rate_limit(&ip) {
        log_admin(&ip, false);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "登录尝试次数过多，请稍后再试"})),
        )
            .into_response();
    }

    // bcrypt 是 CPU 密集型（默认 cost 10，约数十 ms），必须放到 blocking 线程池，
    // 否则并发登录会直接卡住同一 runtime 上的转发/代理任务。
    let (username, admin) = {
        let cfg = state.cfg.read();
        (cfg.admin.username.clone(), cfg.admin.clone())
    };
    let pw = req.password.clone();
    let ok = username == req.username
        && tokio::task::spawn_blocking(move || admin.check_password(&pw))
            .await
            .unwrap_or(false);

    if !ok {
        log_admin(&ip, false);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "用户名或密码错误"})),
        )
            .into_response();
    }

    clear_rate_limit(&ip);
    log_admin(&ip, true);

    let token = generate_token();
    let expires_at = (Utc::now() + chrono::Duration::hours(24)).timestamp();

    let dd_opt = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd_opt {
        let t = token.clone();
        let _ = tokio::task::spawn_blocking(move || db::session_set(&dd, &t, expires_at)).await;
    }
    session_put(&token, expires_at);

    Json(serde_json::json!({"token": token})).into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !token.is_empty() {
        session_remove(&token);
        let dd_opt = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd_opt {
            let t = token.clone();
            let _ = tokio::task::spawn_blocking(move || db::session_delete(&dd, &t)).await;
        }
    }
    Json(serde_json::json!({"ok": true}))
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    // IP filter on admin scope — prefer X-Real-IP/X-Forwarded-For (set by a
    // trusted reverse proxy), then fall back to the real socket address so that
    // direct connections are never mis-identified as 127.0.0.1.
    let socket_ip = connect_info.map(|c| crate::net::ip_string(c.0.ip()));
    let client_ip = extract_client_ip(&headers, socket_ip.as_deref());
    if !state.cfg.check_ip_allowed("admin", "", &client_ip) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if token.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    let dd = state.cfg.read().data_dir.clone();
    let Some(dd) = dd else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no data dir").into_response();
    };

    let exp = match session_expiry(&dd, &token).await {
        Some(e) => e,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };

    let now = Utc::now().timestamp();
    if now > exp {
        session_remove(&token);
        let dd2 = Arc::clone(&dd);
        let t = token.clone();
        let _ = tokio::task::spawn_blocking(move || db::session_delete(&dd2, &t)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    // 滑动续期只更新内存并打 dirty 标记，由后台任务批量落库；
    // 且只在差距超过 60s 时刷新，避免每次请求产生写放大。
    let new_exp = now + 24 * 3600;
    if new_exp.saturating_sub(exp) > 60 {
        session_put(&token, new_exp);
    }

    next.run(req).await
}

// ─── Safe-entry middleware (used in main for static file serving) ──────────────

pub fn check_safe_entry(path: &str, entry: &str) -> bool {
    if path.starts_with("/api/")
        || path.starts_with("/assets/")
        || matches!(
            path,
            "/favicon.svg"
                | "/favicon.ico"
                | "/favicon.png"
                | "/robots.txt"
                | "/manifest.json"
            | "/icon-192.png"
            | "/icon-512.png"
            | "/apple-touch-icon.png"
            | "/icon-192.webp"
            | "/icon-512.webp"
            | "/apple-touch-icon.webp"
        )
    {
        return true;
    }
    if entry.is_empty() {
        return true;
    }
    let prefix = format!("/{}", entry.trim_matches('/'));
    path.starts_with(&prefix)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn generate_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Extract the real client IP.
///
/// Security model:
///   X-Real-IP and X-Forwarded-For are **only trusted when the request arrives
///   from a known trusted reverse proxy** (i.e. socket_ip is in TRUSTED_PROXY_CIDRS).
///   If the connection comes directly from an untrusted source those headers are
///   attacker-controlled and MUST be ignored — otherwise an attacker can send
///   `X-Forwarded-For: 127.0.0.1` to bypass the admin IP whitelist.
///
/// Priority (when socket_ip is a trusted proxy):
///   1. `X-Real-IP` header
///   2. First address in `X-Forwarded-For`
///   3. socket_ip (fallback)
///
/// When socket_ip is NOT a trusted proxy, socket_ip is always used directly.
fn extract_client_ip(headers: &HeaderMap, socket_ip: Option<&str>) -> String {
    let socket = socket_ip.unwrap_or("127.0.0.1");

    if is_trusted_proxy(socket) {
        // Only honour proxy headers when the TCP peer is itself a trusted proxy.
        if let Some(ip) = headers
            .get("x-real-ip")
            .or_else(|| headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return ip;
        }
    }

    socket.to_string()
}

/// CIDRs whose HTTP headers (X-Real-IP, X-Forwarded-For) are trusted.
/// Loopback and link-local are trusted by default (local reverse proxies).
/// Set the `VANE_TRUSTED_PROXIES` environment variable to a comma-separated
/// list of additional CIDR ranges, e.g. `10.0.0.0/8,172.16.0.0/12`.
/// 额外可信代理 CIDR：只在首次访问时解析一次环境变量，
/// 避免每个请求都做 `std::env::var` + 逐条 `IpNetwork::from_str`。
static TRUSTED_PROXIES: Lazy<Vec<IpNetwork>> = Lazy::new(|| {
    std::env::var("VANE_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| <IpNetwork as std::str::FromStr>::from_str(s.trim()).ok())
        .collect()
});

fn is_trusted_proxy(ip: &str) -> bool {
    use std::net::IpAddr;
    use std::str::FromStr;

    let addr = match IpAddr::from_str(ip) {
        Ok(a) => canonical_ip(a),
        Err(_) => return false,
    };

    // Always trust loopback (127.x, ::1) and link-local (169.254.x, fe80::)
    if addr.is_loopback() {
        return true;
    }
    if let IpAddr::V4(v4) = addr {
        // 169.254.0.0/16 link-local
        if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
            return true;
        }
    }

    TRUSTED_PROXIES.iter().any(|net| net.contains(addr))
}

// ─── Purge expired sessions (called from main) ─────────────────────────────────

pub async fn purge_sessions_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        ticker.tick().await;
        let now = Utc::now().timestamp();
        if session_memory_enabled() {
            SESSIONS.write().unwrap().retain(|_, exp| *exp > now);
        }
        let dd_opt = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd_opt {
            let _ = tokio::task::spawn_blocking(move || db::session_purge_expired(&dd)).await;
        }
    }
}
