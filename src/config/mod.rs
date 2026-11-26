pub mod crypto;
pub mod db;
pub mod ipfilter;
pub mod types;

pub use db::DataDir;
pub use ipfilter::{clean_scopes_for_deleted_target, IpFilterCache};
pub use types::*;

use anyhow::Result;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ─── 数据面只读快照（无锁） ──────────────────────────────────────────────────

pub type RouteIndex = HashMap<(String, String), Arc<WebRoute>>;

#[derive(Debug)]
pub struct RuntimeState {
    version: AtomicU64,
    ip_filter_cache: ArcSwap<IpFilterCache>,
    route_index: ArcSwap<RouteIndex>,
}

pub fn normalize_host(host: &str) -> String {
    host.trim_start_matches("www.").to_lowercase()
}

fn build_route_index(services: &[WebService]) -> RouteIndex {
    let mut idx = HashMap::new();
    for svc in services {
        for route in &svc.routes {
            if !route.enabled {
                continue;
            }
            idx.entry((svc.id.clone(), normalize_host(&route.domain)))
                .or_insert_with(|| Arc::new(route.clone()));
        }
    }
    idx
}

impl RuntimeState {
    fn new(inner: &ConfigInner) -> Self {
        Self {
            version: AtomicU64::new(1),
            ip_filter_cache: ArcSwap::from_pointee(IpFilterCache::rebuild(&inner.ip_filter)),
            route_index: ArcSwap::from_pointee(build_route_index(&inner.web_services)),
        }
    }

    /// 配置版本号：任何写操作后自增，TLS / 路由等派生缓存据此自动失效，
    /// 无需在每个 API handler 里手工枚举失效点。
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn ip_filter(&self) -> arc_swap::Guard<Arc<IpFilterCache>> {
        self.ip_filter_cache.load()
    }

    /// O(1) 路由查找，替代原先每请求遍历所有 service/route。
    pub fn route(&self, svc_id: &str, host: &str) -> Option<Arc<WebRoute>> {
        let key = (svc_id.to_string(), normalize_host(host));
        self.route_index.load().get(&key).cloned()
    }

    fn refresh(&self, inner: &ConfigInner) {
        self.version.fetch_add(1, Ordering::Release);
        self.ip_filter_cache
            .store(Arc::new(IpFilterCache::rebuild(&inner.ip_filter)));
        self.route_index
            .store(Arc::new(build_route_index(&inner.web_services)));
    }
}

// ─── Config (shared mutable state) ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    inner: Arc<RwLock<ConfigInner>>,
    runtime: Arc<RuntimeState>,
}

#[derive(Debug, Default)]
pub struct ConfigInner {
    pub admin: AdminConfig,
    pub port_forwards: Vec<PortForwardRule>,
    pub ddns: Vec<DdnsRule>,
    pub web_services: Vec<WebService>,
    pub tls_certs: Vec<TlsCert>,
    pub ip_filter: Vec<IpFilterRule>,
    pub data_dir: Option<Arc<DataDir>>,
}

/// 写 guard：Drop 时自动重建所有派生快照，避免任何配置变更点遗漏失效。
pub struct ConfigWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, ConfigInner>,
    runtime: &'a RuntimeState,
}

impl Deref for ConfigWriteGuard<'_> {
    type Target = ConfigInner;
    fn deref(&self) -> &ConfigInner {
        &self.guard
    }
}
impl DerefMut for ConfigWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut ConfigInner {
        &mut self.guard
    }
}
impl Drop for ConfigWriteGuard<'_> {
    fn drop(&mut self) {
        self.runtime.refresh(&*self.guard);
    }
}

impl Config {
    pub fn new(inner: ConfigInner) -> Self {
        let runtime = Arc::new(RuntimeState::new(&inner));
        Self {
            inner: Arc::new(RwLock::new(inner)),
            runtime,
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ConfigInner> {
        self.inner.read().unwrap()
    }

    pub fn write(&self) -> ConfigWriteGuard<'_> {
        ConfigWriteGuard {
            guard: self.inner.write().unwrap(),
            runtime: &self.runtime,
        }
    }

    pub fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }

    pub fn rebuild_ip_filter_cache(&self) {
        // 写 guard 的 Drop 会重建 IP 过滤缓存与路由索引。
        drop(self.write());
    }

    pub fn check_ip_allowed(&self, scope_type: &str, target_id: &str, client_ip: &str) -> bool {
        self.runtime
            .ip_filter()
            .check_allowed(scope_type, target_id, client_ip)
    }

    /// 数据面热路径：直接传 IpAddr，无字符串解析、无 RwLock 读锁。
    pub fn check_ip_allowed_addr(
        &self,
        scope_type: &str,
        target_id: &str,
        ip: IpAddr,
    ) -> bool {
        self.runtime
            .ip_filter()
            .check_allowed_addr(scope_type, target_id, ip)
    }

    /// 删除 portforward/webservice 目标时清理 scopes，返回被修改的规则供调用方持久化。
    pub fn clean_scopes_for_deleted_target(
        &self,
        scope_type: &str,
        target_id: &str,
    ) -> Vec<IpFilterRule> {
        let mut inner = self.write();
        let modified_ids =
            clean_scopes_for_deleted_target(&mut inner.ip_filter, scope_type, target_id);
        inner
            .ip_filter
            .iter()
            .filter(|r| modified_ids.contains(&r.id))
            .cloned()
            .collect()
    }
}

// ─── Load from DB ─────────────────────────────────────────────────────────────

pub fn load(dd: Arc<DataDir>) -> Result<Config> {
    let mut inner = db::load_from_db(&dd)?;
    inner.data_dir = Some(dd);
    Ok(Config::new(inner))
}
