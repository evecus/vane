//! 全局复用的 HTTP 客户端（DDNS / ACME / DNS 服务商 API）。
//!
//! `reqwest::Client` 内部持有连接池与 DNS 缓存，clone 很廉价且共享同一连接池。
//! 原实现每次定时任务都 `Client::new()` / `Client::builder()...build()`，
//! 导致每次外部调用都要重新做 DNS 解析 + TLS 握手。

use once_cell::sync::Lazy;
use std::time::Duration;

pub static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(8)
        .build()
        .expect("failed to build shared reqwest client")
});
