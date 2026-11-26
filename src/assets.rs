use axum::{
    body::Body,
    http::{header, HeaderMap, Response, StatusCode, Uri},
    response::IntoResponse,
};
use rust_embed::RustEmbed;
use std::borrow::Cow;
use std::hash::{Hash, Hasher};

/// Embeds everything under web/dist/ at compile time.
/// If the directory doesn't exist (e.g. CI without frontend build),
/// the binary still compiles but returns 404 for asset requests.
#[derive(RustEmbed)]
#[folder = "web/dist/"]
#[include = "*"]
pub struct WebAssets;

fn etag(data: &[u8]) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut h);
    format!("\"{:x}-{:x}\"", data.len(), h.finish())
}

/// release 构建下 rust-embed 返回 Cow::Borrowed(&'static [u8])，
/// 用 Bytes::from_static 包一层即可零拷贝交给 Body；debug 构建走运行时
/// 读文件，才需要 owned 回退。
fn body_from(data: Cow<'static, [u8]>) -> Body {
    match data {
        Cow::Borrowed(b) => Body::from(hyper::body::Bytes::from_static(b)),
        Cow::Owned(v) => Body::from(v),
    }
}

pub async fn serve_asset(
    uri: Uri,
    headers: HeaderMap,
    safe_entry: Option<String>,
) -> Response<Body> {
    let mut asset_path = uri.path().trim_start_matches('/').to_string();

    // Strip safe_entry prefix if configured
    if let Some(entry) = safe_entry {
        if !entry.is_empty() {
            let prefix = format!("{}/", entry.trim_matches('/'));
            if let Some(stripped) = asset_path.strip_prefix(&prefix) {
                asset_path = stripped.to_string();
            } else if asset_path == entry.trim_matches('/') {
                asset_path = String::new();
            }
        }
    }
    if asset_path.is_empty() {
        asset_path = "index.html".to_string();
    }

    // SPA fallback: 未知路径统一回 index.html
    let resolved = if WebAssets::get(&asset_path).is_some() {
        asset_path.clone()
    } else {
        "index.html".to_string()
    };
    if WebAssets::get(&resolved).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let accept = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let inm = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // 构建期已生成 .br / .gz 变体，按 Accept-Encoding 直接返回，无运行时压缩开销。
    let (lookup, encoding) = if accept.contains("br")
        && WebAssets::get(&format!("{}.br", resolved)).is_some()
    {
        (format!("{}.br", resolved), Some("br"))
    } else if accept.contains("gzip")
        && WebAssets::get(&format!("{}.gz", resolved)).is_some()
    {
        (format!("{}.gz", resolved), Some("gzip"))
    } else {
        (resolved.clone(), None)
    };

    let content = WebAssets::get(&lookup).expect("variant checked above");
    let tag = etag(content.data.as_ref());

    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .to_string();
    // Vite 产物文件名带内容 hash，可长期强缓存；入口 HTML/manifest 走 no-cache + ETag。
    let immutable = resolved.starts_with("assets/");
    let cache = if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };

    // 304 也必须带 ETag / Cache-Control / Vary / Content-Encoding，
    // 否则代理与浏览器无法按编码变体正确复用协商缓存。
    let status = if inm == tag {
        StatusCode::NOT_MODIFIED
    } else {
        StatusCode::OK
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::ETAG, tag)
        .header(header::CACHE_CONTROL, cache)
        .header(header::VARY, "Accept-Encoding");
    if status == StatusCode::OK {
        builder = builder.header(header::CONTENT_TYPE, mime);
    }
    if let Some(enc) = encoding {
        builder = builder.header(header::CONTENT_ENCODING, enc);
    }
    let body = if status == StatusCode::NOT_MODIFIED {
        Body::empty()
    } else {
        body_from(content.data)
    };
    builder.body(body).unwrap()
}
