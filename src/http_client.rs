//! HTTP Client 构建模块
//!
//! 提供统一的 HTTP Client 构建功能，支持代理配置

use reqwest::{Client, Proxy};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::model::config::TlsBackend;

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 15;
const DEFAULT_READ_TIMEOUT_SECS: u64 = 180;
const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;
const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 30;
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 32;
const SHARED_CLIENT_CACHE_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientCacheKey {
    proxy: Option<ProxyConfig>,
    timeout_secs: u64,
    connect_timeout_secs: u64,
    read_timeout_secs: u64,
    tls_backend: TlsBackend,
}

static SHARED_CLIENTS: LazyLock<Mutex<HashMap<ClientCacheKey, Client>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static GLOBAL_PROXY: LazyLock<Mutex<Option<ProxyConfig>>> = LazyLock::new(|| Mutex::new(None));

pub fn set_global_proxy(proxy: Option<ProxyConfig>) {
    *GLOBAL_PROXY.lock().expect("global proxy mutex poisoned") = proxy;
}

pub fn global_proxy() -> Option<ProxyConfig> {
    GLOBAL_PROXY
        .lock()
        .expect("global proxy mutex poisoned")
        .clone()
}

/// 代理配置
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    /// 代理地址，支持 http/https/socks5
    pub url: String,
    /// 代理认证用户名
    pub username: Option<String>,
    /// 代理认证密码
    pub password: Option<String>,
}

impl ProxyConfig {
    /// 从 url 创建代理配置
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
        }
    }

    /// 设置认证信息
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
}

/// 构建 HTTP Client
///
/// # Arguments
/// * `proxy` - 可选的代理配置
/// * `timeout_secs` - 超时时间（秒）
///
/// # Returns
/// 配置好的 reqwest::Client
pub fn build_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    build_client_with_timeouts(
        proxy,
        timeout_secs,
        DEFAULT_CONNECT_TIMEOUT_SECS,
        DEFAULT_READ_TIMEOUT_SECS,
        tls_backend,
    )
}

fn build_client_with_timeouts(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    connect_timeout_secs: u64,
    read_timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(connect_timeout_secs))
        .read_timeout(Duration::from_secs(read_timeout_secs))
        .pool_idle_timeout(Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS))
        .pool_max_idle_per_host(DEFAULT_POOL_MAX_IDLE_PER_HOST)
        .tcp_keepalive(Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS));

    match tls_backend {
        TlsBackend::Rustls => {
            builder = builder.use_rustls_tls();
        }
        TlsBackend::NativeTls => {
            #[cfg(feature = "native-tls")]
            {
                builder = builder.use_native_tls();
            }
            #[cfg(not(feature = "native-tls"))]
            {
                anyhow::bail!("此构建版本未包含 native-tls 后端，请在配置中改用 rustls");
            }
        }
    }

    if let Some(proxy_config) = proxy {
        let mut proxy = Proxy::all(&proxy_config.url)?;

        // 设置代理认证
        if let (Some(username), Some(password)) = (&proxy_config.username, &proxy_config.password) {
            proxy = proxy.basic_auth(username, password);
        }

        builder = builder.proxy(proxy);
        tracing::debug!("HTTP Client 使用代理: {}", proxy_config.url);
    }

    Ok(builder.build()?)
}

/// 获取可复用的 HTTP Client。
///
/// Token 刷新与额度查询会在后台批量触发，复用 Client 可以共享连接池，
/// 避免每次请求都重新加载证书、建 TCP/TLS 连接。
pub fn shared_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    let key = ClientCacheKey {
        proxy: proxy.cloned(),
        timeout_secs,
        connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        read_timeout_secs: DEFAULT_READ_TIMEOUT_SECS,
        tls_backend,
    };

    {
        let cache = SHARED_CLIENTS
            .lock()
            .map_err(|_| anyhow::anyhow!("共享 HTTP Client 缓存锁已损坏"))?;
        if let Some(client) = cache.get(&key) {
            return Ok(client.clone());
        }
    }

    let client = build_client_with_timeouts(
        proxy,
        timeout_secs,
        DEFAULT_CONNECT_TIMEOUT_SECS,
        DEFAULT_READ_TIMEOUT_SECS,
        tls_backend,
    )?;

    let mut cache = SHARED_CLIENTS
        .lock()
        .map_err(|_| anyhow::anyhow!("共享 HTTP Client 缓存锁已损坏"))?;
    if cache.len() < SHARED_CLIENT_CACHE_LIMIT {
        cache.insert(key, client.clone());
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_new() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        assert_eq!(config.url, "http://127.0.0.1:7890");
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_proxy_config_with_auth() {
        let config = ProxyConfig::new("socks5://127.0.0.1:1080").with_auth("user", "pass");
        assert_eq!(config.url, "socks5://127.0.0.1:1080");
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    #[test]
    fn test_build_client_without_proxy() {
        let client = build_client(None, 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_proxy() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        let client = build_client(Some(&config), 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_shared_client_without_proxy() {
        let client = shared_client(None, 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }
}
