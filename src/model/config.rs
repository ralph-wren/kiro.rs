use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStorageBackend {
    File,
    Sqlite,
}

impl Default for CredentialStorageBackend {
    fn default() -> Self {
        Self::Sqlite
    }
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_region")]
    pub region: String,

    /// Auth Region（用于 Token 刷新），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_region: Option<String>,

    /// API Region（用于 API 请求），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    #[serde(default = "default_tls_backend")]
    pub tls_backend: TlsBackend,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 凭据存储后端，默认使用 SQLite
    #[serde(default)]
    pub credential_storage: CredentialStorageBackend,

    /// SQLite 凭据数据库路径；相对路径以凭据文件所在目录为基准
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_database_path: Option<String>,

    /// 负载均衡模式（"priority" 或 "balanced"）
    #[serde(default = "default_load_balancing_mode")]
    pub load_balancing_mode: String,

    /// 每个凭据允许的最大并发 API 请求数
    #[serde(default = "default_max_concurrent_requests_per_credential")]
    pub max_concurrent_requests_per_credential: usize,

    /// 单凭据滑动窗口请求数上限，0 表示关闭。
    #[serde(default = "default_per_credential_rate_limit_max_requests")]
    pub per_credential_rate_limit_max_requests: usize,

    /// 单凭据滑动窗口长度（秒）。
    #[serde(default = "default_per_credential_rate_limit_window_seconds")]
    pub per_credential_rate_limit_window_seconds: u64,

    /// 全局滑动窗口请求数上限，0 表示关闭。
    #[serde(default = "default_global_rate_limit_max_requests")]
    pub global_rate_limit_max_requests: usize,

    /// 全局滑动窗口长度（秒）。
    #[serde(default = "default_global_rate_limit_window_seconds")]
    pub global_rate_limit_window_seconds: u64,

    /// Prompt Cache 账号保护窗口（秒）。每次命中缓存都会续期；0 表示关闭账号保护。
    #[serde(default = "default_cache_account_protection_seconds")]
    pub cache_account_protection_seconds: u64,

    /// 命中 Prompt Cache 的账号并发已满时，等待原账号释放槽位的时间（秒，最大 60）。
    #[serde(default = "default_cache_account_wait_seconds")]
    pub cache_account_wait_seconds: u64,

    /// HTTP 429 后账号临时冷却时间（秒）。上游返回 Retry-After 时优先使用上游值。
    #[serde(default = "default_rate_limit_cooldown_seconds")]
    pub rate_limit_cooldown_seconds: u64,

    /// 禁用凭据自动恢复检查间隔（秒），0 表示关闭
    #[serde(default = "default_disabled_credential_recovery_interval_seconds")]
    pub disabled_credential_recovery_interval_seconds: u64,

    /// 每轮最多检查的禁用凭据数量，避免恢复探测本身造成上游压力
    #[serde(default = "default_disabled_credential_recovery_batch_size")]
    pub disabled_credential_recovery_batch_size: usize,

    /// Admin UI 批量导入凭据时的前端并发数
    #[serde(default = "default_batch_import_concurrency")]
    pub batch_import_concurrency: usize,

    /// Admin 额度/订阅查询的后端上游并发数
    #[serde(default = "default_usage_request_concurrency")]
    pub usage_request_concurrency: usize,

    /// 可用凭据 access token 后台预刷新间隔（秒），0 表示关闭
    #[serde(default = "default_proactive_token_refresh_interval_seconds")]
    pub proactive_token_refresh_interval_seconds: u64,

    /// 每轮后台最多预刷新的凭据数量
    #[serde(default = "default_proactive_token_refresh_batch_size")]
    pub proactive_token_refresh_batch_size: usize,

    /// 后台预刷新 access token 的并发数
    #[serde(default = "default_proactive_token_refresh_concurrency")]
    pub proactive_token_refresh_concurrency: usize,

    /// 可用凭据后台额度查询间隔（秒），0 表示关闭
    ///
    /// 定期对可用凭据批量查询 getUsageLimits，将月度额度已用尽的凭据提前禁用，
    /// 避免耗尽发现只能依赖请求热路径上的 402。
    /// 每轮账号数与并发数复用 proactiveTokenRefreshBatchSize / proactiveTokenRefreshConcurrency。
    #[serde(default = "default_usage_query_interval_seconds")]
    pub usage_query_interval_seconds: u64,

    /// 额度查询自动禁用阈值。
    ///
    /// 当 getUsageLimits 查询到剩余额度小于该值时，提前禁用账号。
    /// 默认为 1；设置为 0 表示只按上游 402 或用尽状态禁用。
    #[serde(default = "default_usage_query_disable_remaining_threshold")]
    pub usage_query_disable_remaining_threshold: f64,

    /// Prompt Cache 创建 token 模拟值返回倍率。
    #[serde(default = "default_cache_creation_usage_multiplier")]
    pub cache_creation_usage_multiplier: f64,

    /// Prompt Cache 读取 token 模拟值返回倍率。
    #[serde(default = "default_cache_read_usage_multiplier")]
    pub cache_read_usage_multiplier: f64,

    /// 是否开启非流式响应的 thinking 块提取（默认 true）
    ///
    /// 启用后，非流式响应中的 `<thinking>...</thinking>` 标签会被解析为
    /// 独立的 `{"type": "thinking", ...}` 内容块,与流式响应行为一致。
    #[serde(default = "default_extract_thinking")]
    pub extract_thinking: bool,

    /// 请求未显式指定 stream 时是否默认使用流式响应（默认 true）
    #[serde(default = "default_stream")]
    pub default_stream: bool,

    /// Admin 测试凭据弹窗默认模型。
    #[serde(default = "default_test_model")]
    pub test_default_model: String,

    /// 默认端点名称（凭据未显式指定 endpoint 时使用，默认 "ide"）
    #[serde(default = "default_endpoint")]
    pub default_endpoint: String,

    /// 端点特定的配置
    ///
    /// 键为端点名（如 "ide" / "cli"），值为该端点自由定义的参数对象。
    /// 未在此表出现的端点沿用实现内置默认值。
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,

    /// 自定义模型映射（请求模型名 -> Kiro 模型 ID）
    ///
    /// 未配置的模型继续使用转换器内置映射规则。
    #[serde(default)]
    pub model_mappings: HashMap<String, String>,

    /// 配置文件路径（运行时元数据，不写入 JSON）
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    "0.11.107".to_string()
}

fn default_system_version() -> String {
    const SYSTEM_VERSIONS: &[&str] = &["darwin#24.6.0", "win32#10.0.22631"];
    SYSTEM_VERSIONS[fastrand::usize(..SYSTEM_VERSIONS.len())].to_string()
}

fn default_node_version() -> String {
    "22.22.0".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
}

fn default_load_balancing_mode() -> String {
    "priority".to_string()
}

fn default_max_concurrent_requests_per_credential() -> usize {
    1
}

fn default_per_credential_rate_limit_max_requests() -> usize {
    0
}

fn default_per_credential_rate_limit_window_seconds() -> u64 {
    60
}

fn default_global_rate_limit_max_requests() -> usize {
    0
}

fn default_global_rate_limit_window_seconds() -> u64 {
    60
}

fn default_cache_account_protection_seconds() -> u64 {
    5 * 60
}

fn default_cache_account_wait_seconds() -> u64 {
    3
}

fn default_rate_limit_cooldown_seconds() -> u64 {
    60
}

fn default_disabled_credential_recovery_interval_seconds() -> u64 {
    5 * 60
}

fn default_disabled_credential_recovery_batch_size() -> usize {
    10
}

fn default_batch_import_concurrency() -> usize {
    50
}

fn default_usage_request_concurrency() -> usize {
    8
}

fn default_proactive_token_refresh_interval_seconds() -> u64 {
    60
}

fn default_proactive_token_refresh_batch_size() -> usize {
    100
}

fn default_proactive_token_refresh_concurrency() -> usize {
    10
}

fn default_usage_query_interval_seconds() -> u64 {
    0
}

fn default_usage_query_disable_remaining_threshold() -> f64 {
    1.0
}

fn default_cache_creation_usage_multiplier() -> f64 {
    1.0
}

fn default_cache_read_usage_multiplier() -> f64 {
    1.0
}

fn default_extract_thinking() -> bool {
    true
}

fn default_stream() -> bool {
    true
}

fn default_test_model() -> String {
    "claude-sonnet-4-5-20250929".to_string()
}

fn default_endpoint() -> String {
    crate::kiro::endpoint::ide::IDE_ENDPOINT_NAME.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            region: default_region(),
            auth_region: None,
            api_region: None,
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            credential_storage: CredentialStorageBackend::default(),
            credential_database_path: None,
            load_balancing_mode: default_load_balancing_mode(),
            max_concurrent_requests_per_credential: default_max_concurrent_requests_per_credential(
            ),
            per_credential_rate_limit_max_requests: default_per_credential_rate_limit_max_requests(
            ),
            per_credential_rate_limit_window_seconds:
                default_per_credential_rate_limit_window_seconds(),
            global_rate_limit_max_requests: default_global_rate_limit_max_requests(),
            global_rate_limit_window_seconds: default_global_rate_limit_window_seconds(),
            cache_account_protection_seconds: default_cache_account_protection_seconds(),
            cache_account_wait_seconds: default_cache_account_wait_seconds(),
            rate_limit_cooldown_seconds: default_rate_limit_cooldown_seconds(),
            disabled_credential_recovery_interval_seconds:
                default_disabled_credential_recovery_interval_seconds(),
            disabled_credential_recovery_batch_size:
                default_disabled_credential_recovery_batch_size(),
            batch_import_concurrency: default_batch_import_concurrency(),
            usage_request_concurrency: default_usage_request_concurrency(),
            proactive_token_refresh_interval_seconds:
                default_proactive_token_refresh_interval_seconds(),
            proactive_token_refresh_batch_size: default_proactive_token_refresh_batch_size(),
            proactive_token_refresh_concurrency: default_proactive_token_refresh_concurrency(),
            usage_query_interval_seconds: default_usage_query_interval_seconds(),
            usage_query_disable_remaining_threshold:
                default_usage_query_disable_remaining_threshold(),
            cache_creation_usage_multiplier: default_cache_creation_usage_multiplier(),
            cache_read_usage_multiplier: default_cache_read_usage_multiplier(),
            extract_thinking: default_extract_thinking(),
            default_stream: default_stream(),
            test_default_model: default_test_model(),
            default_endpoint: default_endpoint(),
            endpoints: HashMap::new(),
            model_mappings: HashMap::new(),
            config_path: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 获取有效的 Auth Region（用于 Token 刷新）
    /// 优先使用 auth_region，未配置时回退到 region
    pub fn effective_auth_region(&self) -> &str {
        self.auth_region.as_deref().unwrap_or(&self.region)
    }

    /// 获取有效的 API Region（用于 API 请求）
    /// 优先使用 api_region，未配置时回退到 region
    pub fn effective_api_region(&self) -> &str {
        self.api_region.as_deref().unwrap_or(&self.region)
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            let mut config = Self::default();
            config.config_path = Some(path.to_path_buf());
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        config.config_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// 获取配置文件路径（如果有）
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// 将当前配置写回原始配置文件
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置文件路径未知，无法保存配置"))?;

        self.save_to(path)
    }

    /// 将当前配置写入指定配置文件
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let path = path.as_ref();
        let content = serde_json::to_string_pretty(self).context("序列化配置失败")?;
        fs::write(path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.display()))?;
        Ok(())
    }
}
