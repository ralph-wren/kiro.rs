//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use futures::{StreamExt, stream};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as TokioMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use crate::http_client::{ProxyConfig, shared_client};
use crate::kiro::credential_store::CredentialStore;
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::token_refresh::{
    IdcRefreshRequest, IdcRefreshResponse, RefreshRequest, RefreshResponse,
};
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::kiro::quota::{CachedBalance, CreditLedgerStore, CreditMeter, CreditStats};
use crate::model::config::Config;

static BALANCE_CACHE_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn with_balance_cache_file_lock<R>(f: impl FnOnce() -> R) -> R {
    let lock = BALANCE_CACHE_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock();
    f()
}

/// 检查 Token 是否在指定时间内过期
pub(crate) fn is_token_expiring_within(
    credentials: &KiroCredentials,
    minutes: i64,
) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期（提前 5 分钟判断）
pub(crate) fn is_token_expired(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub(crate) fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn is_refresh_rate_limited_error(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("429")
        || message.contains("too many requests")
        || message.contains("rate limit")
        || message.contains("限流")
        || message.contains("请求过于频繁")
}

/// 识别刷新凭据已经不可恢复的 OAuth 错误。
///
/// AWS OIDC/Kiro 对同一类失效凭据可能返回 `invalid_grant` 或
/// `access_denied`。两者都不应继续留在可用账号池中重试。
fn permanent_refresh_error_code(status: u16, body: &str) -> Option<&'static str> {
    if status != 400 {
        return None;
    }

    let payload: serde_json::Value = serde_json::from_str(body).ok()?;
    match payload.get("error").and_then(serde_json::Value::as_str) {
        Some("access_denied") => Some("access_denied"),
        Some("invalid_grant")
            if payload
                .get("error_description")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|description| {
                    description.contains("Invalid refresh token provided")
                }) =>
        {
            Some("invalid_grant")
        }
        _ => None,
    }
}

/// 生成 API Key 脱敏展示(前 4 + ... + 后 4,长度不足或非 ASCII 回退 ***)
fn mask_api_key(key: &str) -> String {
    if key.is_ascii() && key.len() > 16 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "***".to_string()
    }
}

/// 验证 refreshToken 的基本有效性
pub(crate) fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100 || refresh_token.ends_with("...") || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// 刷新凭据永久失效错误
///
/// 当服务端返回 400 + `invalid_grant`/`access_denied` 时，表示刷新凭据已被撤销、
/// 过期或被拒绝，不应重试，需立即禁用对应凭据。
#[derive(Debug)]
pub(crate) struct RefreshTokenInvalidError {
    pub message: String,
}

impl fmt::Display for RefreshTokenInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RefreshTokenInvalidError {}

/// 刷新 Token
pub(crate) async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    // API Key 凭据不支持 Token 刷新：底层契约级拦截
    // 其他调用点（try_ensure_token / 活跃路径 / add_credential）在调用前已显式分流 API Key；
    // 仅 force_refresh_token_for 未分流，此处 bail 让错误自然传播为 400 BAD_REQUEST。
    if credentials.is_api_key_credential() {
        bail!("API Key 凭据不支持刷新 Token");
    }

    validate_refresh_token(credentials)?;

    // 根据 auth_method 选择刷新方式
    // 如果未指定 auth_method，根据是否有 clientId/clientSecret 自动判断
    let auth_method = credentials.auth_method.as_deref().unwrap_or_else(|| {
        if credentials.client_id.is_some() && credentials.client_secret.is_some() {
            "idc"
        } else {
            "social"
        }
    });

    if auth_method.eq_ignore_ascii_case("idc")
        || auth_method.eq_ignore_ascii_case("builder-id")
        || auth_method.eq_ignore_ascii_case("iam")
    {
        refresh_idc_token(credentials, config, proxy).await
    } else {
        refresh_social_token(credentials, config, proxy).await
    }
}

/// 刷新 Social Token
async fn refresh_social_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 Social Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region。
    // 部分导出工具把国家码（例如 `US`、`AU`）写入 region；它们不是
    // Kiro/AWS endpoint 的区域名，直接拼接会产生 prod.US.auth... 这类无效域名。
    // 保留已配置的标准 AWS region，非标准值回退到全局 Auth Region。
    let region = normalize_auth_region(
        credentials.effective_auth_region(config),
        config.effective_auth_region(),
    );

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;

    let client = shared_client(proxy, 60, config.tls_backend)?;
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        if let Some(error_code) = permanent_refresh_error_code(status.as_u16(), &body_text) {
            return Err(RefreshTokenInvalidError {
                message: format!("Social 凭据刷新已失效 ({}): {}", error_code, body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

/// Returns a valid AWS-style region for the Social refresh endpoint.
///
/// `region` is persisted as user-provided metadata, so invalid legacy values
/// must not be rewritten in the database. Normalization is request-local and
/// therefore cannot affect credential identity, deduplication, or existing
/// account records.
fn normalize_auth_region(candidate: &str, fallback: &str) -> String {
    let candidate = candidate.trim().to_ascii_lowercase();
    if is_aws_region(&candidate) {
        return candidate;
    }

    let fallback = fallback.trim().to_ascii_lowercase();
    if is_aws_region(&fallback) {
        tracing::warn!(
            candidate = %candidate,
            fallback = %fallback,
            "凭据 region 不是 AWS 区域名，刷新 Token 时回退到全局 Auth Region"
        );
        return fallback;
    }

    tracing::warn!(
        candidate = %candidate,
        fallback = %fallback,
        "凭据和全局 Auth Region 均不是 AWS 区域名，刷新 Token 时使用 us-east-1"
    );
    "us-east-1".to_string()
}

fn is_aws_region(region: &str) -> bool {
    let mut parts = region.split('-');
    let Some(first) = parts.next() else { return false };
    let Some(last) = parts.next_back() else { return false };
    first.len() == 2
        && first.chars().all(|c| c.is_ascii_lowercase())
        && last.chars().all(|c| c.is_ascii_digit())
        && parts.all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase())
        })
}

/// 刷新 IdC Token (AWS SSO OIDC)
async fn refresh_idc_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 IdC Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientId"))?;
    let client_secret = credentials
        .client_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientSecret"))?;

    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);
    let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let x_amz_user_agent = "aws-sdk-js/3.980.0 KiroIDE";
    let user_agent = format!(
        "aws-sdk-js/3.980.0 ua/2.1 os/{} lang/js md/nodejs#{} api/sso-oidc#3.980.0 m/E KiroIDE",
        os_name, node_version
    );

    let client = shared_client(proxy, 60, config.tls_backend)?;
    let body = IdcRefreshRequest {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        refresh_token: refresh_token.to_string(),
        grant_type: "refresh_token".to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header("x-amz-user-agent", x_amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", format!("oidc.{}.amazonaws.com", region))
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=4")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        if let Some(error_code) = permanent_refresh_error_code(status.as_u16(), &body_text) {
            return Err(RefreshTokenInvalidError {
                message: format!("IdC 凭据刷新已失效 ({}): {}", error_code, body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "IdC 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OIDC 服务暂时不可用",
            _ => "IdC Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: IdcRefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    // 同步更新 profile_arn（如果 IdC 响应中包含）
    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    Ok(new_credentials)
}

/// 获取使用额度信息
pub(crate) async fn get_usage_limits(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息...");

    // 优先级：凭据.api_region > config.api_region > config.region
    let region = credentials.effective_api_region(config);
    let host = format!("q.{}.amazonaws.com", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // 构建 URL
    let mut url = format!(
        "https://{}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST",
        host
    );

    // profileArn 是可选的
    if let Some(profile_arn) = credentials.request_profile_arn() {
        url.push_str(&format!("&profileArn={}", urlencoding::encode(profile_arn)));
    }

    // 构建 User-Agent headers
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = shared_client(proxy, 60, config.tls_backend)?;

    let mut request = client
        .get(&url)
        .header("x-amz-user-agent", &amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", &host)
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=1")
        .header("Authorization", format!("Bearer {}", token));

    if credentials.is_api_key_credential() {
        request = request.header("tokentype", "API_KEY");
    }

    let response = request.send().await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取使用额度",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取使用额度失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: UsageLimitsResponse = response.json().await?;
    Ok(data)
}

// ============================================================================
// 多凭据 Token 管理器
// ============================================================================

/// 单个凭据条目的状态
struct CredentialEntry {
    /// 每次上游调用开始时递增，包含取消和未收到响应的请求。
    quota_generation: u64,
    /// 凭据唯一 ID
    id: u64,
    /// 凭据信息
    credentials: KiroCredentials,
    /// API 调用连续失败次数
    failure_count: u32,
    /// Token 刷新连续失败次数
    refresh_failure_count: u32,
    /// 是否已禁用
    disabled: bool,
    /// 禁用原因（用于区分手动禁用 vs 自动禁用，便于自愈）
    disabled_reason: Option<DisabledReason>,
    /// API 调用成功次数
    success_count: u64,
    /// API 调用总次数（成功 + 失败）
    total_request_count: u64,
    /// 历史累计消耗 Token
    total_token_count: u64,
    /// 当天统计日期（北京时间 YYYY-MM-DD）
    today_key: Option<String>,
    /// 当天 API 调用总次数
    today_request_count: u64,
    /// 当天 API 调用成功次数
    today_success_count: u64,
    /// 当天累计消耗 Token
    today_token_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
    /// 当前凭据最大并发槽位数
    max_concurrent_requests: usize,
    /// 凭据级并发槽位（仅运行时使用）
    request_slots: Arc<Semaphore>,
    /// 最近成功请求的上游响应头耗时 EMA（毫秒），仅运行时用于调度。
    upstream_header_latency_ema_ms: Option<f64>,
    /// 最近请求开始时间，用于单凭据滑动窗口限速。
    recent_request_starts: VecDeque<Instant>,
    /// 瞬态错误后的运行时冷却截止时间，不写入凭据文件。
    cooldown_until: Option<Instant>,
    /// 最近一次进入冷却的原因，仅用于日志和调试。
    cooldown_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProactiveTokenRefreshSettings {
    interval_secs: u64,
    batch_size: usize,
    concurrency: usize,
}

impl ProactiveTokenRefreshSettings {
    fn from_config(config: &Config) -> Self {
        Self {
            interval_secs: config.proactive_token_refresh_interval_seconds,
            batch_size: config.proactive_token_refresh_batch_size.max(1),
            concurrency: config.proactive_token_refresh_concurrency.max(1),
        }
    }
}

/// 后台额度查询设置。
///
/// 查询间隔独立配置；每轮账号数与并发数复用 Token 预刷新的 batch_size / concurrency。
#[derive(Debug, Clone, Copy, PartialEq)]
struct UsageQuerySettings {
    interval_secs: u64,
    batch_size: usize,
    concurrency: usize,
    disable_remaining_threshold: f64,
}

impl UsageQuerySettings {
    fn from_config(config: &Config) -> Self {
        Self {
            interval_secs: config.usage_query_interval_seconds,
            batch_size: config.proactive_token_refresh_batch_size.max(1),
            concurrency: config.proactive_token_refresh_concurrency.max(1),
            disable_remaining_threshold: config.usage_query_disable_remaining_threshold.max(0.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitSettings {
    per_credential_max_requests: usize,
    per_credential_window: StdDuration,
    global_max_requests: usize,
    global_window: StdDuration,
}

impl RateLimitSettings {
    fn from_config(config: &Config) -> Self {
        Self {
            per_credential_max_requests: config.per_credential_rate_limit_max_requests,
            per_credential_window: StdDuration::from_secs(
                config.per_credential_rate_limit_window_seconds.max(1),
            ),
            global_max_requests: config.global_rate_limit_max_requests,
            global_window: StdDuration::from_secs(config.global_rate_limit_window_seconds.max(1)),
        }
    }

    fn per_credential_enabled(self) -> bool {
        self.per_credential_max_requests > 0
    }

    fn global_enabled(self) -> bool {
        self.global_max_requests > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProactiveRefreshOutcome {
    Refreshed,
    Invalid,
    RateLimited,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsageQueryOutcome {
    Ok,
    Exhausted,
    RateLimited,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DisabledCredentialRecoverySettings {
    interval_secs: u64,
    batch_size: usize,
}

impl DisabledCredentialRecoverySettings {
    fn from_config(config: &Config) -> Self {
        Self {
            interval_secs: config.disabled_credential_recovery_interval_seconds,
            batch_size: config.disabled_credential_recovery_batch_size.max(1),
        }
    }
}

/// 禁用原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisabledReason {
    /// Admin API 手动禁用
    Manual,
    /// 连续失败达到阈值后自动禁用
    TooManyFailures,
    /// Token 刷新连续失败达到阈值后自动禁用
    TooManyRefreshFailures,
    /// 额度已用尽（如 MONTHLY_REQUEST_COUNT）
    QuotaExceeded,
    /// 刷新凭据永久失效（服务端返回 invalid_grant/access_denied）
    InvalidRefreshToken,
    /// 上游明确返回账号暂时封禁
    AccountSuspended,
    /// 凭据配置无效（如 authMethod=api_key 但缺少 kiroApiKey）
    InvalidConfig,
}

impl DisabledReason {
    fn as_str(self) -> &'static str {
        match self {
            DisabledReason::Manual => "Manual",
            DisabledReason::TooManyFailures => "TooManyFailures",
            DisabledReason::TooManyRefreshFailures => "TooManyRefreshFailures",
            DisabledReason::QuotaExceeded => "QuotaExceeded",
            DisabledReason::InvalidRefreshToken => "InvalidRefreshToken",
            DisabledReason::AccountSuspended => "AccountSuspended",
            DisabledReason::InvalidConfig => "InvalidConfig",
        }
    }

    fn from_persisted_str(value: &str) -> Option<Self> {
        match value {
            "Manual" => Some(DisabledReason::Manual),
            "TooManyFailures" => Some(DisabledReason::TooManyFailures),
            "TooManyRefreshFailures" => Some(DisabledReason::TooManyRefreshFailures),
            "QuotaExceeded" => Some(DisabledReason::QuotaExceeded),
            "InvalidRefreshToken" => Some(DisabledReason::InvalidRefreshToken),
            "AccountSuspended" => Some(DisabledReason::AccountSuspended),
            "InvalidConfig" => Some(DisabledReason::InvalidConfig),
            _ => None,
        }
    }
}

/// 统计数据持久化条目
#[derive(Serialize, Deserialize)]
struct StatsEntry {
    success_count: u64,
    last_used_at: Option<String>,
    #[serde(default)]
    total_request_count: u64,
    #[serde(default)]
    total_token_count: u64,
    #[serde(default)]
    today_key: Option<String>,
    #[serde(default)]
    today_request_count: u64,
    #[serde(default)]
    today_success_count: u64,
    #[serde(default)]
    today_token_count: u64,
}

// ============================================================================
// Admin API 公开结构
// ============================================================================

/// 凭据条目快照（用于 Admin API 读取）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntrySnapshot {
    #[serde(skip_serializing)]
    pub quota_generation: u64,
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 当前路由允许调用（含冷却、限流、并发检查）。
    pub callable: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// Token 过期时间
    pub expires_at: Option<String>,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// API 调用总次数（成功 + 失败）
    pub total_request_count: u64,
    /// 当天 API 调用总次数
    pub today_request_count: u64,
    /// 当天 API 调用成功次数
    pub today_success_count: u64,
    /// 历史累计消耗 Token
    pub total_token_count: u64,
    /// 当天累计消耗 Token
    pub today_token_count: u64,
    /// 当前正在进行中的 API 调用数
    pub current_concurrent_requests: usize,
    /// 最近成功请求的上游响应头耗时 EMA（毫秒）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_header_latency_ema_ms: Option<f64>,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 端点名称（未显式配置时返回 None，由 Admin 层回退到默认值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Free 账号的展示订阅等级（仅供 Admin 层覆盖展示）
    #[serde(skip_serializing)]
    pub display_subscription_title: Option<String>,
    /// Free 账号的展示额度（仅供 Admin 层覆盖展示）
    #[serde(skip_serializing)]
    pub display_usage_limit: Option<f64>,
}

/// 凭据管理器状态快照
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSnapshot {
    /// 凭据条目列表
    pub entries: Vec<CredentialEntrySnapshot>,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 总凭据数量
    pub total: usize,
    /// 可用凭据数量
    pub available: usize,
    /// 最近 60 秒请求数
    pub rpm: u64,
    /// 历史总请求次数
    pub total_request_count: u64,
    /// 历史累计消耗 Token
    pub total_token_count: u64,
    /// 历史成功次数
    pub total_success_count: u64,
    /// 当天总请求次数（北京时间自然日）
    pub today_request_count: u64,
    /// 当天累计消耗 Token
    pub today_token_count: u64,
    /// 当天成功次数（北京时间自然日）
    pub today_success_count: u64,
    /// 额度耗尽凭据数量
    pub quota_exceeded: usize,
}

/// 多凭据 Token 管理器
///
/// 支持多个凭据的管理，实现固定优先级 + 故障转移策略
/// 故障统计基于 API 调用结果，而非 Token 刷新结果
pub struct MultiTokenManager {
    credit_ledger: Arc<CreditLedgerStore>,
    balance_cache: Mutex<HashMap<u64, CachedBalance>>,
    usage_locks: Mutex<HashMap<u64, Arc<TokioMutex<()>>>>,
    config: Config,
    /// 凭据条目列表
    entries: Mutex<Vec<CredentialEntry>>,
    /// 当前活动凭据 ID
    current_id: Mutex<u64>,
    /// Token 刷新锁，按凭据隔离，避免不同账号刷新互相阻塞。
    refresh_locks: Mutex<HashMap<u64, Arc<TokioMutex<()>>>>,
    /// 凭据持久化适配器
    credential_store: Arc<CredentialStore>,
    /// 负载均衡模式（运行时可修改）
    load_balancing_mode: Mutex<String>,
    /// Prompt Cache 账号保护窗口（秒），支持运行时热更新。
    cache_account_protection_seconds: AtomicU64,
    /// Prompt Cache 命中账号并发已满时的等待窗口（秒）。
    cache_account_wait_seconds: AtomicU64,
    /// HTTP 429 后账号临时冷却时间（秒），支持运行时热更新。
    rate_limit_cooldown_seconds: AtomicU64,
    /// 禁用凭据恢复检查的轮询游标，避免前几个长期不可用账号阻塞后续检查
    disabled_recovery_cursor: Mutex<usize>,
    /// 禁用凭据恢复检查运行时配置。
    disabled_recovery_settings: Mutex<DisabledCredentialRecoverySettings>,
    /// 禁用凭据恢复检查任务句柄，用于配置热更新时替换任务。
    disabled_recovery_task: Mutex<Option<JoinHandle<()>>>,
    /// 可用凭据后台预刷新游标，避免每轮都从列表开头扫。
    proactive_refresh_cursor: Mutex<usize>,
    /// 可用凭据后台预刷新运行时配置。
    proactive_refresh_settings: Mutex<ProactiveTokenRefreshSettings>,
    /// 可用凭据后台预刷新任务句柄，用于配置热更新时替换任务。
    proactive_refresh_task: Mutex<Option<JoinHandle<()>>>,
    /// 后台额度查询游标，避免每轮都从列表开头扫。
    usage_query_cursor: Mutex<usize>,
    /// 后台额度查询运行时配置。
    usage_query_settings: Mutex<UsageQuerySettings>,
    /// 后台额度查询任务句柄，用于配置热更新时替换任务。
    usage_query_task: Mutex<Option<JoinHandle<()>>>,
    /// API 调用滑动窗口限速运行时配置。
    rate_limit_settings: Mutex<RateLimitSettings>,
    /// 全局最近请求开始时间，用于全局滑动窗口限速。
    global_request_starts: Mutex<VecDeque<Instant>>,
    /// 最近一次统计持久化时间（用于 debounce）
    last_stats_save_at: Mutex<Option<Instant>>,
    /// 统计数据是否有未落盘更新
    stats_dirty: AtomicBool,
    /// 最近 60 秒的请求时间戳（Unix 秒，用于 RPM）
    recent_request_timestamps: Mutex<VecDeque<i64>>,
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 3;
/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);

/// API 调用上下文
///
/// 绑定特定凭据的调用上下文，确保 token、credentials 和 id 的一致性
/// 用于解决并发调用时 current_id 竞态问题
pub struct CallContext {
    /// 凭据 ID（用于 report_success/report_failure）
    pub id: u64,
    /// 凭据信息（用于构建请求头）
    pub credentials: KiroCredentials,
    /// 访问 Token
    pub token: String,
    /// 凭据级并发租约，保持到完整响应处理结束
    pub(crate) request_lease: Option<RequestLease>,
}

/// 凭据级并发租约。
///
/// 租约被丢弃后，凭据才会允许下一个请求进入。
pub struct RequestLease {
    _permit: OwnedSemaphorePermit,
    credit_meter: Option<CreditMeter>,
}

impl RequestLease {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _permit: permit,
            credit_meter: None,
        }
    }

    pub(crate) fn observe_event(&mut self, event: &crate::kiro::model::events::Event) {
        if let Some(meter) = &mut self.credit_meter {
            meter.observe(event);
        }
    }

    pub(crate) fn invalidate_metering(&mut self) {
        if let Some(meter) = &mut self.credit_meter {
            meter.invalidate();
        }
    }

    pub(crate) fn finish_metering(&mut self) {
        if let Some(meter) = &mut self.credit_meter {
            meter.finish();
        }
    }
}

impl MultiTokenManager {
    fn current_day_key() -> String {
        (Utc::now() + Duration::hours(8))
            .date_naive()
            .format("%Y-%m-%d")
            .to_string()
    }

    fn prune_recent_request_timestamps(&self, now: i64) {
        let mut recent = self.recent_request_timestamps.lock();
        while let Some(front) = recent.front() {
            if now - *front > 60 {
                recent.pop_front();
            } else {
                break;
            }
        }
    }

    fn record_request_stat(&self, id: u64, success: bool) {
        let now = Utc::now().timestamp();
        let day_key = Self::current_day_key();
        self.prune_recent_request_timestamps(now);
        {
            let mut recent = self.recent_request_timestamps.lock();
            recent.push_back(now);
        }

        let mut found = false;
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                found = true;
                entry.total_request_count += 1;
                if entry.today_key.as_deref() != Some(day_key.as_str()) {
                    entry.today_key = Some(day_key.clone());
                    entry.today_request_count = 0;
                    entry.today_success_count = 0;
                    entry.today_token_count = 0;
                }
                entry.today_request_count += 1;
                if success {
                    entry.today_success_count += 1;
                }
                entry.last_used_at = Some(Utc::now().to_rfc3339());
            }
        }

        if found {
            self.save_stats_debounced();
        }
    }

    fn current_rpm(&self) -> u64 {
        let now = Utc::now().timestamp();
        self.prune_recent_request_timestamps(now);
        self.recent_request_timestamps.lock().len() as u64
    }

    pub fn record_token_usage(&self, id: u64, consumed_tokens: u64) {
        let day_key = Self::current_day_key();
        let mut found = false;
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                found = true;
                if entry.today_key.as_deref() != Some(day_key.as_str()) {
                    entry.today_key = Some(day_key.clone());
                    entry.today_request_count = 0;
                    entry.today_success_count = 0;
                    entry.today_token_count = 0;
                }
                entry.total_token_count += consumed_tokens;
                entry.today_token_count += consumed_tokens;
            }
        }

        if found {
            self.save_stats_debounced();
        }
    }

    pub fn record_upstream_header_latency(&self, id: u64, latency: StdDuration) {
        let latency_ms = latency.as_secs_f64() * 1000.0;
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.upstream_header_latency_ema_ms = Some(
                entry
                    .upstream_header_latency_ema_ms
                    .map_or(latency_ms, |previous| previous * 0.8 + latency_ms * 0.2),
            );
        }
    }

    /// 创建多凭据 Token 管理器
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `credentials` - 凭据列表
    /// * `proxy` - 可选的代理配置
    /// * `credentials_path` - 兼容旧调用方的凭据文件路径
    /// * `is_multiple_format` - 兼容旧调用方的多凭据格式标记
    pub fn new(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
    ) -> anyhow::Result<Self> {
        let path = credentials_path
            .unwrap_or_else(|| PathBuf::from(KiroCredentials::default_credentials_path()));
        Self::new_with_store(
            config,
            credentials,
            proxy,
            CredentialStore::file(path, is_multiple_format),
        )
    }

    /// 使用指定的凭据持久化适配器创建管理器。
    pub fn new_with_store(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credential_store: Arc<CredentialStore>,
    ) -> anyhow::Result<Self> {
        crate::http_client::set_global_proxy(proxy);
        // 计算当前最大 ID，为没有 ID 的凭据分配新 ID
        let max_existing_id = credentials.iter().filter_map(|c| c.id).max().unwrap_or(0);
        let mut next_id = max_existing_id + 1;
        let mut has_new_ids = false;
        let mut has_new_machine_ids = false;
        let config_ref = &config;

        let entries: Vec<CredentialEntry> = credentials
            .into_iter()
            .map(|mut cred| {
                cred.canonicalize_auth_method();
                let id = cred.id.unwrap_or_else(|| {
                    let id = next_id;
                    next_id += 1;
                    cred.id = Some(id);
                    has_new_ids = true;
                    id
                });
                if cred.machine_id.is_none() {
                    cred.machine_id =
                        Some(machine_id::generate_from_credentials(&cred, config_ref));
                    has_new_machine_ids = true;
                }
                CredentialEntry {
                    id,
                    credentials: cred.clone(),
                    failure_count: 0,
                    refresh_failure_count: 0,
                    disabled: cred.disabled, // 从配置文件读取 disabled 状态
                    disabled_reason: if cred.disabled {
                        cred.disabled_reason
                            .as_deref()
                            .and_then(DisabledReason::from_persisted_str)
                            .or(Some(DisabledReason::Manual))
                    } else {
                        None
                    },
                    success_count: 0,
                    total_request_count: 0,
                    quota_generation: 0,
                    total_token_count: 0,
                    today_key: None,
                    today_request_count: 0,
                    today_success_count: 0,
                    today_token_count: 0,
                    last_used_at: None,
                    max_concurrent_requests: config_ref
                        .max_concurrent_requests_per_credential
                        .max(1),
                    request_slots: Arc::new(Semaphore::new(
                        config_ref.max_concurrent_requests_per_credential.max(1),
                    )),
                    upstream_header_latency_ema_ms: None,
                    recent_request_starts: VecDeque::new(),
                    cooldown_until: None,
                    cooldown_reason: None,
                }
            })
            .collect();

        // 校验 API Key 凭据配置完整性：authMethod=api_key 时必须提供 kiroApiKey
        let mut entries = entries;
        for entry in &mut entries {
            if entry.credentials.kiro_api_key.is_none()
                && entry
                    .credentials
                    .auth_method
                    .as_deref()
                    .map(|m| m.eq_ignore_ascii_case("api_key") || m.eq_ignore_ascii_case("apikey"))
                    .unwrap_or(false)
            {
                tracing::warn!(
                    "凭据 #{} 配置了 authMethod=api_key 但缺少 kiroApiKey 字段，已自动禁用",
                    entry.id
                );
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::InvalidConfig);
            }
        }

        // 检测重复 ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicate_ids = Vec::new();
        for entry in &entries {
            if !seen_ids.insert(entry.id) {
                duplicate_ids.push(entry.id);
            }
        }
        if !duplicate_ids.is_empty() {
            anyhow::bail!("检测到重复的凭据 ID: {:?}", duplicate_ids);
        }

        // 选择初始凭据：优先级最高（priority 最小）的可用凭据，无可用凭据时为 0
        let initial_id = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            .map(|e| e.id)
            .unwrap_or(0);

        let load_balancing_mode = config.load_balancing_mode.clone();
        let disabled_recovery_settings = DisabledCredentialRecoverySettings::from_config(&config);
        let proactive_refresh_settings = ProactiveTokenRefreshSettings::from_config(&config);
        let usage_query_settings = UsageQuerySettings::from_config(&config);
        let rate_limit_settings = RateLimitSettings::from_config(&config);
        let cache_account_protection_seconds = config.cache_account_protection_seconds;
        let cache_account_wait_seconds = config.cache_account_wait_seconds;
        let rate_limit_cooldown_seconds = config.rate_limit_cooldown_seconds.max(1);
        let manager = Self {
            balance_cache: Mutex::new(Self::load_balance_cache_from(
                &credential_store
                    .cache_dir()
                    .map(|d| d.join("kiro_balance_cache.json")),
            )),
            credit_ledger: CreditLedgerStore::load(
                credential_store
                    .cache_dir()
                    .map(|d| d.join("kiro_credit_ledger.json")),
            ),
            usage_locks: Mutex::new(HashMap::new()),
            config,
            entries: Mutex::new(entries),
            current_id: Mutex::new(initial_id),
            refresh_locks: Mutex::new(HashMap::new()),
            credential_store,
            load_balancing_mode: Mutex::new(load_balancing_mode),
            cache_account_protection_seconds: AtomicU64::new(cache_account_protection_seconds),
            cache_account_wait_seconds: AtomicU64::new(cache_account_wait_seconds),
            rate_limit_cooldown_seconds: AtomicU64::new(rate_limit_cooldown_seconds),
            disabled_recovery_cursor: Mutex::new(0),
            disabled_recovery_settings: Mutex::new(disabled_recovery_settings),
            disabled_recovery_task: Mutex::new(None),
            proactive_refresh_cursor: Mutex::new(0),
            proactive_refresh_settings: Mutex::new(proactive_refresh_settings),
            proactive_refresh_task: Mutex::new(None),
            usage_query_cursor: Mutex::new(0),
            usage_query_settings: Mutex::new(usage_query_settings),
            usage_query_task: Mutex::new(None),
            rate_limit_settings: Mutex::new(rate_limit_settings),
            global_request_starts: Mutex::new(VecDeque::new()),
            last_stats_save_at: Mutex::new(None),
            stats_dirty: AtomicBool::new(false),
            recent_request_timestamps: Mutex::new(VecDeque::new()),
        };

        // 如果有新分配的 ID 或新生成的 machineId，立即持久化
        if has_new_ids || has_new_machine_ids {
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("补全凭据 ID/machineId 后持久化失败: {}", e);
            } else {
                tracing::info!("已补全凭据 ID/machineId 并写回配置文件");
            }
        }

        // 加载持久化的统计数据（success_count, last_used_at）
        manager.load_stats();

        Ok(manager)
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn get_usage_query_disable_remaining_threshold(&self) -> f64 {
        self.usage_query_settings.lock().disable_remaining_threshold
    }

    pub fn credit_stats(&self) -> CreditStats {
        self.credit_ledger.stats()
    }

    pub(crate) fn start_metering(&self, id: u64, lease: &mut RequestLease) {
        if let Some(entry) = self.entries.lock().iter_mut().find(|entry| entry.id == id) {
            entry.quota_generation += 1;
        }
        self.balance_cache.lock().remove(&id);
        lease.credit_meter = Some(self.credit_ledger.begin());
    }

    pub(crate) fn quota_request_count(&self, id: u64) -> Option<u64> {
        self.entries
            .lock()
            .iter()
            .find(|e| e.id == id)
            .filter(|e| e.request_slots.available_permits() == e.max_concurrent_requests)
            .map(|e| e.quota_generation)
    }

    /// 获取凭据总数
    pub fn total_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// 获取可用凭据数量
    pub fn available_count(&self) -> usize {
        self.entries.lock().iter().filter(|e| !e.disabled).count()
    }

    fn refresh_lock_for(&self, id: u64) -> Arc<TokioMutex<()>> {
        let mut locks = self.refresh_locks.lock();
        locks
            .entry(id)
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone()
    }

    /// 启动禁用凭据自动恢复检查任务。
    ///
    /// 任务会定时抽取少量禁用凭据做轻量探测；确认 token/额度状态可用后才重新启用。
    pub fn start_disabled_credential_recovery(self: Arc<Self>) {
        let settings = *self.disabled_recovery_settings.lock();
        self.restart_disabled_credential_recovery_task(settings);
    }

    pub fn update_disabled_credential_recovery(
        self: &Arc<Self>,
        interval_secs: u64,
        batch_size: usize,
    ) {
        let settings = DisabledCredentialRecoverySettings {
            interval_secs,
            batch_size: batch_size.max(1),
        };

        {
            let mut current = self.disabled_recovery_settings.lock();
            if *current == settings {
                return;
            }
            *current = settings;
        }

        self.restart_disabled_credential_recovery_task(settings);
    }

    fn restart_disabled_credential_recovery_task(
        self: &Arc<Self>,
        settings: DisabledCredentialRecoverySettings,
    ) {
        if let Some(handle) = self.disabled_recovery_task.lock().take() {
            handle.abort();
        }

        if settings.interval_secs == 0 {
            tracing::info!("禁用凭据自动恢复检查已关闭");
            return;
        }

        tracing::info!(
            "禁用凭据自动恢复检查已启用：每 {} 秒最多检查 {} 个凭据",
            settings.interval_secs,
            settings.batch_size
        );

        let manager = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut ticker = interval(StdDuration::from_secs(settings.interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;

            loop {
                ticker.tick().await;
                manager
                    .recover_disabled_credentials_once(settings.batch_size)
                    .await;
            }
        });

        *self.disabled_recovery_task.lock() = Some(handle);
    }

    pub fn update_max_concurrent_requests_per_credential(&self, concurrency: usize) {
        let concurrency = concurrency.max(1);
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            entry.max_concurrent_requests = concurrency;
            entry.request_slots = Arc::new(Semaphore::new(concurrency));
        }
        tracing::info!("单账号最大并发已热更新为 {}", concurrency);
    }

    pub fn update_rate_limits(
        &self,
        per_credential_max_requests: usize,
        per_credential_window_seconds: u64,
        global_max_requests: usize,
        global_window_seconds: u64,
    ) {
        let settings = RateLimitSettings {
            per_credential_max_requests,
            per_credential_window: StdDuration::from_secs(per_credential_window_seconds.max(1)),
            global_max_requests,
            global_window: StdDuration::from_secs(global_window_seconds.max(1)),
        };

        {
            let mut current = self.rate_limit_settings.lock();
            if *current == settings {
                return;
            }
            *current = settings;
        }

        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                entry.recent_request_starts.clear();
            }
        }
        self.global_request_starts.lock().clear();

        tracing::info!(
            "API 滑动窗口限速已热更新：单账号 {}/{}s，全局 {}/{}s（0 表示关闭）",
            settings.per_credential_max_requests,
            settings.per_credential_window.as_secs(),
            settings.global_max_requests,
            settings.global_window.as_secs()
        );
    }

    /// 启动可用凭据 access token 后台预刷新任务。
    ///
    /// 用户请求仍会兜底刷新，但这个任务会提前刷新已过期或即将过期的账号，
    /// 避免大量刷新集中发生在首字返回前。
    pub fn start_proactive_token_refresh(self: Arc<Self>) {
        let settings = *self.proactive_refresh_settings.lock();
        self.restart_proactive_token_refresh_task(settings);
    }

    pub fn update_proactive_token_refresh(
        self: &Arc<Self>,
        interval_secs: u64,
        batch_size: usize,
        concurrency: usize,
    ) {
        let settings = ProactiveTokenRefreshSettings {
            interval_secs,
            batch_size: batch_size.max(1),
            concurrency: concurrency.max(1),
        };

        {
            let mut current = self.proactive_refresh_settings.lock();
            if *current == settings {
                return;
            }
            *current = settings;
        }

        self.restart_proactive_token_refresh_task(settings);
    }

    fn restart_proactive_token_refresh_task(
        self: &Arc<Self>,
        settings: ProactiveTokenRefreshSettings,
    ) {
        if let Some(handle) = self.proactive_refresh_task.lock().take() {
            handle.abort();
        }

        if settings.interval_secs == 0 {
            tracing::info!("可用凭据 Token 后台预刷新已关闭");
            return;
        }

        tracing::info!(
            "可用凭据 Token 后台预刷新已启用：每 {} 秒最多刷新 {} 个凭据，并发 {}",
            settings.interval_secs,
            settings.batch_size,
            settings.concurrency
        );

        let manager = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut ticker = interval(StdDuration::from_secs(settings.interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                manager
                    .proactive_refresh_tokens_once(settings.batch_size, settings.concurrency)
                    .await;
            }
        });

        *self.proactive_refresh_task.lock() = Some(handle);
    }

    async fn proactive_refresh_tokens_once(&self, batch_size: usize, concurrency: usize) {
        let candidates = self.proactive_refresh_candidates(batch_size);
        if candidates.is_empty() {
            return;
        }

        let started_at = Instant::now();
        tracing::info!(
            "开始后台预刷新 {} 个可用凭据 Token，并发 {}",
            candidates.len(),
            concurrency
        );

        let outcomes = stream::iter(candidates)
            .map(|id| async move {
                match self.refresh_credentials_for(id, false, false).await {
                    Ok(_) => ProactiveRefreshOutcome::Refreshed,
                    Err(err) => {
                        if err.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                            self.report_refresh_token_invalid(id);
                            ProactiveRefreshOutcome::Invalid
                        } else if is_refresh_rate_limited_error(&err) {
                            self.report_background_transient_cooldown(
                                id,
                                Self::background_rate_limit_cooldown(),
                                "background token refresh rate limited",
                            );
                            tracing::debug!(
                                "凭据 #{} 后台预刷新被限流，进入运行时冷却: {}",
                                id,
                                err
                            );
                            ProactiveRefreshOutcome::RateLimited
                        } else {
                            tracing::debug!("凭据 #{} 后台预刷新失败，暂不禁用: {}", id, err);
                            ProactiveRefreshOutcome::Failed
                        }
                    }
                }
            })
            .buffer_unordered(concurrency.max(1))
            .collect::<Vec<_>>()
            .await;

        let refreshed = outcomes
            .iter()
            .filter(|&&outcome| outcome == ProactiveRefreshOutcome::Refreshed)
            .count();
        let invalid = outcomes
            .iter()
            .filter(|&&outcome| outcome == ProactiveRefreshOutcome::Invalid)
            .count();
        let rate_limited = outcomes
            .iter()
            .filter(|&&outcome| outcome == ProactiveRefreshOutcome::RateLimited)
            .count();
        let failed = outcomes
            .iter()
            .filter(|&&outcome| outcome == ProactiveRefreshOutcome::Failed)
            .count();

        if refreshed > 0 {
            if let Err(err) = self.persist_credentials() {
                tracing::warn!("后台预刷新 Token 后持久化失败: {}", err);
            }
        }

        tracing::info!(
            "后台预刷新完成：成功 {}，永久失效 {}，限流冷却 {}，暂时失败 {}，耗时 {}ms",
            refreshed,
            invalid,
            rate_limited,
            failed,
            started_at.elapsed().as_millis()
        );
    }

    fn proactive_refresh_candidates(&self, batch_size: usize) -> Vec<u64> {
        let entries = self.entries.lock();
        let total = entries.len();
        if total == 0 {
            return Vec::new();
        }

        let mut cursor = self.proactive_refresh_cursor.lock();
        if *cursor >= total {
            *cursor = 0;
        }

        let mut candidates = Vec::with_capacity(batch_size);
        let mut index = *cursor;

        for _ in 0..total {
            let entry = &entries[index];
            if !entry.disabled
                && !entry.credentials.is_api_key_credential()
                && (is_token_expired(&entry.credentials)
                    || is_token_expiring_soon(&entry.credentials))
            {
                candidates.push(entry.id);
                if candidates.len() >= batch_size {
                    index = (index + 1) % total;
                    break;
                }
            }

            index = (index + 1) % total;
        }

        *cursor = index;
        candidates
    }

    /// 启动可用凭据后台额度查询任务。
    ///
    /// 定期批量查询可用凭据的 getUsageLimits，将月度额度已用尽的凭据提前禁用，
    /// 避免耗尽只能在请求热路径上通过 402 被动发现。
    pub fn start_usage_query(self: Arc<Self>) {
        let settings = *self.usage_query_settings.lock();
        self.restart_usage_query_task(settings);
    }

    /// 热更新额度查询配置。间隔独立传入，每轮账号数与并发数复用 Token 预刷新参数。
    pub fn update_usage_query(
        self: &Arc<Self>,
        interval_secs: u64,
        batch_size: usize,
        concurrency: usize,
        disable_remaining_threshold: f64,
    ) {
        let settings = UsageQuerySettings {
            interval_secs,
            batch_size: batch_size.max(1),
            concurrency: concurrency.max(1),
            disable_remaining_threshold: disable_remaining_threshold.max(0.0),
        };

        {
            let mut current = self.usage_query_settings.lock();
            if *current == settings {
                return;
            }
            *current = settings;
        }

        self.restart_usage_query_task(settings);
    }

    fn restart_usage_query_task(self: &Arc<Self>, settings: UsageQuerySettings) {
        if let Some(handle) = self.usage_query_task.lock().take() {
            handle.abort();
        }

        if settings.interval_secs == 0 {
            tracing::info!("可用凭据后台额度查询已关闭");
            return;
        }

        tracing::info!(
            "可用凭据后台额度查询已启用：每 {} 秒最多查询 {} 个凭据，并发 {}，剩余额度禁用阈值 {}",
            settings.interval_secs,
            settings.batch_size,
            settings.concurrency,
            settings.disable_remaining_threshold
        );

        let manager = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut ticker = interval(StdDuration::from_secs(settings.interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                manager
                    .usage_query_once(
                        settings.batch_size,
                        settings.concurrency,
                        settings.disable_remaining_threshold,
                    )
                    .await;
            }
        });

        *self.usage_query_task.lock() = Some(handle);
    }

    async fn usage_query_once(
        &self,
        batch_size: usize,
        concurrency: usize,
        disable_remaining_threshold: f64,
    ) {
        let candidates = self.usage_query_candidates(batch_size);
        if candidates.is_empty() {
            return;
        }

        let started_at = Instant::now();
        tracing::info!(
            "开始后台额度查询 {} 个可用凭据，并发 {}",
            candidates.len(),
            concurrency
        );

        let outcomes = stream::iter(candidates)
            .map(|id| async move {
                match self.get_usage_limits_for(id).await {
                    Ok(usage) => {
                        if let Some((remaining, threshold, current_usage, usage_limit)) =
                            Self::usage_below_disable_threshold(
                                &usage,
                                disable_remaining_threshold,
                            )
                        {
                            self.report_quota_exhausted(id);
                            tracing::info!(
                                "后台额度查询：凭据 #{} 剩余额度 {} 小于阈值 {}（{} / {}），已提前禁用",
                                id,
                                remaining,
                                threshold,
                                current_usage,
                                usage_limit
                            );
                            UsageQueryOutcome::Exhausted
                        } else {
                            UsageQueryOutcome::Ok
                        }
                    }
                    Err(err) => {
                        if is_refresh_rate_limited_error(&err) {
                            self.report_background_transient_cooldown(
                                id,
                                Self::background_rate_limit_cooldown(),
                                "background usage query rate limited",
                            );
                            tracing::debug!("凭据 #{} 后台额度查询被限流，进入运行时冷却: {}", id, err);
                            UsageQueryOutcome::RateLimited
                        } else {
                            tracing::debug!("凭据 #{} 后台额度查询失败: {}", id, err);
                            UsageQueryOutcome::Failed
                        }
                    }
                }
            })
            .buffer_unordered(concurrency.max(1))
            .collect::<Vec<_>>()
            .await;

        let ok = outcomes
            .iter()
            .filter(|&&outcome| outcome == UsageQueryOutcome::Ok)
            .count();
        let exhausted = outcomes
            .iter()
            .filter(|&&outcome| outcome == UsageQueryOutcome::Exhausted)
            .count();
        let rate_limited = outcomes
            .iter()
            .filter(|&&outcome| outcome == UsageQueryOutcome::RateLimited)
            .count();
        let failed = outcomes
            .iter()
            .filter(|&&outcome| outcome == UsageQueryOutcome::Failed)
            .count();

        tracing::info!(
            "后台额度查询完成：正常 {}，已用尽禁用 {}，限流冷却 {}，失败 {}，耗时 {}ms",
            ok,
            exhausted,
            rate_limited,
            failed,
            started_at.elapsed().as_millis()
        );
    }

    /// 挑选后台额度查询候选：未禁用的凭据，按游标轮转避免饥饿。
    fn usage_query_candidates(&self, batch_size: usize) -> Vec<u64> {
        let entries = self.entries.lock();
        let total = entries.len();
        if total == 0 {
            return Vec::new();
        }

        let mut cursor = self.usage_query_cursor.lock();
        if *cursor >= total {
            *cursor = 0;
        }

        let mut candidates = Vec::with_capacity(batch_size);
        let mut index = *cursor;

        for _ in 0..total {
            let entry = &entries[index];
            if !entry.disabled {
                candidates.push(entry.id);
                if candidates.len() >= batch_size {
                    index = (index + 1) % total;
                    break;
                }
            }

            index = (index + 1) % total;
        }

        *cursor = index;
        candidates
    }

    async fn recover_disabled_credentials_once(&self, batch_size: usize) {
        let candidates = self.disabled_recovery_candidates(batch_size);
        if candidates.is_empty() {
            return;
        }

        if let Err(err) = self.persist_credentials() {
            tracing::debug!("禁用凭据恢复探测时间持久化失败: {}", err);
        }

        tracing::info!("开始检查 {} 个禁用凭据是否可恢复", candidates.len());

        for (id, reason) in candidates {
            match self.probe_disabled_credential(id, reason).await {
                Ok(Some(updated_credentials)) => {
                    if let Err(err) = self.enable_recovered_credential(id, updated_credentials) {
                        tracing::warn!("凭据 #{} 恢复成功但持久化失败: {}", id, err);
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    if Self::is_account_suspended_error(&err.to_string()) {
                        self.report_account_suspended(id);
                        continue;
                    }
                    tracing::debug!("凭据 #{} 禁用恢复探测仍不可用（{:?}）: {}", id, reason, err);
                }
            }
        }
    }

    fn is_account_suspended_error(message: &str) -> bool {
        let message = message.to_ascii_lowercase();
        message.contains("temporarily is suspended")
            || message.contains("temporarily suspended")
            || message.contains("locked your account as a security precaution")
    }

    fn disabled_recovery_candidates(&self, batch_size: usize) -> Vec<(u64, DisabledReason)> {
        let mut entries = self.entries.lock();
        let total = entries.len();
        if total == 0 {
            return Vec::new();
        }

        let mut cursor = self.disabled_recovery_cursor.lock();
        if *cursor >= total {
            *cursor = 0;
        }

        let mut candidates = Vec::with_capacity(batch_size);
        let mut index = *cursor;

        for _ in 0..total {
            let entry = &mut entries[index];
            if entry.disabled {
                let reason = entry.disabled_reason.unwrap_or(DisabledReason::Manual);
                if Self::should_probe_disabled_reason(reason) {
                    if reason == DisabledReason::QuotaExceeded
                        && entry
                            .credentials
                            .quota_last_probed_at
                            .as_deref()
                            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                            .map(|last| {
                                Utc::now().signed_duration_since(last.with_timezone(&Utc))
                                    < Duration::hours(24)
                            })
                            .unwrap_or(false)
                    {
                        index = (index + 1) % total;
                        continue;
                    }

                    if reason == DisabledReason::QuotaExceeded {
                        entry.credentials.quota_last_probed_at = Some(Utc::now().to_rfc3339());
                    }
                    candidates.push((entry.id, reason));
                    if candidates.len() >= batch_size {
                        index = (index + 1) % total;
                        break;
                    }
                }
            }

            index = (index + 1) % total;
        }

        *cursor = index;
        candidates
    }

    fn should_probe_disabled_reason(reason: DisabledReason) -> bool {
        matches!(
            reason,
            DisabledReason::Manual
                | DisabledReason::TooManyFailures
                | DisabledReason::TooManyRefreshFailures
                | DisabledReason::QuotaExceeded
        )
    }

    async fn probe_disabled_credential(
        &self,
        id: u64,
        reason: DisabledReason,
    ) -> anyhow::Result<Option<KiroCredentials>> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|entry| entry.id == id && entry.disabled)
                .map(|entry| entry.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在或已启用: {}", id))?
        };

        let (checked_credentials, token) = if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            (credentials, token)
        } else {
            let refreshed =
                if is_token_expired(&credentials) || is_token_expiring_soon(&credentials) {
                    let global_proxy = crate::http_client::global_proxy();
                    let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
                    refresh_token(&credentials, &self.config, effective_proxy.as_ref()).await?
                } else {
                    credentials
                };
            let token = refreshed
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?;
            (refreshed, token)
        };

        let request_count = self.quota_request_count(id);
        let global_proxy = crate::http_client::global_proxy();
        let effective_proxy = checked_credentials.effective_proxy(global_proxy.as_ref());
        let usage_limits = get_usage_limits(
            &checked_credentials,
            &self.config,
            &token,
            effective_proxy.as_ref(),
        )
        .await?;
        usage_limits.quota_at(Utc::now().timestamp() as f64)?;
        self.save_verified_balance(id, &usage_limits, request_count);

        let disable_remaining_threshold =
            self.usage_query_settings.lock().disable_remaining_threshold;
        if let Some((remaining, threshold, current_usage, usage_limit)) =
            Self::usage_below_disable_threshold(&usage_limits, disable_remaining_threshold)
        {
            if reason != DisabledReason::QuotaExceeded {
                self.mark_disabled_as_quota_exceeded_after_probe(id);
            }
            tracing::debug!(
                "凭据 #{} 额度仍低于恢复阈值: 剩余 {} < 阈值 {}（{} / {}），保持禁用",
                id,
                remaining,
                threshold,
                current_usage,
                usage_limit
            );
            return Ok(None);
        }

        if reason == DisabledReason::QuotaExceeded {
            let usage_limit = usage_limits.usage_limit();
            let current_usage = usage_limits.current_usage();
            if usage_limit > 0.0 && current_usage >= usage_limit {
                tracing::debug!(
                    "凭据 #{} 额度仍未恢复: 当前用量 {} / 限额 {}",
                    id,
                    current_usage,
                    usage_limit
                );
                return Ok(None);
            }
        }

        let mut updated_credentials = checked_credentials;
        if let Some(subscription_title) = usage_limits.subscription_title() {
            updated_credentials.subscription_title = Some(subscription_title.to_string());
        }

        Ok(Some(updated_credentials))
    }

    fn mark_disabled_as_quota_exceeded_after_probe(&self, id: u64) {
        let mut changed = false;
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.id == id && entry.disabled)
            {
                entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
                entry.credentials.quota_last_probed_at = Some(Utc::now().to_rfc3339());
                entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;
                changed = true;
            }
        }

        if changed {
            if let Err(err) = self.persist_credential(id) {
                tracing::warn!("凭据 #{} 低余额恢复探测状态持久化失败: {}", id, err);
            }
        }
    }

    fn enable_recovered_credential(
        &self,
        id: u64,
        updated_credentials: KiroCredentials,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|entry| entry.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            if !entry.disabled {
                return Ok(());
            }

            let previous_reason = entry.disabled_reason;
            entry.credentials = updated_credentials;
            entry.failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
            tracing::info!(
                "凭据 #{} 禁用恢复探测通过，已重新启用（原原因: {:?}）",
                id,
                previous_reason
            );
        }

        self.persist_credential(id)?;
        Ok(())
    }

    /// 报告上游明确返回的账号暂时封禁，立即禁用且不进入自动恢复探测。
    pub fn report_account_suspended(&self, id: u64) -> bool {
        let mut persist_needed = false;
        let (result, found) = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|entry| entry.id == id) {
                Some(entry) => entry,
                None => return entries.iter().any(|entry| !entry.disabled),
            };

            if entry.disabled {
                if entry.disabled_reason != Some(DisabledReason::AccountSuspended) {
                    entry.disabled_reason = Some(DisabledReason::AccountSuspended);
                    persist_needed = true;
                    tracing::error!("凭据 #{} 已确认被上游暂时封禁，停止自动探测", id);
                }
                (entries.iter().any(|entry| !entry.disabled), true)
            } else {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::AccountSuspended);
                entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;
                persist_needed = true;

                tracing::error!("凭据 #{} 被上游暂时封禁，已停止自动探测", id);

                if let Some(next) = entries
                    .iter()
                    .filter(|entry| !entry.disabled)
                    .min_by_key(|entry| entry.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        "已切换到凭据 #{}（优先级 {}）",
                        next.id,
                        next.credentials.priority
                    );
                    (true, true)
                } else {
                    tracing::error!("所有凭据均已禁用！");
                    (false, true)
                }
            }
        };

        if found {
            self.record_request_stat(id, false);
            if persist_needed {
                if let Err(err) = self.persist_credential(id) {
                    tracing::warn!("凭据 #{} 暂时封禁状态持久化失败: {}", id, err);
                }
            }
        }
        result
    }

    /// 根据负载均衡模式选择下一个凭据
    ///
    /// - priority 模式：选择优先级最高（priority 最小）的可用凭据
    /// - balanced 模式：选择当前占用最少的可用凭据，并在并发相同时保持账号均衡
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    fn select_next_credential(
        &self,
        model: Option<&str>,
        preferred_account_ids: &[String],
        reserved_account_ids: &[String],
        excluded_ids: &HashSet<u64>,
    ) -> Option<(u64, KiroCredentials, RequestLease)> {
        let now = Instant::now();
        let settings = *self.rate_limit_settings.lock();
        let mode = self.load_balancing_mode.lock().clone();
        let global_rate_limited = if settings.global_enabled() {
            let mut global_request_starts = self.global_request_starts.lock();
            Self::prune_request_window(&mut global_request_starts, now, settings.global_window);
            Self::request_window_is_full(&global_request_starts, settings.global_max_requests)
        } else {
            false
        };

        let result = {
            let mut entries = self.entries.lock();

            for entry in entries.iter_mut() {
                if entry
                    .cooldown_until
                    .is_some_and(|cooldown_until| cooldown_until <= now)
                {
                    entry.cooldown_until = None;
                    entry.cooldown_reason = None;
                }
                if settings.per_credential_enabled() {
                    Self::prune_request_window(
                        &mut entry.recent_request_starts,
                        now,
                        settings.per_credential_window,
                    );
                }
            }

            if global_rate_limited {
                return None;
            }

            // 检查是否是 opus 模型
            let is_opus = model
                .map(|m| m.to_lowercase().contains("opus"))
                .unwrap_or(false);

            // 过滤可用且尚有并发槽位的凭据
            let available: Vec<_> = entries
                .iter()
                .filter(|e| {
                    if e.disabled
                        || excluded_ids.contains(&e.id)
                        || e.request_slots.available_permits() == 0
                        || e.cooldown_until
                            .is_some_and(|cooldown_until| cooldown_until > now)
                        || (settings.per_credential_enabled()
                            && Self::request_window_is_full(
                                &e.recent_request_starts,
                                settings.per_credential_max_requests,
                            ))
                    {
                        return false;
                    }
                    // 如果是 opus 模型，需要检查订阅等级
                    if is_opus && !e.credentials.supports_opus() {
                        return false;
                    }
                    true
                })
                .collect();

            if available.is_empty() {
                return None;
            }

            let mode = mode.as_str();

            let id = match mode {
                "balanced" => {
                    let cache_candidates: Vec<_> = if preferred_account_ids.is_empty() {
                        Vec::new()
                    } else {
                        available
                            .iter()
                            .copied()
                            .filter(|entry| {
                                let manager_id = entry.id.to_string();
                                let credential_id = entry.credentials.id.map(|id| id.to_string());
                                preferred_account_ids.iter().any(|preferred_id| {
                                    preferred_id == &manager_id
                                        || credential_id.as_deref() == Some(preferred_id.as_str())
                                })
                            })
                            .collect()
                    };
                    let has_cache_candidates = !cache_candidates.is_empty();
                    let candidates = if has_cache_candidates {
                        cache_candidates
                    } else {
                        let ready_available: Vec<_> = available
                            .iter()
                            .copied()
                            .filter(|entry| {
                                Self::credential_ready_without_refresh(&entry.credentials)
                            })
                            .collect();
                        let candidates = if ready_available.is_empty() {
                            available
                        } else {
                            ready_available
                        };
                        let max_slots = self.config.max_concurrent_requests_per_credential.max(1);
                        let min_in_flight = candidates
                            .iter()
                            .map(|entry| {
                                max_slots.saturating_sub(entry.request_slots.available_permits())
                            })
                            .min()?;
                        let balanced_candidates: Vec<_> = candidates
                            .iter()
                            .copied()
                            .filter(|entry| {
                                max_slots.saturating_sub(entry.request_slots.available_permits())
                                    == min_in_flight
                            })
                            .collect();
                        let unreserved_candidates: Vec<_> = balanced_candidates
                            .iter()
                            .copied()
                            .filter(|entry| !Self::account_id_matches(entry, reserved_account_ids))
                            .collect();

                        // 正常情况下缓存账号只给命中其缓存的请求使用；如果所有
                        // 空闲账号都被缓存保留，则允许兜底使用，避免普通请求永久等待。
                        if !reserved_account_ids.is_empty() && !unreserved_candidates.is_empty() {
                            unreserved_candidates
                        } else {
                            balanced_candidates
                        }
                    };

                    let selected = if has_cache_candidates {
                        // 多个缓存账号之间仍按最久未使用优先，既保留缓存命中范围，
                        // 又避免连续对话长期粘在最近用过的少数账号上。
                        candidates.iter().min_by(|left, right| {
                            Self::compare_last_used_at(
                                left.last_used_at.as_deref(),
                                right.last_used_at.as_deref(),
                            )
                            .then_with(|| {
                                Self::compare_upstream_header_latency(
                                    left.upstream_header_latency_ema_ms,
                                    right.upstream_header_latency_ema_ms,
                                )
                            })
                            .then_with(|| {
                                left.credentials.priority.cmp(&right.credentials.priority)
                            })
                            .then_with(|| left.id.cmp(&right.id))
                        })
                    } else {
                        // 没有缓存命中时，最久未使用优先，保持账号均衡；
                        // latency 只作为 last_used_at 打平时的辅助排序。
                        candidates.iter().min_by(|left, right| {
                            Self::compare_last_used_at(
                                left.last_used_at.as_deref(),
                                right.last_used_at.as_deref(),
                            )
                            .then_with(|| {
                                Self::compare_upstream_header_latency(
                                    left.upstream_header_latency_ema_ms,
                                    right.upstream_header_latency_ema_ms,
                                )
                            })
                            .then_with(|| {
                                left.credentials.priority.cmp(&right.credentials.priority)
                            })
                            .then_with(|| left.id.cmp(&right.id))
                        })
                    };
                    selected?.id
                }
                _ => {
                    // priority 模式也优先复用命中 Prompt Cache 的账号。
                    let preferred = available
                        .iter()
                        .filter(|entry| Self::account_id_matches(entry, preferred_account_ids))
                        .min_by_key(|entry| (entry.credentials.priority, entry.id));
                    preferred
                        .or_else(|| {
                            available
                                .iter()
                                .min_by_key(|entry| (entry.credentials.priority, entry.id))
                        })?
                        .id
                }
            };

            let entry = entries.iter_mut().find(|candidate| candidate.id == id)?;
            let permit = entry.request_slots.clone().try_acquire_owned().ok()?;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            if settings.per_credential_enabled() {
                entry.recent_request_starts.push_back(now);
            }
            let entry_id = entry.id;
            let credentials = entry.credentials.clone();
            drop(entries);

            if settings.global_enabled() {
                self.global_request_starts.lock().push_back(now);
            }

            Some((entry_id, credentials, RequestLease::new(permit)))
        };

        if result.is_some() {
            self.save_stats_debounced();
        }
        result
    }

    fn account_id_matches(entry: &CredentialEntry, account_ids: &[String]) -> bool {
        let manager_id = entry.id.to_string();
        let credential_id = entry.credentials.id.map(|id| id.to_string());
        account_ids.iter().any(|account_id| {
            account_id == &manager_id || credential_id.as_deref() == Some(account_id.as_str())
        })
    }

    fn credential_ready_without_refresh(credentials: &KiroCredentials) -> bool {
        credentials.is_api_key_credential()
            || (!is_token_expired(credentials) && !is_token_expiring_soon(credentials))
    }

    fn matching_cache_accounts_are_busy(
        &self,
        model: Option<&str>,
        preferred_account_ids: &[String],
        excluded_ids: &HashSet<u64>,
    ) -> bool {
        if preferred_account_ids.is_empty() {
            return false;
        }

        let now = Instant::now();
        let settings = *self.rate_limit_settings.lock();
        let is_opus = model
            .map(|model| model.to_lowercase().contains("opus"))
            .unwrap_or(false);
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if settings.per_credential_enabled() {
                Self::prune_request_window(
                    &mut entry.recent_request_starts,
                    now,
                    settings.per_credential_window,
                );
            }
        }

        let mut found_busy = false;
        for entry in entries.iter() {
            let eligible = Self::account_id_matches(entry, preferred_account_ids)
                && !entry.disabled
                && !excluded_ids.contains(&entry.id)
                && entry
                    .cooldown_until
                    .is_none_or(|cooldown_until| cooldown_until <= now)
                && (!settings.per_credential_enabled()
                    || !Self::request_window_is_full(
                        &entry.recent_request_starts,
                        settings.per_credential_max_requests,
                    ))
                && (!is_opus || entry.credentials.supports_opus());
            if !eligible {
                continue;
            }
            if entry.request_slots.available_permits() > 0 {
                return false;
            }
            found_busy = true;
        }
        found_busy
    }

    fn compare_last_used_at(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
        match (left, right) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => left.cmp(right),
        }
    }

    fn compare_upstream_header_latency(
        left: Option<f64>,
        right: Option<f64>,
    ) -> std::cmp::Ordering {
        match (left, right) {
            (Some(left), Some(right)) => left
                .partial_cmp(&right)
                .unwrap_or(std::cmp::Ordering::Equal),
            _ => std::cmp::Ordering::Equal,
        }
    }

    fn background_rate_limit_cooldown() -> StdDuration {
        StdDuration::from_secs(60)
    }

    fn prune_request_window(queue: &mut VecDeque<Instant>, now: Instant, window: StdDuration) {
        while queue
            .front()
            .is_some_and(|started_at| now.duration_since(*started_at) >= window)
        {
            queue.pop_front();
        }
    }

    fn request_window_is_full(queue: &VecDeque<Instant>, max_requests: usize) -> bool {
        max_requests > 0 && queue.len() >= max_requests
    }

    fn request_window_delay(
        queue: &VecDeque<Instant>,
        now: Instant,
        window: StdDuration,
    ) -> Option<StdDuration> {
        queue
            .front()
            .and_then(|started_at| started_at.checked_add(window))
            .and_then(|until| until.checked_duration_since(now))
    }

    fn next_blocked_delay(
        &self,
        model: Option<&str>,
        tried_ids: &HashSet<u64>,
    ) -> Option<StdDuration> {
        let now = Instant::now();
        let settings = *self.rate_limit_settings.lock();
        let is_opus = model
            .map(|m| m.to_lowercase().contains("opus"))
            .unwrap_or(false);
        let mut delays = Vec::new();

        let global_delay = if settings.global_enabled() {
            let mut global_request_starts = self.global_request_starts.lock();
            Self::prune_request_window(&mut global_request_starts, now, settings.global_window);
            if Self::request_window_is_full(&global_request_starts, settings.global_max_requests) {
                Self::request_window_delay(&global_request_starts, now, settings.global_window)
            } else {
                None
            }
        } else {
            None
        };

        let mut entries = self.entries.lock();
        for entry in entries.iter_mut().filter(|entry| {
            !entry.disabled
                && !tried_ids.contains(&entry.id)
                && (entry.request_slots.available_permits() > 0)
                && (!is_opus || entry.credentials.supports_opus())
        }) {
            if let Some(delay) = entry
                .cooldown_until
                .and_then(|until| until.checked_duration_since(now))
            {
                delays.push(delay);
            }

            if settings.per_credential_enabled() {
                Self::prune_request_window(
                    &mut entry.recent_request_starts,
                    now,
                    settings.per_credential_window,
                );
                if Self::request_window_is_full(
                    &entry.recent_request_starts,
                    settings.per_credential_max_requests,
                ) {
                    if let Some(delay) = Self::request_window_delay(
                        &entry.recent_request_starts,
                        now,
                        settings.per_credential_window,
                    ) {
                        delays.push(delay);
                    }
                }
            }

            if let Some(delay) = global_delay {
                delays.push(delay);
            }
        }

        delays.into_iter().min()
    }

    /// 获取 API 调用上下文
    ///
    /// 返回绑定了 id、credentials 和 token 的调用上下文
    /// 确保整个 API 调用过程中使用一致的凭据信息
    ///
    /// 如果 Token 过期或即将过期，会自动刷新
    /// Token 刷新失败会累计到当前凭据，达到阈值后禁用并切换
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    pub async fn acquire_context(&self, model: Option<&str>) -> anyhow::Result<CallContext> {
        self.acquire_context_with_preferred_accounts_and_reserved_accounts(model, &[], &[])
            .await
    }

    /// 获取 API 调用上下文，并在 balanced 模式下优先尝试已有 Prompt Cache 的账号。
    pub async fn acquire_context_with_preferred_accounts(
        &self,
        model: Option<&str>,
        preferred_account_ids: &[String],
    ) -> anyhow::Result<CallContext> {
        self.acquire_context_with_preferred_accounts_and_reserved_accounts(
            model,
            preferred_account_ids,
            &[],
        )
        .await
    }

    /// 获取 API 调用上下文，并在 balanced 模式下保留已有 Prompt Cache 的账号。
    pub async fn acquire_context_with_preferred_accounts_and_reserved_accounts(
        &self,
        model: Option<&str>,
        preferred_account_ids: &[String],
        reserved_account_ids: &[String],
    ) -> anyhow::Result<CallContext> {
        let total = self.total_count();
        let max_attempts = total.min(10).max(1);
        let mut attempt_count = 0;
        let mut tried_ids = HashSet::new();
        let cache_wait = StdDuration::from_secs(
            self.cache_account_wait_seconds
                .load(Ordering::Relaxed)
                .min(60),
        );
        let cache_wait_deadline = Instant::now() + cache_wait;
        let mut cache_wait_timed_out = false;

        loop {
            if attempt_count >= max_attempts {
                anyhow::bail!(
                    "本次请求已尝试 {} 个不同凭据，仍无法获取有效 Token（可用: {}/{}）",
                    attempt_count,
                    self.available_count(),
                    total
                );
            }

            if attempt_count == 0
                && !preferred_account_ids.is_empty()
                && !cache_wait_timed_out
                && self.matching_cache_accounts_are_busy(model, preferred_account_ids, &tried_ids)
            {
                if !cache_wait.is_zero() && Instant::now() < cache_wait_deadline {
                    sleep(StdDuration::from_millis(10)).await;
                    continue;
                }
                cache_wait_timed_out = true;
                tracing::info!(
                    "Prompt Cache 命中账号并发等待超时（{} 秒），降级到普通账号调度",
                    cache_wait.as_secs()
                );
            }

            let (id, credentials, request_lease) = {
                let mode = self.load_balancing_mode.lock().clone();
                let is_dynamic_mode = mode == "balanced";
                let preferred_for_attempt: &[String] = if attempt_count == 0 {
                    preferred_account_ids
                } else {
                    &[]
                };

                // balanced 模式：每次请求都重新均衡选择，不固定 current_id
                // priority 模式：优先使用 current_id 指向的凭据
                let current_hit = if is_dynamic_mode || !preferred_for_attempt.is_empty() {
                    None
                } else {
                    let now = Instant::now();
                    let settings = *self.rate_limit_settings.lock();
                    let global_rate_limited = if settings.global_enabled() {
                        let mut global_request_starts = self.global_request_starts.lock();
                        Self::prune_request_window(
                            &mut global_request_starts,
                            now,
                            settings.global_window,
                        );
                        Self::request_window_is_full(
                            &global_request_starts,
                            settings.global_max_requests,
                        )
                    } else {
                        false
                    };

                    let result = if global_rate_limited {
                        None
                    } else {
                        let mut entries = self.entries.lock();
                        let current_id = *self.current_id.lock();
                        for entry in entries.iter_mut() {
                            if entry
                                .cooldown_until
                                .is_some_and(|cooldown_until| cooldown_until <= now)
                            {
                                entry.cooldown_until = None;
                                entry.cooldown_reason = None;
                            }
                            if settings.per_credential_enabled() {
                                Self::prune_request_window(
                                    &mut entry.recent_request_starts,
                                    now,
                                    settings.per_credential_window,
                                );
                            }
                        }
                        entries
                            .iter_mut()
                            .find(|e| {
                                e.id == current_id
                                    && !e.disabled
                                    && !tried_ids.contains(&e.id)
                                    && e.cooldown_until.is_none_or(|cooldown_until| {
                                        cooldown_until <= Instant::now()
                                    })
                                    && (!settings.per_credential_enabled()
                                        || !Self::request_window_is_full(
                                            &e.recent_request_starts,
                                            settings.per_credential_max_requests,
                                        ))
                            })
                            .and_then(|entry| {
                                let permit =
                                    entry.request_slots.clone().try_acquire_owned().ok()?;
                                entry.last_used_at = Some(Utc::now().to_rfc3339());
                                if settings.per_credential_enabled() {
                                    entry.recent_request_starts.push_back(now);
                                }
                                Some((
                                    entry.id,
                                    entry.credentials.clone(),
                                    RequestLease::new(permit),
                                ))
                            })
                    };
                    if result.is_some() {
                        if settings.global_enabled() {
                            self.global_request_starts.lock().push_back(now);
                        }
                        self.save_stats_debounced();
                    }
                    result
                };

                if let Some(hit) = current_hit {
                    hit
                } else {
                    // 当前凭据不可用或 balanced 模式，根据负载均衡策略选择
                    let mut best = self.select_next_credential(
                        model,
                        preferred_for_attempt,
                        reserved_account_ids,
                        &tried_ids,
                    );

                    // 没有可用凭据：如果是"自动禁用导致全灭"，做一次类似重启的自愈
                    if best.is_none() {
                        let has_eligible_credential = {
                            let entries = self.entries.lock();
                            let is_opus = model
                                .map(|m| m.to_lowercase().contains("opus"))
                                .unwrap_or(false);
                            entries.iter().any(|e| {
                                !e.disabled
                                    && !tried_ids.contains(&e.id)
                                    && e.cooldown_until.is_none_or(|until| until <= Instant::now())
                                    && (!is_opus || e.credentials.supports_opus())
                            })
                        };

                        // 有可用账号但并发槽位都被占用时等待，而不是误报“全部禁用”。
                        if has_eligible_credential {
                            if let Some(wait) = self.next_blocked_delay(model, &tried_ids) {
                                sleep(wait.min(StdDuration::from_secs(5))).await;
                                continue;
                            }
                            sleep(StdDuration::from_millis(10)).await;
                            continue;
                        }

                        if let Some(wait) = self.next_blocked_delay(model, &tried_ids) {
                            sleep(wait.min(StdDuration::from_secs(5))).await;
                            continue;
                        }

                        let mut entries = self.entries.lock();
                        if entries.iter().any(|e| {
                            e.disabled && e.disabled_reason == Some(DisabledReason::TooManyFailures)
                        }) {
                            tracing::warn!(
                                "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
                            );
                            for e in entries.iter_mut() {
                                if e.disabled_reason == Some(DisabledReason::TooManyFailures) {
                                    e.disabled = false;
                                    e.disabled_reason = None;
                                    e.failure_count = 0;
                                }
                            }
                            drop(entries);
                            best = self.select_next_credential(
                                model,
                                preferred_for_attempt,
                                reserved_account_ids,
                                &tried_ids,
                            );
                        }
                    }

                    if let Some((new_id, new_creds, request_lease)) = best {
                        // 更新 current_id
                        let mut current_id = self.current_id.lock();
                        *current_id = new_id;
                        (new_id, new_creds, request_lease)
                    } else {
                        let entries = self.entries.lock();
                        // 注意：必须在 bail! 之前计算 available_count，
                        // 因为 available_count() 会尝试获取 entries 锁，
                        // 而此时我们已经持有该锁，会导致死锁
                        let available = entries.iter().filter(|e| !e.disabled).count();
                        anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                    }
                }
            };

            // 尝试获取/刷新 Token
            match self.try_ensure_token(id, &credentials, request_lease).await {
                Ok(ctx) => {
                    return Ok(ctx);
                }
                Err(e) => {
                    tried_ids.insert(id);
                    attempt_count = tried_ids.len();

                    if is_refresh_rate_limited_error(&e) {
                        self.report_background_transient_cooldown(
                            id,
                            Self::background_rate_limit_cooldown(),
                            "token refresh rate limited",
                        );
                        tracing::warn!(
                            "凭据 #{} Token 刷新被限流，本次请求切换其它凭据重试: {}",
                            id,
                            e
                        );
                        continue;
                    }

                    // refreshToken 永久失效 → 立即禁用，不累计重试
                    let has_available = if e.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                        tracing::warn!("凭据 #{} refreshToken 永久失效: {}", id, e);
                        self.report_refresh_token_invalid(id)
                    } else {
                        tracing::warn!("凭据 #{} Token 刷新失败: {}", id, e);
                        self.report_refresh_failure(id)
                    };
                    if !has_available {
                        anyhow::bail!("所有凭据均已禁用（0/{}）", total);
                    }
                }
            }
        }
    }

    /// 获取指定凭据的调用上下文，不允许回退到其它凭据。
    pub async fn acquire_context_for_credential_id(
        &self,
        credential_id: u64,
    ) -> anyhow::Result<CallContext> {
        let (credentials, request_lease) = {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|entry| entry.id == credential_id)
                .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", credential_id))?;

            if entry.disabled {
                anyhow::bail!("凭据 #{} 已禁用", credential_id);
            }

            let permit = entry
                .request_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow::anyhow!("凭据 #{} 当前并发已满", credential_id))?;

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            (entry.credentials.clone(), RequestLease::new(permit))
        };

        self.save_stats_debounced();
        self.try_ensure_token(credential_id, &credentials, request_lease)
            .await
    }

    /// 选择优先级最高的未禁用凭据作为当前凭据（内部方法）
    ///
    /// 纯粹按优先级选择，不排除当前凭据，用于优先级变更后立即生效
    fn select_highest_priority(&self) {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（不排除当前凭据）
        if let Some(best) = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
        {
            if best.id != *current_id {
                tracing::info!(
                    "优先级变更后切换凭据: #{} -> #{}（优先级 {}）",
                    *current_id,
                    best.id,
                    best.credentials.priority
                );
                *current_id = best.id;
            }
        }
    }

    /// 尝试使用指定凭据获取有效 Token
    ///
    /// 使用双重检查锁定模式，确保同一凭据同一时间只有一个刷新操作。
    ///
    /// # Arguments
    /// * `id` - 凭据 ID，用于更新正确的条目
    /// * `credentials` - 凭据信息
    async fn try_ensure_token(
        &self,
        id: u64,
        credentials: &KiroCredentials,
        request_lease: RequestLease,
    ) -> anyhow::Result<CallContext> {
        // API Key 凭据直接使用 kiro_api_key 作为 Bearer Token，无需刷新
        if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok(CallContext {
                id,
                credentials: credentials.clone(),
                token,
                request_lease: Some(request_lease),
            });
        }

        // 第一次检查（无锁）：快速判断是否需要刷新
        let needs_refresh = is_token_expired(credentials) || is_token_expiring_soon(credentials);

        let creds = if needs_refresh {
            self.refresh_credentials_for(id, false, true).await?
        } else {
            credentials.clone()
        };

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.refresh_failure_count = 0;
            }
        }

        Ok(CallContext {
            id,
            credentials: creds,
            token,
            request_lease: Some(request_lease),
        })
    }

    async fn refresh_credentials_for(
        &self,
        id: u64,
        force: bool,
        persist: bool,
    ) -> anyhow::Result<KiroCredentials> {
        let refresh_lock = self.refresh_lock_for(id);
        let _guard = refresh_lock.lock().await;

        let current_creds = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?
        };

        if current_creds.is_api_key_credential() {
            if force {
                anyhow::bail!("API Key 凭据不支持刷新 Token");
            }
            return Ok(current_creds);
        }

        let needs_refresh =
            force || is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds);
        if !needs_refresh {
            tracing::debug!("Token 已被其他请求刷新，跳过刷新");
            return Ok(current_creds);
        }

        let global_proxy = crate::http_client::global_proxy();
        let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
        let new_creds =
            refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;

        if is_token_expired(&new_creds) {
            anyhow::bail!("刷新后的 Token 仍然无效或已过期");
        }

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials = new_creds.clone();
                entry.refresh_failure_count = 0;
            }
        }

        if persist {
            if let Err(e) = self.persist_credential(id) {
                tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
            }
        }

        Ok(new_creds)
    }

    fn credential_for_persistence(&self, id: u64) -> Option<KiroCredentials> {
        let entries = self.entries.lock();
        entries.iter().find(|entry| entry.id == id).map(|entry| {
            let mut credential = entry.credentials.clone();
            credential.canonicalize_auth_method();
            credential.disabled = entry.disabled;
            credential.disabled_reason = entry
                .disabled_reason
                .map(|reason| reason.as_str().to_string());
            credential.quota_last_probed_at = entry.credentials.quota_last_probed_at.clone();
            credential
        })
    }

    fn persist_credential(&self, id: u64) -> anyhow::Result<bool> {
        let Some(credential) = self.credential_for_persistence(id) else {
            return Ok(false);
        };
        self.credential_store.save_one(&credential)
    }

    /// 将凭据列表写回当前存储后端。
    fn persist_credentials(&self) -> anyhow::Result<bool> {
        let credentials: Vec<KiroCredentials> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    let mut cred = e.credentials.clone();
                    cred.canonicalize_auth_method();
                    cred.disabled = e.disabled;
                    cred.disabled_reason =
                        e.disabled_reason.map(|reason| reason.as_str().to_string());
                    cred.quota_last_probed_at = e.credentials.quota_last_probed_at.clone();
                    cred
                })
                .collect()
        };

        self.credential_store.save_all(&credentials)
    }

    /// 获取缓存目录（凭据文件或 SQLite 数据库所在目录）
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.credential_store.cache_dir()
    }

    /// 统计数据文件路径
    fn stats_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_stats.json"))
    }

    fn balance_cache_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_balance_cache.json"))
    }

    pub(crate) fn load_balance_cache_from(
        cache_path: &Option<PathBuf>,
    ) -> HashMap<u64, CachedBalance> {
        let path = match cache_path {
            Some(p) => p,
            None => return HashMap::new(),
        };

        with_balance_cache_file_lock(|| {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return HashMap::new(),
            };

            // 文件中使用字符串 key 以兼容 JSON 格式
            let map: HashMap<String, CachedBalance> = match serde_json::from_str(&content) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("解析余额缓存失败，将忽略: {}", e);
                    return HashMap::new();
                }
            };

            map.into_iter()
                .filter_map(|(k, mut v)| {
                    let id = k.parse::<u64>().ok()?;
                    // 重启后必须重新向上游核实，不能把磁盘快照当作当前可用额度。
                    v.schema_version = 0;
                    Some((id, v))
                })
                .collect()
        })
    }

    pub(crate) fn balance_snapshot(&self) -> HashMap<u64, CachedBalance> {
        self.balance_cache.lock().clone()
    }

    fn save_verified_balance(
        &self,
        id: u64,
        usage: &UsageLimitsResponse,
        request_count: Option<u64>,
    ) {
        let Ok(balance) = CachedBalance::from_usage(id, usage, request_count) else {
            self.invalidate_balance(id);
            return;
        };
        self.balance_cache.lock().insert(id, balance);
        self.persist_balance_cache();
    }

    pub(crate) fn invalidate_balance(&self, id: u64) {
        self.balance_cache.lock().remove(&id);
        self.persist_balance_cache();
    }

    fn persist_balance_cache(&self) {
        let Some(path) = self.balance_cache_path() else {
            return;
        };
        with_balance_cache_file_lock(|| {
            // 只保存本进程核实后的状态，不从磁盘回读已失效的额度。
            let cache = self.balance_cache.lock();
            if let Err(error) = serde_json::to_vec_pretty(&*cache)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| std::fs::write(&path, bytes).map_err(anyhow::Error::from))
            {
                tracing::warn!("保存余额缓存失败: {error}");
            }
        });
    }

    fn usage_below_disable_threshold(
        usage: &UsageLimitsResponse,
        threshold: f64,
    ) -> Option<(f64, f64, f64, f64)> {
        let quota = usage.quota_at(Utc::now().timestamp() as f64).ok()?;
        let threshold = if threshold.is_finite() {
            threshold.max(0.0)
        } else {
            0.0
        };
        (quota.remaining <= 0.0 || quota.remaining < threshold).then_some((
            quota.remaining,
            threshold,
            quota.usage,
            quota.limit,
        ))
    }

    /// 从磁盘加载统计数据并应用到当前条目
    fn load_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };

        let stats: HashMap<String, StatsEntry> = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("解析统计缓存失败，将忽略: {}", e);
                return;
            }
        };

        let mut entries = self.entries.lock();
        let today_key = Self::current_day_key();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.last_used_at = s.last_used_at.clone();
                entry.total_request_count = s.total_request_count.max(s.success_count);
                entry.total_token_count = s.total_token_count;
                if s.today_key.as_deref() == Some(today_key.as_str()) {
                    entry.today_key = s.today_key.clone();
                    entry.today_request_count = s.today_request_count;
                    entry.today_success_count = s.today_success_count;
                    entry.today_token_count = s.today_token_count;
                } else {
                    entry.today_key = Some(today_key.clone());
                    entry.today_request_count = 0;
                    entry.today_success_count = 0;
                    entry.today_token_count = 0;
                }
            }
        }
        *self.last_stats_save_at.lock() = Some(Instant::now());
        self.stats_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条统计数据", stats.len());
    }

    /// 将当前统计数据持久化到磁盘
    fn save_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let stats: HashMap<String, StatsEntry> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    (
                        e.id.to_string(),
                        StatsEntry {
                            success_count: e.success_count,
                            last_used_at: e.last_used_at.clone(),
                            total_request_count: e.total_request_count.max(e.success_count),
                            total_token_count: e.total_token_count,
                            today_key: e.today_key.clone(),
                            today_request_count: e.today_request_count,
                            today_success_count: e.today_success_count,
                            today_token_count: e.today_token_count,
                        },
                    )
                })
                .collect()
        };

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("保存统计缓存失败: {}", e);
                } else {
                    *self.last_stats_save_at.lock() = Some(Instant::now());
                    self.stats_dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化统计数据失败: {}", e),
        }
    }

    /// 标记统计数据已更新，并按 debounce 策略决定是否立即落盘
    fn save_stats_debounced(&self) {
        self.stats_dirty.store(true, Ordering::Relaxed);

        let should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if should_flush {
            self.save_stats();
        }
    }

    /// 报告指定凭据 API 调用成功
    ///
    /// 重置该凭据的失败计数
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_success(&self, id: u64) {
        let mut found = false;
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                found = true;
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.cooldown_until = None;
                entry.cooldown_reason = None;
                entry.success_count += 1;
                tracing::debug!(
                    "凭据 #{} API 调用成功（累计 {} 次）",
                    id,
                    entry.success_count
                );
            }
        }
        if found {
            self.record_request_stat(id, true);
        }
    }

    fn set_transient_cooldown_locked(
        entry: &mut CredentialEntry,
        cooldown: StdDuration,
        reason: &str,
    ) {
        let until = Instant::now()
            .checked_add(cooldown)
            .unwrap_or_else(Instant::now);
        match entry.cooldown_until {
            Some(current_until) if current_until >= until => {}
            _ => {
                entry.cooldown_until = Some(until);
            }
        }
        entry.cooldown_reason = Some(reason.to_string());
    }

    fn report_transient_cooldown_inner(
        &self,
        id: u64,
        cooldown: StdDuration,
        reason: String,
        count_request_stat: bool,
    ) -> bool {
        let found = {
            let mut entries = self.entries.lock();
            let Some(entry) = entries.iter_mut().find(|e| e.id == id) else {
                return entries.iter().any(|e| !e.disabled);
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            Self::set_transient_cooldown_locked(entry, cooldown, &reason);
            tracing::warn!(
                "凭据 #{} 进入瞬态冷却（{} 秒，原因: {}）",
                id,
                cooldown.as_secs().max(1),
                reason
            );
            true
        };

        if found && count_request_stat {
            self.record_request_stat(id, false);
        }
        self.entries.lock().iter().any(|e| !e.disabled)
    }

    /// 报告指定凭据遭遇瞬态错误，进入短暂冷却期。
    pub fn report_transient_cooldown(
        &self,
        id: u64,
        cooldown: StdDuration,
        reason: impl Into<String>,
    ) -> bool {
        self.report_transient_cooldown_inner(id, cooldown, reason.into(), true)
    }

    fn report_background_transient_cooldown(
        &self,
        id: u64,
        cooldown: StdDuration,
        reason: impl Into<String>,
    ) -> bool {
        self.report_transient_cooldown_inner(id, cooldown, reason.into(), false)
    }

    /// 报告指定凭据 API 调用失败
    ///
    /// 增加失败计数，达到阈值时禁用凭据并切换到优先级最高的可用凭据
    /// 返回是否还有可用凭据可以重试
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_failure(&self, id: u64) -> bool {
        let (result, found, persist_needed) = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.failure_count += 1;
            let failure_count = entry.failure_count;

            tracing::warn!(
                "凭据 #{} API 调用失败（{}/{}）",
                id,
                failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::TooManyFailures);
                tracing::error!("凭据 #{} 已连续失败 {} 次，已被禁用", id, failure_count);

                // 切换到优先级最高的可用凭据
                if let Some(next) = entries
                    .iter()
                    .filter(|e| !e.disabled)
                    .min_by_key(|e| e.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        "已切换到凭据 #{}（优先级 {}）",
                        next.id,
                        next.credentials.priority
                    );
                } else {
                    tracing::error!("所有凭据均已禁用！");
                }
            }

            (
                entries.iter().any(|e| !e.disabled),
                true,
                failure_count >= MAX_FAILURES_PER_CREDENTIAL,
            )
        };
        if found {
            self.record_request_stat(id, false);
            if persist_needed {
                if let Err(err) = self.persist_credential(id) {
                    tracing::warn!("账号失败禁用状态持久化失败: {}", err);
                }
            }
        }
        result
    }

    /// 报告指定凭据额度已用尽
    ///
    /// 用于处理 402 Payment Required 且 reason 为 `MONTHLY_REQUEST_COUNT` 的场景：
    /// - 立即禁用该凭据（不等待连续失败阈值）
    /// - 切换到下一个可用凭据继续重试
    /// - 返回是否还有可用凭据
    pub fn report_quota_exhausted(&self, id: u64) -> bool {
        let (result, found) = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
            entry.credentials.quota_last_probed_at = None;
            // 设为阈值，便于在管理面板中直观看到该凭据已不可用
            entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;

            tracing::error!("凭据 #{} 额度已用尽（MONTHLY_REQUEST_COUNT），已被禁用", id);

            // 切换到优先级最高的可用凭据
            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                (true, true)
            } else {
                tracing::error!("所有凭据均已禁用！");
                (false, true)
            }
        };
        if found {
            self.record_request_stat(id, false);
            if let Err(err) = self.persist_credential(id) {
                tracing::warn!("额度用尽禁用状态持久化失败: {}", err);
            }
        }
        result
    }

    /// 报告指定凭据刷新 Token 失败。
    ///
    /// 连续刷新失败达到阈值后禁用凭据并切换，阈值内保持当前凭据不切换，
    /// 与 API 401/403 的累计失败策略保持一致。
    pub fn report_refresh_failure(&self, id: u64) -> bool {
        let should_record;
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.refresh_failure_count += 1;
            let refresh_failure_count = entry.refresh_failure_count;
            should_record = true;

            tracing::warn!(
                "凭据 #{} Token 刷新失败（{}/{}）",
                id,
                refresh_failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if refresh_failure_count < MAX_FAILURES_PER_CREDENTIAL {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::TooManyRefreshFailures);

            tracing::error!(
                "凭据 #{} Token 已连续刷新失败 {} 次，已被禁用",
                id,
                refresh_failure_count
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        if should_record {
            self.record_request_stat(id, false);
        }
        result
    }

    /// 报告指定凭据的刷新凭据永久失效（invalid_grant/access_denied）。
    ///
    /// 立即禁用凭据，不累计、不重试。
    /// 返回是否还有可用凭据。
    pub fn report_refresh_token_invalid(&self, id: u64) -> bool {
        let (result, found) = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::InvalidRefreshToken);

            tracing::error!("凭据 #{} 刷新凭据已失效，已立即禁用", id);

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                (true, true)
            } else {
                tracing::error!("所有凭据均已禁用！");
                (false, true)
            }
        };
        if found {
            self.record_request_stat(id, false);
            if let Err(err) = self.persist_credential(id) {
                tracing::warn!("refreshToken 失效状态持久化失败: {}", err);
            }
        }
        result
    }

    /// 切换到优先级最高的可用凭据
    ///
    /// 返回是否成功切换
    pub fn switch_to_next(&self) -> bool {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（排除当前凭据）
        if let Some(next) = entries
            .iter()
            .filter(|e| !e.disabled && e.id != *current_id)
            .min_by_key(|e| e.credentials.priority)
        {
            *current_id = next.id;
            tracing::info!(
                "已切换到凭据 #{}（优先级 {}）",
                next.id,
                next.credentials.priority
            );
            true
        } else {
            // 没有其他可用凭据，检查当前凭据是否可用
            entries.iter().any(|e| e.id == *current_id && !e.disabled)
        }
    }

    // ========================================================================
    // Admin API 方法
    // ========================================================================

    /// 获取管理器状态快照（用于 Admin API）
    pub fn snapshot(&self) -> ManagerSnapshot {
        self.snapshot_internal(true)
    }

    /// 获取不包含凭据去重哈希的轻量快照（用于分页列表）
    pub fn snapshot_without_hashes(&self) -> ManagerSnapshot {
        self.snapshot_internal(false)
    }

    /// 获取指定凭据的持久化展示方案。
    pub fn display_metadata(&self, id: u64) -> (Option<String>, Option<f64>) {
        let entries = self.entries.lock();
        entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| {
                if KiroCredentials::is_free_subscription_title(
                    entry.credentials.subscription_title.as_deref(),
                ) {
                    (
                        entry.credentials.display_subscription_title.clone(),
                        entry.credentials.display_usage_limit,
                    )
                } else {
                    (None, None)
                }
            })
            .unwrap_or((None, None))
    }

    fn snapshot_internal(&self, include_hashes: bool) -> ManagerSnapshot {
        let now = Instant::now();
        let settings = *self.rate_limit_settings.lock();
        let global_ready = !settings.global_enabled()
            || self
                .global_request_starts
                .lock()
                .iter()
                .filter(|time| now.duration_since(**time) < settings.global_window)
                .count()
                < settings.global_max_requests;
        let entries = self.entries.lock();
        let current_id = *self.current_id.lock();
        let available = entries.iter().filter(|e| !e.disabled).count();
        let total_success_count = entries.iter().map(|e| e.success_count).sum();
        let total_request_count = entries.iter().map(|e| e.total_request_count).sum();
        let total_token_count = entries.iter().map(|e| e.total_token_count).sum();
        let today_request_count = entries.iter().map(|e| e.today_request_count).sum();
        let today_token_count = entries.iter().map(|e| e.today_token_count).sum();
        let today_success_count = entries.iter().map(|e| e.today_success_count).sum();
        let quota_exceeded = entries
            .iter()
            .filter(|e| e.disabled_reason == Some(DisabledReason::QuotaExceeded))
            .count();

        ManagerSnapshot {
            entries: entries
                .iter()
                .map(|e| CredentialEntrySnapshot {
                    id: e.id,
                    priority: e.credentials.priority,
                    disabled: e.disabled,
                    callable: !e.disabled
                        && global_ready
                        && e.cooldown_until.is_none_or(|until| until <= now)
                        && e.request_slots.available_permits() > 0
                        && (!settings.per_credential_enabled()
                            || e.recent_request_starts
                                .iter()
                                .filter(|time| {
                                    now.duration_since(**time) < settings.per_credential_window
                                })
                                .count()
                                < settings.per_credential_max_requests),
                    failure_count: e.failure_count,
                    auth_method: if e.credentials.is_api_key_credential() {
                        Some("api_key".to_string())
                    } else {
                        e.credentials.auth_method.as_deref().map(|m| {
                            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam")
                            {
                                "idc".to_string()
                            } else {
                                m.to_string()
                            }
                        })
                    },
                    has_profile_arn: e.credentials.profile_arn.is_some(),
                    expires_at: if e.credentials.is_api_key_credential() {
                        None // API Key 凭据本地不维护过期时间（服务端策略未知）
                    } else {
                        e.credentials.expires_at.clone()
                    },
                    refresh_token_hash: if include_hashes && e.credentials.is_api_key_credential() {
                        None
                    } else if include_hashes {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    } else {
                        None
                    },
                    api_key_hash: if include_hashes && e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else if include_hashes {
                        None
                    } else {
                        None
                    },
                    masked_api_key: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(mask_api_key)
                    } else {
                        None
                    },
                    email: e.credentials.email.clone(),
                    success_count: e.success_count,
                    total_request_count: e.total_request_count,
                    quota_generation: e.quota_generation,
                    today_request_count: e.today_request_count,
                    today_success_count: e.today_success_count,
                    total_token_count: e.total_token_count,
                    today_token_count: e.today_token_count,
                    current_concurrent_requests: e
                        .max_concurrent_requests
                        .saturating_sub(e.request_slots.available_permits()),
                    upstream_header_latency_ema_ms: e
                        .upstream_header_latency_ema_ms
                        .map(|value| (value * 10.0).round() / 10.0),
                    last_used_at: e.last_used_at.clone(),
                    has_proxy: e.credentials.proxy_url.is_some(),
                    proxy_url: e.credentials.proxy_url.clone(),
                    refresh_failure_count: e.refresh_failure_count,
                    disabled_reason: e.disabled_reason.map(|r| {
                        match r {
                            DisabledReason::Manual
                            | DisabledReason::TooManyFailures
                            | DisabledReason::TooManyRefreshFailures
                            | DisabledReason::QuotaExceeded
                            | DisabledReason::InvalidRefreshToken
                            | DisabledReason::AccountSuspended
                            | DisabledReason::InvalidConfig => r.as_str(),
                        }
                        .to_string()
                    }),
                    endpoint: e.credentials.endpoint.clone(),
                    display_subscription_title: if KiroCredentials::is_free_subscription_title(
                        e.credentials.subscription_title.as_deref(),
                    ) {
                        e.credentials.display_subscription_title.clone()
                    } else {
                        None
                    },
                    display_usage_limit: if KiroCredentials::is_free_subscription_title(
                        e.credentials.subscription_title.as_deref(),
                    ) {
                        e.credentials.display_usage_limit
                    } else {
                        None
                    },
                })
                .collect(),
            current_id,
            total: entries.len(),
            available,
            rpm: self.current_rpm(),
            total_request_count,
            total_token_count,
            total_success_count,
            today_request_count,
            today_token_count,
            today_success_count,
            quota_exceeded,
        }
    }

    /// 设置凭据禁用状态（Admin API）
    pub fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = disabled;
            if !disabled {
                // 启用时重置失败计数
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.disabled_reason = None;
            } else {
                entry.disabled_reason = Some(DisabledReason::Manual);
            }
        }
        // 持久化更改
        self.persist_credential(id)?;
        Ok(())
    }

    /// 设置凭据优先级（Admin API）
    ///
    /// 修改优先级后会立即按新优先级重新选择当前凭据。
    /// 即使持久化失败，内存中的优先级和当前凭据选择也会生效。
    pub fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.priority = priority;
        }
        // 立即按新优先级重新选择当前凭据（无论持久化是否成功）
        self.select_highest_priority();
        // 持久化更改
        self.persist_credential(id)?;
        Ok(())
    }

    /// 设置凭据邮箱（Admin API）
    pub fn set_email(&self, id: u64, email: Option<String>) -> anyhow::Result<()> {
        let normalized_email = email
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.email = normalized_email;
        }

        self.persist_credential(id)?;
        Ok(())
    }

    /// 重置凭据失败计数并重新启用（Admin API）
    pub fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            if entry.disabled_reason == Some(DisabledReason::InvalidConfig) {
                anyhow::bail!("凭据 #{} 因配置无效被禁用，请修正配置后重启服务", id);
            }
            entry.failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
            entry.credentials.quota_last_probed_at = None;
        }
        // 持久化更改
        self.persist_credential(id)?;
        Ok(())
    }

    /// 获取指定凭据的使用额度（Admin API）
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let lock = self
            .usage_locks
            .lock()
            .entry(id)
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        let request_count = self.quota_request_count(id);
        let result = self.query_usage_limits_for(id, request_count).await;
        if result.is_err() {
            self.invalidate_balance(id);
        }
        result
    }

    async fn query_usage_limits_for(
        &self,
        id: u64,
        request_count: Option<u64>,
    ) -> anyhow::Result<UsageLimitsResponse> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 检查是否需要刷新 token
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let refreshed = match self.refresh_credentials_for(id, false, true).await {
                    Ok(credentials) => credentials,
                    Err(err) => {
                        if err.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                            self.report_refresh_token_invalid(id);
                        }
                        return Err(err);
                    }
                };
                refreshed
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let global_proxy = crate::http_client::global_proxy();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let usage_limits =
            get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await?;
        usage_limits.quota_at(Utc::now().timestamp() as f64)?;
        self.save_verified_balance(id, &usage_limits, request_count);

        let disable_remaining_threshold =
            self.usage_query_settings.lock().disable_remaining_threshold;
        if let Some((remaining, threshold, current_usage, usage_limit)) =
            Self::usage_below_disable_threshold(&usage_limits, disable_remaining_threshold)
        {
            self.report_quota_exhausted(id);
            tracing::info!(
                "额度查询：凭据 #{} 剩余额度 {} 小于阈值 {}（{} / {}），已禁用",
                id,
                remaining,
                threshold,
                current_usage,
                usage_limit
            );
        }

        // 更新订阅等级到凭据（仅在发生变化时持久化）
        if let Some(subscription_title) = usage_limits.subscription_title().map(str::to_owned) {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let old_title = entry.credentials.subscription_title.clone();
                    let mut changed = false;
                    if old_title.as_deref() != Some(subscription_title.as_str()) {
                        entry.credentials.subscription_title = Some(subscription_title.clone());
                        tracing::info!(
                            "凭据 #{} 订阅等级已更新: {:?} -> {}",
                            id,
                            old_title,
                            subscription_title
                        );
                        changed = true;
                    }
                    changed |= entry.credentials.ensure_display_metadata();
                    changed
                } else {
                    false
                }
            };

            if changed {
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("订阅等级更新后持久化失败（不影响本次请求）: {}", e);
                }
            }
        }

        Ok(usage_limits)
    }

    /// 添加新凭据（Admin API）
    ///
    /// # 流程
    /// 1. 验证凭据基本字段（API Key: kiroApiKey 不为空; OAuth: refreshToken 不为空）
    /// 2. 基于 kiroApiKey 或 refreshToken 的 SHA-256 哈希检测重复
    /// 3. OAuth: 尝试刷新 Token 验证凭据有效性; API Key: 跳过
    /// 4. 分配新 ID（当前最大 ID + 1）
    /// 5. 添加到 entries 列表
    /// 6. 持久化到配置文件
    ///
    /// # 返回
    /// - `Ok(u64)` - 新凭据 ID
    /// - `Err(_)` - 验证失败或添加失败
    pub async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        // 1. 基本验证
        if new_cred.is_api_key_credential() {
            let api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            if api_key.is_empty() {
                anyhow::bail!("kiroApiKey 为空");
            }
        } else {
            validate_refresh_token(&new_cred)?;
        }

        // 2. 基于哈希检测重复
        if new_cred.is_api_key_credential() {
            let new_api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?;
            let new_api_key_hash = sha256_hex(new_api_key);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（kiroApiKey 重复）");
            }
        } else {
            let new_refresh_token = new_cred
                .refresh_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;
            let new_refresh_token_hash = sha256_hex(new_refresh_token);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（refreshToken 重复）");
            }
        }

        // 3. 验证凭据有效性（API Key 无需网络刷新）
        let mut validated_cred = if new_cred.is_api_key_credential() {
            new_cred.clone()
        } else {
            let global_proxy = crate::http_client::global_proxy();
            let effective_proxy = new_cred.effective_proxy(global_proxy.as_ref());
            refresh_token(&new_cred, &self.config, effective_proxy.as_ref()).await?
        };

        let is_api_key_credential = new_cred.is_api_key_credential();
        let new_api_key_hash_for_insert = if is_api_key_credential {
            Some(sha256_hex(
                new_cred
                    .kiro_api_key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?,
            ))
        } else {
            None
        };
        let new_refresh_token_hash_for_insert = if is_api_key_credential {
            None
        } else {
            Some(sha256_hex(
                new_cred
                    .refresh_token
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?,
            ))
        };

        // 4. 设置用户输入的元数据
        validated_cred.priority = new_cred.priority;
        validated_cred.auth_method = new_cred.auth_method.clone().map(|m| {
            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam") {
                "idc".to_string()
            } else {
                m
            }
        });
        validated_cred.client_id = new_cred.client_id;
        validated_cred.client_secret = new_cred.client_secret;
        validated_cred.region = new_cred.region;
        validated_cred.auth_region = new_cred.auth_region;
        validated_cred.api_region = new_cred.api_region;
        validated_cred.machine_id = new_cred.machine_id;
        validated_cred.email = new_cred.email;
        validated_cred.proxy_url = new_cred.proxy_url;
        validated_cred.proxy_username = new_cred.proxy_username;
        validated_cred.proxy_password = new_cred.proxy_password;
        validated_cred.kiro_api_key = new_cred.kiro_api_key.clone();

        // 5. 在同一个 entries 锁内重新查重、分配 ID、追加 entries。
        // 批量导入会并发调用本接口，锁外分配 max(id)+1 会产生重复 ID。
        let new_id = {
            let mut entries = self.entries.lock();
            if let Some(new_api_key_hash) = new_api_key_hash_for_insert.as_deref() {
                let duplicate_exists = entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash)
                });
                if duplicate_exists {
                    anyhow::bail!("凭据已存在（kiroApiKey 重复）");
                }
            } else if let Some(new_refresh_token_hash) =
                new_refresh_token_hash_for_insert.as_deref()
            {
                let duplicate_exists = entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash)
                });
                if duplicate_exists {
                    anyhow::bail!("凭据已存在（refreshToken 重复）");
                }
            }

            let new_id = entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
            validated_cred.id = Some(new_id);
            entries.push(CredentialEntry {
                id: new_id,
                credentials: validated_cred,
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                total_request_count: 0,
                quota_generation: 0,
                total_token_count: 0,
                today_key: None,
                today_request_count: 0,
                today_success_count: 0,
                today_token_count: 0,
                last_used_at: None,
                max_concurrent_requests: self.config.max_concurrent_requests_per_credential.max(1),
                request_slots: Arc::new(Semaphore::new(
                    self.config.max_concurrent_requests_per_credential.max(1),
                )),
                upstream_header_latency_ema_ms: None,
                recent_request_starts: VecDeque::new(),
                cooldown_until: None,
                cooldown_reason: None,
            });
            new_id
        };

        // 6. 持久化
        self.persist_credential(new_id)?;

        tracing::info!("成功添加凭据 #{}", new_id);
        Ok(new_id)
    }

    /// 删除凭据（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true）
    ///
    /// # 行为
    /// 1. 验证凭据存在
    /// 2. 验证凭据已禁用
    /// 3. 从 entries 移除
    /// 4. 如果删除的是当前凭据，切换到优先级最高的可用凭据
    /// 5. 如果删除后没有凭据，将 current_id 重置为 0
    /// 6. 持久化到文件
    ///
    /// # 返回
    /// - `Ok(())` - 删除成功
    /// - `Err(_)` - 凭据不存在、未禁用或持久化失败
    pub fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let was_current = {
            let mut entries = self.entries.lock();

            // 查找凭据
            let entry = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            // 检查是否已禁用
            if !entry.disabled {
                anyhow::bail!("只能删除已禁用的凭据（请先禁用凭据 #{}）", id);
            }

            // 记录是否是当前凭据
            let current_id = *self.current_id.lock();
            let was_current = current_id == id;

            // 删除凭据
            entries.retain(|e| e.id != id);

            was_current
        };

        // 如果删除的是当前凭据，切换到优先级最高的可用凭据
        if was_current {
            self.select_highest_priority();
        }

        // 如果删除后没有任何凭据，将 current_id 重置为 0（与初始化行为保持一致）
        {
            let entries = self.entries.lock();
            if entries.is_empty() {
                let mut current_id = self.current_id.lock();
                *current_id = 0;
                tracing::info!("所有凭据已删除，current_id 已重置为 0");
            }
        }

        self.refresh_locks.lock().remove(&id);

        // 持久化更改
        self.credential_store.delete_one(id)?;

        // 立即回写统计数据，清除已删除凭据的残留条目
        self.save_stats();

        tracing::info!("已删除凭据 #{}", id);
        Ok(())
    }

    /// 强制刷新指定凭据的 Token（Admin API）
    ///
    /// 无条件调用上游 API 重新获取 access token，不检查是否过期。
    /// 适用于排查问题、Token 异常但未过期、主动更新凭据状态等场景。
    pub async fn force_refresh_token_for(&self, id: u64) -> anyhow::Result<()> {
        if let Err(err) = self.refresh_credentials_for(id, true, true).await {
            if err.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                self.report_refresh_token_invalid(id);
            }
            return Err(err);
        }

        tracing::info!("凭据 #{} Token 已强制刷新", id);
        Ok(())
    }

    /// 获取负载均衡模式（Admin API）
    pub fn get_load_balancing_mode(&self) -> String {
        self.load_balancing_mode.lock().clone()
    }

    pub fn get_cache_account_protection_seconds(&self) -> u64 {
        self.cache_account_protection_seconds
            .load(Ordering::Relaxed)
    }

    pub fn update_cache_account_protection_seconds(&self, seconds: u64) {
        self.cache_account_protection_seconds
            .store(seconds, Ordering::Relaxed);
        tracing::info!("Prompt Cache 账号保护窗口已热更新为 {} 秒", seconds);
    }

    pub fn update_cache_account_wait_seconds(&self, seconds: u64) {
        let seconds = seconds.min(60);
        self.cache_account_wait_seconds
            .store(seconds, Ordering::Relaxed);
        tracing::info!("Prompt Cache 账号并发等待已热更新为 {} 秒", seconds);
    }

    pub fn get_rate_limit_cooldown_seconds(&self) -> u64 {
        self.rate_limit_cooldown_seconds.load(Ordering::Relaxed)
    }

    pub fn update_rate_limit_cooldown_seconds(&self, seconds: u64) {
        let seconds = seconds.max(1);
        self.rate_limit_cooldown_seconds
            .store(seconds, Ordering::Relaxed);
        tracing::info!("HTTP 429 账号冷却时间已热更新为 {} 秒", seconds);
    }

    fn persist_load_balancing_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，负载均衡模式仅在当前进程生效: {}", mode);
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.load_balancing_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化负载均衡模式失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 设置负载均衡模式（Admin API）
    pub fn set_load_balancing_mode(&self, mode: String) -> anyhow::Result<()> {
        // 验证模式值
        if !matches!(mode.as_str(), "priority" | "balanced") {
            anyhow::bail!("无效的负载均衡模式: {}", mode);
        }

        let previous_mode = self.get_load_balancing_mode();
        if previous_mode == mode {
            return Ok(());
        }

        *self.load_balancing_mode.lock() = mode.clone();

        if let Err(err) = self.persist_load_balancing_mode(&mode) {
            *self.load_balancing_mode.lock() = previous_mode;
            return Err(err);
        }

        tracing::info!("负载均衡模式已设置为: {}", mode);
        Ok(())
    }
}

impl Drop for MultiTokenManager {
    fn drop(&mut self) {
        if self.stats_dirty.load(Ordering::Relaxed) {
            self.save_stats();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_balances_are_invalidated_in_memory_and_not_trusted_after_restart() {
        let test_dir = std::env::temp_dir().join(format!("kiro-balance-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&test_dir).unwrap();
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![KiroCredentials::default()],
            None,
            Some(test_dir.join("credentials.json")),
            false,
        )
        .unwrap();
        let usage: UsageLimitsResponse = serde_json::from_str(
            r#"{
            "usageBreakdownList": [{"resourceType":"AGENTIC_REQUEST",
            "currentUsageWithPrecision":1.25,"usageLimitWithPrecision":50}]
        }"#,
        )
        .unwrap();
        manager.save_verified_balance(1, &usage, Some(0));
        let cached = manager.balance_snapshot();
        assert!(cached[&1].is_fresh(Utc::now().timestamp() as f64, 0, 0));
        assert_eq!(cached[&1].data.remaining, 48.75);

        let path = test_dir.join("old-balance.json");
        std::fs::write(&path, serde_json::to_vec(&cached).unwrap()).unwrap();
        let reloaded = MultiTokenManager::load_balance_cache_from(&Some(path.clone()));
        assert!(!reloaded[&1].is_fresh(Utc::now().timestamp() as f64, 0, 0));
        manager.invalidate_balance(1);
        assert!(manager.balance_snapshot().is_empty());
        manager.save_verified_balance(1, &usage, Some(0));
        let slots = manager.entries.lock()[0].request_slots.clone();
        let mut lease = RequestLease::new(slots.try_acquire_owned().unwrap());
        manager.start_metering(1, &mut lease);
        drop(lease); // 在响应返回、统计请求次数之前取消。
        assert_eq!(manager.snapshot().entries[0].total_request_count, 0);
        assert_eq!(manager.quota_request_count(1), Some(1));
        assert!(manager.balance_snapshot().is_empty());
        // 并发余额查询迟到的旧结果也不能变为有效余额。
        manager.save_verified_balance(1, &usage, Some(0));
        assert!(!manager.balance_snapshot()[&1].is_fresh(Utc::now().timestamp() as f64, 1, 0,));
        manager.invalidate_balance(1);
        // 磁盘旧值仍存在，也不能重新混入当前进程的汇总。
        assert!(path.exists());
        assert!(manager.balance_snapshot().is_empty());
        std::fs::remove_file(path).unwrap();
        drop(manager);
        std::fs::remove_file(test_dir.join("kiro_balance_cache.json")).unwrap();
        std::fs::remove_file(test_dir.join("kiro_credit_ledger.json")).unwrap();
        std::fs::remove_file(test_dir.join("credentials.json")).unwrap();
        std::fs::remove_dir(test_dir).unwrap();
    }

    #[test]
    fn permanent_refresh_error_code_handles_idc_access_denied() {
        assert_eq!(
            permanent_refresh_error_code(
                400,
                r#"{"error":"access_denied","error_description":"Access denied"}"#,
            ),
            Some("access_denied")
        );
        assert_eq!(
            permanent_refresh_error_code(
                400,
                r#"{"error":"invalid_grant","error_description":"Invalid refresh token provided"}"#,
            ),
            Some("invalid_grant")
        );
    }

    #[test]
    fn permanent_refresh_error_code_ignores_transient_or_unknown_errors() {
        assert_eq!(
            permanent_refresh_error_code(
                400,
                r#"{"error":"invalid_grant","error_description":"temporary failure"}"#,
            ),
            None
        );
        assert_eq!(
            permanent_refresh_error_code(429, r#"{"error":"access_denied"}"#),
            None
        );
        assert_eq!(permanent_refresh_error_code(400, "not json"), None);
    }

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());
        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(3);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("a".repeat(150));
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("test");
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_disabled_reason_loaded_from_credentials() {
        let config = Config::default();
        let mut credentials = KiroCredentials::default();
        credentials.id = Some(7);
        credentials.disabled = true;
        credentials.disabled_reason = Some("TooManyFailures".to_string());

        let manager = MultiTokenManager::new(config, vec![credentials], None, None, false).unwrap();
        let snapshot = manager.snapshot();

        assert_eq!(snapshot.available, 0);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("TooManyFailures")
        );
    }

    #[test]
    fn test_disabled_recovery_candidates_rotate_and_skip_permanent_reasons() {
        let config = Config::default();
        let mut recoverable_one = KiroCredentials::default();
        recoverable_one.id = Some(1);
        recoverable_one.disabled = true;
        recoverable_one.disabled_reason = Some("TooManyFailures".to_string());

        let mut permanent = KiroCredentials::default();
        permanent.id = Some(2);
        permanent.disabled = true;
        permanent.disabled_reason = Some("InvalidRefreshToken".to_string());

        let mut recoverable_two = KiroCredentials::default();
        recoverable_two.id = Some(3);
        recoverable_two.disabled = true;
        recoverable_two.disabled_reason = Some("QuotaExceeded".to_string());

        let mut recoverable_three = KiroCredentials::default();
        recoverable_three.id = Some(4);
        recoverable_three.disabled = true;
        recoverable_three.disabled_reason = Some("Manual".to_string());

        let manager = MultiTokenManager::new(
            config,
            vec![
                recoverable_one,
                permanent,
                recoverable_two,
                recoverable_three,
            ],
            None,
            None,
            false,
        )
        .unwrap();

        let first = manager.disabled_recovery_candidates(2);
        assert_eq!(
            first.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![1, 3]
        );

        let second = manager.disabled_recovery_candidates(2);
        assert_eq!(
            second.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![4, 1]
        );
    }

    #[test]
    fn test_quota_recovery_probe_is_limited_to_once_per_day() {
        let config = Config::default();
        let mut quota = KiroCredentials::default();
        quota.id = Some(1);
        quota.disabled = true;
        quota.disabled_reason = Some("QuotaExceeded".to_string());
        quota.quota_last_probed_at = Some(Utc::now().to_rfc3339());

        let manager = MultiTokenManager::new(config, vec![quota], None, None, false).unwrap();
        assert!(manager.disabled_recovery_candidates(1).is_empty());

        {
            let mut entries = manager.entries.lock();
            entries[0].credentials.quota_last_probed_at =
                Some((Utc::now() - Duration::hours(25)).to_rfc3339());
        }

        let candidates = manager.disabled_recovery_candidates(1);
        assert_eq!(candidates, vec![(1, DisabledReason::QuotaExceeded)]);
    }

    #[test]
    fn test_account_suspended_is_permanent_and_excluded_from_recovery() {
        let config = Config::default();
        let mut suspended = KiroCredentials::default();
        suspended.id = Some(1);
        suspended.disabled = true;
        suspended.disabled_reason = Some("AccountSuspended".to_string());

        let manager = MultiTokenManager::new(config, vec![suspended], None, None, false).unwrap();
        assert!(manager.disabled_recovery_candidates(1).is_empty());
        assert_eq!(
            manager.snapshot().entries[0].disabled_reason.as_deref(),
            Some("AccountSuspended")
        );
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_api_key_credential() {
        let config = Config::default();
        let mut credentials = KiroCredentials::default();
        credentials.kiro_api_key = Some("ksk_test_key_123".to_string());
        credentials.auth_method = Some("api_key".to_string());

        let result = refresh_token(&credentials, &config, None).await;

        assert!(result.is_err(), "API Key 凭据应被 refresh_token 拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("API Key 凭据不支持刷新"),
            "期望错误消息包含 'API Key 凭据不支持刷新'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_refresh_token() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.refresh_token = Some("a".repeat(150));

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("凭据已存在"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_success() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_test_key_123".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_api_key() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.kiro_api_key = Some("ksk_existing_key".to_string());
        existing.auth_method = Some("api_key".to_string());

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.kiro_api_key = Some("ksk_existing_key".to_string());
        duplicate.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 重复")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_empty_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some(String::new());
        cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 为空")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_missing_key_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        // kiro_api_key is None

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("缺少 kiroApiKey")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_and_oauth_coexist() {
        let config = Config::default();

        let mut oauth_cred = KiroCredentials::default();
        oauth_cred.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![oauth_cred], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_new_key".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    // MultiTokenManager 测试

    #[test]
    fn test_multi_token_manager_new() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.priority = 0;
        let mut cred2 = KiroCredentials::default();
        cred2.priority = 1;

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    #[test]
    fn test_record_token_usage_updates_snapshot_totals() {
        let config = Config::default();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        manager.record_token_usage(1, 120);
        manager.record_token_usage(1, 30);

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.total_token_count, 150);
        assert_eq!(snapshot.today_token_count, 150);

        let entry = snapshot.entries.iter().find(|entry| entry.id == 1).unwrap();
        assert_eq!(entry.total_token_count, 150);
        assert_eq!(entry.today_token_count, 150);
    }

    #[test]
    fn test_multi_token_manager_empty_credentials() {
        let config = Config::default();
        let result = MultiTokenManager::new(config, vec![], None, None, false);
        // 支持 0 个凭据启动（可通过管理面板添加）
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_duplicate_ids() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(1); // 重复 ID

        let result = MultiTokenManager::new(config, vec![cred1, cred2], None, None, false);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("重复的凭据 ID"),
            "错误消息应包含 '重复的凭据 ID'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_parallel_add_api_key_credentials_assigns_unique_ids() {
        let config = Config::default();
        let manager =
            std::sync::Arc::new(MultiTokenManager::new(config, vec![], None, None, false).unwrap());

        let mut handles = Vec::new();
        for index in 0..50 {
            let manager = manager.clone();
            handles.push(tokio::spawn(async move {
                let mut cred = KiroCredentials::default();
                cred.auth_method = Some("api_key".to_string());
                cred.kiro_api_key = Some(format!("ksk_parallel_test_key_{index:03}"));
                manager.add_credential(cred).await.unwrap()
            }));
        }

        let mut ids = Vec::new();
        for handle in handles {
            ids.push(handle.await.unwrap());
        }
        ids.sort_unstable();

        let expected: Vec<u64> = (1..=50).collect();
        assert_eq!(ids, expected);

        let mut snapshot_ids: Vec<u64> = manager
            .snapshot()
            .entries
            .iter()
            .map(|entry| entry.id)
            .collect();
        snapshot_ids.sort_unstable();
        assert_eq!(snapshot_ids, expected);
    }

    #[test]
    fn test_multi_token_manager_api_key_missing_kiro_api_key_auto_disabled() {
        let config = Config::default();

        // auth_method=api_key 但缺少 kiro_api_key → 应被自动禁用
        let mut bad_cred = KiroCredentials::default();
        bad_cred.auth_method = Some("api_key".to_string());
        // kiro_api_key 保持 None

        let mut good_cred = KiroCredentials::default();
        good_cred.refresh_token = Some("valid_token".to_string());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 1); // bad_cred 被禁用，只剩 1 个可用
    }

    #[test]
    fn test_multi_token_manager_api_key_with_kiro_api_key_not_disabled() {
        let config = Config::default();

        // auth_method=api_key 且有 kiro_api_key → 不应被禁用
        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        cred.kiro_api_key = Some("ksk_test123".to_string());

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_report_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        // 前两次失败不会禁用（使用 ID 1）
        assert!(manager.report_failure(1));
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 2);

        // 第三次失败会禁用第一个凭据
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 1);

        // 继续失败第二个凭据（使用 ID 2）
        assert!(manager.report_failure(2));
        assert!(manager.report_failure(2));
        assert!(!manager.report_failure(2)); // 所有凭据都禁用了
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_report_success() {
        let config = Config::default();
        let cred = KiroCredentials::default();

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();

        // 失败两次（使用 ID 1）
        manager.report_failure(1);
        manager.report_failure(1);

        // 成功后重置计数（使用 ID 1）
        manager.report_success(1);

        // 再失败两次不会禁用
        manager.report_failure(1);
        manager.report_failure(1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_switch_to_next() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.refresh_token = Some("token1".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.refresh_token = Some("token2".to_string());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        let initial_id = manager.snapshot().current_id;

        // 切换到下一个
        assert!(manager.switch_to_next());
        assert_ne!(manager.snapshot().current_id, initial_id);
    }

    #[test]
    fn test_set_load_balancing_mode_persists_to_config_file() {
        let config_path =
            std::env::temp_dir().join(format!("kiro-load-balancing-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&config_path, r#"{"loadBalancingMode":"priority"}"#).unwrap();

        let config = Config::load(&config_path).unwrap();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        manager
            .set_load_balancing_mode("balanced".to_string())
            .unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(persisted.load_balancing_mode, "balanced");
        assert_eq!(manager.get_load_balancing_mode(), "balanced");

        std::fs::remove_file(&config_path).unwrap();
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_auto_recovers_all_disabled() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(1);
        }
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(2);
        }

        assert_eq!(manager.available_count(), 0);

        // 应触发自愈：重置失败计数并重新启用，避免必须重启进程
        let ctx = manager.acquire_context(None).await.unwrap();
        assert!(ctx.token == "t1" || ctx.token == "t2");
        assert_eq!(manager.available_count(), 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_balanced_retries_until_bad_credential_disabled()
     {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut bad_cred = KiroCredentials::default();
        bad_cred.priority = 0;
        bad_cred.refresh_token = Some("bad".to_string());

        let mut good_cred = KiroCredentials::default();
        good_cred.priority = 1;
        good_cred.access_token = Some("good-token".to_string());
        good_cred.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "good-token");
    }

    #[tokio::test]
    async fn test_transient_cooldown_skips_current_priority_credential() {
        let mut first = KiroCredentials::default();
        first.id = Some(1);
        first.priority = 0;
        first.auth_method = Some("api_key".to_string());
        first.kiro_api_key = Some("ksk_first".to_string());

        let mut second = KiroCredentials::default();
        second.id = Some(2);
        second.priority = 1;
        second.auth_method = Some("api_key".to_string());
        second.kiro_api_key = Some("ksk_second".to_string());

        let manager =
            MultiTokenManager::new(Config::default(), vec![first, second], None, None, false)
                .unwrap();

        assert!(manager.report_transient_cooldown(1, StdDuration::from_secs(60), "HTTP 429"));

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
    }

    #[test]
    fn test_background_transient_cooldown_does_not_count_as_request_failure() {
        let mut credential = KiroCredentials::default();
        credential.id = Some(99_999_991);
        credential.auth_method = Some("api_key".to_string());
        credential.kiro_api_key = Some("ksk_first".to_string());

        let manager =
            MultiTokenManager::new(Config::default(), vec![credential], None, None, false).unwrap();

        assert!(manager.report_background_transient_cooldown(
            99_999_991,
            StdDuration::from_secs(60),
            "background rate limited"
        ));

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|entry| entry.id == 99_999_991).unwrap();
        assert_eq!(entry.total_request_count, 0);
        assert_eq!(entry.today_request_count, 0);
    }

    #[test]
    fn test_per_credential_sliding_window_skips_limited_account() {
        let mut config = Config::default();
        config.per_credential_rate_limit_max_requests = 1;
        config.per_credential_rate_limit_window_seconds = 60;

        let mut first = KiroCredentials::default();
        first.id = Some(1);
        first.auth_method = Some("api_key".to_string());
        first.kiro_api_key = Some("ksk_first".to_string());

        let mut second = KiroCredentials::default();
        second.id = Some(2);
        second.auth_method = Some("api_key".to_string());
        second.kiro_api_key = Some("ksk_second".to_string());

        let manager =
            MultiTokenManager::new(config, vec![first, second], None, None, false).unwrap();
        let excluded_ids = HashSet::new();

        let (first_id, _, first_lease) = manager
            .select_next_credential(None, &[], &[], &excluded_ids)
            .unwrap();
        assert_eq!(first_id, 1);
        drop(first_lease);

        let (second_id, _, second_lease) = manager
            .select_next_credential(None, &[], &[], &excluded_ids)
            .unwrap();
        assert_eq!(second_id, 2);
        drop(second_lease);

        assert!(
            manager
                .select_next_credential(None, &[], &[], &excluded_ids)
                .is_none()
        );
    }

    #[test]
    fn test_global_sliding_window_blocks_all_accounts() {
        let mut config = Config::default();
        config.global_rate_limit_max_requests = 1;
        config.global_rate_limit_window_seconds = 60;

        let mut first = KiroCredentials::default();
        first.id = Some(1);
        first.auth_method = Some("api_key".to_string());
        first.kiro_api_key = Some("ksk_first".to_string());

        let mut second = KiroCredentials::default();
        second.id = Some(2);
        second.auth_method = Some("api_key".to_string());
        second.kiro_api_key = Some("ksk_second".to_string());

        let manager =
            MultiTokenManager::new(config, vec![first, second], None, None, false).unwrap();
        let excluded_ids = HashSet::new();

        let (first_id, _, first_lease) = manager
            .select_next_credential(None, &[], &[], &excluded_ids)
            .unwrap();
        assert_eq!(first_id, 1);
        drop(first_lease);

        assert!(
            manager
                .select_next_credential(None, &[], &[], &excluded_ids)
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_balanced_selects_oldest_last_used_instead_of_success_count() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut old_credential = KiroCredentials::default();
        old_credential.access_token = Some("old-token".to_string());
        old_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut new_credential = KiroCredentials::default();
        new_credential.access_token = Some("new-token".to_string());
        new_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![old_credential, new_credential],
            None,
            None,
            false,
        )
        .unwrap();

        {
            let mut entries = manager.entries.lock();
            entries[0].success_count = 200;
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].success_count = 0;
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
        }

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "old-token");
    }

    #[tokio::test]
    async fn test_balanced_uses_latency_only_as_tiebreaker() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut slow_credential = KiroCredentials::default();
        slow_credential.access_token = Some("slow-token".to_string());
        slow_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut fast_credential = KiroCredentials::default();
        fast_credential.access_token = Some("fast-token".to_string());
        fast_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![slow_credential, fast_credential],
            None,
            None,
            false,
        )
        .unwrap();

        manager.record_upstream_header_latency(1, StdDuration::from_millis(1200));
        manager.record_upstream_header_latency(2, StdDuration::from_millis(120));
        {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
        }

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "slow-token");
        drop(ctx);

        let shared_last_used_at = (Utc::now() - Duration::hours(2)).to_rfc3339();
        {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some(shared_last_used_at.clone());
            entries[1].last_used_at = Some(shared_last_used_at);
        }

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "fast-token");
    }

    #[tokio::test]
    async fn test_balanced_prefers_less_busy_credential_before_oldest_last_used() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config.max_concurrent_requests_per_credential = 2;

        let mut busy_credential = KiroCredentials::default();
        busy_credential.access_token = Some("busy-token".to_string());
        busy_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut idle_credential = KiroCredentials::default();
        idle_credential.access_token = Some("idle-token".to_string());
        idle_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![busy_credential, idle_credential],
            None,
            None,
            false,
        )
        .unwrap();

        let _busy_permit = {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
            entries[0]
                .request_slots
                .clone()
                .try_acquire_owned()
                .unwrap()
        };

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "idle-token");
    }

    #[tokio::test]
    async fn test_balanced_prefers_cache_account_when_hint_matches() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut first = KiroCredentials::default();
        first.access_token = Some("first-token".to_string());
        first.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut second = KiroCredentials::default();
        second.access_token = Some("second-token".to_string());
        second.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![first, second], None, None, false).unwrap();

        {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
        }

        let preferred = vec!["2".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts(None, &preferred)
            .await
            .unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "second-token");
    }

    #[tokio::test]
    async fn test_priority_mode_prefers_cache_account_over_priority() {
        let mut config = Config::default();
        config.load_balancing_mode = "priority".to_string();

        let mut high_priority = KiroCredentials::default();
        high_priority.priority = 0;
        high_priority.access_token = Some("high-priority-token".to_string());
        high_priority.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut cache_credential = KiroCredentials::default();
        cache_credential.priority = 10;
        cache_credential.access_token = Some("cache-token".to_string());
        cache_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![high_priority, cache_credential],
            None,
            None,
            false,
        )
        .unwrap();
        let preferred = vec!["2".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts(None, &preferred)
            .await
            .unwrap();

        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "cache-token");
    }

    #[tokio::test]
    async fn test_balanced_prefers_busier_cache_account_before_load_balancing() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config.max_concurrent_requests_per_credential = 2;

        let mut cache_credential = KiroCredentials::default();
        cache_credential.access_token = Some("cache-token".to_string());
        cache_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut idle_credential = KiroCredentials::default();
        idle_credential.access_token = Some("idle-token".to_string());
        idle_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![cache_credential, idle_credential],
            None,
            None,
            false,
        )
        .unwrap();
        let _cache_account_load = manager.entries.lock()[0]
            .request_slots
            .clone()
            .try_acquire_owned()
            .unwrap();

        let preferred = vec!["1".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts(None, &preferred)
            .await
            .unwrap();

        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "cache-token");
    }

    #[tokio::test]
    async fn test_cache_account_waits_for_busy_preferred_account() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config.max_concurrent_requests_per_credential = 1;
        config.cache_account_wait_seconds = 1;

        let mut cache_credential = KiroCredentials::default();
        cache_credential.access_token = Some("cache-token".to_string());
        cache_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut idle_credential = KiroCredentials::default();
        idle_credential.access_token = Some("idle-token".to_string());
        idle_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = Arc::new(
            MultiTokenManager::new(
                config,
                vec![cache_credential, idle_credential],
                None,
                None,
                false,
            )
            .unwrap(),
        );
        let cache_account_load = manager.entries.lock()[0]
            .request_slots
            .clone()
            .try_acquire_owned()
            .unwrap();
        let preferred = vec!["1".to_string()];
        let waiting_manager = Arc::clone(&manager);
        let task = tokio::spawn(async move {
            waiting_manager
                .acquire_context_with_preferred_accounts(None, &preferred)
                .await
        });

        sleep(StdDuration::from_millis(50)).await;
        drop(cache_account_load);
        let ctx = tokio::time::timeout(StdDuration::from_millis(500), task)
            .await
            .expect("缓存账号释放后应在等待窗口内完成调度")
            .expect("调度任务不应 panic")
            .expect("应获取缓存账号");

        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "cache-token");
    }

    #[tokio::test]
    async fn test_cache_account_zero_wait_degrades_to_idle_account() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config.max_concurrent_requests_per_credential = 1;
        config.cache_account_wait_seconds = 0;

        let mut cache_credential = KiroCredentials::default();
        cache_credential.access_token = Some("cache-token".to_string());
        cache_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut idle_credential = KiroCredentials::default();
        idle_credential.access_token = Some("idle-token".to_string());
        idle_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![cache_credential, idle_credential],
            None,
            None,
            false,
        )
        .unwrap();
        let _cache_account_load = manager.entries.lock()[0]
            .request_slots
            .clone()
            .try_acquire_owned()
            .unwrap();

        let preferred = vec!["1".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts(None, &preferred)
            .await
            .unwrap();

        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "idle-token");
    }

    #[tokio::test]
    async fn test_balanced_selects_oldest_cache_account_when_multiple_hints_match() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut first = KiroCredentials::default();
        first.access_token = Some("first-token".to_string());
        first.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut second = KiroCredentials::default();
        second.access_token = Some("second-token".to_string());
        second.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![first, second], None, None, false).unwrap();

        {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
        }

        let preferred = vec!["1".to_string(), "2".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts(None, &preferred)
            .await
            .unwrap();
        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "first-token");
    }

    #[tokio::test]
    async fn test_balanced_reserves_cache_accounts_for_matching_requests() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut cached = KiroCredentials::default();
        cached.access_token = Some("cached-token".to_string());
        cached.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut regular = KiroCredentials::default();
        regular.access_token = Some("regular-token".to_string());
        regular.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![cached, regular], None, None, false).unwrap();

        let reserved = vec!["1".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts_and_reserved_accounts(None, &[], &reserved)
            .await
            .unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "regular-token");
        drop(ctx);

        let preferred = vec!["1".to_string()];
        let ctx = manager
            .acquire_context_with_preferred_accounts_and_reserved_accounts(
                None, &preferred, &reserved,
            )
            .await
            .unwrap();
        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "cached-token");
    }

    #[tokio::test]
    async fn test_balanced_prefers_ready_token_over_expired_oldest_credential() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut expired_credential = KiroCredentials::default();
        expired_credential.access_token = Some("expired-token".to_string());
        expired_credential.refresh_token = Some("expired-refresh".to_string());
        expired_credential.expires_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());

        let mut ready_credential = KiroCredentials::default();
        ready_credential.access_token = Some("ready-token".to_string());
        ready_credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager = MultiTokenManager::new(
            config,
            vec![expired_credential, ready_credential],
            None,
            None,
            false,
        )
        .unwrap();

        {
            let mut entries = manager.entries.lock();
            entries[0].last_used_at = Some((Utc::now() - Duration::hours(2)).to_rfc3339());
            entries[1].last_used_at = Some((Utc::now() - Duration::hours(1)).to_rfc3339());
        }

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "ready-token");
    }

    #[test]
    fn test_proactive_refresh_candidates_only_include_refreshable_expiring_tokens() {
        let config = Config::default();

        let mut expired = KiroCredentials::default();
        expired.id = Some(1);
        expired.access_token = Some("expired-token".to_string());
        expired.refresh_token = Some("a".repeat(150));
        expired.expires_at = Some((Utc::now() - Duration::minutes(1)).to_rfc3339());

        let mut soon = KiroCredentials::default();
        soon.id = Some(2);
        soon.access_token = Some("soon-token".to_string());
        soon.refresh_token = Some("b".repeat(150));
        soon.expires_at = Some((Utc::now() + Duration::minutes(8)).to_rfc3339());

        let mut ready = KiroCredentials::default();
        ready.id = Some(3);
        ready.access_token = Some("ready-token".to_string());
        ready.refresh_token = Some("c".repeat(150));
        ready.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let mut api_key = KiroCredentials::default();
        api_key.id = Some(4);
        api_key.auth_method = Some("api_key".to_string());
        api_key.kiro_api_key = Some("ksk_test_key_123".to_string());

        let mut disabled = KiroCredentials::default();
        disabled.id = Some(5);
        disabled.access_token = Some("disabled-token".to_string());
        disabled.refresh_token = Some("d".repeat(150));
        disabled.expires_at = Some((Utc::now() - Duration::minutes(1)).to_rfc3339());
        disabled.disabled = true;

        let manager = MultiTokenManager::new(
            config,
            vec![expired, soon, ready, api_key, disabled],
            None,
            None,
            false,
        )
        .unwrap();

        assert_eq!(manager.proactive_refresh_candidates(10), vec![1, 2]);
    }

    #[tokio::test]
    async fn test_per_credential_concurrency_defaults_to_one() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config.max_concurrent_requests_per_credential = 1;

        let mut credential = KiroCredentials::default();
        credential.access_token = Some("token".to_string());
        credential.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            Arc::new(MultiTokenManager::new(config, vec![credential], None, None, false).unwrap());

        let first = manager.acquire_context(None).await.unwrap();
        let second_attempt =
            tokio::time::timeout(StdDuration::from_millis(50), manager.acquire_context(None)).await;
        assert!(second_attempt.is_err(), "同一凭据不应同时发起第二个请求");

        drop(first);
        let second = manager.acquire_context(None).await.unwrap();
        assert_eq!(second.id, 1);
    }

    #[test]
    fn test_multi_token_manager_report_refresh_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        assert_eq!(manager.available_count(), 2);
        for _ in 0..(MAX_FAILURES_PER_CREDENTIAL - 1) {
            assert!(manager.report_refresh_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        assert!(manager.report_refresh_failure(1));
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.refresh_failure_count, MAX_FAILURES_PER_CREDENTIAL);
        assert_eq!(snapshot.current_id, 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_refresh_failure_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_refresh_failure(1);
            manager.report_refresh_failure(2);
        }
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
    }

    #[test]
    fn test_multi_token_manager_report_quota_exhausted() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        assert_eq!(manager.available_count(), 2);
        assert!(manager.report_quota_exhausted(1));
        assert_eq!(manager.available_count(), 1);

        // 再禁用第二个后，无可用凭据
        assert!(!manager.report_quota_exhausted(2));
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_usage_below_disable_threshold_uses_remaining_less_than_threshold() {
        let usage = UsageLimitsResponse {
            next_date_reset: None,
            subscription_info: None,
            usage_breakdown_list: vec![crate::kiro::model::usage_limits::UsageBreakdown {
                current_usage_with_precision: Some(49.5),
                usage_limit_with_precision: Some(50.0),
                ..Default::default()
            }],
        };

        assert!(MultiTokenManager::usage_below_disable_threshold(&usage, 1.0).is_some());
        assert!(MultiTokenManager::usage_below_disable_threshold(&usage, 0.5).is_none());
        assert!(MultiTokenManager::usage_below_disable_threshold(&usage, 0.0).is_none());
    }

    #[test]
    fn test_recovery_probe_low_balance_marks_manual_disabled_as_quota_exceeded() {
        let config = Config::default();
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.disabled = true;
        credential.disabled_reason = Some("Manual".to_string());

        let manager = MultiTokenManager::new(config, vec![credential], None, None, false).unwrap();
        manager.mark_disabled_as_quota_exceeded_after_probe(1);

        let snapshot = manager.snapshot();
        let entry = &snapshot.entries[0];
        assert!(entry.disabled);
        assert_eq!(entry.disabled_reason.as_deref(), Some("QuotaExceeded"));
        assert_eq!(entry.failure_count, MAX_FAILURES_PER_CREDENTIAL);

        let candidates = manager.disabled_recovery_candidates(1);
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn test_multi_token_manager_quota_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        manager.report_quota_exhausted(1);
        manager.report_quota_exhausted(2);
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
        assert_eq!(manager.available_count(), 0);
    }

    // ============ 凭据级 Region 优先级测试 ============

    #[test]
    fn test_credential_region_priority_uses_credential_auth_region() {
        // 凭据配置了 auth_region 时，应使用凭据的 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-west-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_credential_region() {
        // 凭据未配置 auth_region 但配置了 region 时，应回退到凭据.region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-central-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_config() {
        // 凭据未配置 auth_region 和 region 时，应回退到 config
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials::default();
        assert!(credentials.auth_region.is_none());
        assert!(credentials.region.is_none());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_multiple_credentials_use_respective_regions() {
        // 多凭据场景下，不同凭据使用各自的 auth_region
        let mut config = Config::default();
        config.region = "ap-northeast-1".to_string();

        let mut cred1 = KiroCredentials::default();
        cred1.auth_region = Some("us-east-1".to_string());

        let mut cred2 = KiroCredentials::default();
        cred2.region = Some("eu-west-1".to_string());

        let cred3 = KiroCredentials::default(); // 无 region，使用 config

        assert_eq!(cred1.effective_auth_region(&config), "us-east-1");
        assert_eq!(cred2.effective_auth_region(&config), "eu-west-1");
        assert_eq!(cred3.effective_auth_region(&config), "ap-northeast-1");
    }

    #[test]
    fn test_idc_oidc_endpoint_uses_credential_auth_region() {
        // 验证 IdC OIDC endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);

        assert_eq!(refresh_url, "https://oidc.eu-central-1.amazonaws.com/token");
    }

    #[test]
    fn test_social_refresh_endpoint_uses_credential_auth_region() {
        // 验证 Social refresh endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("ap-southeast-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);

        assert_eq!(
            refresh_url,
            "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_normalize_auth_region_keeps_aws_region() {
        assert_eq!(normalize_auth_region("us-east-1", "us-west-2"), "us-east-1");
        assert_eq!(normalize_auth_region("US-EAST-1", "us-west-2"), "us-east-1");
    }

    #[test]
    fn test_normalize_auth_region_falls_back_for_country_code() {
        assert_eq!(normalize_auth_region("US", "us-east-1"), "us-east-1");
        assert_eq!(normalize_auth_region("AU", "us-east-1"), "us-east-1");
        assert_eq!(normalize_auth_region("GB", "us-east-1"), "us-east-1");
    }

    #[test]
    fn test_normalize_auth_region_falls_back_when_both_values_invalid() {
        assert_eq!(normalize_auth_region("US", "US"), "us-east-1");
    }

    #[test]
    fn test_api_call_uses_effective_api_region() {
        // 验证 API 调用使用 effective_api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-west-1".to_string());

        // 凭据.region 不参与 api_region 回退链
        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.us-west-2.amazonaws.com");
    }

    #[test]
    fn test_api_call_uses_credential_api_region() {
        // 凭据配置了 api_region 时，API 调用应使用凭据的 api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.api_region = Some("eu-central-1".to_string());

        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.eu-central-1.amazonaws.com");
    }

    #[test]
    fn test_credential_region_empty_string_treated_as_set() {
        // 空字符串 auth_region 被视为已设置（虽然不推荐，但行为应一致）
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("".to_string());

        let region = credentials.effective_auth_region(&config);
        // 空字符串被视为已设置，不会回退到 config
        assert_eq!(region, "");
    }

    #[test]
    fn test_auth_and_api_region_independent() {
        // auth_region 和 api_region 互不影响
        let mut config = Config::default();
        config.region = "default".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("auth-only".to_string());
        credentials.api_region = Some("api-only".to_string());

        assert_eq!(credentials.effective_auth_region(&config), "auth-only");
        assert_eq!(credentials.effective_api_region(&config), "api-only");
    }
}
