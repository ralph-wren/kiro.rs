//! Admin API 业务逻辑服务

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use chrono::Utc;
use parking_lot::Mutex;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::anthropic::{list_models_with_mappings, map_model_with_mappings};
use crate::http_client::build_client;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::events::Event;
use crate::kiro::model::requests::conversation::{
    ConversationState, CurrentMessage, UserInputMessage,
};
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::provider::KiroProvider;
use crate::kiro::token_manager::{
    ManagerSnapshot, MultiTokenManager, with_balance_cache_file_lock,
};
use crate::model::config::Config;

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, AdminConfigResponse, AdminModelsResponse,
    BalanceResponse, CredentialStatusCounts, CredentialStatusItem, CredentialsQuery,
    CredentialsStatusResponse, DisabledReasonCount, LoadBalancingModeResponse, RequestStatsSummary,
    ServiceTestResponse, SetLoadBalancingModeRequest,
};

/// 余额缓存过期时间（秒），5 分钟
const BALANCE_CACHE_TTL_SECS: i64 = 300;
const SERVICE_TEST_TIMEOUT_SECS: u64 = 45;
const SERVICE_TEST_PREVIEW_LIMIT: usize = 240;

/// 缓存的余额条目（含时间戳）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedBalance {
    /// 缓存时间（Unix 秒）
    #[serde(alias = "cached_at")]
    cached_at: f64,
    /// 缓存的余额数据
    data: BalanceResponse,
}

/// Admin 服务
///
/// 封装所有 Admin API 的业务逻辑
pub struct AdminService {
    token_manager: Arc<MultiTokenManager>,
    provider: Arc<KiroProvider>,
    balance_cache: Mutex<HashMap<u64, CachedBalance>>,
    usage_request_semaphore: Arc<RwLock<Arc<Semaphore>>>,
    cache_path: Option<PathBuf>,
    model_mappings: Arc<RwLock<HashMap<String, String>>>,
    extract_thinking: Arc<AtomicBool>,
    default_stream: Arc<AtomicBool>,
    /// 已注册的端点名称集合（用于 add_credential 校验）
    known_endpoints: HashSet<String>,
}

impl AdminService {
    pub fn new(
        token_manager: Arc<MultiTokenManager>,
        provider: Arc<KiroProvider>,
        known_endpoints: impl IntoIterator<Item = String>,
        model_mappings: Arc<RwLock<HashMap<String, String>>>,
        extract_thinking: Arc<AtomicBool>,
        default_stream: Arc<AtomicBool>,
    ) -> Self {
        let cache_path = token_manager
            .cache_dir()
            .map(|d| d.join("kiro_balance_cache.json"));

        let balance_cache = Self::load_balance_cache_from(&cache_path);
        let usage_request_concurrency = token_manager.config().usage_request_concurrency.max(1);

        Self {
            token_manager,
            provider,
            balance_cache: Mutex::new(balance_cache),
            // 批量导入仍可并发写入，但限制额度查询并发，避免触发上游 429。
            usage_request_semaphore: Arc::new(RwLock::new(Arc::new(Semaphore::new(
                usage_request_concurrency,
            )))),
            cache_path,
            model_mappings,
            extract_thinking,
            default_stream,
            known_endpoints: known_endpoints.into_iter().collect(),
        }
    }

    /// 获取所有凭据状态
    pub fn get_all_credentials(&self, query: CredentialsQuery) -> CredentialsStatusResponse {
        self.refresh_balance_cache_from_disk();

        let paginated = query.is_paginated();
        let snapshot = if paginated {
            self.token_manager.snapshot_without_hashes()
        } else {
            self.token_manager.snapshot()
        };
        let default_endpoint = self.token_manager.config().default_endpoint.clone();
        let balance_cache = self.balance_cache.lock();
        let stats = Self::build_request_stats_summary(&snapshot, &balance_cache);
        let disabled_ids = if paginated {
            Some(
                snapshot
                    .entries
                    .iter()
                    .filter(|entry| entry.disabled)
                    .map(|entry| entry.id)
                    .collect(),
            )
        } else {
            None
        };

        let mut credentials: Vec<CredentialStatusItem> = snapshot
            .entries
            .into_iter()
            .map(|entry| CredentialStatusItem {
                id: entry.id,
                priority: entry.priority,
                disabled: entry.disabled,
                failure_count: entry.failure_count,
                is_current: entry.id == snapshot.current_id,
                expires_at: entry.expires_at,
                auth_method: entry.auth_method,
                has_profile_arn: entry.has_profile_arn,
                refresh_token_hash: entry.refresh_token_hash,
                api_key_hash: entry.api_key_hash,
                masked_api_key: entry.masked_api_key,
                email: entry.email,
                success_count: entry.success_count,
                current_concurrent_requests: entry.current_concurrent_requests,
                last_used_at: entry.last_used_at.clone(),
                has_proxy: entry.has_proxy,
                proxy_url: entry.proxy_url,
                refresh_failure_count: entry.refresh_failure_count,
                disabled_reason: entry.disabled_reason,
                endpoint: entry.endpoint.unwrap_or_else(|| default_endpoint.clone()),
                balance: balance_cache
                    .get(&entry.id)
                    .map(|cached| cached.data.clone()),
            })
            .collect();

        let status_counts = Self::build_status_counts(&credentials);

        if matches!(query.status.as_deref(), Some("enabled")) {
            credentials.retain(|credential| !credential.disabled);
        } else if matches!(query.status.as_deref(), Some("disabled")) {
            credentials.retain(|credential| credential.disabled);
        }

        if let Some(reason) = query
            .disabled_reason
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            credentials.retain(|credential| {
                credential.disabled
                    && if reason == "Unknown" {
                        credential
                            .disabled_reason
                            .as_deref()
                            .map(|value| value.trim().is_empty())
                            .unwrap_or(true)
                    } else {
                        credential.disabled_reason.as_deref() == Some(reason)
                    }
            });
        }

        let filtered_total = credentials.len();

        let sort_field = query.sort_field.as_deref().unwrap_or("priority");
        let descending = query
            .sort_direction
            .as_deref()
            .map(|direction| direction.eq_ignore_ascii_case("desc"))
            .unwrap_or(matches!(sort_field, "success" | "lastUsed"));

        credentials.sort_by(|left, right| {
            let ordering = match sort_field {
                "success" => left.success_count.cmp(&right.success_count),
                "lastUsed" => left.last_used_at.cmp(&right.last_used_at),
                "remaining" => left
                    .balance
                    .as_ref()
                    .map(|balance| balance.remaining)
                    .partial_cmp(&right.balance.as_ref().map(|balance| balance.remaining))
                    .unwrap_or(Ordering::Equal),
                _ => left.priority.cmp(&right.priority),
            };

            let ordering = if descending {
                ordering.reverse()
            } else {
                ordering
            };

            ordering.then_with(|| left.id.cmp(&right.id))
        });

        if paginated {
            let page = query.page.unwrap_or(1).max(1);
            let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
            let start = page.saturating_sub(1).saturating_mul(page_size);
            credentials = credentials
                .into_iter()
                .skip(start)
                .take(page_size)
                .collect();
        }

        CredentialsStatusResponse {
            total: snapshot.total,
            available: snapshot.available,
            filtered_total,
            quota_exceeded: snapshot.quota_exceeded,
            status_counts,
            current_id: snapshot.current_id,
            stats,
            credentials,
            disabled_ids,
        }
    }

    fn build_status_counts(credentials: &[CredentialStatusItem]) -> CredentialStatusCounts {
        let mut reason_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut enabled = 0;
        let mut disabled = 0;

        for credential in credentials {
            if credential.disabled {
                disabled += 1;
                let reason = credential
                    .disabled_reason
                    .clone()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "Unknown".to_string());
                *reason_counts.entry(reason).or_insert(0) += 1;
            } else {
                enabled += 1;
            }
        }

        CredentialStatusCounts {
            total: credentials.len(),
            enabled,
            disabled,
            disabled_reasons: reason_counts
                .into_iter()
                .map(|(reason, count)| DisabledReasonCount { reason, count })
                .collect(),
        }
    }

    /// 设置凭据禁用状态
    pub fn set_disabled(&self, id: u64, disabled: bool) -> Result<(), AdminServiceError> {
        // 先获取当前凭据 ID，用于判断是否需要切换
        let snapshot = self.token_manager.snapshot();
        let current_id = snapshot.current_id;

        self.token_manager
            .set_disabled(id, disabled)
            .map_err(|e| self.classify_error(e, id))?;

        // 只有禁用的是当前凭据时才尝试切换到下一个
        if disabled && id == current_id {
            let _ = self.token_manager.switch_to_next();
        }
        Ok(())
    }

    /// 设置凭据优先级
    pub fn set_priority(&self, id: u64, priority: u32) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_priority(id, priority)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 重置失败计数并重新启用
    pub fn reset_and_enable(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .reset_and_enable(id)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 获取凭据余额（带缓存）
    pub async fn get_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        // 先查缓存
        {
            let cache = self.balance_cache.lock();
            if let Some(cached) = cache.get(&id) {
                let now = Utc::now().timestamp() as f64;
                if (now - cached.cached_at) < BALANCE_CACHE_TTL_SECS as f64 {
                    tracing::debug!("凭据 #{} 余额命中缓存", id);
                    return Ok(cached.data.clone());
                }
            }
        }

        // 缓存未命中或已过期，从上游获取
        let balance = self.fetch_balance(id).await?;

        self.store_balance(balance.clone());

        Ok(balance)
    }

    /// 从上游获取余额（无缓存）
    async fn fetch_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        let semaphore = self.usage_request_semaphore.read().clone();
        let _permit = semaphore.acquire_owned().await.map_err(|e| {
            AdminServiceError::InternalError(format!("额度查询并发控制不可用: {e}"))
        })?;

        let usage = self
            .token_manager
            .get_usage_limits_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))?;

        let current_usage = usage.current_usage();
        let usage_limit = usage.usage_limit();
        let remaining = (usage_limit - current_usage).max(0.0);
        let usage_percentage = if usage_limit > 0.0 {
            (current_usage / usage_limit * 100.0).min(100.0)
        } else {
            0.0
        };

        Ok(BalanceResponse {
            id,
            subscription_title: usage.subscription_title().map(|s| s.to_string()),
            current_usage,
            usage_limit,
            remaining,
            usage_percentage,
            next_reset_at: usage.next_date_reset,
        })
    }

    /// 添加新凭据
    pub async fn add_credential(
        &self,
        req: AddCredentialRequest,
    ) -> Result<AddCredentialResponse, AdminServiceError> {
        // 校验端点名：未指定则默认合法，指定则必须已注册
        if let Some(ref name) = req.endpoint {
            if !self.known_endpoints.contains(name) {
                let mut known: Vec<&str> =
                    self.known_endpoints.iter().map(|s| s.as_str()).collect();
                known.sort();
                return Err(AdminServiceError::InvalidCredential(format!(
                    "未知端点 \"{}\"，已注册端点: {:?}",
                    name, known
                )));
            }
        }

        // 构建凭据对象
        let email = req.email.clone();
        let new_cred = KiroCredentials {
            id: None,
            access_token: None,
            refresh_token: req.refresh_token,
            profile_arn: None,
            expires_at: None,
            auth_method: Some(req.auth_method),
            client_id: req.client_id,
            client_secret: req.client_secret,
            priority: req.priority,
            region: req.region,
            auth_region: req.auth_region,
            api_region: req.api_region,
            machine_id: req.machine_id,
            email: req.email,
            subscription_title: None, // 将在首次获取使用额度时自动更新
            proxy_url: req.proxy_url,
            proxy_username: req.proxy_username,
            proxy_password: req.proxy_password,
            disabled: false, // 新添加的凭据默认启用
            disabled_reason: None,
            quota_last_probed_at: None,
            kiro_api_key: req.kiro_api_key,
            endpoint: req.endpoint,
        };

        // 调用 token_manager 添加凭据
        let credential_id = self
            .token_manager
            .add_credential(new_cred)
            .await
            .map_err(|e| self.classify_add_error(e))?;

        Ok(AddCredentialResponse {
            success: true,
            message: format!("凭据添加成功，ID: {}", credential_id),
            credential_id,
            email,
        })
    }

    /// 删除凭据
    pub fn delete_credential(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .delete_credential(id)
            .map_err(|e| self.classify_delete_error(e, id))?;

        // 清理已删除凭据的余额缓存
        {
            let mut cache = self.balance_cache.lock();
            cache.remove(&id);
        }
        self.save_balance_cache();

        Ok(())
    }

    /// 获取负载均衡模式
    pub fn get_load_balancing_mode(&self) -> LoadBalancingModeResponse {
        LoadBalancingModeResponse {
            mode: self.token_manager.get_load_balancing_mode(),
        }
    }

    /// 设置负载均衡模式
    pub fn set_load_balancing_mode(
        &self,
        req: SetLoadBalancingModeRequest,
    ) -> Result<LoadBalancingModeResponse, AdminServiceError> {
        // 验证模式值
        if !matches!(req.mode.as_str(), "priority" | "balanced") {
            return Err(AdminServiceError::InvalidCredential(
                "mode 必须是 'priority' 或 'balanced'".to_string(),
            ));
        }

        self.token_manager
            .set_load_balancing_mode(req.mode.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(LoadBalancingModeResponse { mode: req.mode })
    }

    /// 获取当前服务配置。
    ///
    /// 优先读取配置文件，确保页面能看到刚保存但尚未重启的配置；
    /// 负载均衡模式使用运行时值，因为它支持热更新。
    pub fn get_config(&self) -> Result<AdminConfigResponse, AdminServiceError> {
        let mut config = self.load_persisted_config()?;
        config.load_balancing_mode = self.token_manager.get_load_balancing_mode();

        Ok(AdminConfigResponse {
            config,
            changed_fields: Vec::new(),
            restart_required_fields: Vec::new(),
            restart_required: false,
        })
    }

    /// 保存服务配置。
    ///
    /// 负载均衡模式和模型映射支持热更新，其余配置会先写入 config.json，
    /// 由页面提示用户重启服务后生效。
    pub fn update_config(
        &self,
        requested: Config,
    ) -> Result<AdminConfigResponse, AdminServiceError> {
        Self::validate_config(&requested, &self.known_endpoints)?;

        let current = self.load_persisted_config()?;
        let runtime_mode = self.token_manager.get_load_balancing_mode();
        let mut changed_fields = Vec::new();

        macro_rules! changed {
            ($field:ident, $name:literal) => {
                if current.$field != requested.$field {
                    changed_fields.push($name.to_string());
                }
            };
        }

        changed!(host, "host");
        changed!(port, "port");
        changed!(region, "region");
        changed!(auth_region, "authRegion");
        changed!(api_region, "apiRegion");
        changed!(kiro_version, "kiroVersion");
        changed!(machine_id, "machineId");
        changed!(api_key, "apiKey");
        changed!(system_version, "systemVersion");
        changed!(node_version, "nodeVersion");
        changed!(tls_backend, "tlsBackend");
        changed!(count_tokens_api_url, "countTokensApiUrl");
        changed!(count_tokens_api_key, "countTokensApiKey");
        changed!(count_tokens_auth_type, "countTokensAuthType");
        changed!(proxy_url, "proxyUrl");
        changed!(proxy_username, "proxyUsername");
        changed!(proxy_password, "proxyPassword");
        changed!(admin_api_key, "adminApiKey");
        changed!(credential_storage, "credentialStorage");
        changed!(credential_database_path, "credentialDatabasePath");
        changed!(load_balancing_mode, "loadBalancingMode");
        changed!(
            max_concurrent_requests_per_credential,
            "maxConcurrentRequestsPerCredential"
        );
        changed!(
            disabled_credential_recovery_interval_seconds,
            "disabledCredentialRecoveryIntervalSeconds"
        );
        changed!(
            disabled_credential_recovery_batch_size,
            "disabledCredentialRecoveryBatchSize"
        );
        changed!(batch_import_concurrency, "batchImportConcurrency");
        changed!(usage_request_concurrency, "usageRequestConcurrency");
        changed!(
            proactive_token_refresh_interval_seconds,
            "proactiveTokenRefreshIntervalSeconds"
        );
        changed!(
            proactive_token_refresh_batch_size,
            "proactiveTokenRefreshBatchSize"
        );
        changed!(
            proactive_token_refresh_concurrency,
            "proactiveTokenRefreshConcurrency"
        );
        changed!(usage_query_interval_seconds, "usageQueryIntervalSeconds");
        changed!(
            usage_query_disable_remaining_threshold,
            "usageQueryDisableRemainingThreshold"
        );
        changed!(extract_thinking, "extractThinking");
        changed!(default_stream, "defaultStream");
        changed!(default_endpoint, "defaultEndpoint");
        changed!(endpoints, "endpoints");
        changed!(model_mappings, "modelMappings");

        let config_path = self
            .token_manager
            .config()
            .config_path()
            .ok_or_else(|| AdminServiceError::InternalError("配置文件路径未知".to_string()))?
            .to_path_buf();

        requested
            .save_to(&config_path)
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        if requested.model_mappings != current.model_mappings {
            *self.model_mappings.write() = requested.model_mappings.clone();
        }

        if requested.usage_request_concurrency != current.usage_request_concurrency {
            *self.usage_request_semaphore.write() =
                Arc::new(Semaphore::new(requested.usage_request_concurrency.max(1)));
        }

        if requested.max_concurrent_requests_per_credential
            != current.max_concurrent_requests_per_credential
        {
            self.token_manager
                .update_max_concurrent_requests_per_credential(
                    requested.max_concurrent_requests_per_credential,
                );
        }

        if requested.disabled_credential_recovery_interval_seconds
            != current.disabled_credential_recovery_interval_seconds
            || requested.disabled_credential_recovery_batch_size
                != current.disabled_credential_recovery_batch_size
        {
            self.token_manager.update_disabled_credential_recovery(
                requested.disabled_credential_recovery_interval_seconds,
                requested.disabled_credential_recovery_batch_size,
            );
        }

        if requested.proactive_token_refresh_interval_seconds
            != current.proactive_token_refresh_interval_seconds
            || requested.proactive_token_refresh_batch_size
                != current.proactive_token_refresh_batch_size
            || requested.proactive_token_refresh_concurrency
                != current.proactive_token_refresh_concurrency
        {
            self.token_manager.update_proactive_token_refresh(
                requested.proactive_token_refresh_interval_seconds,
                requested.proactive_token_refresh_batch_size,
                requested.proactive_token_refresh_concurrency,
            );
        }

        // 额度查询间隔独立；每轮账号数/并发数复用 Token 预刷新参数，因此这些参数变化也需重启该任务。
        if requested.usage_query_interval_seconds != current.usage_query_interval_seconds
            || requested.proactive_token_refresh_batch_size
                != current.proactive_token_refresh_batch_size
            || requested.proactive_token_refresh_concurrency
                != current.proactive_token_refresh_concurrency
            || requested.usage_query_disable_remaining_threshold
                != current.usage_query_disable_remaining_threshold
        {
            self.token_manager.update_usage_query(
                requested.usage_query_interval_seconds,
                requested.proactive_token_refresh_batch_size,
                requested.proactive_token_refresh_concurrency,
                requested.usage_query_disable_remaining_threshold,
            );
        }

        if requested.extract_thinking != current.extract_thinking {
            self.extract_thinking
                .store(requested.extract_thinking, AtomicOrdering::Relaxed);
        }

        if requested.default_stream != current.default_stream {
            self.default_stream
                .store(requested.default_stream, AtomicOrdering::Relaxed);
        }

        if requested.load_balancing_mode != runtime_mode {
            self.token_manager
                .set_load_balancing_mode(requested.load_balancing_mode.clone())
                .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;
        }

        let restart_required_fields: Vec<String> = changed_fields
            .iter()
            .filter(|field| {
                !matches!(
                    field.as_str(),
                    "loadBalancingMode"
                        | "maxConcurrentRequestsPerCredential"
                        | "disabledCredentialRecoveryIntervalSeconds"
                        | "disabledCredentialRecoveryBatchSize"
                        | "modelMappings"
                        | "batchImportConcurrency"
                        | "usageRequestConcurrency"
                        | "proactiveTokenRefreshIntervalSeconds"
                        | "proactiveTokenRefreshBatchSize"
                        | "proactiveTokenRefreshConcurrency"
                        | "usageQueryIntervalSeconds"
                        | "usageQueryDisableRemainingThreshold"
                        | "extractThinking"
                        | "defaultStream"
                )
            })
            .cloned()
            .collect();

        Ok(AdminConfigResponse {
            config: requested,
            restart_required: !restart_required_fields.is_empty(),
            restart_required_fields,
            changed_fields,
        })
    }

    fn load_persisted_config(&self) -> Result<Config, AdminServiceError> {
        let path = self
            .token_manager
            .config()
            .config_path()
            .ok_or_else(|| AdminServiceError::InternalError("配置文件路径未知".to_string()))?;

        Config::load(path).map_err(|e| AdminServiceError::InternalError(e.to_string()))
    }

    fn validate_config(
        config: &Config,
        known_endpoints: &HashSet<String>,
    ) -> Result<(), AdminServiceError> {
        if config.host.trim().is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "host 不能为空".to_string(),
            ));
        }
        if config.port == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "port 必须大于 0".to_string(),
            ));
        }
        if config.api_key.as_deref().unwrap_or("").trim().is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "apiKey 不能为空".to_string(),
            ));
        }
        if !matches!(config.load_balancing_mode.as_str(), "priority" | "balanced") {
            return Err(AdminServiceError::InvalidCredential(
                "loadBalancingMode 必须是 priority 或 balanced".to_string(),
            ));
        }
        if config.max_concurrent_requests_per_credential == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "maxConcurrentRequestsPerCredential 必须大于 0".to_string(),
            ));
        }
        if config.disabled_credential_recovery_interval_seconds > 0
            && config.disabled_credential_recovery_batch_size == 0
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用禁用凭据恢复检查时，disabledCredentialRecoveryBatchSize 必须大于 0"
                    .to_string(),
            ));
        }
        if config.batch_import_concurrency == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "batchImportConcurrency 必须大于 0".to_string(),
            ));
        }
        if config.usage_request_concurrency == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "usageRequestConcurrency 必须大于 0".to_string(),
            ));
        }
        if config.proactive_token_refresh_interval_seconds > 0
            && config.proactive_token_refresh_batch_size == 0
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用 Token 后台预刷新时，proactiveTokenRefreshBatchSize 必须大于 0".to_string(),
            ));
        }
        if config.proactive_token_refresh_interval_seconds > 0
            && config.proactive_token_refresh_concurrency == 0
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用 Token 后台预刷新时，proactiveTokenRefreshConcurrency 必须大于 0".to_string(),
            ));
        }
        if config.usage_query_interval_seconds > 0
            && (config.proactive_token_refresh_batch_size == 0
                || config.proactive_token_refresh_concurrency == 0)
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用后台额度查询时，proactiveTokenRefreshBatchSize 与 proactiveTokenRefreshConcurrency 必须大于 0（两者与额度查询共用）"
                    .to_string(),
            ));
        }
        if !config.usage_query_disable_remaining_threshold.is_finite()
            || config.usage_query_disable_remaining_threshold < 0.0
        {
            return Err(AdminServiceError::InvalidCredential(
                "usageQueryDisableRemainingThreshold 必须是大于等于 0 的数字".to_string(),
            ));
        }
        if config.count_tokens_auth_type != "x-api-key" && config.count_tokens_auth_type != "bearer"
        {
            return Err(AdminServiceError::InvalidCredential(
                "countTokensAuthType 必须是 x-api-key 或 bearer".to_string(),
            ));
        }
        if !known_endpoints.contains(&config.default_endpoint) {
            return Err(AdminServiceError::InvalidCredential(format!(
                "未知默认端点 \"{}\"，已注册端点: {:?}",
                config.default_endpoint, known_endpoints
            )));
        }
        let mut mapping_sources = HashSet::new();
        for (source, target) in &config.model_mappings {
            let normalized_source = source.trim().to_lowercase();
            if normalized_source.is_empty() {
                return Err(AdminServiceError::InvalidCredential(
                    "modelMappings 中的请求模型名不能为空".to_string(),
                ));
            }
            if target.trim().is_empty() {
                return Err(AdminServiceError::InvalidCredential(format!(
                    "modelMappings 中模型 \"{}\" 的目标模型不能为空",
                    source
                )));
            }
            if !mapping_sources.insert(normalized_source) {
                return Err(AdminServiceError::InvalidCredential(format!(
                    "modelMappings 中存在重复的请求模型名: {}",
                    source
                )));
            }
        }

        Ok(())
    }

    pub fn get_models(&self) -> AdminModelsResponse {
        let model_mappings = self.model_mappings.read().clone();
        AdminModelsResponse {
            object: "list".to_string(),
            data: list_models_with_mappings(&model_mappings),
        }
    }

    pub async fn test_service(
        &self,
        prompt: String,
        model: String,
        credential_id: Option<u64>,
    ) -> Result<ServiceTestResponse, AdminServiceError> {
        let config = self.load_persisted_config()?;
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "测试内容不能为空".to_string(),
            ));
        }

        let model = model.trim().to_string();
        if model.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "测试模型不能为空".to_string(),
            ));
        }

        if let Some(credential_id) = credential_id {
            let mappings = self.model_mappings.read().clone();
            let kiro_model =
                map_model_with_mappings(&model, &mappings).unwrap_or_else(|| model.clone());
            return self
                .test_specific_credential(credential_id, prompt, &model, &kiro_model)
                .await;
        }

        let api_key = config.api_key.as_deref().unwrap_or("").trim();
        if api_key.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "apiKey 未配置，无法测试服务".to_string(),
            ));
        }

        let request_host = match config.host.as_str() {
            "0.0.0.0" | "::" => "127.0.0.1",
            host => host,
        };
        let url = format!("http://{}:{}/v1/messages", request_host, config.port);
        let client = build_client(None, SERVICE_TEST_TIMEOUT_SECS, config.tls_backend)
            .map_err(|e| AdminServiceError::InternalError(format!("构建测试客户端失败: {e}")))?;

        let started_at = Instant::now();
        let response = client
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&serde_json::json!({
                "model": model,
                "max_tokens": 32,
                "stream": false,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            }))
            .send()
            .await
            .map_err(|e| AdminServiceError::UpstreamError(format!("测试请求发送失败: {e}")))?;

        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(|e| AdminServiceError::UpstreamError(format!("读取测试响应失败: {e}")))?;

        if !status.is_success() {
            return Err(AdminServiceError::UpstreamError(format!(
                "测试请求返回 HTTP {}: {}",
                status.as_u16(),
                Self::preview_text(&raw_body)
            )));
        }

        let parsed: Value = serde_json::from_str(&raw_body)
            .map_err(|e| AdminServiceError::UpstreamError(format!("解析测试响应失败: {e}")))?;
        let reply_text = Self::extract_test_reply_text(&parsed);
        let response_preview = reply_text
            .as_deref()
            .map(Self::preview_text)
            .filter(|preview| !preview.is_empty())
            .unwrap_or_else(|| Self::preview_text(&raw_body));

        Ok(ServiceTestResponse {
            success: true,
            model,
            prompt: prompt.to_string(),
            status: status.as_u16(),
            latency_ms: started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
            credential_id: None,
            email: None,
            reply_text,
            response_preview,
        })
    }

    async fn test_specific_credential(
        &self,
        credential_id: u64,
        prompt: &str,
        requested_model: &str,
        kiro_model: &str,
    ) -> Result<ServiceTestResponse, AdminServiceError> {
        let request = KiroRequest {
            conversation_state: ConversationState::new(format!(
                "admin-test-{}",
                Uuid::new_v4().simple()
            ))
            .with_agent_task_type("vibe")
            .with_chat_trigger_type("MANUAL")
            .with_current_message(CurrentMessage::new(UserInputMessage::new(
                prompt, kiro_model,
            ))),
            profile_arn: None,
        };

        let request_body = serde_json::to_string(&request)
            .map_err(|e| AdminServiceError::InternalError(format!("序列化测试请求失败: {e}")))?;

        let started_at = Instant::now();
        let (response, account_id, _request_lease) = self
            .provider
            .call_api_for_credential(&request_body, credential_id)
            .await
            .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))?;

        let status = response.status();
        let body_bytes = response.bytes().await.map_err(|e| {
            AdminServiceError::UpstreamError(format!("读取指定账号测试响应失败: {e}"))
        })?;

        let reply_text = Self::extract_kiro_reply_text(&body_bytes);
        let response_preview = reply_text
            .as_deref()
            .map(Self::preview_text)
            .filter(|preview| !preview.is_empty())
            .unwrap_or_else(|| "已收到响应，但未解析到文本内容".to_string());

        let actual_credential_id = account_id.parse::<u64>().ok().or(Some(credential_id));
        let email = actual_credential_id.and_then(|id| self.lookup_credential_email(id));

        Ok(ServiceTestResponse {
            success: true,
            model: requested_model.to_string(),
            prompt: prompt.to_string(),
            status: status.as_u16(),
            latency_ms: started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
            credential_id: actual_credential_id,
            email,
            reply_text,
            response_preview,
        })
    }

    fn extract_test_reply_text(payload: &Value) -> Option<String> {
        let content = payload.get("content")?.as_array()?;
        let mut chunks = Vec::new();

        for item in content {
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                let text = text.trim();
                if !text.is_empty() {
                    chunks.push(text.to_string());
                }
            }
        }

        if chunks.is_empty() {
            None
        } else {
            Some(chunks.join("\n"))
        }
    }

    fn extract_kiro_reply_text(body_bytes: &[u8]) -> Option<String> {
        let mut decoder = EventStreamDecoder::new();
        if decoder.feed(body_bytes).is_err() {
            return None;
        }

        let mut text_content = String::new();
        for result in decoder.decode_iter() {
            let Ok(frame) = result else {
                continue;
            };
            let Ok(event) = Event::from_frame(frame) else {
                continue;
            };
            if let Event::AssistantResponse(response) = event {
                text_content.push_str(&response.content);
            }
        }

        let text_content = text_content.trim();
        if text_content.is_empty() {
            None
        } else {
            Some(text_content.to_string())
        }
    }

    fn preview_text(input: &str) -> String {
        let mut preview = input.split_whitespace().collect::<Vec<_>>().join(" ");
        if preview.chars().count() > SERVICE_TEST_PREVIEW_LIMIT {
            preview = preview.chars().take(SERVICE_TEST_PREVIEW_LIMIT).collect();
            preview.push_str("...");
        }
        preview
    }

    fn lookup_credential_email(&self, credential_id: u64) -> Option<String> {
        self.token_manager
            .snapshot_without_hashes()
            .entries
            .into_iter()
            .find(|entry| entry.id == credential_id)
            .and_then(|entry| entry.email)
    }

    /// 强制刷新指定凭据的 Token
    pub async fn force_refresh_token(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .force_refresh_token_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))
    }

    // ============ 余额缓存持久化 ============

    fn load_balance_cache_from(cache_path: &Option<PathBuf>) -> HashMap<u64, CachedBalance> {
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
                .filter_map(|(k, v)| {
                    let id = k.parse::<u64>().ok()?;
                    // 旧缓存仍用于列表展示；单个余额查询会按 TTL 决定是否刷新上游。
                    Some((id, v))
                })
                .collect()
        })
    }

    fn refresh_balance_cache_from_disk(&self) {
        let loaded = Self::load_balance_cache_from(&self.cache_path);
        if loaded.is_empty() {
            return;
        }

        let mut cache = self.balance_cache.lock();
        for (id, disk_entry) in loaded {
            let should_replace = cache
                .get(&id)
                .map(|current| disk_entry.cached_at >= current.cached_at)
                .unwrap_or(true);
            if should_replace {
                cache.insert(id, disk_entry);
            }
        }
    }

    fn store_balance(&self, balance: BalanceResponse) {
        {
            let mut cache = self.balance_cache.lock();
            cache.insert(
                balance.id,
                CachedBalance {
                    cached_at: Utc::now().timestamp() as f64,
                    data: balance,
                },
            );
        }
        self.save_balance_cache();
    }

    fn save_balance_cache(&self) {
        let path = match &self.cache_path {
            Some(p) => p,
            None => return,
        };

        // 持有锁期间完成序列化和写入，防止并发损坏
        let cache = self.balance_cache.lock();
        let map: HashMap<String, &CachedBalance> =
            cache.iter().map(|(k, v)| (k.to_string(), v)).collect();

        with_balance_cache_file_lock(|| match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("保存余额缓存失败: {}", e);
                }
            }
            Err(e) => tracing::warn!("序列化余额缓存失败: {}", e),
        });
    }

    fn build_request_stats_summary(
        snapshot: &ManagerSnapshot,
        balance_cache: &HashMap<u64, CachedBalance>,
    ) -> RequestStatsSummary {
        let mut remaining_quota = 0.0;
        let mut today_consumed_quota = 0.0;
        let mut total_consumed_quota = 0.0;

        for entry in &snapshot.entries {
            today_consumed_quota += entry.today_token_count as f64;

            if let Some(cached) = balance_cache.get(&entry.id) {
                let balance = &cached.data;
                if balance.remaining.is_finite() {
                    remaining_quota += balance.remaining;
                }
                if balance.current_usage.is_finite() {
                    total_consumed_quota += balance.current_usage;
                }
            }
        }

        RequestStatsSummary {
            rpm: snapshot.rpm,
            total_request_count: snapshot.total_request_count,
            total_token_count: snapshot.total_token_count,
            total_success_count: snapshot.total_success_count,
            total_success_rate: if snapshot.total_request_count > 0 {
                snapshot.total_success_count as f64 * 100.0 / snapshot.total_request_count as f64
            } else {
                0.0
            },
            today_request_count: snapshot.today_request_count,
            today_token_count: snapshot.today_token_count,
            today_success_count: snapshot.today_success_count,
            today_success_rate: if snapshot.today_request_count > 0 {
                snapshot.today_success_count as f64 * 100.0 / snapshot.today_request_count as f64
            } else {
                0.0
            },
            remaining_quota,
            today_consumed_quota,
            total_consumed_quota,
        }
    }

    // ============ 错误分类 ============

    /// 分类简单操作错误（set_disabled, set_priority, reset_and_enable）
    fn classify_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类余额查询错误（可能涉及上游 API 调用）
    fn classify_balance_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();

        // 1. 凭据不存在
        if msg.contains("不存在") {
            return AdminServiceError::NotFound { id };
        }

        // 2. API Key 凭据不支持刷新：客户端请求错误，映射为 400
        if msg.contains("API Key 凭据不支持刷新") {
            return AdminServiceError::InvalidCredential(msg);
        }

        // 3. 上游服务错误特征：HTTP 响应错误或网络错误
        let is_upstream_error =
            // HTTP 响应错误（来自 refresh_*_token 的错误消息）
            msg.contains("凭证已过期或无效") ||
            msg.contains("权限不足") ||
            msg.contains("已被限流") ||
            msg.contains("服务器错误") ||
            msg.contains("Token 刷新失败") ||
            msg.contains("暂时不可用") ||
            // 网络错误（reqwest 错误）
            msg.contains("error trying to connect") ||
            msg.contains("connection") ||
            msg.contains("timeout") ||
            msg.contains("timed out");

        if is_upstream_error {
            AdminServiceError::UpstreamError(msg)
        } else {
            // 4. 默认归类为内部错误（本地验证失败、配置错误等）
            // 包括：缺少 refreshToken、refreshToken 已被截断、无法生成 machineId 等
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类添加凭据错误
    fn classify_add_error(&self, e: anyhow::Error) -> AdminServiceError {
        let msg = e.to_string();

        // 凭据验证失败（refreshToken 无效、格式错误等）
        let is_invalid_credential = msg.contains("缺少 refreshToken")
            || msg.contains("refreshToken 为空")
            || msg.contains("refreshToken 已被截断")
            || msg.contains("凭据已存在")
            || msg.contains("refreshToken 重复")
            || msg.contains("kiroApiKey 重复")
            || msg.contains("缺少 kiroApiKey")
            || msg.contains("kiroApiKey 为空")
            || msg.contains("凭证已过期或无效")
            || msg.contains("权限不足")
            || msg.contains("已被限流");

        if is_invalid_credential {
            AdminServiceError::InvalidCredential(msg)
        } else if msg.contains("error trying to connect")
            || msg.contains("connection")
            || msg.contains("timeout")
        {
            AdminServiceError::UpstreamError(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类删除凭据错误
    fn classify_delete_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else if msg.contains("只能删除已禁用的凭据") || msg.contains("请先禁用凭据")
        {
            AdminServiceError::InvalidCredential(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_balance_cache_keeps_stale_entries_for_list_display() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "kiro_balance_cache_test_{}.json",
            uuid::Uuid::new_v4()
        ));

        let stale_balance = BalanceResponse {
            id: 42,
            subscription_title: Some("KIRO FREE".to_string()),
            current_usage: 12.0,
            usage_limit: 50.0,
            remaining: 38.0,
            usage_percentage: 24.0,
            next_reset_at: Some(1_785_542_400.0),
        };
        let cached = CachedBalance {
            cached_at: 1.0,
            data: stale_balance.clone(),
        };
        let json = serde_json::json!({
            "42": cached,
        });
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cache_path = Some(path.clone());
        let loaded = AdminService::load_balance_cache_from(&cache_path);

        fs::remove_file(path).ok();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get(&42).unwrap().data.remaining,
            stale_balance.remaining
        );
    }

    #[test]
    fn load_balance_cache_accepts_camel_case_file_written_by_token_manager() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "kiro_balance_cache_test_{}.json",
            uuid::Uuid::new_v4()
        ));

        let json = serde_json::json!({
            "8": {
                "cachedAt": 1_785_542_400.0,
                "data": {
                    "id": 8,
                    "subscriptionTitle": "KIRO FREE",
                    "currentUsage": 12.0,
                    "usageLimit": 50.0,
                    "remaining": 38.0,
                    "usagePercentage": 24.0,
                    "nextResetAt": 1_785_628_800.0
                }
            }
        });
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cache_path = Some(path.clone());
        let loaded = AdminService::load_balance_cache_from(&cache_path);

        fs::remove_file(path).ok();
        let balance = &loaded.get(&8).unwrap().data;
        assert_eq!(loaded.len(), 1);
        assert_eq!(balance.subscription_title.as_deref(), Some("KIRO FREE"));
        assert_eq!(balance.remaining, 38.0);
    }
}
