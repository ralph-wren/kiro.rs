//! Admin API 业务逻辑服务

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use crate::kiro::quota::{CachedBalance, CreditStats};
use chrono::Utc;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::anthropic::{
    active_entry_counts, list_models_with_mappings, map_model_with_mappings, set_usage_multipliers,
};
use crate::http_client::build_client;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::events::Event;
use crate::kiro::model::requests::conversation::{
    ConversationState, CurrentMessage, UserInputMessage,
};
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::provider::KiroProvider;
use crate::kiro::token_manager::{ManagerSnapshot, MultiTokenManager};
use crate::model::config::Config;

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, AdminConfigResponse, AdminModelsResponse,
    BalanceResponse, CredentialStatusCounts, CredentialStatusItem, CredentialsQuery,
    CredentialsStatusResponse, DisabledReasonCount, LoadBalancingModeResponse, RequestStatsSummary,
    ServiceTestResponse, SetCredentialEmailRequest, SetLoadBalancingModeRequest,
};

const SERVICE_TEST_TIMEOUT_SECS: u64 = 45;
const SERVICE_TEST_PREVIEW_LIMIT: usize = 240;

fn remaining_quota_percentage(balance: Option<&BalanceResponse>) -> Option<f64> {
    let balance = balance?;
    if !balance.usage_limit.is_finite()
        || balance.usage_limit <= 0.0
        || !balance.remaining.is_finite()
        || balance.remaining < 0.0
    {
        return None;
    }
    Some((balance.remaining / balance.usage_limit).clamp(0.0, 1.0) * 100.0)
}

fn compare_remaining_percentage(
    left: Option<f64>,
    right: Option<f64>,
    descending: bool,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            let ordering = left.total_cmp(&right);
            if descending {
                ordering.reverse()
            } else {
                ordering
            }
        }
        // 未获取到额度的账号在两个排序方向下都放到最后。
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn has_valid_cached_balance(cached: &CachedBalance) -> bool {
    [
        cached.data.remaining,
        cached.data.current_usage,
        cached.data.usage_limit,
    ]
    .iter()
    .all(|value| value.is_finite() && *value >= 0.0)
}

/// Admin 服务
///
/// 封装所有 Admin API 的业务逻辑
pub struct AdminService {
    token_manager: Arc<MultiTokenManager>,
    provider: Arc<KiroProvider>,
    usage_request_semaphore: Arc<RwLock<Arc<Semaphore>>>,
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
        let usage_request_concurrency = token_manager.config().usage_request_concurrency.max(1);

        Self {
            token_manager,
            provider,
            // 批量导入仍可并发写入，但限制额度查询并发，避免触发上游 429。
            usage_request_semaphore: Arc::new(RwLock::new(Arc::new(Semaphore::new(
                usage_request_concurrency,
            )))),
            model_mappings,
            extract_thinking,
            default_stream,
            known_endpoints: known_endpoints.into_iter().collect(),
        }
    }

    /// 获取所有凭据状态
    pub fn get_all_credentials(&self, query: CredentialsQuery) -> CredentialsStatusResponse {
        let paginated = query.is_paginated();
        let snapshot = if paginated {
            self.token_manager.snapshot_without_hashes()
        } else {
            self.token_manager.snapshot()
        };
        let default_endpoint = self.token_manager.config().default_endpoint.clone();
        let active_cache_entry_counts = active_entry_counts();
        let balance_cache = self.token_manager.balance_snapshot();
        let credit_stats = self.token_manager.credit_stats();
        let stats = Self::build_request_stats_summary(
            &snapshot,
            &balance_cache,
            self.token_manager
                .get_usage_query_disable_remaining_threshold(),
            &credit_stats,
        );
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
            .map(|entry| {
                let balance = balance_cache
                    .get(&entry.id)
                    // 列表展示最后一次成功查询并已落盘的真实快照；
                    // 顶部“可调用剩余额度”仍在 build_request_stats_summary 中严格只计新鲜快照。
                    .filter(|cached| entry.callable && has_valid_cached_balance(cached))
                    .map(|cached| cached.data.clone());
                CredentialStatusItem {
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
                    active_cache_entry_count: active_cache_entry_counts
                        .get(&entry.id.to_string())
                        .copied()
                        .unwrap_or(0),
                    current_concurrent_requests: entry.current_concurrent_requests,
                    upstream_header_latency_ema_ms: entry.upstream_header_latency_ema_ms,
                    last_used_at: entry.last_used_at.clone(),
                    has_proxy: entry.has_proxy,
                    proxy_url: entry.proxy_url,
                    refresh_failure_count: entry.refresh_failure_count,
                    disabled_reason: entry.disabled_reason,
                    endpoint: entry.endpoint.unwrap_or_else(|| default_endpoint.clone()),
                    display_subscription_title: entry.display_subscription_title,
                    display_usage_limit: entry.display_usage_limit,
                    remaining_percentage: remaining_quota_percentage(balance.as_ref()),
                    balance,
                }
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

        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let normalized_search = search.trim_start_matches('#').to_lowercase();
            credentials.retain(|credential| {
                credential.id.to_string().contains(&normalized_search)
                    || credential
                        .email
                        .as_deref()
                        .map(|email| email.to_lowercase().contains(&normalized_search))
                        .unwrap_or(false)
            });
        }

        let filtered_total = credentials.len();
        let filtered_ids: Vec<u64> = credentials.iter().map(|credential| credential.id).collect();
        let filtered_disabled_ids: Vec<u64> = credentials
            .iter()
            .filter(|credential| credential.disabled)
            .map(|credential| credential.id)
            .collect();
        let filtered_failed_ids: Vec<u64> = credentials
            .iter()
            .filter(|credential| {
                credential.failure_count > 0 || credential.refresh_failure_count > 0
            })
            .map(|credential| credential.id)
            .collect();

        let sort_field = query.sort_field.as_deref().unwrap_or("priority");
        let descending = query
            .sort_direction
            .as_deref()
            .map(|direction| direction.eq_ignore_ascii_case("desc"))
            .unwrap_or(matches!(
                sort_field,
                "success" | "lastUsed" | "remainingPercentage"
            ));

        credentials.sort_by(|left, right| {
            if sort_field == "remainingPercentage" {
                return compare_remaining_percentage(
                    left.remaining_percentage,
                    right.remaining_percentage,
                    descending,
                )
                .then_with(|| left.id.cmp(&right.id));
            }
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
            filtered_ids,
            filtered_disabled_ids,
            filtered_failed_ids,
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

    /// 设置凭据邮箱
    pub fn set_email(
        &self,
        id: u64,
        req: SetCredentialEmailRequest,
    ) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_email(id, req.email)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 重置失败计数并重新启用
    pub fn reset_and_enable(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .reset_and_enable(id)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 用户主动查询时重新读取上游，不把旧余额当作验活结果。
    pub async fn get_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        let semaphore = self.usage_request_semaphore.read().clone();
        let _permit = semaphore.acquire_owned().await.map_err(|e| {
            AdminServiceError::InternalError(format!("额度查询并发控制不可用: {e}"))
        })?;
        let usage = self
            .token_manager
            .get_usage_limits_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))?;
        CachedBalance::from_usage(id, &usage, None)
            .map(|cached| cached.data)
            .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))
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
        let email = req
            .email
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
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
            email: email.clone(),
            subscription_title: None, // 将在首次获取使用额度时自动更新
            display_subscription_title: None,
            display_usage_limit: None,
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

        self.token_manager.invalidate_balance(id);

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
            per_credential_rate_limit_max_requests,
            "perCredentialRateLimitMaxRequests"
        );
        changed!(
            per_credential_rate_limit_window_seconds,
            "perCredentialRateLimitWindowSeconds"
        );
        changed!(global_rate_limit_max_requests, "globalRateLimitMaxRequests");
        changed!(
            global_rate_limit_window_seconds,
            "globalRateLimitWindowSeconds"
        );
        changed!(
            cache_account_protection_seconds,
            "cacheAccountProtectionSeconds"
        );
        changed!(cache_account_wait_seconds, "cacheAccountWaitSeconds");
        changed!(rate_limit_cooldown_seconds, "rateLimitCooldownSeconds");
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
        changed!(
            cache_creation_usage_multiplier,
            "cacheCreationUsageMultiplier"
        );
        changed!(cache_read_usage_multiplier, "cacheReadUsageMultiplier");
        changed!(extract_thinking, "extractThinking");
        changed!(default_stream, "defaultStream");
        changed!(test_default_model, "testDefaultModel");
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

        if requested.per_credential_rate_limit_max_requests
            != current.per_credential_rate_limit_max_requests
            || requested.per_credential_rate_limit_window_seconds
                != current.per_credential_rate_limit_window_seconds
            || requested.global_rate_limit_max_requests != current.global_rate_limit_max_requests
            || requested.global_rate_limit_window_seconds
                != current.global_rate_limit_window_seconds
        {
            self.token_manager.update_rate_limits(
                requested.per_credential_rate_limit_max_requests,
                requested.per_credential_rate_limit_window_seconds,
                requested.global_rate_limit_max_requests,
                requested.global_rate_limit_window_seconds,
            );
        }

        if requested.cache_account_protection_seconds != current.cache_account_protection_seconds {
            self.token_manager.update_cache_account_protection_seconds(
                requested.cache_account_protection_seconds,
            );
        }
        if requested.cache_account_wait_seconds != current.cache_account_wait_seconds {
            self.token_manager
                .update_cache_account_wait_seconds(requested.cache_account_wait_seconds);
        }

        if requested.rate_limit_cooldown_seconds != current.rate_limit_cooldown_seconds {
            self.token_manager
                .update_rate_limit_cooldown_seconds(requested.rate_limit_cooldown_seconds);
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

        if requested.cache_creation_usage_multiplier != current.cache_creation_usage_multiplier
            || requested.cache_read_usage_multiplier != current.cache_read_usage_multiplier
        {
            set_usage_multipliers(
                requested.cache_creation_usage_multiplier,
                requested.cache_read_usage_multiplier,
            );
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
                        | "perCredentialRateLimitMaxRequests"
                        | "perCredentialRateLimitWindowSeconds"
                        | "globalRateLimitMaxRequests"
                        | "globalRateLimitWindowSeconds"
                        | "cacheAccountProtectionSeconds"
                        | "cacheAccountWaitSeconds"
                        | "rateLimitCooldownSeconds"
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
                        | "cacheCreationUsageMultiplier"
                        | "cacheReadUsageMultiplier"
                        | "extractThinking"
                        | "defaultStream"
                        | "testDefaultModel"
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
        if config.cache_account_wait_seconds > 60 {
            return Err(AdminServiceError::InvalidCredential(
                "cacheAccountWaitSeconds 不能大于 60".to_string(),
            ));
        }
        if config.per_credential_rate_limit_max_requests > 0
            && config.per_credential_rate_limit_window_seconds == 0
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用单账号滑动窗口限速时，perCredentialRateLimitWindowSeconds 必须大于 0"
                    .to_string(),
            ));
        }
        if config.global_rate_limit_max_requests > 0 && config.global_rate_limit_window_seconds == 0
        {
            return Err(AdminServiceError::InvalidCredential(
                "启用全局滑动窗口限速时，globalRateLimitWindowSeconds 必须大于 0".to_string(),
            ));
        }
        if config.rate_limit_cooldown_seconds == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "rateLimitCooldownSeconds 必须大于 0".to_string(),
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
        if !config.cache_creation_usage_multiplier.is_finite()
            || config.cache_creation_usage_multiplier < 0.0
        {
            return Err(AdminServiceError::InvalidCredential(
                "cacheCreationUsageMultiplier 必须是大于等于 0 的数字".to_string(),
            ));
        }
        if !config.cache_read_usage_multiplier.is_finite()
            || config.cache_read_usage_multiplier < 0.0
        {
            return Err(AdminServiceError::InvalidCredential(
                "cacheReadUsageMultiplier 必须是大于等于 0 的数字".to_string(),
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
        let (response, account_id, mut request_lease) = self
            .provider
            .call_api_for_credential(&request_body, credential_id)
            .await
            .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))?;

        let status = response.status();
        let body_bytes = response.bytes().await.map_err(|e| {
            AdminServiceError::UpstreamError(format!("读取指定账号测试响应失败: {e}"))
        })?;

        let reply_text = Self::extract_kiro_reply_text(&body_bytes, &mut request_lease);
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

    fn extract_kiro_reply_text(
        body_bytes: &[u8],
        request_lease: &mut crate::kiro::token_manager::RequestLease,
    ) -> Option<String> {
        let mut decoder = EventStreamDecoder::new();
        if decoder.feed(body_bytes).is_err() {
            request_lease.invalidate_metering();
            return None;
        }

        let mut text_content = String::new();
        for result in decoder.decode_iter() {
            let Ok(frame) = result else {
                request_lease.invalidate_metering();
                continue;
            };
            let Ok(event) = Event::from_frame(frame) else {
                request_lease.invalidate_metering();
                continue;
            };
            request_lease.observe_event(&event);
            if let Event::AssistantResponse(response) = event {
                text_content.push_str(&response.content);
            }
        }

        if decoder.is_complete() {
            request_lease.finish_metering();
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

    fn build_request_stats_summary(
        snapshot: &ManagerSnapshot,
        balance_cache: &HashMap<u64, CachedBalance>,
        threshold: f64,
        credits: &CreditStats,
    ) -> RequestStatsSummary {
        let now = Utc::now().timestamp() as f64;
        let mut confirmed_remaining_quota = 0.0;
        let mut quota_pending_credentials = 0;
        let mut quota_verified_credentials = 0;
        let mut quota_excluded_credentials = 0;
        let mut quota_oldest_observed_at: Option<f64> = None;
        for entry in &snapshot.entries {
            if !entry.callable {
                quota_excluded_credentials += 1;
                continue;
            }
            let cached = balance_cache.get(&entry.id).filter(|cached| {
                cached.is_fresh(
                    now,
                    entry.quota_generation,
                    entry.current_concurrent_requests,
                )
            });
            let Some(cached) = cached else {
                quota_pending_credentials += 1;
                continue;
            };
            quota_verified_credentials += 1;
            let remaining = cached.data.remaining;
            if remaining > 0.0 && remaining >= threshold.max(0.0) {
                confirmed_remaining_quota += remaining;
            }
            quota_oldest_observed_at = Some(
                quota_oldest_observed_at.map_or(cached.cached_at, |old| old.min(cached.cached_at)),
            );
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
            remaining_quota: (quota_pending_credentials == 0).then_some(confirmed_remaining_quota),
            confirmed_remaining_quota,
            quota_pending_credentials,
            quota_verified_credentials,
            quota_excluded_credentials,
            quota_oldest_observed_at,
            today_consumed_quota: credits.today,
            today_confirmed_consumed_quota: credits.today_confirmed,
            total_consumed_quota: credits.total_confirmed,
            quota_tracking_started_at: credits.tracking_started_at,
            quota_missing_metering_requests: credits.missing_requests,
            quota_pending_metering_requests: credits.pending_requests,
            quota_ledger_persistence_ok: credits.persistence_ok,
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

        // 刷新凭据已被上游永久拒绝（例如 IdC 400 access_denied）
        if msg.contains("凭据刷新已失效") || msg.contains("refreshToken 已失效") {
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
    use crate::kiro::token_manager::CredentialEntrySnapshot;
    use std::fs;

    #[test]
    fn remaining_percentage_uses_real_limit_and_leaves_unknown_empty() {
        let mut balance = BalanceResponse {
            id: 12054,
            subscription_title: Some("KIRO FREE".to_string()),
            current_usage: 47.03,
            usage_limit: 50.0,
            remaining: 2.97,
            usage_percentage: 94.06,
            next_reset_at: None,
        };
        assert!((remaining_quota_percentage(Some(&balance)).unwrap() - 5.94).abs() < 1e-10);
        assert_eq!(remaining_quota_percentage(None), None);
        balance.remaining = 0.0;
        assert_eq!(remaining_quota_percentage(Some(&balance)), Some(0.0));
        balance.usage_limit = 0.0;
        assert_eq!(remaining_quota_percentage(Some(&balance)), None);
        balance.usage_limit = f64::INFINITY;
        assert_eq!(remaining_quota_percentage(Some(&balance)), None);
        balance.usage_limit = 50.0;
        balance.remaining = f64::NAN;
        assert_eq!(remaining_quota_percentage(Some(&balance)), None);
        balance.remaining = -1.0;
        assert_eq!(remaining_quota_percentage(Some(&balance)), None);
    }

    #[test]
    fn percentage_sort_keeps_unknown_last_and_breaks_ties_by_id() {
        let entries = vec![
            (7, None),
            (3, Some(5.94)),
            (2, Some(100.0)),
            (1, Some(0.0)),
            (6, None),
            (4, Some(5.94)),
        ];
        for (descending, expected) in [
            (false, vec![1, 3, 4, 2, 6, 7]),
            (true, vec![2, 3, 4, 1, 6, 7]),
        ] {
            let mut sorted = entries.clone();
            sorted.sort_by(|left, right| {
                compare_remaining_percentage(left.1, right.1, descending)
                    .then_with(|| left.0.cmp(&right.0))
            });
            assert_eq!(
                sorted.iter().map(|entry| entry.0).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn list_balance_accepts_persisted_snapshot_after_freshness_expires() {
        let cached = CachedBalance {
            cached_at: 1.0,
            data: BalanceResponse {
                id: 12054,
                subscription_title: Some("KIRO FREE".to_string()),
                current_usage: 47.03,
                usage_limit: 50.0,
                remaining: 2.97,
                usage_percentage: 94.06,
                next_reset_at: None,
            },
            schema_version: 2,
            request_count: Some(0),
            valid_until: None,
        };
        assert!(!cached.is_fresh(Utc::now().timestamp() as f64, 0, 0));
        assert!(has_valid_cached_balance(&cached));
    }

    #[test]
    fn legacy_balance_cache_is_loaded_but_not_trusted() {
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
            schema_version: 0,
            request_count: None,
            valid_until: None,
        };
        let json = serde_json::json!({
            "42": cached,
        });
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cache_path = Some(path.clone());
        let loaded = MultiTokenManager::load_balance_cache_from(&cache_path);

        fs::remove_file(path).ok();
        assert_eq!(loaded.len(), 1);
        assert!(
            !loaded
                .values()
                .next()
                .unwrap()
                .is_fresh(Utc::now().timestamp() as f64, 0, 0)
        );
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
        let loaded = MultiTokenManager::load_balance_cache_from(&cache_path);

        fs::remove_file(path).ok();
        let balance = &loaded.get(&8).unwrap().data;
        assert_eq!(loaded.len(), 1);
        assert_eq!(balance.subscription_title.as_deref(), Some("KIRO FREE"));
        assert_eq!(balance.remaining, 38.0);
    }

    #[test]
    fn request_stats_use_metered_credits_and_only_fresh_callable_balances() {
        let mut snapshot = ManagerSnapshot {
            entries: vec![CredentialEntrySnapshot {
                quota_generation: 0,
                id: 7,
                priority: 0,
                disabled: false,
                callable: true,
                failure_count: 0,
                auth_method: Some("idc".to_string()),
                has_profile_arn: false,
                expires_at: None,
                refresh_token_hash: None,
                api_key_hash: None,
                masked_api_key: None,
                email: None,
                success_count: 0,
                total_request_count: 0,
                today_request_count: 0,
                today_success_count: 0,
                total_token_count: 99_000,
                today_token_count: 12_345,
                current_concurrent_requests: 0,
                upstream_header_latency_ema_ms: None,
                last_used_at: None,
                has_proxy: false,
                proxy_url: None,
                refresh_failure_count: 0,
                disabled_reason: None,
                endpoint: None,
                display_subscription_title: Some("KIRO PRO+".to_string()),
                display_usage_limit: Some(2000.0),
            }],
            current_id: 7,
            total: 1,
            available: 1,
            rpm: 0,
            total_request_count: 1,
            total_token_count: 99_000,
            total_success_count: 1,
            today_request_count: 1,
            today_token_count: 12_345,
            today_success_count: 1,
            quota_exceeded: 0,
        };
        let mut cache = HashMap::new();
        cache.insert(
            7,
            CachedBalance {
                cached_at: Utc::now().timestamp() as f64,
                data: BalanceResponse {
                    id: 7,
                    subscription_title: Some("KIRO FREE".to_string()),
                    current_usage: 23.5,
                    usage_limit: 50.0,
                    remaining: 26.5,
                    usage_percentage: 47.0,
                    next_reset_at: None,
                },
                schema_version: 2,
                request_count: Some(0),
                valid_until: None,
            },
        );

        let mut credits = CreditStats {
            today: Some(0.0123),
            today_confirmed: 0.0123,
            total_confirmed: 1.25,
            missing_requests: 0,
            pending_requests: 0,
            tracking_started_at: 1,
            persistence_ok: true,
        };
        let stats = AdminService::build_request_stats_summary(&snapshot, &cache, 0.0, &credits);
        assert_eq!(stats.today_token_count, 12_345);
        assert_eq!(stats.today_consumed_quota, Some(0.0123));
        assert_eq!(stats.total_consumed_quota, 1.25);
        assert_eq!(stats.remaining_quota, Some(26.5));

        // 新请求后旧余额立即失效，不把旧值当作剩余真实额度。
        snapshot.entries[0].quota_generation = 1;
        let stats = AdminService::build_request_stats_summary(&snapshot, &cache, 0.0, &credits);
        assert_eq!(stats.remaining_quota, None);
        assert_eq!(stats.quota_pending_credentials, 1);
        assert_eq!(stats.confirmed_remaining_quota, 0.0);

        // 冷却、限流或禁用账号一律不计入当前可调用汇总。
        snapshot.entries[0].callable = false;
        let stats = AdminService::build_request_stats_summary(&snapshot, &cache, 0.0, &credits);
        assert_eq!(stats.remaining_quota, Some(0.0));
        assert_eq!(stats.quota_excluded_credentials, 1);

        snapshot.entries[0].callable = true;
        snapshot.entries[0].quota_generation = 0;
        let stats = AdminService::build_request_stats_summary(&snapshot, &cache, 30.0, &credits);
        assert_eq!(stats.remaining_quota, Some(0.0));

        credits.today = None;
        credits.missing_requests = 1;
        cache.get_mut(&7).unwrap().cached_at -= 301.0;
        let stats = AdminService::build_request_stats_summary(&snapshot, &cache, 0.0, &credits);
        assert_eq!(stats.remaining_quota, None);
        assert_eq!(stats.today_consumed_quota, None);
        assert_eq!(stats.today_confirmed_consumed_quota, 0.0123);
    }
}
