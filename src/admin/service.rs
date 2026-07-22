//! Admin API 业务逻辑服务

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{MultiTokenManager, with_balance_cache_file_lock};

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, BalanceResponse, CredentialStatusCounts,
    CredentialStatusItem, CredentialsQuery, CredentialsStatusResponse, DisabledReasonCount,
    LoadBalancingModeResponse, RequestStatsSummary, SetLoadBalancingModeRequest,
};

/// 余额缓存过期时间（秒），5 分钟
const BALANCE_CACHE_TTL_SECS: i64 = 300;

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
    balance_cache: Mutex<HashMap<u64, CachedBalance>>,
    cache_path: Option<PathBuf>,
    /// 已注册的端点名称集合（用于 add_credential 校验）
    known_endpoints: HashSet<String>,
}

impl AdminService {
    pub fn new(
        token_manager: Arc<MultiTokenManager>,
        known_endpoints: impl IntoIterator<Item = String>,
    ) -> Self {
        let cache_path = token_manager
            .cache_dir()
            .map(|d| d.join("kiro_balance_cache.json"));

        let balance_cache = Self::load_balance_cache_from(&cache_path);

        Self {
            token_manager,
            balance_cache: Mutex::new(balance_cache),
            cache_path,
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
            stats: RequestStatsSummary {
                rpm: snapshot.rpm,
                total_request_count: snapshot.total_request_count,
                total_token_count: snapshot.total_token_count,
                total_success_count: snapshot.total_success_count,
                total_success_rate: if snapshot.total_request_count > 0 {
                    snapshot.total_success_count as f64 * 100.0
                        / snapshot.total_request_count as f64
                } else {
                    0.0
                },
                today_request_count: snapshot.today_request_count,
                today_token_count: snapshot.today_token_count,
                today_success_count: snapshot.today_success_count,
                today_success_rate: if snapshot.today_request_count > 0 {
                    snapshot.today_success_count as f64 * 100.0
                        / snapshot.today_request_count as f64
                } else {
                    0.0
                },
            },
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

        // 主动获取订阅等级，避免首次请求时 Free 账号绕过 Opus 模型过滤
        if let Err(e) = self.token_manager.get_usage_limits_for(credential_id).await {
            tracing::warn!("添加凭据后获取订阅等级失败（不影响凭据添加）: {}", e);
        }

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
        if req.mode != "priority" && req.mode != "balanced" {
            return Err(AdminServiceError::InvalidCredential(
                "mode 必须是 'priority' 或 'balanced'".to_string(),
            ));
        }

        self.token_manager
            .set_load_balancing_mode(req.mode.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(LoadBalancingModeResponse { mode: req.mode })
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
