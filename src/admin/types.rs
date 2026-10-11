//! Admin API 类型定义

use serde::{Deserialize, Serialize};

use crate::anthropic::types::Model;
use crate::model::config::Config;

// ============ 凭据状态 ============

/// 所有凭据状态响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsStatusResponse {
    /// 凭据总数
    pub total: usize,
    /// 可用凭据数量（未禁用）
    pub available: usize,
    /// 当前筛选条件下的凭据数量
    pub filtered_total: usize,
    /// 额度已用尽凭据数量
    pub quota_exceeded: usize,
    /// 状态筛选统计
    pub status_counts: CredentialStatusCounts,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 全局请求统计
    pub stats: RequestStatsSummary,
    /// 各凭据状态列表
    pub credentials: Vec<CredentialStatusItem>,
    /// 当前筛选条件下的全部凭据 ID，供跨页全选使用
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filtered_ids: Vec<u64>,
    /// 当前筛选条件下的全部已禁用凭据 ID，供跨页批量启用/删除使用
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filtered_disabled_ids: Vec<u64>,
    /// 当前筛选条件下的全部失败凭据 ID，供跨页恢复异常使用
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filtered_failed_ids: Vec<u64>,
    /// 分页查询时返回全部已禁用凭据 ID，供批量清理使用
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_ids: Option<Vec<u64>>,
}

/// 凭据列表查询参数
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsQuery {
    /// 页码，从 1 开始
    pub page: Option<usize>,
    /// 每页数量
    pub page_size: Option<usize>,
    /// 排序字段：priority / success / lastUsed / remaining
    pub sort_field: Option<String>,
    /// 排序方向：asc / desc
    pub sort_direction: Option<String>,
    /// 状态筛选：all / enabled / disabled
    pub status: Option<String>,
    /// 禁用原因筛选
    pub disabled_reason: Option<String>,
    /// 账号搜索，支持 ID 或邮箱关键字
    pub search: Option<String>,
}

impl CredentialsQuery {
    pub fn is_paginated(&self) -> bool {
        self.page.is_some() || self.page_size.is_some()
    }
}

/// 凭据状态筛选统计
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusCounts {
    /// 全部凭据数量
    pub total: usize,
    /// 启用凭据数量
    pub enabled: usize,
    /// 已禁用凭据数量
    pub disabled: usize,
    /// 各禁用原因数量
    pub disabled_reasons: Vec<DisabledReasonCount>,
}

/// 禁用原因数量
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisabledReasonCount {
    /// 禁用原因
    pub reason: String,
    /// 数量
    pub count: usize,
}

/// 单个凭据的状态信息
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusItem {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级（数字越小优先级越高）
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 是否为当前活跃凭据
    pub is_current: bool,
    /// Token 过期时间（RFC3339 格式）
    pub expires_at: Option<String>,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
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
    /// 当前仍在有效期内的 Prompt Cache 写入数
    pub active_cache_entry_count: u64,
    /// 当前正在进行中的 API 调用数
    pub current_concurrent_requests: usize,
    /// 最近成功请求的上游响应头耗时 EMA（毫秒）
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
    /// 端点名称（决定该凭据走哪套 Kiro API，已回退到默认端点）
    pub endpoint: String,
    /// 原有账号套餐展示配置，仅用于账号列表，不参与额度统计。
    pub display_subscription_title: Option<String>,
    pub display_usage_limit: Option<f64>,
    /// 最近一次缓存的余额/用量信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<BalanceResponse>,
}

/// 全局请求统计
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestStatsSummary {
    /// 最近 60 秒请求数
    pub rpm: u64,
    /// 历史总请求次数
    pub total_request_count: u64,
    /// 历史累计消耗 Token
    pub total_token_count: u64,
    /// 历史成功次数
    pub total_success_count: u64,
    /// 历史成功率（0-100）
    pub total_success_rate: f64,
    /// 当天总请求次数
    pub today_request_count: u64,
    /// 当天累计消耗 Token
    pub today_token_count: u64,
    /// 当天成功次数
    pub today_success_count: u64,
    /// 当天成功率（0-100）
    pub today_success_rate: f64,
    /// 当前可调用账号的已核实余额；有待刷新账号时为 null。
    pub remaining_quota: Option<f64>,
    pub confirmed_remaining_quota: f64,
    pub quota_pending_credentials: usize,
    pub quota_verified_credentials: usize,
    pub quota_excluded_credentials: usize,
    pub quota_oldest_observed_at: Option<f64>,
    /// UTC+8 本服务当天上游 credit 计费；覆盖不完整时为 null。
    pub today_consumed_quota: Option<f64>,
    pub today_confirmed_consumed_quota: f64,
    /// 账本启用以来收到的真实 credit，不是账号周期用量之和。
    pub total_consumed_quota: f64,
    pub quota_tracking_started_at: i64,
    pub quota_missing_metering_requests: u64,
    pub quota_pending_metering_requests: u64,
    pub quota_ledger_persistence_ok: bool,
}

// ============ 操作请求 ============

/// 启用/禁用凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisabledRequest {
    /// 是否禁用
    pub disabled: bool,
}

/// 修改优先级请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPriorityRequest {
    /// 新优先级值
    pub priority: u32,
}

/// 修改凭据邮箱请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCredentialEmailRequest {
    /// 用户邮箱；空字符串会清除邮箱
    pub email: Option<String>,
}

/// 添加凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialRequest {
    /// 刷新令牌（OAuth 凭据必填，API Key 凭据不需要）
    pub refresh_token: Option<String>,

    /// 认证方式（可选，默认 social）
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// OIDC Client ID（IdC 认证需要）
    pub client_id: Option<String>,

    /// OIDC Client Secret（IdC 认证需要）
    pub client_secret: Option<String>,

    /// 优先级（可选，默认 0）
    #[serde(default)]
    pub priority: u32,

    /// 凭据级 Region 配置（用于 OIDC token 刷新）
    /// 未配置时回退到 config.json 的全局 region
    pub region: Option<String>,

    /// 凭据级 Auth Region（用于 Token 刷新）
    pub auth_region: Option<String>,

    /// 凭据级 API Region（用于 API 请求）
    pub api_region: Option<String>,

    /// 凭据级 Machine ID（可选，64 位字符串）
    /// 未配置时回退到 config.json 的 machineId
    pub machine_id: Option<String>,

    /// 用户邮箱（可选，用于前端显示）
    #[serde(alias = "mail", alias = "account", alias = "username", alias = "login")]
    pub email: Option<String>,

    /// 凭据级代理 URL（可选，特殊值 "direct" 表示不使用代理）
    pub proxy_url: Option<String>,

    /// 凭据级代理认证用户名（可选）
    pub proxy_username: Option<String>,

    /// 凭据级代理认证密码（可选）
    pub proxy_password: Option<String>,

    /// Kiro API Key（API Key 凭据必填，格式: ksk_xxxxxxxx）
    /// 设置后直接作为 Bearer Token 使用，无需 refreshToken
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kiro_api_key: Option<String>,

    /// 端点名称（可选，未配置时使用 config.defaultEndpoint）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

fn default_auth_method() -> String {
    "social".to_string()
}

/// 添加凭据成功响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialResponse {
    pub success: bool,
    pub message: String,
    /// 新添加的凭据 ID
    pub credential_id: u64,
    /// 用户邮箱（如果获取成功）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

// ============ 余额查询 ============

/// 余额查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    /// 凭据 ID
    pub id: u64,
    /// 订阅类型
    pub subscription_title: Option<String>,
    /// 当前使用量
    pub current_usage: f64,
    /// 使用限额
    pub usage_limit: f64,
    /// 剩余额度
    pub remaining: f64,
    /// 使用百分比
    pub usage_percentage: f64,
    /// 下次重置时间（Unix 时间戳）
    pub next_reset_at: Option<f64>,
}

// ============ 负载均衡配置 ============

/// 负载均衡模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancingModeResponse {
    /// 当前模式（"priority" 或 "balanced"）
    pub mode: String,
}

/// 设置负载均衡模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetLoadBalancingModeRequest {
    /// 模式（"priority" 或 "balanced"）
    pub mode: String,
}

// ============ 服务配置 ============

/// Admin 页面使用的服务配置响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminConfigResponse {
    /// 当前配置
    pub config: Config,
    /// 本次保存检测到的配置变化
    pub changed_fields: Vec<String>,
    /// 需要重启服务才能生效的配置项
    pub restart_required_fields: Vec<String>,
    /// 是否存在需要重启的配置变化
    pub restart_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceTestRequest {
    pub prompt: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceTestResponse {
    pub success: bool,
    pub model: String,
    pub prompt: String,
    pub status: u16,
    pub latency_ms: u64,
    pub credential_id: Option<u64>,
    pub email: Option<String>,
    pub reply_text: Option<String>,
    pub response_preview: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminModelsResponse {
    pub object: String,
    pub data: Vec<Model>,
}

// ============ 通用响应 ============

/// 操作成功响应
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

impl SuccessResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }
}

/// 错误响应
#[derive(Debug, Serialize)]
pub struct AdminErrorResponse {
    pub error: AdminError,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl AdminErrorResponse {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: AdminError {
                error_type: error_type.into(),
                message: message.into(),
            },
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }

    pub fn authentication_error() -> Self {
        Self::new("authentication_error", "Invalid or missing admin API key")
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn api_error(message: impl Into<String>) -> Self {
        Self::new("api_error", message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}
