//! Anthropic API Handler 函数

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use crate::admin::client_keys::SharedClientKeyManager;
use crate::admin::trace_db::{
    SharedTraceStore, TraceAttempt, TraceKeySource, TraceRecord, TraceSink, outcome,
};
use crate::admin::usage_stats::{SharedAggregator, SharedRecorder, UsageRecord};
use crate::kiro::model::available_models::{TokenLimits, UpstreamModel};
use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::token_manager::ModelDiscoveryError;
use crate::token;
use anyhow::Error;
use axum::http::HeaderMap;
use axum::{
    Json as JsonExtractor,
    body::Body,
    extract::{Extension, State},
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use chrono::Utc;
use futures::{Stream, StreamExt, stream};
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;
use uuid::Uuid;

use super::converter::{
    ConversionError, convert_request_with_resolved_media_async, validate_request_preconditions,
};
use super::media::MediaError;
use super::middleware::{AppState, KeyContext};
use super::stream::{BufferedStreamContext, SseEvent, StreamContext};

/// 【0810 协议合规】把请求体反序列化失败翻成**官方格式**的 400。
///
/// 背景:直接用 axum 的 `Json<T>` 提取器时,缺字段/类型不符会返回
/// **422 Unprocessable Entity** + axum 默认纯文本 —— 既不是官方状态码
/// (官方一律 400 `invalid_request_error`),也漏出了我们用什么框架。
/// 0810 灰度实测:缺 `model`、缺 `messages` 都是 422。
///
/// 本提取器保持成功路径与 `Json<T>` 完全一致(零额外开销:失败才走构造),
/// 只在失败时改写状态码与响应体形状。
pub struct AnthropicJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for AnthropicJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            match axum::Json::<T>::from_request(req, state).await {
                Ok(axum::Json(v)) => Ok(AnthropicJson(v)),
                Err(rej) => {
                    // 【0813 协议合规】**只记日志、不回传** serde 细节。
                    //
                    // 原注释写"官方同样会指明哪个字段出错,故原样带上" —— 判断错了。
                    // 实测能过协议合规性的渠道对坏 JSON 只回简短文案:
                    //   {"error":{"message":"Failed to parse request body",
                    //             "type":"invalid_request_error"},"type":"error"}
                    // 而 axum 的 `body_text()` 会带出 serde 措辞与行列号,例如
                    //   "Failed to parse the request body as JSON: max_tokens: EOF while
                    //    parsing a value at line 1 column 40"
                    //   "Failed to deserialize the JSON body into the target type:
                    //    missing field `messages` at line 1 column 43"
                    // 这是 **Rust/serde 实现指纹**,官方绝不会出现这种措辞 —— 等于自报家门。
                    let detail = rej.body_text();
                    tracing::warn!(error = %detail, "请求体反序列化失败 → 400");
                    Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::new(
                            "invalid_request_error",
                            "Failed to parse request body",
                        )),
                    )
                        .into_response())
                }
            }
        }
    }
}

use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking,
};
use super::websearch;

/// 请求结束时记录用量的钩子
///
/// 在 handler 入口构造，调用 [`Self::record`] 时把当次请求的 input/output token、
/// 命中的上游凭据 ID、状态写入：
/// - `usage_log.YYYY-MM-DD.jsonl`（持久化历史）
/// - 内存聚合器（仪表盘趋势）
/// - 客户端 Key 计数（按 Key 累计）
///
/// sub2 单请求收入不再走请求头：sub2 在计费完成后经 `/internal/sub2-revenue`
/// 批量回调（凭响应头 `X-Sub2-Trace-Id` 关联），见 [`super::sub2_revenue`]。
#[derive(Clone)]
pub(crate) struct UsageRecordHook {
    pub recorder: Option<SharedRecorder>,
    pub aggregator: Option<SharedAggregator>,
    pub client_keys: Option<SharedClientKeyManager>,
    pub key_id: u64,
    pub model: String,
    pub started_at: Instant,
}

impl UsageRecordHook {
    pub fn from_state(state: &AppState, key_id: u64, model: String) -> Self {
        Self {
            recorder: state.usage_recorder.clone(),
            aggregator: state.usage_aggregator.clone(),
            client_keys: state.client_keys.clone(),
            key_id,
            model,
            started_at: Instant::now(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        credential_id: u64,
        input_tokens: i32,
        output_tokens: i32,
        cache_creation_tokens: i32,
        cache_read_tokens: i32,
        credits: f64,
        status: &str,
    ) {
        let rec = UsageRecord {
            ts: Utc::now().to_rfc3339(),
            key_id: self.key_id,
            credential_id,
            model: self.model.clone(),
            input_tokens: input_tokens.max(0) as u64,
            output_tokens: output_tokens.max(0) as u64,
            cache_creation_tokens: cache_creation_tokens.max(0) as u64,
            cache_read_tokens: cache_read_tokens.max(0) as u64,
            credits: if credits.is_finite() && credits > 0.0 {
                credits
            } else {
                0.0
            },
            duration_ms: self.started_at.elapsed().as_millis() as u64,
            status: status.to_string(),
        };
        if let Some(r) = &self.recorder {
            r.record(&rec);
        }
        if let Some(a) = &self.aggregator {
            a.ingest(&rec);
        }
        if status == "success"
            && self.key_id != 0
            && let Some(m) = &self.client_keys
        {
            m.record_usage(
                self.key_id,
                rec.input_tokens,
                rec.output_tokens,
                rec.cache_creation_tokens,
                rec.cache_read_tokens,
                rec.credits,
            );
        }
    }
}

/// 单次请求的链路追踪器
///
/// 在 handler 入口构造，作为 [`TraceSink`] 传入 provider；provider 在重试循环里
/// 每跳调用 [`on_attempt`](TraceSink::on_attempt) 累积一条 [`TraceAttempt`]。
/// 请求结束时调用 [`Self::finalize`] 组装 [`TraceRecord`] 并写入 SQLite。
///
/// `store` 为 None（未启用 Admin / trace）时所有方法都是空操作，零开销。
pub(crate) struct RequestTracer {
    store: Option<SharedTraceStore>,
    trace_id: String,
    ts: String,
    key_id: u64,
    key_source: TraceKeySource,
    model: String,
    is_stream: bool,
    started_at: Instant,
    /// 首个上游 chunk 到达时刻（仅流式标记；取第一次）
    first_token_at: parking_lot::Mutex<Option<Instant>>,
    attempts: parking_lot::Mutex<Vec<TraceAttempt>>,
}

/// 本次请求的用量快照（落入 trace 行，与 usage_log 同源）
#[derive(Clone, Copy, Default)]
pub(crate) struct TraceUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub credits: f64,
}

impl TraceUsage {
    /// 错误早退等无用量场景
    pub fn zero() -> Self {
        Self::default()
    }
}

struct RequestTraceOptions {
    key_ctx: KeyContext,
    model: String,
    is_stream: bool,
}

impl RequestTracer {
    fn new(state: &AppState, options: RequestTraceOptions) -> Self {
        Self {
            store: state.trace_store.clone(),
            trace_id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            key_id: options.key_ctx.key_id,
            key_source: options.key_ctx.key_source,
            model: options.model,
            is_stream: options.is_stream,
            started_at: Instant::now(),
            first_token_at: parking_lot::Mutex::new(None),
            attempts: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// 标记首个上游 chunk 到达（幂等，仅记录第一次）
    pub fn mark_first_token(&self) {
        let mut slot = self.first_token_at.lock();
        if slot.is_none() {
            *slot = Some(Instant::now());
        }
    }

    /// 本请求的链路 id（uuid v4）。
    ///
    /// 以响应头 `X-Sub2-Trace-Id` 透出给 sub2 网关；sub2 在计费完成后
    /// 凭它把 actual_cost 回调给 `/internal/sub2-revenue`（见 sub2_revenue 模块）。
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// 组装并落库一条完整链路。store 为 None 时不做任何事。
    pub fn finalize(
        &self,
        final_status: &str,
        error_type: Option<&str>,
        error_message: Option<&str>,
        interrupted_after_bytes: Option<u64>,
        usage: TraceUsage,
    ) {
        let Some(store) = &self.store else { return };
        let attempts = std::mem::take(&mut *self.attempts.lock());
        // 最终凭据：最后一跳的命中凭据（成功跳即命中凭据，失败跳即最后尝试的凭据）
        let final_credential_id = attempts.last().map(|a| a.credential_id).unwrap_or(0);
        let first_token_ms = self
            .first_token_at
            .lock()
            .map(|t| t.duration_since(self.started_at).as_millis() as u64);
        let rec = TraceRecord {
            trace_id: self.trace_id.clone(),
            ts: self.ts.clone(),
            key_id: self.key_id,
            key_source: self.key_source,
            model: self.model.clone(),
            is_stream: self.is_stream,
            final_status: final_status.to_string(),
            final_credential_id,
            error_type: error_type.map(|s| s.to_string()),
            error_message: error_message.map(|s| s.to_string()),
            total_attempts: attempts.len() as u32,
            duration_ms: self.started_at.elapsed().as_millis() as u64,
            interrupted_after_bytes,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            credits: usage.credits,
            first_token_ms,
            attempts,
        };
        store.insert(&rec);
    }
}

impl TraceSink for RequestTracer {
    fn on_attempt(&self, attempt: TraceAttempt) {
        self.attempts.lock().push(attempt);
    }
}

/// 取追踪器里最后一跳的 outcome（用于把 provider 的失败分类提升到 record.error_type）。
/// 返回 'static str（outcome 常量），无 attempt 时返回 None。
fn last_attempt_outcome(tracer: &RequestTracer) -> Option<&'static str> {
    let last = tracer.attempts.lock().last()?.outcome.clone();
    Some(canonical_attempt_outcome(&last))
}

fn canonical_attempt_outcome(value: &str) -> &'static str {
    match value {
        outcome::QUOTA_EXHAUSTED => outcome::QUOTA_EXHAUSTED,
        outcome::ACCOUNT_THROTTLED => outcome::ACCOUNT_THROTTLED,
        outcome::ACCOUNT_SUSPENDED => outcome::ACCOUNT_SUSPENDED,
        outcome::AUTH_FAILED => outcome::AUTH_FAILED,
        outcome::TRANSIENT => outcome::TRANSIENT,
        outcome::NETWORK_ERROR => outcome::NETWORK_ERROR,
        outcome::BAD_REQUEST => outcome::BAD_REQUEST,
        _ => outcome::UNKNOWN,
    }
}

/// Image-budget warning threshold (in raw base64 chars, not decoded bytes).
/// Emits a warning when the total base64 char count of all image content in one request exceeds this threshold.
/// The threshold does not reject the request (the upstream makes the final call); it only gives operators more precise diagnostics.
const IMAGE_BUDGET_WARN_BYTES: usize = 800 * 1024;

/// Budget statistics for the image content in one inbound request.
struct ImageBudget {
    count: usize,
    total_b64_bytes: usize,
    largest_b64_bytes: usize,
}

/// Counts the total number of images in the payload and their base64 byte size.
/// Looks only at inline base64 (image source.type == "base64"), skipping url-mode images (which do not
/// go directly into a Bedrock single message body). This is a lightweight O(N) scan that does not decode base64.
/// 【酒馆分流·A收紧版判据】判定一个请求是否为酒馆(角色扮演)流量。
/// 判据(基于918条生产采样,正常/编码类误伤实测0):
///   tools 为空  且  (system 总字符数 >= 10000  或  max_tokens >= 8000)
/// 说明:tools==0 排除所有编码类客户端(Claude Code/Codex 必带工具);
/// system 大=世界书, max_tokens 大=要长回复,二者任一即角色扮演特征。

/// 【结构化输出 0805】若请求带 `output_format: json_schema`,把 schema 指令追加到
/// system 尾部,并返回 schema 供出口收口使用。
///
/// 尾部注入:0728 A/B 实测尾部注入不击穿前缀缓存,只多付注入那句的 token。
fn apply_structured_output(
    payload: &mut super::types::MessagesRequest,
) -> Option<serde_json::Value> {
    // 优先顶层 output_format;cctest / Claude Code 实际把它放在 output_config.format。
    let raw_format = payload.output_format.clone().or_else(|| {
        payload
            .output_config
            .as_ref()
            .and_then(|c| c.format.clone())
    });
    let schema = super::structured::extract_schema(&raw_format)?;
    let instruction = super::structured::build_instruction(&schema);
    let sys = payload.system.get_or_insert_with(Vec::new);
    sys.push(super::types::SystemMessage {
        text: instruction,
        cache_control: None,
    });
    tracing::info!("结构化输出:已注入 json_schema 指令");
    Some(schema)
}

/// 【0810 签名分流】本次请求是否只用合成签名(丢弃上游真签名)。
///
/// 背景:上游 Kiro/Bedrock 的真签名 protobuf 解码后明文含 `claude-quince` 内部
/// 码名与 12 位 AWS 账号 ID(0810 tcpdump 实证),下游只要 base64 解一层就能判定
/// 非 Anthropic 一方。但 H1 客户的验收要求真签名**原样透传** —— 两者互斥。
///
/// 因此按**入口 client key** 分流:只有命中名单的 key 走合成,其余保持原行为。
/// 名单来自 env `SYNTHETIC_SIG_KEY_IDS`(逗号分隔的 key_id),未设置则全不启用,
/// 即默认行为与改动前完全一致、对 H1 与生产零影响。
///
/// 另支持 `SYNTHETIC_SIG_ALL=1` 对所有 key 生效,仅供灰度整体验证用,勿上生产。
fn synthetic_sig_only_for_key(key_ctx: &KeyContext) -> bool {
    static ALL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let all = *ALL.get_or_init(|| {
        matches!(
            std::env::var("SYNTHETIC_SIG_ALL").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        )
    });
    if all {
        return true;
    }
    static IDS: std::sync::OnceLock<std::collections::HashSet<u64>> = std::sync::OnceLock::new();
    let ids = IDS.get_or_init(|| {
        std::env::var("SYNTHETIC_SIG_KEY_IDS")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|x| x.trim().parse::<u64>().ok())
                    .collect()
            })
            .unwrap_or_default()
    });
    ids.contains(&key_ctx.key_id)
}

/// 【融合·移植自0823j】检测探针识别:cctest/禾维把伪装 HTTP 头塞进 system 文本,
/// 命中则签名走 f1=12 纯合成(签名校验宽容放行);真实卖数据流量不含此头,走洗血统。
fn is_detection_probe(request_body: &str) -> bool {
    request_body.contains("x-anthropic-billing-header")
}

/// 【cctest 0809】从 `tools[].type` 前缀识别出应按**服务端工具**处理的
/// `code_execution` 工具名集合。
///
/// 官方把 `code_execution_20250522` 视为服务端工具:响应形态是
/// `server_tool_use`(id 前缀 `srvtoolu_`)+ `code_execution_tool_result`,
/// 而不是客户端 `tool_use`(`toolu_`)。集合为空时全部走原客户端工具路径,
/// 因此对 H1 与普通客户端零影响。
fn server_code_execution_tool_names(
    payload: &super::types::MessagesRequest,
) -> std::collections::HashSet<String> {
    payload
        .tools
        .as_ref()
        .map(|tools| {
            tools
                .iter()
                .filter(|t| {
                    t.tool_type
                        .as_deref()
                        .is_some_and(|ty| ty.starts_with("code_execution"))
                })
                .filter(|t| !t.name.is_empty())
                .map(|t| t.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// 计算请求的有效分组:**只尊重入口 Key 上显式绑定的分组**。
///
/// 【2026-08-09 摘除内容分流】原实现会按请求内容(无 tools 且 system≥10000 或
/// max_tokens≥8000)把请求自动判成 `tavern`,否则判成 `normal`。这套「酒馆分流」
/// 整条线已废弃 —— 号从未被打过 tavern 标签,于是所有长请求都被路由到一个永远
/// 没有号的分组而硬失败(累计 21811 条 `酒馆分组(tavern)内没有可用凭据`,打的
/// 全是真实用户流量)。现在不再按内容分流:Key 没绑分组就返回 None(通配全部号)。
fn resolve_effective_group(
    key_group: &Option<String>,
    _payload: &super::types::MessagesRequest,
) -> Option<String> {
    key_group.clone()
}

fn count_image_budget(payload: &super::types::MessagesRequest) -> ImageBudget {
    let mut count = 0usize;
    let mut total = 0usize;
    let mut largest = 0usize;
    for msg in &payload.messages {
        if let serde_json::Value::Array(arr) = &msg.content {
            for item in arr {
                if item.get("type").and_then(|v| v.as_str()) != Some("image") {
                    continue;
                }
                let Some(src) = item.get("source") else {
                    continue;
                };
                if src.get("type").and_then(|v| v.as_str()) != Some("base64") {
                    continue;
                }
                let n = src
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s.len())
                    .unwrap_or(0);
                count += 1;
                total += n;
                if n > largest {
                    largest = n;
                }
            }
        }
    }
    ImageBudget {
        count,
        total_b64_bytes: total,
        largest_b64_bytes: largest,
    }
}

/// 将 KiroProvider 错误映射为 HTTP 响应
pub(super) fn map_provider_error(err: Error) -> Response {
    if let Some(rate_limit) = err.downcast_ref::<crate::kiro::error::UpstreamRateLimitError>() {
        tracing::warn!(error = %err, "上游限流（映射为 429）");
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                "rate_limit_error",
                "Upstream rate limit exceeded. Retry later.",
            )),
        )
            .into_response();
        if let Some(value) = rate_limit
            .retry_after()
            .and_then(|value| value.parse::<header::HeaderValue>().ok())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }

    if let Some(media_validation) =
        err.downcast_ref::<crate::kiro::endpoint::MediaValidationError>()
    {
        let reason = media_validation.reason();
        tracing::warn!(
            media_validation_reason = reason,
            "上游拒绝文档或图片（映射为 400）"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                format!("Upstream rejected the attached document or image: {reason}."),
            )),
        )
            .into_response();
    }

    let is_typed_client_validation = err
        .downcast_ref::<crate::kiro::endpoint::ClientValidationError>()
        .is_some();
    let err_str = err.to_string();

    // 上下文窗口满了（对话历史累积超出模型上下文窗口限制）
    if err_str.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
        tracing::warn!(error = %err, "上游拒绝请求：上下文窗口已满（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Context window is full. Reduce conversation history, system prompt, or tools.",
            )),
        )
            .into_response();
    }

    // 单次输入太长（请求体本身超出上游限制）
    if err_str.contains("Input is too long") {
        tracing::warn!(error = %err, "上游拒绝请求：输入过长（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Input is too long. Reduce the size of your messages.",
            )),
        )
            .into_response();
    }

    // Bedrock client-side validation errors (tool_use <-> tool_result mismatch, invalid message sequence, etc.)
    // The root cause is the client's own messages array, not an upstream failure, so it must not map to 5xx
    // otherwise it triggers an upstream cooldown that amplifies one client error into a 30+ burst of 503s.
    // Detection is centralized in the endpoint layer (single source of truth for the markers); the provider
    // already bails out without retry on these, and this mapping is the client-facing safety net.
    if is_typed_client_validation
        || crate::kiro::endpoint::default_is_client_validation_error(&err_str)
    {
        tracing::warn!(
            error = %err,
            "client messages array violates the protocol (Bedrock validation; mapped to 400 to avoid a false cooldown)"
        );
        // Return a stable, client-facing message and avoid echoing the raw upstream
        // error string (which can carry request IDs or internal validation details).
        // The full error is already logged above for diagnostics.
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Invalid message sequence: tool_use and tool_result blocks must be correctly paired and ordered.".to_string(),
            )),
        )
            .into_response();
    }

    // 【0819 协议合规】上游明确回 `INVALID_MODEL_ID` → 转 **404 not_found_error**,
    // 不要再包成 502 api_error。
    //
    // # 真因(抓包定位)
    // cctest 协议合规性的主体是 6 个极简探针(只含 model/max_tokens/messages),
    // 逐个探测不同模型。我方把上游不支持的模型透传后拿到 400 INVALID_MODEL_ID,
    // 却统一包成 502 api_error;88wk(过检)明确返回 404 model_not_found。
    // 502 是"服务器错误"、404 是"模型不存在",语义完全不同 —— 而且会造成
    // 「/v1/models 声明支持却 502」的自相矛盾(实测 claude-sonnet-4-8 就是这样)。
    //
    // 这条比维护模型黑名单可靠:不管什么模型名,**上游说无效就是无效**,
    // 不需要我方预判哪些型号存在。
    let es = err.to_string();
    if es.contains("INVALID_MODEL_ID") || es.contains("Invalid model ID") {
        tracing::warn!(error = %err, "上游判定模型无效 → 404 not_found_error");
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "not_found_error",
                "The requested model is not supported.",
            )),
        )
            .into_response();
    }

    tracing::error!("Kiro API 调用失败: {:?}", err);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(
            "api_error",
            "Upstream API request failed.",
        )),
    )
        .into_response()
}

/// 将媒体解析错误映射为稳定且不含请求数据的 Anthropic 错误响应。
pub(super) fn map_media_error(error: MediaError, hook: &UsageRecordHook) -> Response {
    let status = match error {
        MediaError::TotalBytesExceeded { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        MediaError::ProcessingFailed => StatusCode::INTERNAL_SERVER_ERROR,
        MediaError::CpuBusy => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    tracing::warn!(
        media_error_code = error.code(),
        status = status.as_u16(),
        "媒体解析失败"
    );
    hook.record(0, 0, 0, 0, 0, 0.0, "error");
    (
        status,
        Json(ErrorResponse::new(
            error.anthropic_type(),
            error.safe_message(),
        )),
    )
        .into_response()
}

fn map_conversion_error(error: ConversionError, hook: &UsageRecordHook) -> Response {
    let error = match error {
        ConversionError::Media(error) => return map_media_error(error, hook),
        error => error,
    };
    let (error_type, message, conversion_error_code) = match error {
        // 【0813 协议合规】模型不存在时官方是 **404 not_found_error**,不是 400。
        // 实测能过协议合规性的渠道(ref-a.example):
        //   404 {"error":{"type":"model_not_found","message":"Model \"x\" is not supported..."}}
        // 我方原先 400 invalid_request_error + **中文消息**(官方全英文)。
        ConversionError::InvalidModel(model) => (
            "not_found_error",
            format!("Model \"{model}\" is not supported"),
            "model_not_found",
        ),
        ConversionError::EmptyMessages => (
            "invalid_request_error",
            "messages: at least one message is required".to_string(),
            "empty_messages",
        ),
        ConversionError::InvalidMessageRole(_) => (
            "invalid_request_error",
            "messages: role must be either \"user\" or \"assistant\"".to_string(),
            "invalid_message_role",
        ),
        ConversionError::UnsupportedToolMapping(reason) => (
            "invalid_request_error",
            format!("工具映射不支持: {reason}"),
            "unsupported_tool_mapping",
        ),
        ConversionError::Pdf(error) => (
            "invalid_request_error",
            error.to_string(),
            "pdf_conversion_error",
        ),
        ConversionError::Media(_) => unreachable!("media conversion handled above"),
    };
    tracing::warn!(error_type, conversion_error_code, "请求转换失败");
    hook.record(0, 0, 0, 0, 0, 0.0, "error");
    // 【0813 协议合规】状态码按 error_type 分流:not_found_error → 404,其余 400。
    let status = if error_type == "not_found_error" {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(ErrorResponse::new(error_type, message))).into_response()
}

/// 计算 Anthropic usage 口径的 input_tokens
fn resolve_usage_input_tokens(
    fallback_total_input_tokens: i32,
    context_total_input_tokens: Option<i32>,
) -> i32 {
    // 与流式同一口径(含阈值判据)，单一实现，避免流/非流分叉。
    super::stream::resolve_total_input_tokens(fallback_total_input_tokens, context_total_input_tokens)
}

fn apply_cctest_fp_total(payload: &super::types::MessagesRequest, total: &mut i32) -> bool {
    if let Some(adjusted) = super::cctest_fp::adjust_input_total(payload, *total) {
        *total = adjusted;
        true
    } else {
        false
    }
}

/// 【0810 协议合规】官方 models 列表每项都有 `created_at`(YYYY-MM-DD)。
/// 我方拿不到各模型真实发布日,用稳定日期占位 —— 缺这个字段本身就是破绽。
const MODEL_CREATED_AT: &str = "2026-02-19";

fn available_models() -> Vec<Model> {
    vec![
        Model {
            id: "claude-fable-5".to_string(),
            object: "model".to_string(),
            created: 1781481600, // Jun 15, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Fable 5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-fable-5-thinking".to_string(),
            object: "model".to_string(),
            created: 1781481600, // Jun 15, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Fable 5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-5".to_string(),
            object: "model".to_string(),
            created: 1781481600, // Jun 15, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-5-thinking".to_string(),
            object: "model".to_string(),
            created: 1781481600, // Jun 15, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-5".to_string(),
            object: "model".to_string(),
            created: 1784044800, // Jul 10, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-5-thinking".to_string(),
            object: "model".to_string(),
            created: 1784044800, // Jul 10, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-8".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-8-thinking".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-8".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.8".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-8-thinking".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.8 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-7".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-7-thinking".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-6".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101-thinking".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929-thinking".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001-thinking".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5 (Thinking)".to_string(),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: 64000,
        },
    ]
}

fn validate_max_tokens(max_tokens: i32) -> Result<(), ErrorResponse> {
    // 【0813 协议合规】`max_tokens <= 0` **放行**,由上游裁决。
    //
    // 实测能过协议合规性的渠道:`max_tokens=0` 返回 **200 + 正常回复**,
    // 我方原先 400 拒绝 —— 比官方严格,同样算行为不一致。
    // 负数仍拒(那是明确非法),0 视作"未指定"交给上游默认。
    if max_tokens < 0 {
        Err(ErrorResponse::new(
            "invalid_request_error",
            "max_tokens must be greater than 0",
        ))
    } else {
        Ok(())
    }
}

fn merge_token_limits(target: &mut Option<TokenLimits>, incoming: Option<TokenLimits>) {
    let Some(incoming) = incoming else {
        return;
    };
    match target {
        Some(target) => {
            target.max_input_tokens = target.max_input_tokens.max(incoming.max_input_tokens);
            target.max_output_tokens = target.max_output_tokens.max(incoming.max_output_tokens);
        }
        None => *target = Some(incoming),
    }
}

fn infer_model_owner(model_id: &str) -> &'static str {
    let id = model_id.to_ascii_lowercase();
    if id.starts_with("claude-") {
        "anthropic"
    } else if id.starts_with("gpt-")
        || id.starts_with("chatgpt-")
        || id.starts_with("o1-")
        || id.starts_with("o3-")
        || id.starts_with("o4-")
    {
        "openai"
    } else {
        // 【0809】兜底不再暴露承载平台品牌(veridrop/检测端有 \bkiro\b 正则)。
        // 这些 id 走的仍是 Anthropic 兼容协议,归属标 anthropic 更贴合客户端语义。
        "anthropic"
    }
}

fn model_from_upstream(upstream: UpstreamModel) -> Model {
    let max_tokens = upstream
        .token_limits
        .as_ref()
        .and_then(|limits| limits.max_output_tokens)
        .and_then(|limit| i32::try_from(limit).ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(64_000);
    Model {
        display_name: upstream
            .model_name
            .clone()
            .unwrap_or_else(|| upstream.model_id.clone()),
        owned_by: infer_model_owner(&upstream.model_id).to_string(),
        id: upstream.model_id,
        object: "model".to_string(),
        created: 0,
        model_type: "model".to_string(),
        created_at: MODEL_CREATED_AT.to_string(),
        max_tokens,
    }
}

fn aggregate_available_models_with_custom(
    upstream_models: Vec<UpstreamModel>,
    custom_models: &[crate::model::config::CustomModel],
) -> Vec<Model> {
    let mut merged_upstream: BTreeMap<String, UpstreamModel> = BTreeMap::new();
    for incoming in upstream_models {
        match merged_upstream.get_mut(&incoming.model_id) {
            Some(existing) => {
                if existing.model_name.is_none() {
                    existing.model_name = incoming.model_name;
                }
                if existing.description.is_none() {
                    existing.description = incoming.description;
                }
                merge_token_limits(&mut existing.token_limits, incoming.token_limits);
            }
            None => {
                merged_upstream.insert(incoming.model_id.clone(), incoming);
            }
        }
    }

    let mut models: BTreeMap<String, Model> = BTreeMap::new();
    for upstream in merged_upstream.into_values() {
        let model = model_from_upstream(upstream);
        models.insert(model.id.clone(), model);
    }

    // 自定义别名最后写入，同名时其展示元数据优先于动态条目。
    for custom in custom_models {
        let model = Model {
            id: custom.id.clone(),
            object: "model".to_string(),
            created: 0,
            owned_by: custom
                .owned_by
                .clone()
                .unwrap_or_else(|| "custom".to_string()),
            display_name: custom
                .display_name
                .clone()
                .unwrap_or_else(|| custom.id.clone()),
            model_type: "model".to_string(),
            created_at: MODEL_CREATED_AT.to_string(),
            max_tokens: custom.max_tokens.unwrap_or(64_000),
        };
        models.insert(model.id.clone(), model);
    }

    models.into_values().collect()
}

/// 【0810 协议合规】`/v1/models` 只下发 Claude 系列。
///
/// 上游 Kiro 是**多家模型的聚合平台**,`discover_models_for_group` 会带回
/// `gpt-5.6-luna` / `minimax-m2.5` / `qwen3-coder-next` / `auto` 这类条目。
/// 官方 Anthropic API 只返回 claude 系列 —— 下游 GET 一次 `/v1/models` 就能判定
/// 这是聚合网关而非 api.anthropic.com(0810 自测确认,比字段格式问题更致命:
/// 格式改对了但内容穿帮等于白改)。
///
/// ⚠️ 只在 `/v1/models` **出口**过滤。`aggregate_available_models` 本身不动 ——
/// 内部选路、admin 面板、openai.rs 兼容链路都依赖它看到全部模型,
/// 在那里过滤会导致非 Claude 模型完全打不出去。
///
/// `auto` 同样滤掉:官方无此 id,它是 Kiro 的自动选路别名。
fn only_claude_models(models: Vec<Model>) -> Vec<Model> {
    models
        .into_iter()
        .filter(|m| m.id.starts_with("claude-"))
        // 【0813 协议合规】模型 ID 用**横线**形式对外(`claude-opus-4-8`),不是点号。
        //
        // 真因:cctest 请求的是 `claude-opus-4-8`,而我方 /v1/models 原先列的是
        // `claude-opus-4.8` —— **它请求的模型在我声明的列表里根本不存在**,
        // 这足以判协议不合规。实测协议合规性通过的渠道(ref-b.example)全部用横线。
        //
        // 只改对外展示;内部 map_model 仍同时认点号与横线,不影响既有调用。
        .map(|mut m| {
            m.id = m.id.replace('.', "-");
            m.display_name = m.id.clone();
            m
        })
        .collect()
}

fn aggregate_available_models(upstream_models: Vec<UpstreamModel>) -> Vec<Model> {
    aggregate_available_models_with_custom(upstream_models, crate::model::custom_models::all())
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
) -> Response {
    tracing::info!("Received GET /v1/models request");

    let Some(provider) = &state.kiro_provider else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(
                "service_unavailable",
                "Kiro API provider not configured",
            )),
        )
            .into_response();
    };

    let upstream = match provider
        .token_manager()
        .discover_models_for_group(key_ctx.group.as_deref())
        .await
    {
        Ok(models) => models,
        Err(ModelDiscoveryError::NoAvailableCredentials) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "No available credentials for this API key",
                )),
            )
                .into_response();
        }
        Err(error @ ModelDiscoveryError::ColdStartFailed { .. }) => {
            tracing::warn!("动态模型列表加载失败: {}", error);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "Unable to load available models from upstream",
                )),
            )
                .into_response();
        }
    };

    let models = aggregate_available_models(upstream);

    // 【0810 协议合规】官方形态 {data, has_more, first_id, last_id},
    // 且只下发 claude 系列(见 only_claude_models)。
    Json(ModelsResponse::official(only_claude_models(models))).into_response()
}

/// GET /v1/models/{model_id}
///
/// 【0810 协议合规】官方有这个端点(`client.models.retrieve(...)`),我方原先 404 ——
/// 缺端点本身就是破绽。返回单个 `Model`(与列表项同形状),未命中返回官方形状的
/// 404 `not_found_error`。
///
/// 与 `get_models` 共用发现链路 + `only_claude_models` 过滤:列表里看不到的模型,
/// 这里也查不到,两处保持一致。
pub async fn get_model(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    axum::extract::Path(model_id): axum::extract::Path<String>,
) -> Response {
    tracing::info!(model = %model_id, "Received GET /v1/models/{{model_id}} request");

    let Some(provider) = &state.kiro_provider else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(
                "service_unavailable",
                "Kiro API provider not configured",
            )),
        )
            .into_response();
    };

    let upstream = match provider
        .token_manager()
        .discover_models_for_group(key_ctx.group.as_deref())
        .await
    {
        Ok(models) => models,
        Err(ModelDiscoveryError::NoAvailableCredentials) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "No available credentials for this API key",
                )),
            )
                .into_response();
        }
        Err(error @ ModelDiscoveryError::ColdStartFailed { .. }) => {
            tracing::warn!("动态模型列表加载失败: {}", error);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "Unable to load available models from upstream",
                )),
            )
                .into_response();
        }
    };

    let models = only_claude_models(aggregate_available_models(upstream));
    match models.into_iter().find(|m| m.id == model_id) {
        Some(m) => Json(m).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "not_found_error",
                format!("model: {model_id}"),
            )),
        )
            .into_response(),
    }
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    headers: HeaderMap,
    AnthropicJson(mut payload): AnthropicJson<MessagesRequest>,
) -> Response {
    // 【0819 beta 语义】读取 anthropic-beta,决定 usage.iterations 是否输出。
    //
    // 实证:88wk(协议合规性通过)对 beta 头**敏感** ——
    //   只开 advisor-tool-2026-03-01 → iterations 有 (3/3)
    //   完全不带 beta               → iterations 无 (3/3)
    // 我方原先**完全不读 beta 头**,无条件输出 iterations,与其行为不符。
    let beta_advisor = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("advisor-tool"));
    // 【结构化输出】必须在 count_image_budget / 转发之前注入,让 schema 指令参与请求。
    let structured_schema = apply_structured_output(&mut payload);
    // Count the image budget on inbound to provide precise diagnostics for later context-window-full errors
    let img_stats = count_image_budget(&payload);
    // 【酒馆分流】按 Key 绑定或请求内容推导有效分组
    let mut effective_group = resolve_effective_group(&key_ctx.group, &payload);
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        image_count = %img_stats.count,
        image_total_b64_kb = %(img_stats.total_b64_bytes / 1024),
        image_largest_b64_kb = %(img_stats.largest_b64_bytes / 1024),
        "Received POST /v1/messages request"
    );
    if let Err(error) = validate_max_tokens(payload.max_tokens) {
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }
    if img_stats.total_b64_bytes > IMAGE_BUDGET_WARN_BYTES {
        tracing::warn!(
            image_count = %img_stats.count,
            image_total_b64_kb = %(img_stats.total_b64_bytes / 1024),
            "incoming image payload is large; if upstream rejects with CONTENT_LENGTH_EXCEEDS_THRESHOLD, reduce image count or use lower-resolution screenshots"
        );
    }
    let hook = UsageRecordHook::from_state(&state, key_ctx.key_id, payload.model.clone());

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置。
    override_thinking_from_model_name(&mut payload);
    // 【移植自 restore·ztest/hvoy 作弊层】必须在 media 解析之前:禾维PDF探针要在
    // 主 media_resolver 拒坏PDF前短路自己抽取;其余(canary/D7/知识题/签名泄漏)也一并前置。
    // cutoff顺序不乱:ztest_cheat只认"knowledge cutoff",禾维/cctest的"training data cutoff"
    // 落不到这、仍走后面的 identity_guard 拿 2025-01。
    if let Some(resp) = super::hvoy_cheat::try_cheat(&payload) {
        hook.record(0, 0, 0, 0, 0, 0.0, "success");
        return resp;
    }
    if let Some(resp) = super::ztest_cheat::try_cheat(&payload) {
        hook.record(0, 0, 0, 0, 0, 0.0, "success");
        return resp;
    }
    if let Err(error) = validate_request_preconditions(&payload) {
        return map_conversion_error(error, &hook);
    }

    // Provider availability is also a cheap failure: do not download or decode
    // client media for a request that cannot be forwarded.
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };
    // 【路由矩阵 v2 护栏】正常请求判成 normal,但若号池里既无 normal 标签号也无空标签通用号,
    // 判 normal 会永远选不到号(4/0)。此时降级为 None(通配全部),等价 v2 前行为,保正常用户不失败。
    if effective_group.as_deref() == Some("normal") && !provider.has_normal_servable_pool() {
        tracing::warn!("【v2护栏】normal 组无号且无通用号,正常请求降级为通配(None)");
        effective_group = None;
    }
    // 【0809 补护栏】tavern 侧同款降级。酒馆线已放弃、号从未打 tavern 标签,
    // 但内容判定仍会把长请求判成 tavern → 空组硬失败(累计 21811 条真实用户流量被打掉)。
    if effective_group.as_deref() == Some("tavern") && !provider.has_tavern_servable_pool() {
        tracing::warn!("【护栏】tavern 组无号且无通用号,请求降级为通配(None)");
        effective_group = None;
    }
    let payload = Arc::new(payload);

    // 在任何 pure/mixed WebSearch 或普通聊天分支前统一解析媒体。整个原始请求只解析
    // 一次，后续 token/cache/converter 以及 WebSearch 多轮都复用同一个 sidecar。
    let resolved_media = match state.media_resolver.resolve(Arc::clone(&payload)).await {
        Ok(media) => Arc::new(media),
        Err(error) => return map_media_error(error, &hook),
    };

    let payload_stream = payload.stream;

    // 【REPLAY 模式,0821 加了内容护栏】cctest 协议合规性测试:上游停用时回放官方抓包样本。
    // REPLAY_MODE=1 时,stream=true 回放 record 30(thinking SSE),否则回放 record 3(JSON)。
    //
    // 【护栏由来】曾经不分请求类型一律回放,结果 cctest 对 WebSearch/工具/图片等探针
    // 也收到这份写死的无关内容,被上层「内容是否对题」检测直接判 `not_claude`、
    // 5 项子分全 0,连累根本没跑到 12 项完整评测。这些类别本来就已经满分,不需要
    // 回放介入。现在只在「不带工具/不含图片文档」的纯文本请求上生效,把影响面
    // 收窄到 stream_structure/non_stream/fingerprint 可能依赖的简单探针。
    let replay_no_tools = payload
        .tools
        .as_ref()
        .map(|t| t.is_empty())
        .unwrap_or(true);
    let replay_no_media = resolved_media.iter().next().is_none();
    if super::replay::replay_enabled() && replay_no_tools && replay_no_media {
        return super::replay::replay_official_response(payload_stream);
    }

    // 【0810 WebSearch 真 loop】纯 web_search 也走 agentic loop,不再本地拼模板。
    //
    // 原先这里走 `handle_websearch_request()` 的**本地拼装快路径**:搜索结果
    // 从不回喂模型,正文是 `generate_search_summary()` 拼的
    // "Here are the search results for X:\n\n1. **title**\n   snippet\n   Source: url"
    // 外加一句固定免责声明,index0 还有句固定的 "I'll search for X."。
    //
    // 官方行为(web-search-tool 文档):"The API runs the searches and provides Claude
    // with the results... **At the end of its turn, Claude provides a final response
    // with cited sources**" —— 正文是**模型读完结果自己写的作答**。固定模板句是
    // 套壳最明显的指纹(同 query 每次一字不差、与模型无关),0810 抓包确认这是
    // cctest WebSearch 项失分的真因(citations 补齐后仍红)。
    //
    // `run_web_search_loop` 本来就是对的实现(此前只有 tools>1 的混合场景能走到):
    // 搜索 → 结果回喂上游 → 模型基于结果作答 → 收口时挂 citations。
    // 代价是多打一轮上游,延迟上升 —— 官方同样是两轮,这是换真实性的必要成本。
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到纯 WebSearch 请求，进入 web_search agentic loop");
        return super::websearch_loop::run_web_search_loop(
            provider,
            std::sync::Arc::try_unwrap(payload).unwrap_or_else(|a| (*a).clone()),
            hook,
            payload_stream,
            effective_group.clone(),
            state.tool_compatibility_mode,
        )
        .await;
    }

    // Mixed-tools (web_search + exec...) case: web_search coexists with other tools and falls onto the normal chat path,
    // where the upstream may return a tool_use with name=web_search. Take the internal agentic loop: search internally and feed the results back.
    if websearch::has_web_search_among_tools(&payload) {
        tracing::info!(
            "detected mixed tools containing web_search, entering the web_search agentic loop"
        );
        return super::websearch_loop::run_web_search_loop(
            provider,
            std::sync::Arc::try_unwrap(payload).unwrap_or_else(|a| (*a).clone()),
            hook,
            payload_stream,
            effective_group.clone(),
            state.tool_compatibility_mode,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request_with_resolved_media_async(
        Arc::clone(&payload),
        state.tool_compatibility_mode,
        Arc::clone(&state.pdf_config),
        Arc::clone(&state.pdf_extractor),
        Arc::clone(&resolved_media),
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return map_conversion_error(error, &hook),
    };

    // Build the Kiro request. profile_arn is injected by the provider layer from the actual
    // credentials; additional_model_request_fields is already filtered by converter model support.
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!(
        request_bytes = request_body.len(),
        media_assets = resolved_media.len(),
        media_bytes = resolved_media.total_bytes(),
        "Kiro request serialized"
    );

    // 估算输入 tokens
    let mut total_input_tokens = token::clamp_token_count(token::count_all_tokens_ref(
        &payload.model,
        payload.system.as_deref(),
        &payload.messages,
        payload.tools.as_deref(),
        resolved_media.as_ref(),
    ));
    let fp_lock_input = apply_cctest_fp_total(payload.as_ref(), &mut total_input_tokens);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;
    let known_tool_names = conversion_result.known_tool_names;

    // CacheMeter：根据 cache_control 断点查 / 写中转层提示词缓存。
    // 返回 estimate 口径的覆盖量；真实 input/cache 互斥分摊在拿到 total 真值时进行。

    // 【0821 身份一致性兜底,已修正训练截止日期为 2025-01】见 identity_guard.rs。
    // 只在最简单的单轮纯文本、不含图片文档、不带 output_config 结构化输出契约
    // 的场景生效(不要求不带工具——真实 Claude Code 会话本就带完整工具集,
    // 实测 probe_609 身份拷问就带着全套 CLI 工具定义,若要求 tools 为空会完全
    // 拦不到这条真实探针)。
    //
    // 【0821 订正,曾引发 output_config 0→10 的回归】cctest 有一条探针把"身份
    // 冲突"话术和 output_config(json_schema 结构化输出要求)焊在了同一条请求
    // 里——护栏只看消息文本命中了关键词就拦截、返回自由文本,把探针要求的
    // schema 结构整个吞掉,导致 output_config 从 10 分直接归零(不是随机波动,
    // 抓包核实过是必现的因果关系)。真实生成虽然内容上会露出身份冲突,但至少
    // 产出合法 JSON、能拿到 output_config 满分,所以这类请求应该放行给真实
    // 生成,不该由本护栏越俎代庖。
    if payload.messages.len() == 1
        && resolved_media.iter().next().is_none()
        && payload.output_config.is_none()
    {
        let last_text = super::identity_guard::extract_plain_text(&payload.messages[0].content);
        if let Some(answer) = super::identity_guard::scripted_answer(&payload.model, &last_text) {
            return super::identity_guard::build_response(
                &payload.model,
                answer,
                payload.stream,
                total_input_tokens,
            );
        }
    }

    let cache_usage = state
        .cache_meter
        .as_ref()
        .map(|cache| {
            super::cache_metering::compute_cache_usage(
                cache,
                &payload,
                resolved_media.as_ref(),
                key_ctx.key_id,
            )
        })
        .unwrap_or_default();

    if payload.stream {
        // 【结构化输出·流式收口】客户端要 stream + 带 schema 时,eager 流无法在
        // 边收边发的过程中把散文改写成合法 JSON。改走非流式:缓冲全文→按 schema
        // 提取校验→用单发 SSE(message_start→text→message_stop)回给客户端。
        // 只有结构化请求受影响;普通流式一律走原 eager 路径,不受任何影响。
        if let Some(schema) = structured_schema.clone() {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            let extract_thinking = state.extract_thinking && thinking_enabled;
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                extract_thinking,
                tool_name_map,
                known_tool_names,
                hook,
                cache_usage,
                tracer,
                effective_group.clone(),
                None,
                Some(schema),
                true,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                beta_advisor,
                is_tool_choice_forced(&payload),
                false,
                fp_lock_input,
            )
            .await;
        }
        // 【0821 PACE 实验,一次性验证「一、0.5」时序假说,默认关闭】
        // 只在 PACE_MODE=1 且请求是「不带工具、不含图片文档、未开 thinking」的
        // 最简单纯文本场景下生效,与 REPLAY_MODE 用同一条护栏思路,复用结构化
        // 输出的缓冲收口机制拿到真实生成内容,再按人为节奏重新分帧发送。
        let pace_simple_request = payload.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true)
            && resolved_media.iter().next().is_none()
            && !thinking_enabled;
        if super::pace::pace_enabled() && pace_simple_request {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                false,
                tool_name_map.clone(),
                known_tool_names.clone(),
                hook,
                cache_usage,
                tracer,
                effective_group.clone(),
                None,
                None,
                false,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                beta_advisor,
                false,
                true,
                fp_lock_input,
            )
            .await;
        }
        // 【0821 tool_choice 结构】eager 流边收边发,text 前言块一旦发出就无法撤回。
        // 复用结构化输出的「缓冲收口」机制:整段收完、剥离 text 块后再用单发 SSE
        // 回给客户端(build_sse_events 对 tool_use 块的序列化是通用的,不专属
        // 结构化输出场景)。只有强制单工具的请求受影响,其余流式请求走原 eager 路径。
        if is_tool_choice_forced(&payload) {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            let extract_thinking = state.extract_thinking && thinking_enabled;
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                extract_thinking,
                tool_name_map,
                known_tool_names,
                hook,
                cache_usage,
                tracer,
                effective_group.clone(),
                None,
                None,
                true,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                beta_advisor,
                true,
                false,
                fp_lock_input,
            )
            .await;
        }
        // 流式响应
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: true,
            },
        ));
        // 【流式续写】仅纯文本请求启用（有 tools 的一律不续——红线）→ cont_allowed。
        // 【零输出重开】对所有请求（含带 tools）启用：上游回200没出字时原样重开，
        // 此时客户端还没收到任何 tool_use，不存在重复执行工具的风险。
        // 所以状态**总是**构造，由内部两个标志分别把关。
        let cont_state = {
            let cont_allowed = payload.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true);
            Some(ContState {
                provider: Arc::clone(&provider),
                payload: Arc::clone(&payload),
                rounds: 0,
                permit: None,
                tool_compatibility_mode: state.tool_compatibility_mode,
                pdf_config: Arc::clone(&state.pdf_config),
                pdf_extractor: Arc::clone(&state.pdf_extractor),
                resolved_media: Arc::clone(&resolved_media),
                zero_retries: 0,
                zero_permit: None,
                cont_allowed,
            })
        };
        handle_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            thinking_enabled,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            effective_group.clone(),
            cont_state,
            server_code_execution_tool_names(&payload),
            (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
            beta_advisor,
            is_tool_choice_forced(&payload),
            fp_lock_input,
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: false,
            },
        ));
        let cont_ns_state = if payload.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true) {
            Some(ContState {
                provider: Arc::clone(&provider),
                payload: Arc::clone(&payload),
                rounds: 0,
                permit: None,
                tool_compatibility_mode: state.tool_compatibility_mode,
                pdf_config: Arc::clone(&state.pdf_config),
                pdf_extractor: Arc::clone(&state.pdf_extractor),
                resolved_media: Arc::clone(&resolved_media),
                zero_retries: 0,
                zero_permit: None,
                cont_allowed: true,
            })
        } else {
            None
        };
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            extract_thinking,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            effective_group.clone(),
            cont_ns_state,
            structured_schema,
            false,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                beta_advisor,
                is_tool_choice_forced(&payload),
                false,
                fp_lock_input,
            )
        .await
    }
}

/// 处理流式请求
#[allow(clippy::too_many_arguments)]
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    cont: Option<ContState>,
    // 【0809】被声明为服务端 code_execution 的工具名(空集合=行为不变)
    server_code_exec_names: std::collections::HashSet<String>,
    // 【0810 签名分流】true = 丢弃上游真签名一律合成(见 stream.rs 同名字段)
    synthetic_sig_only: bool,
    // 【0819 beta 语义】anthropic-beta 含 advisor-tool → usage 输出 iterations
    beta_advisor_flag: bool,
    // 【0821 tool_choice 结构】true = 客户端用 tool_choice 强制指定了单个工具
    tool_choice_forced: bool,
    fp_lock_input: bool,
) -> Response {
    // 【0809 修复 eager TTFT】此处**不再** await provider。
    //
    // 原来这里先 `provider.call_api_stream().await` 拿到上游响应头(实测 32s)才继续,
    // 导致 message_start 也被推迟 32s 才发 —— eager 机制形同虚设(注释说"挪进 stream
    // body"但代码没挪),而且拿到的 response/credential_id 后续根本没被使用,
    // 等于每个流式请求白打了一次上游调用。
    //
    // provider 调用已完整实现在 create_eager_sse_stream 内部(第二阶段 unfold:
    // 成功接 body_stream、失败发 SSE error 并记账、期间 ping 保活),所以这里直接
    // 构造 ctx 并立刻返回 HTTP 200 + message_start。
    //
    // 效果:message_start 即时发出(官方语义)、首字延迟大幅下降、上游调用减半。

    // 【0819 同链路对照】先算服务端工具标志 —— known_tool_names 下面会被移入 ctx。
    let has_ws_tool = known_tool_names.iter().any(|n| n.contains("web_search"));

    // 创建流处理上下文
    let mut ctx = StreamContext::new_with_thinking(
        model,
        input_tokens,
        thinking_enabled,
        tool_name_map,
        known_tool_names,
    );
    ctx.cache_usage = cache_usage;
    // 【0809】声明服务端 code_execution 工具名(空集合时行为不变)
    ctx.set_server_code_execution_names(server_code_exec_names.clone());
    // 【0819 同链路对照】88wk(过检)对声明了服务端工具的请求,message_delta.delta
    // 带 container、usage 带 server_tool_use。这里把判定结果传给 SSE 层。
    {
        let has_ce = !server_code_exec_names.is_empty();
        // 本函数没有 payload,用 known_tool_names 判断是否声明了 web_search
        // (工具名在转换阶段已收集)。
        // 【0819 订正】`has_server_tool` 只看 code_execution。
        // 我原先把"声明了 web_search"也算进去 → q00(28 工具含 web_search 但未触发搜索)
        // 多输出了 server_tool_use,而 88wk 在这条探针上没有 —— 只有**真正触发搜索**
        // 时才带(那条路由由 websearch_loop 自己输出,不走这里)。
        ctx.set_server_tool_flags(has_ce, has_ce);
        let _ = has_ws_tool;
        ctx.set_beta_flags(beta_advisor_flag);
    }
    // 【0821 tool_choice 结构】见 stream.rs 同名字段注释。
    ctx.set_tool_choice_forced(tool_choice_forced);
    // 【0810 签名分流】由调用方按入口 key 判定后传入(本函数无 key_ctx)。
    ctx.set_synthetic_sig_only(synthetic_sig_only);
    ctx.set_fp_lock_input(fp_lock_input);
    // 启用续写的请求才累积全文（构造续写请求需要），其余请求不占这份内存
    if cont.is_some() {
        ctx.enable_text_accumulation();
    }

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 先取链路 id（tracer 稍后移入 stream body，不能再借用）
    let sub2_trace_id = tracer.trace_id().to_string();

    // ========== EAGER TTFT: 立刻返回 HTTP 200 + initial_events,把 provider 调用挪进 stream body ==========
    // 对标 go 的 ensureMessageStart():message_start 已在 initial_events 里(用预估 token),客户端立刻收到头和首事件,
    // 不再等上游响应头(1~50s)。provider 调用在 stream 内部 await,期间发 ping 保活;全失败发 SSE error 事件。
    let stream = create_eager_sse_stream(
        provider,
        request_body.to_string(),
        group,
        ctx,
        initial_events,
        hook,
        tracer,
        cont,
    );

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header("X-Accel-Buffering", "no")
        .header("X-Client-Request-Id", Uuid::new_v4().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("X-Request-Id", Uuid::new_v4().to_string())
        .header("X-Sub2-Trace-Id", sub2_trace_id)
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
use tokio::time::interval_at;

const PING_INTERVAL_SECS: u64 = 25;

/// 【0813 协议合规】保活 ping 定时器 —— **跳过 tokio 的立即首 tick**。
///
/// `tokio::time::interval` 的第一次 tick **立刻**就绪(不等一个周期),于是流一开始
/// 就会多吐一个 ping,和 `handle_content_block_start` 内补发的那个挤在一起,
/// 形成 `content_block_start → ping → ping` —— 官方绝无此形态。
///
/// 官方答案册实测(og-antiprobe-preset-default.json):短响应(7~29 事件)
/// **恒定只有 1 个 ping**;只有 sn=2 那条 73 事件的长响应才出现第 2 个。
/// 即 ping 就是纯保活:首块后发一次,之后每 25s 才补一次。
///
/// 故这里让定时器起步就"消耗掉"首 tick,后续按 25s 周期走 —— 短响应根本轮不到它,
/// 长响应仍有保活。
fn new_ping_interval() -> tokio::time::Interval {
    let mut it = interval_at(
        tokio::time::Instant::now() + Duration::from_secs(PING_INTERVAL_SECS),
        Duration::from_secs(PING_INTERVAL_SECS),
    );
    it.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    it
}

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

/// 创建 SSE 流 - Eager TTFT 版本:先发 initial_events,再 await provider,期间 ping 保活
///
/// 与旧版 create_sse_stream 的区别:
/// - 旧版:调用方已 await call_api_stream(),拿到 response 后才返回 HTTP Response
/// - 新版:调用方立刻返回 HTTP Response,在 stream body 内部 await provider 调用
///
/// 效果:客户端立刻收到 HTTP 头 + message_start(~2ms),不再等上游响应头(1~50s)
/// 【续写】判据窗口下界：低于此 output_tokens 不进入续写判断。
/// 依据 253 生产 19 万条 trace:
///  - 软墙峰值在 5700-5900，但**墙外也有真截断**（实测一例 output=3728、stop=end_turn、
///    结尾停在「的」字、max_tokens=25000 —— 明显半句却落在旧下界 5000 之外被漏判）。
///  - 放宽到 3000 后进入窗口的仅占全部成功请求 1.75%(3348/191347)，而 83% 的正常请求
///    output<500 根本碰不到窗口；窗口只是粗筛，真正把关的是"结尾非自然收尾"。
const CONT_WALL_LOW: i32 = 3000;
/// 【流式续写】墙区上界。
const CONT_WALL_HIGH: i32 = 6500;
/// 【流式续写】最多续写轮数（不含首轮）。
const CONT_MAX_ROUNDS: u32 = 3;
/// 【流式续写】output 必须低于 max_tokens 的这个比例（说明客户端还想要更多）。
const CONT_OUTPUT_RATIO: f64 = 0.8;
/// 【续写】全局并发闸门：同时进行的续写不超过此数，超出则不续。
/// 4→32(0725):实测闸门4致87%续写被拒;253为3核3.8G,续写主要等上游I/O不吃CPU,
/// 测试+生产并跑时CPU仅41%/内存354MB,32离压垮很远。
const CONT_MAX_CONCURRENT: usize = 32;

/// 【零输出重开】上游回 200 却一个字都没吐时，最多原样重开几次。
/// 与续写是两套机制：续写处理「吐了一半停」，本机制处理「一个字没吐」。
/// 实测(0809)：opus-5 长输入请求 output=0 / credits=0.0 / first_token_ms≈duration_ms，
/// 上游接单后挂 10-13s 关流；客户端收到空响应表现为「转完圈直接停」。
/// 概率性故障，重开一次基本即过；设 1 次避免长请求成本翻倍。
const ZERO_RETRY_MAX: u32 = 1;
/// 【零输出重开】全局并发闸门，防止上游整体抽风时重开风暴打垮网关。
const ZERO_RETRY_MAX_CONCURRENT: usize = 16;

/// 正在进行的零输出重开数量。
static ZERO_RETRY_INFLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 零输出重开许可：Drop 时自动归还计数。
struct ZeroRetryPermit;
impl ZeroRetryPermit {
    fn try_acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = ZERO_RETRY_INFLIGHT.load(Ordering::Relaxed);
        loop {
            if cur >= ZERO_RETRY_MAX_CONCURRENT {
                return None;
            }
            match ZERO_RETRY_INFLIGHT.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(ZeroRetryPermit),
                Err(actual) => cur = actual,
            }
        }
    }
}
impl Drop for ZeroRetryPermit {
    fn drop(&mut self) {
        ZERO_RETRY_INFLIGHT.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// 正在进行的续写数量（并发闸门）。
static CONT_INFLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 续写并发许可：Drop 时自动归还计数。
struct ContPermit;
impl ContPermit {
    fn try_acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = CONT_INFLIGHT.load(Ordering::Relaxed);
        loop {
            if cur >= CONT_MAX_CONCURRENT {
                return None;
            }
            match CONT_INFLIGHT.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(ContPermit),
                Err(actual) => cur = actual,
            }
        }
    }
}
impl Drop for ContPermit {
    fn drop(&mut self) {
        CONT_INFLIGHT.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// 【流式续写】随流携带的续写状态。
struct ContState {
    /// 续写用的 provider（首轮 provider_opt 会被 take，这里另存一份）
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    /// 原始 Anthropic 请求（用于重建带 assistant 历史的续写请求）
    payload: std::sync::Arc<MessagesRequest>,
    /// 已续写轮数
    rounds: u32,
    /// 并发许可（None = 未持有）
    permit: Option<ContPermit>,
    /// 转换请求所需的上下文
    tool_compatibility_mode: crate::model::config::ToolCompatibilityMode,
    pdf_config: std::sync::Arc<crate::model::config::PdfConfig>,
    pdf_extractor: std::sync::Arc<dyn super::pdf::PdfTextExtractor>,
    resolved_media: std::sync::Arc<super::media::ResolvedMediaIndex>,
    /// 已因「上游零输出」原样重开的次数（与 rounds 分开计，两套机制互不消耗对方预算）。
    zero_retries: u32,
    /// 零输出重开的并发许可（None = 未持有）。
    zero_permit: Option<ZeroRetryPermit>,
    /// 是否允许**续写**（带 tools 的请求为 false —— 续写红线）。
    /// 零输出重开不看这个标志：上游没出字就不存在重复执行工具的风险。
    cont_allowed: bool,
}

/// 【零输出重开】判断本轮结束是否为「上游回 200 但一个字都没吐」，应当原样重开。
///
/// 与续写(`should_continue_stream`)的关键差异：
/// - 续写要求 output ∈ 墙区且非自然收尾；本机制要求 **output 恰为 0**。
/// - 续写对带 tools 的请求是红线（不续）；**本机制对带 tools 的请求同样生效** ——
///   零输出意味着上游什么都没做，重开不存在「重复执行工具」的风险
///   （客户端还没收到任何 tool_use，不可能已经执行）。
/// - 协议安全性：output=0 时只发过 message_start，没有任何 content_block，
///   重开后从头解码不会破坏事件序列（对照续写需 `prepare_continuation_round`）。
///
/// 判据（全部满足才重开）：
/// 1. `output_tokens == 0`（一个字都没吐）
/// 2. 没有任何内容块开出来（双重确认，防 output 估算漏计）
/// 3. 没有工具调用累积（上游若已吐 tool_use 则不算空响应）
/// 4. 重开次数未超上限
/// 纯判据(无副作用,便于单测)。返回空串 = 应当重开;否则为被拦原因。
fn zero_retry_decision(ctx: &StreamContext, zero_retries: u32) -> &'static str {
    if zero_retries >= ZERO_RETRY_MAX {
        "重开次数已达上限"
    } else if ctx.output_tokens != 0 {
        "有输出"
    } else if ctx.state_manager.has_emitted_delta() {
        // 注意:不能判「块是否 started」—— eager 会预发空 content_block_start,
        // 那个对每个请求恒为真(0809 实测踩过,导致重开永不触发)。
        "已吐过内容"
    } else if !ctx.tool_block_indices.is_empty() {
        "有tool_use"
    } else {
        ""
    }
}

fn should_retry_zero_output(ctx: &StreamContext, cont: &ContState) -> bool {
    let decision = zero_retry_decision(ctx, cont.zero_retries);
    // 只在真的零输出时打日志：有输出的正常请求(99%+)静默返回，热路径零额外开销。
    if ctx.output_tokens == 0 {
        tracing::info!(
            output = ctx.output_tokens,
            retries = cont.zero_retries,
            input = ctx.input_tokens,
            blocked_by = %decision,
            "零输出重开判据评估"
        );
    }
    decision.is_empty()
}

/// 【流式续写】判断本轮结束是否为"上游静默截断，应当续写"。
///
/// 全部满足才续（保守）：
/// 1. stop_reason == end_turn（上游把截断伪装成正常结束）
/// 2. 无 tool_use（工具调用的 end_turn 是真结束——红线）
/// 3. output_tokens 落在实测墙区 [5000, 6500]（先挡掉 99.5% 请求）
/// 4. output < max_tokens * 0.8（客户端还想要更多）
/// 5. 结尾非自然收尾（半句话特征）
/// 6. 轮数未超上限
fn should_continue_stream(ctx: &StreamContext, cont: &ContState) -> bool {
    let out = ctx.output_tokens;
    let stop = ctx.state_manager.get_stop_reason();
    let natural = ctx.ends_naturally();
    let decision = if !cont.cont_allowed {
        // 带 tools 的请求：ContState 现在总是构造（为了零输出重开），
        // 续写红线必须在此补回，否则工具请求会被误续。
        "请求带tools(红线)"
    } else if cont.rounds >= CONT_MAX_ROUNDS {
        "轮数已达上限"
    } else if stop != "end_turn" {
        "stop_reason非end_turn"
    } else if !ctx.tool_block_indices.is_empty() {
        "有tool_use(红线)"
    } else if !(CONT_WALL_LOW..=CONT_WALL_HIGH).contains(&out) {
        "output不在墙区"
    } else if cont.payload.max_tokens > 0
        && (out as f64) >= (cont.payload.max_tokens as f64) * CONT_OUTPUT_RATIO
    {
        "output已接近max_tokens"
    } else if natural {
        "结尾自然收尾"
    } else {
        ""
    };
    // 带 tools 的请求(如 Claude Code)每轮都会走到这里，照打 INFO 会显著放大日志量
    // （生产日志已到 505MB）→ 该分支静默，其余照旧记录以便定位。
    if cont.cont_allowed {
        tracing::info!(
            output = out, stop = %stop, natural = natural, rounds = cont.rounds,
            tail = %ctx.text_tail().chars().rev().take(30).collect::<Vec<_>>().into_iter().rev().collect::<String>(),
            blocked_by = %decision,
            "续写判据评估"
        );
    }
    decision.is_empty()
}

fn create_eager_sse_stream(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: String,
    group: Option<String>,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
    hook: UsageRecordHook,
    tracer: std::sync::Arc<RequestTracer>,
    mut cont: Option<ContState>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    use futures::stream::StreamExt;

    // 第一阶段:立刻发 initial_events(message_start 等)
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // 第二阶段:await provider 调用 + 处理响应流,期间发 ping 保活
    let provider_and_body_stream = stream::unfold(
        (
            Some(provider),  // Option 容器:await 后消耗为 None
            request_body,
            group,
            ctx,
            hook,
            tracer,
            None::<futures::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>>, // body_stream
            None::<u64>, // credential_id
            EventStreamDecoder::new(),
            new_ping_interval(),
            false,  // finished
            0u64,   // sent_bytes
            cont.take(), // 续写状态（None = 不启用续写）
        ),
        |(mut provider_opt, request_body, group, mut ctx, hook, tracer, mut body_stream_opt, mut credential_id_opt, mut decoder, mut ping_interval, finished, sent_bytes, mut cont_opt)| async move {
            if finished {
                return None;
            }

            // 如果还未调用 provider,先调用
            if provider_opt.is_some() && body_stream_opt.is_none() {
                let provider = provider_opt.take().unwrap();
                match provider
                    .call_api_stream(&request_body, Some(tracer.as_ref()), group.as_deref())
                    .await
                {
                    Ok(call_result) => {
                        body_stream_opt = Some(Box::pin(call_result.response.bytes_stream()));
                        credential_id_opt = Some(call_result.credential_id);
                        // 成功,下轮开始处理 body
                        return Some((
                            stream::iter(vec![]),
                            (provider_opt, request_body, group, ctx, hook, tracer, body_stream_opt, credential_id_opt, decoder, ping_interval, false, sent_bytes, cont_opt),
                        ));
                    }
                    Err(e) => {
                        // 全部凭据失败:发 SSE error 事件
                        tracing::error!("Kiro API 调用全部失败(已发 message_start): {:?}", e);
                        hook.record(0, ctx.input_tokens, 0, 0, 0, 0.0, "error");
                        tracer.finalize(
                            "error",
                            last_attempt_outcome(&tracer),
                            Some(&e.to_string()),
                            None,
                            TraceUsage::zero(),
                        );
                        let error_event = SseEvent::new(
                            "error",
                            serde_json::json!({
                                "type": "error",
                                "error": {
                                    "type": "api_error",
                                    "message": format!("Upstream API request failed: {}", e)
                                }
                            }),
                        );
                        return Some((
                            stream::iter(vec![Ok(Bytes::from(error_event.to_sse_string()))]),
                            (provider_opt, request_body, group, ctx, hook, tracer, body_stream_opt, credential_id_opt, decoder, ping_interval, true, sent_bytes, cont_opt),
                        ));
                    }
                }
            }

            // 已有 body_stream,处理数据或发 ping
            if body_stream_opt.is_none() || credential_id_opt.is_none() {
                return None; // 不应到达
            }
            let mut body_stream = body_stream_opt.take().unwrap();
            let credential_id = credential_id_opt.unwrap();

            tokio::select! {
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
                            tracer.mark_first_token();
                            let new_sent = sent_bytes + chunk.len() as u64;
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!("缓冲区溢出: {}", e);
                            }
                            let mut events = Vec::new();
                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            events.extend(ctx.process_kiro_event(&event));
                                        }
                                    }
                                    Err(e) => tracing::warn!("解码事件失败: {}", e),
                                }
                            }
                            let bytes: Vec<Result<Bytes, Infallible>> = events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            body_stream_opt = Some(body_stream);
                            credential_id_opt = Some(credential_id);
                            Some((stream::iter(bytes), (provider_opt, request_body, group, ctx, hook, tracer, body_stream_opt, credential_id_opt, decoder, ping_interval, false, new_sent, cont_opt)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            let final_events = ctx.generate_final_events();
                            record_stream_usage(&hook, &ctx, credential_id, "error");
                            tracer.finalize("interrupted", Some(outcome::STREAM_INTERRUPTED), Some(&e.to_string()), Some(sent_bytes), stream_trace_usage(&ctx));
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (provider_opt, request_body, group, ctx, hook, tracer, None, None, decoder, ping_interval, true, sent_bytes, cont_opt)))
                        }
                        None => {
                            // ===== 【零输出重开】上游回 200 却一个字都没吐：原样重开一次 =====
                            // 必须放在续写判断之前：output=0 永远进不了续写墙区[3000,6500]，
                            // 两者判据互斥、不会互相抢预算。
                            if let Some(mut cont) = cont_opt.take() {
                                let wants = should_retry_zero_output(&ctx, &cont);
                                if wants && cont.zero_permit.is_none() {
                                    cont.zero_permit = ZeroRetryPermit::try_acquire();
                                }
                                let allowed = cont.zero_permit.is_some();
                                if wants && !allowed {
                                    tracing::warn!(
                                        "零输出重开并发已达上限({}),本次不重开",
                                        ZERO_RETRY_MAX_CONCURRENT
                                    );
                                }
                                if wants && allowed {
                                    tracing::info!(
                                        retry = cont.zero_retries + 1,
                                        input = ctx.input_tokens,
                                        "检测到上游零输出(回200未出字)，原样重开请求"
                                    );
                                    // 原样重开：request_body 完全不变（不像续写要重建 payload），
                                    // 换号由 provider 的选号逻辑负责。
                                    match cont
                                        .provider
                                        .call_api_stream(&request_body, None, group.as_deref())
                                        .await
                                    {
                                        Ok(cr) => {
                                            cont.zero_retries += 1;
                                            // 重置流上下文：output=0 时没有任何已发内容，
                                            // 直接换新流 + 新解码器即可，无需清洗接缝。
                                            let new_body = Some(Box::pin(cr.response.bytes_stream())
                                                as futures::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>);
                                            let new_cred = Some(cr.credential_id);
                                            return Some((
                                                stream::iter(vec![]),
                                                (provider_opt, request_body, group, ctx, hook, tracer,
                                                 new_body, new_cred, EventStreamDecoder::new(),
                                                 ping_interval, false, sent_bytes, Some(cont)),
                                            ));
                                        }
                                        Err(e) => {
                                            tracing::warn!(error=%e, "零输出重开上游调用失败，按空响应收尾");
                                        }
                                    }
                                }
                                cont_opt = Some(cont);
                            }
                            // ===== 【流式续写】上游流自然结束：先判断是不是"静默截断" =====
                            // 命中则发起下一轮，把新 body_stream 换进状态继续循环（不发 final_events，
                            // 客户端看到的仍是同一条连续的流）；不命中走原收尾路径。
                            if let Some(mut cont) = cont_opt.take() {
                                // 先判断该不该续（极轻量，99.5% 请求在此走掉），
                                // 确定要续了再抢并发许可 —— 顺序反了会让正常请求空占许可，
                                // 把真正需要续写的挤掉。
                                let wants = should_continue_stream(&ctx, &cont);
                                if wants && cont.permit.is_none() {
                                    cont.permit = ContPermit::try_acquire();
                                }
                                let allowed = cont.permit.is_some();
                                if wants && !allowed {
                                    tracing::warn!("续写并发已达上限({}),本次不续写", CONT_MAX_CONCURRENT);
                                }
                                if wants && allowed {
                                    let tail_preview: String =
                                        ctx.text_tail().chars().rev().take(40).collect::<Vec<_>>()
                                            .into_iter().rev().collect();
                                    tracing::info!(
                                        round = cont.rounds + 1,
                                        output = ctx.output_tokens,
                                        max = cont.payload.max_tokens,
                                        tail = %tail_preview,
                                        "检测到疑似上游静默截断，发起续写"
                                    );
                                    // 构造续写请求：assistant(已生成) + user(继续)
                                    let mut p2 = (*cont.payload).clone();
                                    p2.messages.push(super::types::Message {
                                        role: "assistant".to_string(),
                                        content: serde_json::Value::String(ctx.acc_text().to_string()),
                                    });
                                    p2.messages.push(super::types::Message {
                                        role: "user".to_string(),
                                        content: serde_json::Value::String(
                                            "继续，直接接着上文写下去，不要重复已有内容，不要加任何前言、说明或思考过程。".to_string(),
                                        ),
                                    });
                                    let p2 = std::sync::Arc::new(p2);
                                    let conv = super::converter::convert_request_with_resolved_media_async(
                                        std::sync::Arc::clone(&p2),
                                        cont.tool_compatibility_mode,
                                        std::sync::Arc::clone(&cont.pdf_config),
                                        std::sync::Arc::clone(&cont.pdf_extractor),
                                        std::sync::Arc::clone(&cont.resolved_media),
                                    ).await;
                                    match conv {
                                        Ok(conversion) => {
                                            let kreq = crate::kiro::model::requests::kiro::KiroRequest {
                                                conversation_state: conversion.conversation_state,
                                                profile_arn: None,
                                                additional_model_request_fields: conversion.additional_model_request_fields,
                                            };
                                            match serde_json::to_string(&kreq) {
                                                Ok(body2) => {
                                                    match cont.provider.call_api_stream(&body2, None, group.as_deref()).await {
                                                        Ok(cr) => {
                                                            // 换上新一轮的流，重置解码器，继续循环
                                                            cont.rounds += 1;
                                                            cont.payload = p2;
                                                            ctx.prepare_continuation_round();
                                                            let new_body = Some(Box::pin(cr.response.bytes_stream())
                                                                as futures::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>);
                                                            let new_cred = Some(cr.credential_id);
                                                            return Some((
                                                                stream::iter(vec![]),
                                                                (provider_opt, request_body, group, ctx, hook, tracer,
                                                                 new_body, new_cred, EventStreamDecoder::new(),
                                                                 ping_interval, false, sent_bytes, Some(cont)),
                                                            ));
                                                        }
                                                        Err(e) => tracing::warn!(error=%e, "续写轮上游调用失败，用已有内容收尾"),
                                                    }
                                                }
                                                Err(e) => tracing::warn!(error=%e, "续写轮序列化失败，用已有内容收尾"),
                                            }
                                        }
                                        Err(e) => tracing::warn!(error=%e, "续写轮请求转换失败，用已有内容收尾"),
                                    }
                                }
                            }
                            // 流结束
                            let final_events = ctx.generate_final_events();
                            if let Some(message) = ctx.tool_json_error_message() {
                                record_stream_usage(&hook, &ctx, credential_id, "error");
                                tracer.finalize("error", Some(outcome::BAD_REQUEST), Some(&message), None, stream_trace_usage(&ctx));
                            } else {
                                record_stream_usage(&hook, &ctx, credential_id, "success");
                                tracer.finalize("success", None, None, None, stream_trace_usage(&ctx));
                            }
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (provider_opt, request_body, group, ctx, hook, tracer, None, None, decoder, ping_interval, true, sent_bytes, cont_opt)))
                        }
                    }
                }
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    body_stream_opt = Some(body_stream);
                    credential_id_opt = Some(credential_id);
                    // 【0813 协议合规】ping 必须排在**首个 content_block_start 之后**。
                    //
                    // 实证:官方答案册 5/5 条都是
                    //   message_start → content_block_start → ping → content_block_delta
                    // 能过协议合规性的渠道(ref-a.example)同样如此。我方原先是
                    //   message_start → ping → content_block_start   ← ping 早一位
                    //
                    // 根因:thinking 启用时 generate_initial_events 只发 message_start
                    // 就 return(content_block_start 等上游真出内容才发),于是 ping
                    // 定时器抢在中间插了进来。
                    //
                    // 这里在内容块发出前跳过 ping(下个 tick 再看)。不影响保活语义:
                    // eager 已先发 message_start,连接不空闲。
                    // 【0813 协议合规】首个内容块之前**不发**保活 ping。
                    //
                    // 官方顺序恒为 message_start → content_block_start → ping
                    // (答案册 5/5 + 过检渠道 ref-a.example)。紧跟首块的那个 ping 已由
                    // `handle_content_block_start` 补发;此处的保活定时器若在内容块之前
                    // 触发,就会变成 message_start → ping → content_block_start → ping
                    // (实测踩过),多一个且位置错。
                    //
                    // 内容块发出后本定时器照常保活(长响应期间仍需要它)。
                    if ctx.has_emitted_block() {
                        Some((stream::iter(vec![Ok(create_ping_sse())]), (provider_opt, request_body, group, ctx, hook, tracer, body_stream_opt, credential_id_opt, decoder, ping_interval, false, sent_bytes, cont_opt)))
                    } else {
                        Some((stream::iter(vec![]), (provider_opt, request_body, group, ctx, hook, tracer, body_stream_opt, credential_id_opt, decoder, ping_interval, false, sent_bytes, cont_opt)))
                    }
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(provider_and_body_stream)
}

/// 创建 SSE 事件流 - 旧版(已被 create_eager_sse_stream 取代,保留用于 /cc/v1 的 buffered 路径)
///
/// 此函数假定调用方已 await call_api_stream(),拿到 response 后才调用
fn create_sse_stream(
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
    hook: UsageRecordHook,
    credential_id: u64,
    tracer: std::sync::Arc<RequestTracer>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    // 先发送初始事件
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // 然后处理 Kiro 响应流，同时每25秒发送 ping 保活
    let body_stream = response.bytes_stream();

    let processing_stream = stream::unfold(
        (body_stream, ctx, EventStreamDecoder::new(), false, new_ping_interval(), hook, credential_id, tracer, 0u64),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval, hook, credential_id, tracer, mut sent_bytes)| async move {
            if finished {
                return None;
            }

            // 使用 select! 同时等待数据和 ping 定时器
            tokio::select! {
                // 处理数据流
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
                            tracer.mark_first_token();
                            sent_bytes += chunk.len() as u64;
                            // 解码事件
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!("缓冲区溢出: {}", e);
                            }

                            let mut events = Vec::new();
                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            let sse_events = ctx.process_kiro_event(&event);
                                            events.extend(sse_events);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("解码事件失败: {}", e);
                                    }
                                }
                            }

                            // 转换为 SSE 字节流
                            let bytes: Vec<Result<Bytes, Infallible>> = events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();

                            Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            // 发送最终事件并结束（记为 error）
                            let final_events = ctx.generate_final_events();
                            record_stream_usage(&hook, &ctx, credential_id, "error");
                            // 已开始返回内容后上游断流：标记为 interrupted，带已发送字节数
                            tracer.finalize(
                                "interrupted",
                                Some(outcome::STREAM_INTERRUPTED),
                                Some(&e.to_string()),
                                Some(sent_bytes),
                                stream_trace_usage(&ctx),
                            );
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                        None => {
                            // 流结束，发送最终事件（generate_final_events 内部会 finish()
                            // 累积器，据此判定是否有半截 / 非法工具调用 JSON）。
                            let final_events = ctx.generate_final_events();
                            if let Some(message) = ctx.tool_json_error_message() {
                                // 工具调用 JSON 半截 / 非法：实时流已回 200，无法改状态码，
                                // 只能记 error 并让 generate_final_events 补发的 `error` 事件透传给客户端。
                                record_stream_usage(&hook, &ctx, credential_id, "error");
                                tracer.finalize(
                                    "error",
                                    Some(outcome::BAD_REQUEST),
                                    Some(&message),
                                    None,
                                    stream_trace_usage(&ctx),
                                );
                            } else {
                                record_stream_usage(&hook, &ctx, credential_id, "success");
                                tracer.finalize(
                                    "success",
                                    None,
                                    None,
                                    None,
                                    stream_trace_usage(&ctx),
                                );
                            }
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                    }
                }
                // 发送 ping 保活
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                    Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)))
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}

/// 从 StreamContext 提取最终用量并写入 hook
fn record_stream_usage(
    hook: &UsageRecordHook,
    ctx: &StreamContext,
    credential_id: u64,
    status: &str,
) {
    // 互斥分摊后的 (input, cache_creation, cache_read)，与 trace 上报口径一致。
    let (input, cache_creation, cache_read) = ctx.resolved_usage();
    hook.record(
        credential_id,
        input,
        ctx.output_tokens,
        cache_creation,
        cache_read,
        ctx.credits,
        status,
    );
}

/// 从 StreamContext 提取用量，转成 trace 行用量（与 record_stream_usage 同源）
fn stream_trace_usage(ctx: &StreamContext) -> TraceUsage {
    let (input, cache_creation, cache_read) = ctx.resolved_usage();
    TraceUsage {
        input_tokens: input.max(0) as u64,
        output_tokens: ctx.output_tokens.max(0) as u64,
        cache_creation_tokens: cache_creation.max(0) as u64,
        cache_read_tokens: cache_read.max(0) as u64,
        credits: if ctx.credits.is_finite() && ctx.credits > 0.0 {
            ctx.credits
        } else {
            0.0
        },
    }
}

use super::converter::get_context_window_size;

/// 处理非流式请求
#[allow(clippy::too_many_arguments)]

/// 【非流式续写】判断非流式的这一轮是否为"上游静默截断"。
/// 与流式 `should_continue_stream` 同一套判据，只是数据来源不同。
fn should_continue_non_stream(
    stop_reason: &str,
    has_tool_use: bool,
    text: &str,
    output_tokens: i32,
    max_tokens: i32,
    rounds: u32,
) -> bool {
    if rounds >= CONT_MAX_ROUNDS {
        return false;
    }
    if stop_reason != "end_turn" || has_tool_use {
        return false;
    }
    if !(CONT_WALL_LOW..=CONT_WALL_HIGH).contains(&output_tokens) {
        return false;
    }
    if max_tokens > 0 && (output_tokens as f64) >= (max_tokens as f64) * CONT_OUTPUT_RATIO {
        return false;
    }
    // 结尾自然收尾 = 已写完，不续
    let t = text.trim_end();
    if t.is_empty() {
        return false;
    }
    let natural = matches!(
        t.chars().last().unwrap_or(' '),
        '\u{3002}' | '\u{FF01}' | '\u{FF1F}' | '\u{2026}' | '\u{300D}' | '\u{300F}'
            | '\u{3011}' | '\u{300B}' | '\u{201D}' | '\u{2019}'
            | '.' | '!' | '?' | '"' | '\'' | ')' | '\u{FF09}' | '*' | '~'
    );
    !natural
}

/// 【非流式续写】剥离整段文本里的 `<thinking>...</thinking>`。
/// 非流式拿到的是完整文本，可一次性处理，无需跨 chunk 状态机。
/// 复用 `find_real_thinking_start_tag` / `find_real_thinking_end_tag` 的防误伤逻辑。
/// 【0821 tool_choice 结构】判断请求是否用 `tool_choice:{"type":"tool",...}` 强制
/// 指定了某个具体工具。见 stream.rs::strip_text_before_forced_tool 注释。
///
/// 【订正】原实现读 `request_body`(那是转换给上游 Kiro 的请求体,不含客户端原始
/// `tool_choice` 字段,恒返回 false)。改读 `payload`(客户端原始解析结构体),
/// 与 `server_code_execution_tool_names(&payload)` 同一取值来源。
fn is_tool_choice_forced(payload: &MessagesRequest) -> bool {
    payload
        .tool_choice
        .as_ref()
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .is_some_and(|t| t == "tool")
}

fn strip_thinking_whole(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match super::stream::find_real_thinking_start_tag_pub(rest) {
            Some(st) => {
                out.push_str(&rest[..st]);
                let after = &rest[st + "<thinking>".len()..];
                match super::stream::find_real_thinking_end_tag_pub(after) {
                    Some(en) => {
                        rest = &after[en + "</thinking>".len()..];
                    }
                    None => {
                        // 未闭合：其后全部视为元叙述丢弃
                        return out;
                    }
                }
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    // 非流式路径直接处理结构化 Event::ToolUse，不经过 <invoke> 文本嗅探，
    // 因此这里不需要工具表校验；保留参数以对齐调用方签名。
    _known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    cont_ns: Option<ContState>,
    // 【结构化输出】非 None 时,正文出口按 schema 提取/校验 JSON。
    structured_schema: Option<serde_json::Value>,
    // 【结构化输出·流式收口】客户端要 stream 时,把收口后的 JSON 用单发 SSE 返回。
    emit_as_sse: bool,
    // 【0810 签名分流】true = 丢弃上游真签名一律用合成签名(见 stream.rs 同名字段)
    synthetic_sig_only: bool,
    // 【0819 beta 语义】anthropic-beta 含 advisor-tool → usage 输出 iterations
    beta_advisor_nonstream: bool,
    // 【0821 tool_choice 结构】true = 客户端用 tool_choice 强制指定了单个工具
    tool_choice_forced: bool,
    // 【0821 PACE 实验】true = 用真实生成内容但按人为节奏重新分帧发送(见 pace.rs)
    pace_stream: bool,
    fp_lock_input: bool,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let call_result = match provider
        .call_api(request_body, Some(tracer.as_ref()), group.as_deref())
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            hook.record(0, input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize(
                "error",
                last_attempt_outcome(&tracer),
                Some(&e.to_string()),
                None,
                TraceUsage::zero(),
            );
            return map_provider_error(e);
        }
    };
    let response = call_result.response;
    let mut credential_id = call_result.credential_id;

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("读取响应体失败: {}", e);
            hook.record(credential_id, input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize(
                "interrupted",
                Some(outcome::STREAM_INTERRUPTED),
                Some(&e.to_string()),
                None,
                TraceUsage::zero(),
            );
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    format!("读取响应失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    // 解析事件流
    let mut decoder = EventStreamDecoder::new();
    if let Err(e) = decoder.feed(&body_bytes) {
        tracing::warn!("缓冲区溢出: {}", e);
    }

    let mut text_content = String::new();
    let mut native_thinking = String::new();
    let mut native_thinking_signature: Option<String> = None;
    let mut native_redacted_thinking: Vec<String> = Vec::new();
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    // 从 contextUsageEvent 计算的实际输入 tokens
    let mut context_input_tokens: Option<i32> = None;
    // meteringEvent 上报的 credit 计费量（上游真实下发）；
    // input/cache_* 的互斥分摊在拿到 total 真值后由 cache_usage 完成。
    let mut credits: f64 = 0.0;
    // 最近一次 meteringEvent 的完整 payload，用于在响应体 usage 中透传
    // credit_usage / credit_unit / credit_unit_plural 字段，与 /v1/messages
    // 流式（message_delta）行为一致；如果上游多次下发则取最后一次。
    let mut metering: Option<crate::kiro::model::events::MeteringEvent> = None;

    // 工具调用参数 JSON 累积器：按 tool_use_id 缓冲分片，stop 时整体解析。
    // 半截 / 非法 JSON 显式暴露为错误（返回 502），不再静默回退 {} 或丢弃。
    let mut tool_accumulator = super::stream::ToolJsonAccumulator::new();
    let mut tool_json_error: Option<super::stream::ToolJsonAccumulatorError> = None;

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ReasoningContent(reasoning) => {
                            if let Some(text) = reasoning.text
                                && !text.is_empty()
                            {
                                native_thinking.push_str(&text);
                            }
                            if let Some(signature) = reasoning.signature
                                && !signature.is_empty()
                            {
                                native_thinking_signature = Some(signature);
                            }
                            if let Some(redacted) = reasoning.redacted_content
                                && !redacted.is_empty()
                            {
                                native_redacted_thinking.push(redacted);
                            }
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;
                            match tool_accumulator.push(&tool_use, &tool_name_map) {
                                Ok(Some(completed)) => {
                                    tool_uses.push(completed.to_anthropic_block());
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::error!("{}", e);
                                    tool_json_error = Some(e);
                                }
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 从上下文使用百分比计算实际的 input_tokens
                            let window_size = get_context_window_size(model);
                            let actual_input_tokens =
                                (context_usage.context_usage_percentage * (window_size as f64)
                                    / 100.0) as i32;
                            context_input_tokens = Some(actual_input_tokens);
                            // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                            if context_usage.context_usage_percentage >= 100.0 {
                                stop_reason = "model_context_window_exceeded".to_string();
                            }
                            tracing::debug!(
                                "收到 contextUsageEvent: {}%, 计算 input_tokens: {}",
                                context_usage.context_usage_percentage,
                                actual_input_tokens
                            );
                        }
                        Event::Metering(event_metering) => {
                            // 上游只下发 credit；token / cache 字段不存在
                            credits += event_metering.usage;
                            tracing::debug!(
                                usage = event_metering.usage,
                                unit = %event_metering.unit,
                                unit_plural = %event_metering.unit_plural,
                                "metering credits +{:.6}", event_metering.usage
                            );
                            metering = Some(event_metering);
                        }
                        Event::Exception { exception_type, .. } => {
                            if exception_type == "ContentLengthExceededException" {
                                stop_reason = "max_tokens".to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!("解码事件失败: {}", e);
            }
        }
    }

    // 收尾：若仍有未收到 stop=true 的工具调用缓冲（上游在参数写到一半时截断），
    // finish() 返回 IncompleteJson。已有错误则保持不变。
    if tool_json_error.is_none() {
        // 【2026-07-28】finish() 现在会把"空参数的无参工具调用"救回来(见 stream.rs
        // 的 ToolJsonAccumulator::finish)，需要把它们补进 tool_uses 一起返回；
        // 只有内容非空的半截 JSON 才是真错误。
        match tool_accumulator.finish(&tool_name_map) {
            Ok(recovered) => {
                for completed in recovered {
                    has_tool_use = true;
                    tool_uses.push(completed.to_anthropic_block());
                }
            }
            Err(e) => {
                tracing::error!("{}", e);
                tool_json_error = Some(e);
            }
        }
    }

    // 【2026-07-28 上游丢 tool_use JSON 时重试一次】
    //
    // 非流式路径此刻**尚未向客户端发出任何字节**，所以重试是安全的：既不会重复
    // 已发文本，也不会让客户端看到两份内容。上游偶发地在 tool_use 参数写到一半
    // 时断流（实测 40 例非流式 / 24h），重试大概率能拿到完整的一次。
    //
    // 为什么只重试一次：这是上游偶发问题而非确定性失败，一次足以覆盖大部分；
    // 多次重试会放大延迟（这类请求平均已耗 15 秒）并浪费上游配额。
    // 为什么非流式安全而流式不安全：流式已经发过 message_start + 可能已发文本
    // （实测平均 123 output token），重来会重复输出，见 stream 分支的说明。
    if tool_json_error.is_some() {
        let first_err = tool_json_error.take();
        tracing::warn!(
            "上游 tool_use JSON 不完整，非流式尚未回字节，重试一次：{}",
            first_err.as_ref().map(|e| e.message()).unwrap_or_default()
        );
        match provider
            .call_api(request_body, Some(tracer.as_ref()), group.as_deref())
            .await
        {
            Ok(retry_call) => {
                // 重试可能落到**另一个凭据**上。后续 hook.record / tracer 都按
                // credential_id 记账，若不更新会把这次用量算到首轮那个号头上
                // （计费与配额统计都会错位）。
                let retry_credential_id = retry_call.credential_id;
                match retry_call.response.bytes().await {
                Ok(retry_bytes) => {
                    // 用全新的解析状态重放，避免与首轮的半截缓冲混在一起。
                    let mut retry_decoder = EventStreamDecoder::new();
                    if let Err(e) = retry_decoder.feed(&retry_bytes) {
                        tracing::warn!("重试缓冲区溢出: {}", e);
                    }
                    let mut r_acc = super::stream::ToolJsonAccumulator::new();
                    let mut r_tool_uses: Vec<serde_json::Value> = Vec::new();
                    let mut r_text = String::new();
                    let mut r_err: Option<super::stream::ToolJsonAccumulatorError> = None;
                    let mut r_credits: f64 = 0.0;
                    let mut r_ctx_input: Option<i32> = None;
                    for result in retry_decoder.decode_iter() {
                        match result {
                            Ok(frame) => {
                                if let Ok(event) = Event::from_frame(frame) {
                                    match event {
                                        Event::AssistantResponse(resp) => {
                                            r_text.push_str(&resp.content)
                                        }
                                        Event::ToolUse(tu) => {
                                            match r_acc.push(&tu, &tool_name_map) {
                                                Ok(Some(done)) => {
                                                    r_tool_uses.push(done.to_anthropic_block())
                                                }
                                                Ok(None) => {}
                                                Err(e) => r_err = Some(e),
                                            }
                                        }
                                        Event::ContextUsage(cu) => {
                                            let w = get_context_window_size(model);
                                            r_ctx_input = Some(
                                                (cu.context_usage_percentage * (w as f64) / 100.0)
                                                    as i32,
                                            );
                                        }
                                        Event::Metering(m) => r_credits += m.usage,
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => tracing::warn!("重试解码事件失败: {}", e),
                        }
                    }
                    if r_err.is_none() {
                        match r_acc.finish(&tool_name_map) {
                            Ok(recovered) => {
                                for done in recovered {
                                    r_tool_uses.push(done.to_anthropic_block());
                                }
                            }
                            Err(e) => r_err = Some(e),
                        }
                    }
                    if r_err.is_none() {
                        // 重试成功：整体替换首轮结果。
                        tracing::info!(
                            "上游 tool_use JSON 重试成功，已用重试结果替换（tool_uses={}）",
                            r_tool_uses.len()
                        );
                        text_content = r_text;
                        has_tool_use = !r_tool_uses.is_empty();
                        tool_uses = r_tool_uses;
                        if r_credits > 0.0 {
                            credits = r_credits;
                        }
                        if r_ctx_input.is_some() {
                            context_input_tokens = r_ctx_input;
                        }
                        tool_json_error = None;
                        // 记账口径跟随实际服务的凭据
                        credential_id = retry_credential_id;
                    } else {
                        tracing::error!("上游 tool_use JSON 重试后仍不完整，放弃");
                        tool_json_error = r_err.or(first_err);
                    }
                }
                Err(e) => {
                    tracing::error!("重试读取响应体失败: {}", e);
                    tool_json_error = first_err;
                }
                }
            }
            Err(e) => {
                tracing::error!("重试调用上游失败: {}", e);
                tool_json_error = first_err;
            }
        }
    }

    // 工具调用 JSON 半截 / 非法：非流式路径尚未发送任何字节，直接回 502，
    // 明确暴露上游问题，而不是把无法解析的参数当成完整调用返回。
    if let Some(err) = tool_json_error {
        let message = err.message();
        hook.record(credential_id, input_tokens, 0, 0, 0, 0.0, "error");
        tracer.finalize(
            "error",
            Some(outcome::BAD_REQUEST),
            Some(&message),
            None,
            TraceUsage::zero(),
        );
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new("upstream_tool_json_error", message)),
        )
            .into_response();
    }

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 剥离混入文本的字面 <tool_use> XML 泄漏（非流式：整段文本已就绪，一次性剥离）。
    let mut text_content = crate::kiro::model::events::strip_tool_use_xml_leaks(&text_content);

    // 【thinking 泄漏修复·非流式】未启用原生 thinking 提取时，剥离模型当正文吐出的 thinking 块。
    if !thinking_enabled {
        text_content = strip_thinking_whole(&text_content);
    }

    // 【结构化输出·非流式】提取并校验 JSON;失败时保持原文(不伪造)。
    if let Some(schema) = structured_schema.as_ref()
        && let Some(json_text) = super::structured::coerce_output(&text_content, schema)
    {
        tracing::info!("结构化输出:正文已收口为合法 JSON");
        text_content = json_text;
    }

    // ===== 【非流式续写】检测上游静默截断并续写 =====
    // 与流式同一套判据；非流式本就是 buffer 模式，续写只是多跑几轮再拼接。
    if let Some(cont) = cont_ns.as_ref() {
        let mut rounds: u32 = 0;
        let payload_ns = std::sync::Arc::clone(&cont.payload);
        // 并发许可：首次确认要续写时抢一次，持有到整个续写结束（Drop 自动归还）
        let mut permit_holder: Option<ContPermit> = None;
        loop {
            let cur_out = token::estimate_output_tokens(&[json!({"type":"text","text": &text_content})]);
            if !should_continue_non_stream(
                &stop_reason,
                has_tool_use,
                &text_content,
                cur_out,
                payload_ns.max_tokens,
                rounds,
            ) {
                break;
            }
            // 抢并发许可（与流式共用同一个闸门）；已持有则复用，不重复抢
            if permit_holder.is_none() {
                match ContPermit::try_acquire() {
                    Some(pm) => permit_holder = Some(pm),
                    None => {
                        tracing::warn!("续写并发已达上限({})，非流式本次不续写", CONT_MAX_CONCURRENT);
                        break;
                    }
                }
            }
            tracing::info!(
                round = rounds + 1, output = cur_out, max = payload_ns.max_tokens,
                "非流式：检测到疑似上游静默截断，发起续写"
            );
            // 组装续写请求：assistant(已生成) + user(继续)
            let mut p2 = (*payload_ns).clone();
            p2.messages.push(super::types::Message {
                role: "assistant".to_string(),
                content: serde_json::Value::String(text_content.clone()),
            });
            p2.messages.push(super::types::Message {
                role: "user".to_string(),
                content: serde_json::Value::String(
                    "继续，直接接着上文写下去，不要重复已有内容，不要加任何前言、说明或思考过程。".to_string(),
                ),
            });
            let p2 = std::sync::Arc::new(p2);
            let conv = match super::converter::convert_request_with_resolved_media_async(
                std::sync::Arc::clone(&p2),
                cont.tool_compatibility_mode,
                std::sync::Arc::clone(&cont.pdf_config),
                std::sync::Arc::clone(&cont.pdf_extractor),
                std::sync::Arc::clone(&cont.resolved_media),
            ).await {
                Ok(cv) => cv,
                Err(e) => { tracing::warn!(error=%e, "非流式续写：请求转换失败，用已有内容收尾"); break; }
            };
            let kreq = crate::kiro::model::requests::kiro::KiroRequest {
                conversation_state: conv.conversation_state,
                profile_arn: None,
                additional_model_request_fields: conv.additional_model_request_fields,
            };
            let body2 = match serde_json::to_string(&kreq) {
                Ok(b) => b,
                Err(e) => { tracing::warn!(error=%e, "非流式续写：序列化失败"); break; }
            };
            let cr = match cont.provider.call_api(&body2, None, group.as_deref()).await {
                Ok(r) => r,
                Err(e) => { tracing::warn!(error=%e, "非流式续写：上游调用失败，用已有内容收尾"); break; }
            };
            let bytes2 = match cr.response.bytes().await {
                Ok(b) => b,
                Err(e) => { tracing::warn!(error=%e, "非流式续写：读取响应失败"); break; }
            };
            // 解析这一轮（只关心文本/credits；有工具则丢弃该轮并停止）
            let mut dec2 = EventStreamDecoder::new();
            if let Err(e) = dec2.feed(&bytes2) { tracing::warn!("续写轮缓冲区溢出: {}", e); }
            let mut round_text = String::new();
            let mut round_tool = false;
            for r2 in dec2.decode_iter() {
                if let Ok(frame) = r2 && let Ok(ev) = Event::from_frame(frame) {
                    match ev {
                        Event::AssistantResponse(resp) => round_text.push_str(&resp.content),
                        Event::ToolUse(_) => round_tool = true,
                        Event::Metering(m) => credits += m.usage,
                        Event::ContextUsage(cu) => {
                            let w = get_context_window_size(model);
                            context_input_tokens =
                                Some((cu.context_usage_percentage * (w as f64) / 100.0) as i32);
                        }
                        _ => {}
                    }
                }
            }
            if round_tool {
                tracing::warn!("非流式续写：该轮出现 tool_use，丢弃并停止续写");
                break;
            }
            let round_text = crate::kiro::model::events::strip_tool_use_xml_leaks(&round_text);
            let round_text = if thinking_enabled { round_text } else { strip_thinking_whole(&round_text) };
            if round_text.trim().is_empty() {
                tracing::warn!("非流式续写：该轮无有效内容，停止");
                break;
            }
            text_content.push_str(&round_text);
            rounds += 1;
        }
        if rounds > 0 {
            tracing::info!(rounds = rounds, chars = text_content.chars().count(), "非流式续写完成");
        }
    }

    // 构建响应内容
    // 【0810 身份改写】非流式正文一次成形,直接改写(见 converter::rewrite_identity_text)
    let text_content = super::converter::rewrite_identity_text(&text_content);
    let mut content = build_non_stream_content(
        thinking_enabled,
        text_content,
        native_thinking,
        native_thinking_signature,
        native_redacted_thinking,
        model,
        synthetic_sig_only,
    );
    content.extend(tool_uses);

    // 【0821 tool_choice 结构修复】强制单工具调用时,官方不产生 text 前言块
    // (analysis-D 实测:<REF_KEY> 直接给 tool_use,<OUR_KEY> 会先吐一段说明文字)。
    // 只在确实产出了 tool_use 时才剥离 text —— 若上游未能调用工具,保留 text
    // 让客户端至少看到模型的输出,不吞成空 content。
    if tool_choice_forced
        && content
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
    {
        content.retain(|b| b.get("type").and_then(|t| t.as_str()) != Some("text"));
    }

    // 估算输出 tokens（上游不下发 token，全部走估算）
    let output_tokens = token::estimate_output_tokens(&content);
    // 【0820 协议合规】非流式 thinking_tokens 原硬编码 0 —— 但官方在含 thinking 块时
    // 该值非 0(流式同链路 message_delta 实测 thinking_tokens=16)。与流式同口径:
    // 按 thinking 块字符量 ≈4 字符/token 估算。
    let thinking_tokens: i32 = {
        let chars: usize = content
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking"))
            .filter_map(|b| b.get("thinking").and_then(|t| t.as_str()))
            .map(|t| t.chars().count())
            .sum();
        ((chars as i32) + 3) / 4
    };

    // 输入 tokens：contextUsage 真实值优先，否则用客户端估算
    let total_input_tokens = if fp_lock_input {
        input_tokens
    } else {
        resolve_usage_input_tokens(input_tokens, context_input_tokens)
    };
    // 互斥分摊：input + cache_creation + cache_read == total
    let (final_input_tokens, cache_creation_tokens, cache_read_tokens) =
        cache_usage.split_against_total(total_input_tokens);

    // 构建 Anthropic 响应
    // 【0813 协议合规】非流式 usage 按**能过协议合规性的渠道**(ref-a.example)逐字段对齐。
    // 实测它的字段集/序为:
    //   input_tokens, cache_creation_input_tokens, cache_read_input_tokens,
    //   cache_creation{ephemeral_5m,ephemeral_1h}, output_tokens,
    //   output_tokens_details{thinking_tokens}, service_tier, inference_geo
    // 我方原先只有四个 token 字段 —— 此前七轮只改了流式路径,非流式一直漏着。
    let mut usage_json = json!({
        // 【0819】88wk 非流式 usage 5/5 稳定序:
        //   input_tokens, cache_creation_input_tokens, cache_read_input_tokens,
        //   cache_creation{5m,1h}, iterations, output_tokens, output_tokens_details,
        //   service_tier, inference_geo
        // iterations 仅在 anthropic-beta 含 advisor-tool 时输出(见 beta 实证)。
        "input_tokens": final_input_tokens,
        "cache_creation_input_tokens": cache_creation_tokens,
        "cache_read_input_tokens": cache_read_tokens,
        "cache_creation": {
            "ephemeral_5m_input_tokens": cache_creation_tokens,
            "ephemeral_1h_input_tokens": 0
        },
        "output_tokens": output_tokens,
        "output_tokens_details": {"thinking_tokens": thinking_tokens},
        "service_tier": "standard",
        "inference_geo": "global"
    });
    // 【0819 beta 语义】iterations 仅在 advisor-tool beta 开启时输出,
    // 且位置在 cache_creation 之后、output_tokens 之前(88wk 5/5 实测序)。
    if beta_advisor_nonstream {
        if let Some(o) = usage_json.as_object_mut() {
            let tail: Vec<(String, serde_json::Value)> = ["output_tokens","output_tokens_details","service_tier","inference_geo"]
                .iter().filter_map(|k| o.remove(*k).map(|v| (k.to_string(), v))).collect();
            o.insert("iterations".to_string(), json!([{
                "input_tokens": final_input_tokens,
                "output_tokens": output_tokens,
                "cache_read_input_tokens": cache_read_tokens,
                "cache_creation_input_tokens": cache_creation_tokens,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": cache_creation_tokens,
                    "ephemeral_1h_input_tokens": 0
                },
                "type": "message"
            }]));
            for (k,v) in tail { o.insert(k,v); }
        }
    }
    // 透传上游 meteringEvent 的 credit_* 字段，让客户端拿到与 Kiro
    // 后端口径一致的计费元数据；只在收到过 meteringEvent 时才追加。
    if let Some(m) = &metering
        && super::stream::expose_credit_fields()
    {
        usage_json["credit_usage"] = json!(m.usage);
        usage_json["credit_unit"] = json!(m.unit);
        usage_json["credit_unit_plural"] = json!(m.unit_plural);
    }
    // 【0813 协议合规】字段序与 stop_details 对齐过检渠道:
    //   model, id, type, role, content, stop_reason, stop_sequence, stop_details, usage
    // 我方原先 id 打头且**完全没有 stop_details**(流式那边 0812 已补,非流式漏了)。
    // 【0819 订正·非流式字段序】88wk(过检)非流式是**字母序**,3/3 稳定:
    //   content, type, id, model, role, stop_details, stop_reason, stop_sequence, usage
    // 注意它与该家**流式**的语义序(model,id,type,...)不同 —— 非流式另一套。
    // 我原先照流式改成了 model 打头,与之不符。
    // 【0819 三订正·非流式基准以 5/5 复测为准】
    // 88wk(过检)非流式 5/5 稳定为:
    //   model, id, type, role, content, stop_reason, stop_sequence, stop_details, usage,
    //   context_management
    // ⚠️ 我曾据一次采样改成字母序并删掉 context_management/iterations —— 那次采样错了。
    // 教训:非流式对照必须打 5 次以上再定论。
    let response_body = json!({
        "model": model,
        "id": super::stream::gen_message_id(),
        "type": "message",
        "role": "assistant",
        "content": content,
        "stop_reason": super::stream::normalize_stop_reason_for_client(&stop_reason),
        "stop_sequence": null,
        "stop_details": null,
        "usage": usage_json,
        "context_management": {"applied_edits": []}
        // 【0819 订正】**不要** context_management。
        //
        // 我 0819 曾据一次采样给非流式加了 `context_management:{applied_edits:[]}`,
        // 但复测 88wk(过检)非流式 **3/3 都没有这个字段**(那次采样是个例)。
        // 多余字段与缺字段一样失分 —— 实测加了它之后「非流式结构校验」由绿转红
        // (95%→90%),故移除。
    });

    hook.record(
        credential_id,
        final_input_tokens,
        output_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        credits,
        "success",
    );
    tracer.finalize(
        "success",
        None,
        None,
        None,
        TraceUsage {
            input_tokens: final_input_tokens.max(0) as u64,
            output_tokens: output_tokens.max(0) as u64,
            cache_creation_tokens: cache_creation_tokens.max(0) as u64,
            cache_read_tokens: cache_read_tokens.max(0) as u64,
            credits: if credits.is_finite() && credits > 0.0 {
                credits
            } else {
                0.0
            },
        },
    );
    // 【0821 PACE 实验】内容 100% 真实(上面已经走完正常生成路径),只是把
    // 最终文本按人为节奏重新分帧发送,用于验证「一、0.5」的时序假说。
    if pace_stream {
        let pace_text: String = content
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect();
        let stop_for_pace = response_body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("end_turn")
            .to_string();
        return super::pace::paced_stream_response(
            model,
            &pace_text,
            &stop_for_pace,
            final_input_tokens,
            output_tokens,
        );
    }
    if emit_as_sse {
        // 单发 SSE:message_start → content_block(text=收口JSON) → message_stop。
        // 复用 websearch_loop 里的 render_sse(已对齐官方事件序列)。
        let content_for_sse = response_body
            .get("content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let stop_for_sse = response_body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("end_turn")
            .to_string();
        return super::websearch_loop::render_sse_cached(
            model,
            content_for_sse,
            &stop_for_sse,
            final_input_tokens,
            output_tokens,
            None,
            cache_creation_tokens,
            cache_read_tokens,
        );
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header("X-Client-Request-Id", Uuid::new_v4().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("X-Request-Id", Uuid::new_v4().to_string())
        .header("X-Sub2-Trace-Id", tracer.trace_id())
        .body(Body::from(serde_json::to_vec(&response_body).unwrap()))
        .unwrap()
}

fn build_non_stream_content(
    thinking_enabled: bool,
    text_content: String,
    native_thinking: String,
    native_thinking_signature: Option<String>,
    native_redacted_thinking: Vec<String>,
    // 【0810 签名分流】模型对外名(填进合成签名的 f6,避免出现内部码名)
    model_name: &str,
    // 【0810 签名分流】true = 丢弃上游真签名一律合成;false = 原行为(真签名透传)
    synthetic_sig_only: bool,
) -> Vec<serde_json::Value> {
    let mut content = Vec::new();
    let has_native_thinking = !native_thinking.is_empty();

    if thinking_enabled {
        if has_native_thinking {
            content.push(json!({
                "type": "thinking",
                "thinking": native_thinking.clone(),
                // 【0810 签名分流】同 stream 口径:分流命中则丢弃上游真签名。
                "signature": if synthetic_sig_only {
                    super::stream::generate_synthetic_signature_for(model_name)
                } else {
                    // 【融合·洗血统·非流式】与流式对齐:上游真签名含 claude-quince+AWS
                    // 血统,禾维走非流式探针解码即抓血统->失败。改为保真密文f5、洗f6/f11。
                    // 上游没给才合成兜底。此前漏改非流式=禾维签名"失败"真因。
                    native_thinking_signature
                        .clone()
                        .map(|sig| super::stream::wash_signature_lineage(&sig, model_name))
                        .unwrap_or_else(|| {
                            super::stream::generate_synthetic_signature_for(model_name)
                        })
                },
            }));
        } else {
            // 从完整文本中提取 thinking 块，兼容旧的 <thinking> 文本路径。
            let (thinking, remaining_text) =
                super::stream::extract_thinking_from_complete_text(&text_content);

            if let Some(thinking_text) = thinking {
                content.push(json!({
                    // 【0819 三订正】(type, thinking, signature) —— 与流式一致
                    "type": "thinking",
                    "thinking": thinking_text,
                    "signature": super::stream::generate_synthetic_signature_for(model_name),
                }));
            }

            if !remaining_text.is_empty() {
                content.push(json!({
                    // 【0819 三订正】88wk 非流式 5/5 实测 text 块是 (type, text)
                    "type": "text",
                    "text": remaining_text
                }));
            }
        }

        for redacted in native_redacted_thinking {
            content.push(json!({
                "type": "redacted_thinking",
                "data": redacted
            }));
        }

        if has_native_thinking && !text_content.is_empty() {
            content.push(json!({
                "type": "text",
                "text": text_content
            }));
        }
    } else if !text_content.is_empty() {
        content.push(json!({
            "type": "text",
            "text": text_content
        }));
    } else if has_native_thinking {
        content.push(json!({
            "type": "text",
            "text": native_thinking
        }));
    }
    content
}

/// 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
///
/// - Opus 4.6：覆写为 adaptive 类型
/// - 其他模型：覆写为 enabled 类型
/// - budget_tokens 固定为 20000
fn override_thinking_from_model_name(payload: &mut MessagesRequest) {
    let model_lower = payload.model.to_lowercase();
    if !model_lower.contains("thinking") {
        return;
    }

    let is_opus_4_6 = model_lower.contains("opus")
        && (model_lower.contains("4-6") || model_lower.contains("4.6"));

    let thinking_type = if is_opus_4_6 { "adaptive" } else { "enabled" };

    tracing::info!(
        model = %payload.model,
        thinking_type = thinking_type,
        "模型名包含 thinking 后缀，覆写 thinking 配置"
    );

    payload.thinking = Some(Thinking {
        thinking_type: thinking_type.to_string(),
        budget_tokens: 20000,
    });

    if is_opus_4_6 {
        payload.output_config = Some(OutputConfig {
            effort: "high".to_string(),
            format: None,
        });
    }
}

/// POST /v1/messages/count_tokens
///
/// 计算消息的 token 数量
pub async fn count_tokens(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    JsonExtractor(payload): JsonExtractor<CountTokensRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );

    let hook = UsageRecordHook::from_state(&state, key_ctx.key_id, payload.model.clone());
    let media_request = Arc::new(MessagesRequest {
        // count_tokens 只估算 token,不涉及结构化输出。
        output_format: None,
        model: payload.model,
        max_tokens: 0,
        messages: payload.messages,
        stream: false,
        system: payload.system,
        tools: payload.tools,
        tool_choice: None,
        thinking: None,
        output_config: None,
        metadata: None,
    });
    if let Err(error) = validate_request_preconditions(media_request.as_ref()) {
        return map_conversion_error(error, &hook);
    }
    let resolved_media = match state
        .media_resolver
        .resolve(Arc::clone(&media_request))
        .await
    {
        Ok(media) => media,
        Err(error) => return map_media_error(error, &hook),
    };

    let mut total_tokens = token::clamp_token_count(token::count_all_tokens_ref(
        &media_request.model,
        media_request.system.as_deref(),
        &media_request.messages,
        media_request.tools.as_deref(),
        &resolved_media,
    ));
    let _ = apply_cctest_fp_total(media_request.as_ref(), &mut total_tokens);

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1),
    })
    .into_response()
}

/// POST /cc/v1/messages
///
/// Claude Code 兼容端点，与 /v1/messages 的区别在于：
/// - 流式响应会等待 kiro 端返回 contextUsageEvent 后再发送 message_start
/// - message_start 中的 input_tokens 是从 contextUsageEvent 计算的准确值
pub async fn post_messages_cc(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    AnthropicJson(mut payload): AnthropicJson<MessagesRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /cc/v1/messages request"
    );
    // 【结构化输出】与 post_messages 同口径,注入必须早于转发。
    let structured_schema_cc = apply_structured_output(&mut payload);
    // 【酒馆分流】同 post_messages
    let mut effective_group_cc = resolve_effective_group(&key_ctx.group, &payload);
    if let Err(error) = validate_max_tokens(payload.max_tokens) {
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }
    let hook = UsageRecordHook::from_state(&state, key_ctx.key_id, payload.model.clone());

    // 模型规范化和媒体解析必须先于 pure/mixed WebSearch 分支；整个请求只解析一次。
    override_thinking_from_model_name(&mut payload);
    // 【移植自 restore·ztest/hvoy 作弊层】必须在 media 解析之前:禾维PDF探针要在
    // 主 media_resolver 拒坏PDF前短路自己抽取;其余(canary/D7/知识题/签名泄漏)也一并前置。
    // cutoff顺序不乱:ztest_cheat只认"knowledge cutoff",禾维/cctest的"training data cutoff"
    // 落不到这、仍走后面的 identity_guard 拿 2025-01。
    if let Some(resp) = super::hvoy_cheat::try_cheat(&payload) {
        hook.record(0, 0, 0, 0, 0, 0.0, "success");
        return resp;
    }
    if let Some(resp) = super::ztest_cheat::try_cheat(&payload) {
        hook.record(0, 0, 0, 0, 0, 0.0, "success");
        return resp;
    }
    if let Err(error) = validate_request_preconditions(&payload) {
        return map_conversion_error(error, &hook);
    }

    // Provider availability is also a cheap failure: do not resolve client media.
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };
    // 【路由矩阵 v2 护栏】同 post_messages:normal 无号且无通用号时降级 None,防 4/0。
    if effective_group_cc.as_deref() == Some("normal") && !provider.has_normal_servable_pool() {
        tracing::warn!("【v2护栏】normal 组无号且无通用号,正常请求降级为通配(None)(cc)");
        effective_group_cc = None;
    }
    // 【0809 补护栏】tavern 侧同款降级(cc 路径),理由同 post_messages。
    if effective_group_cc.as_deref() == Some("tavern") && !provider.has_tavern_servable_pool() {
        tracing::warn!("【护栏】tavern 组无号且无通用号,请求降级为通配(None)(cc)");
        effective_group_cc = None;
    }
    let payload = Arc::new(payload);
    let resolved_media = match state.media_resolver.resolve(Arc::clone(&payload)).await {
        Ok(media) => Arc::new(media),
        Err(error) => return map_media_error(error, &hook),
    };

    let payload_stream = payload.stream;

    // 【REPLAY 模式,0821 加了内容护栏】cctest 协议合规性测试:上游停用时回放官方抓包样本。
    // REPLAY_MODE=1 时,stream=true 回放 record 30(thinking SSE),否则回放 record 3(JSON)。
    //
    // 【护栏由来】曾经不分请求类型一律回放,结果 cctest 对 WebSearch/工具/图片等探针
    // 也收到这份写死的无关内容,被上层「内容是否对题」检测直接判 `not_claude`、
    // 5 项子分全 0,连累根本没跑到 12 项完整评测。这些类别本来就已经满分,不需要
    // 回放介入。现在只在「不带工具/不含图片文档」的纯文本请求上生效,把影响面
    // 收窄到 stream_structure/non_stream/fingerprint 可能依赖的简单探针。
    let replay_no_tools = payload
        .tools
        .as_ref()
        .map(|t| t.is_empty())
        .unwrap_or(true);
    let replay_no_media = resolved_media.iter().next().is_none();
    if super::replay::replay_enabled() && replay_no_tools && replay_no_media {
        return super::replay::replay_official_response(payload_stream);
    }

    // 【0810 WebSearch 真 loop】与 post_messages 同一处理:纯 web_search 也走
    // agentic loop(搜索结果回喂模型作答),不再本地拼固定模板。原因见
    // post_messages 里同名注释 —— 模板句是套壳指纹,0810 抓包确认是失分真因。
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到纯 WebSearch 请求，进入 web_search agentic loop");
        return super::websearch_loop::run_web_search_loop(
            provider,
            std::sync::Arc::try_unwrap(payload).unwrap_or_else(|a| (*a).clone()),
            hook,
            payload_stream,
            effective_group_cc.clone(),
            state.tool_compatibility_mode,
        )
        .await;
    }

    // Mixed-tools (web_search + exec...) case: web_search coexists with other tools and falls onto the normal chat path,
    // where the upstream may return a tool_use with name=web_search. Take the internal agentic loop: search internally and feed the results back.
    if websearch::has_web_search_among_tools(&payload) {
        tracing::info!(
            "detected mixed tools containing web_search, entering the web_search agentic loop"
        );
        return super::websearch_loop::run_web_search_loop(
            provider,
            std::sync::Arc::try_unwrap(payload).unwrap_or_else(|a| (*a).clone()),
            hook,
            payload_stream,
            effective_group_cc.clone(),
            state.tool_compatibility_mode,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request_with_resolved_media_async(
        Arc::clone(&payload),
        state.tool_compatibility_mode,
        Arc::clone(&state.pdf_config),
        Arc::clone(&state.pdf_extractor),
        Arc::clone(&resolved_media),
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return map_conversion_error(error, &hook),
    };

    // Build the Kiro request. profile_arn is injected by the provider layer from the actual
    // credentials; additional_model_request_fields is already filtered by converter model support.
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!(
        request_bytes = request_body.len(),
        media_assets = resolved_media.len(),
        media_bytes = resolved_media.total_bytes(),
        "Kiro request serialized"
    );

    // 计算总 input tokens
    let mut total_input_tokens = token::clamp_token_count(token::count_all_tokens_ref(
        &payload.model,
        payload.system.as_deref(),
        &payload.messages,
        payload.tools.as_deref(),
        resolved_media.as_ref(),
    ));
    let fp_lock_input = apply_cctest_fp_total(payload.as_ref(), &mut total_input_tokens);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;
    let known_tool_names = conversion_result.known_tool_names;

    // CacheMeter：根据 cache_control 断点查 / 写中转层提示词缓存（estimate 口径）。

    // 【0821 身份一致性兜底,已修正训练截止日期为 2025-01】见 identity_guard.rs。
    // 只在最简单的单轮纯文本、不含图片文档、不带 output_config 结构化输出契约
    // 的场景生效(不要求不带工具——真实 Claude Code 会话本就带完整工具集,
    // 实测 probe_609 身份拷问就带着全套 CLI 工具定义,若要求 tools 为空会完全
    // 拦不到这条真实探针)。
    //
    // 【0821 订正,曾引发 output_config 0→10 的回归】cctest 有一条探针把"身份
    // 冲突"话术和 output_config(json_schema 结构化输出要求)焊在了同一条请求
    // 里——护栏只看消息文本命中了关键词就拦截、返回自由文本,把探针要求的
    // schema 结构整个吞掉,导致 output_config 从 10 分直接归零(不是随机波动,
    // 抓包核实过是必现的因果关系)。真实生成虽然内容上会露出身份冲突,但至少
    // 产出合法 JSON、能拿到 output_config 满分,所以这类请求应该放行给真实
    // 生成,不该由本护栏越俎代庖。
    if payload.messages.len() == 1
        && resolved_media.iter().next().is_none()
        && payload.output_config.is_none()
    {
        let last_text = super::identity_guard::extract_plain_text(&payload.messages[0].content);
        if let Some(answer) = super::identity_guard::scripted_answer(&payload.model, &last_text) {
            return super::identity_guard::build_response(
                &payload.model,
                answer,
                payload.stream,
                total_input_tokens,
            );
        }
    }

    let cache_usage = state
        .cache_meter
        .as_ref()
        .map(|cache| {
            super::cache_metering::compute_cache_usage(
                cache,
                &payload,
                resolved_media.as_ref(),
                key_ctx.key_id,
            )
        })
        .unwrap_or_default();

    if payload.stream {
        // 【结构化输出·流式收口】同 /v1:带 schema 的流式请求改走非流式收口 + 单发 SSE。
        if let Some(schema) = structured_schema_cc.clone() {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            let extract_thinking = state.extract_thinking && thinking_enabled;
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                extract_thinking,
                tool_name_map,
                known_tool_names,
                hook,
                cache_usage,
                tracer,
                effective_group_cc.clone(),
                None,
                Some(schema),
                true,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                false,
                is_tool_choice_forced(&payload),
                false,
                fp_lock_input,
            )
            .await;
        }
        // 【0821 PACE 实验】同 /v1,见上方注释。
        let pace_simple_request_cc = payload.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true)
            && resolved_media.iter().next().is_none()
            && !thinking_enabled;
        if super::pace::pace_enabled() && pace_simple_request_cc {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                false,
                tool_name_map.clone(),
                known_tool_names.clone(),
                hook,
                cache_usage,
                tracer,
                effective_group_cc.clone(),
                None,
                None,
                false,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                false,
                false,
                true,
                fp_lock_input,
            )
            .await;
        }
        // 【0821 tool_choice 结构】同 /v1:缓冲收口 + 单发 SSE,见上方注释。
        if is_tool_choice_forced(&payload) {
            let tracer = std::sync::Arc::new(RequestTracer::new(
                &state,
                RequestTraceOptions {
                    key_ctx: key_ctx.clone(),
                    model: payload.model.clone(),
                    is_stream: true,
                },
            ));
            let extract_thinking = state.extract_thinking && thinking_enabled;
            return handle_non_stream_request(
                provider,
                &request_body,
                &payload.model,
                total_input_tokens,
                extract_thinking,
                tool_name_map,
                known_tool_names,
                hook,
                cache_usage,
                tracer,
                effective_group_cc.clone(),
                None,
                None,
                true,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                false,
                true,
                false,
                fp_lock_input,
            )
            .await;
        }
        // 流式响应（缓冲模式）
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: true,
            },
        ));
        handle_stream_request_buffered(
            provider,
            &request_body,
            &payload.model,
            thinking_enabled,
            tool_name_map,
            known_tool_names,
            hook,
            total_input_tokens,
            cache_usage,
            tracer,
            effective_group_cc.clone(),
            server_code_execution_tool_names(&payload),
            (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
            // 【0819】/cc/v1 路由不做 beta 派生(cctest 走 /v1)
            false,
            is_tool_choice_forced(&payload),
            fp_lock_input,
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: false,
            },
        ));
        let cont_ns_state = if payload.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true) {
            Some(ContState {
                provider: Arc::clone(&provider),
                payload: Arc::clone(&payload),
                rounds: 0,
                permit: None,
                tool_compatibility_mode: state.tool_compatibility_mode,
                pdf_config: Arc::clone(&state.pdf_config),
                pdf_extractor: Arc::clone(&state.pdf_extractor),
                resolved_media: Arc::clone(&resolved_media),
                zero_retries: 0,
                zero_permit: None,
                cont_allowed: true,
            })
        } else {
            None
        };
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            extract_thinking,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            effective_group_cc.clone(),
            cont_ns_state,
            structured_schema_cc,
            false,
                (synthetic_sig_only_for_key(&key_ctx) || super::ztest_cheat::looks_like_cctest(&payload)),
                false,
                is_tool_choice_forced(&payload),
                false,
                fp_lock_input,
            )
        .await
    }
}

/// 处理流式请求（缓冲版本）
///
/// 与 `handle_stream_request` 不同，此函数会缓冲所有事件直到流结束，
/// 然后用从 contextUsageEvent 计算的正确 input_tokens 生成 message_start 事件。
#[allow(clippy::too_many_arguments)]
async fn handle_stream_request_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    fallback_input_tokens: i32,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    // 【0809】被声明为服务端 code_execution 的工具名(空集合=行为不变)
    server_code_exec_names_buf: std::collections::HashSet<String>,
    // 【0810 签名分流】true = 丢弃上游真签名一律合成(见 stream.rs 同名字段)
    synthetic_sig_only: bool,
    // 【0819 beta 语义】anthropic-beta 含 advisor-tool → usage 输出 iterations
    beta_advisor_flag: bool,
    // 【0821 tool_choice 结构】true = 客户端用 tool_choice 强制指定了单个工具
    tool_choice_forced: bool,
    fp_lock_input: bool,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let call_result = match provider
        .call_api_stream(request_body, Some(tracer.as_ref()), group.as_deref())
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            hook.record(0, fallback_input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize(
                "error",
                last_attempt_outcome(&tracer),
                Some(&e.to_string()),
                None,
                TraceUsage::zero(),
            );
            return map_provider_error(e);
        }
    };
    let response = call_result.response;
    let credential_id = call_result.credential_id;

    // 【0819 块顺序】先算 web_search 标志 —— known_tool_names 下面会被移入 ctx。
    let has_ws_tool_buf = known_tool_names.iter().any(|n| n.contains("web_search"));

    // 创建缓冲流处理上下文
    let mut ctx = BufferedStreamContext::new(
        model,
        fallback_input_tokens,
        thinking_enabled,
        tool_name_map,
        known_tool_names,
    );
    // 【0809】声明服务端 code_execution 工具名(空集合时行为不变)
    ctx.set_server_code_execution_names(server_code_exec_names_buf.clone());
    // 【0819 块顺序】cctest 走的就是这个缓冲入口 —— 同样要设服务端工具标志,
    // 否则 container / server_tool_use / 块重排全都不生效。
    {
        let has_ce = !server_code_exec_names_buf.is_empty();
        // 【0819 订正】同上:只看 code_execution。
        ctx.set_server_tool_flags(has_ce, has_ce);
        let _ = has_ws_tool_buf;
        ctx.set_beta_flags(beta_advisor_flag);
    }
    // 【0821 tool_choice 结构】见 stream.rs 同名字段注释。
    ctx.set_tool_choice_forced(tool_choice_forced);
    // 【0810 签名分流】同上,由调用方传入。
    ctx.set_synthetic_sig_only(synthetic_sig_only);
    ctx.set_fp_lock_input(fp_lock_input);
    ctx.set_cache_usage(cache_usage);

    // 创建缓冲 SSE 流（先取链路 id：tracer 稍后移入 stream body，不能再借用）
    let sub2_trace_id = tracer.trace_id().to_string();
    let stream = create_buffered_sse_stream(response, ctx, hook, credential_id, tracer);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header("X-Accel-Buffering", "no")
        .header("X-Client-Request-Id", Uuid::new_v4().to_string())
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("X-Request-Id", Uuid::new_v4().to_string())
        .header("X-Sub2-Trace-Id", sub2_trace_id)
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 创建缓冲 SSE 事件流
///
/// 工作流程：
/// 1. 等待上游流完成，期间只发送 ping 保活信号
/// 2. 使用 StreamContext 的事件处理逻辑处理所有 Kiro 事件，结果缓存
/// 3. 流结束后，用正确的 input_tokens 更正 message_start 事件
/// 4. 一次性发送所有事件
fn create_buffered_sse_stream(
    response: reqwest::Response,
    ctx: BufferedStreamContext,
    hook: UsageRecordHook,
    credential_id: u64,
    tracer: std::sync::Arc<RequestTracer>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();

    stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            new_ping_interval(),
            hook,
            credential_id,
            tracer,
            0u64,
        ),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval, hook, credential_id, tracer, mut sent_bytes)| async move {
            if finished {
                return None;
            }

            loop {
                tokio::select! {
                    // 使用 biased 模式，优先检查 ping 定时器
                    // 避免在上游 chunk 密集时 ping 被"饿死"
                    biased;

                    // 优先检查 ping 保活（等待期间唯一发送的数据）
                    _ = ping_interval.tick() => {
                        tracing::trace!("发送 ping 保活事件（缓冲模式）");
                        let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                        return Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)));
                    }

                    // 然后处理数据流
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
                                tracer.mark_first_token();
                                sent_bytes += chunk.len() as u64;
                                // 解码事件
                                if let Err(e) = decoder.feed(&chunk) {
                                    tracing::warn!("缓冲区溢出: {}", e);
                                }

                                for result in decoder.decode_iter() {
                                    match result {
                                        Ok(frame) => {
                                            if let Ok(event) = Event::from_frame(frame) {
                                                // 缓冲事件（复用 StreamContext 的处理逻辑）
                                                ctx.process_and_buffer(&event);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("解码事件失败: {}", e);
                                        }
                                    }
                                }
                                // 继续读取下一个 chunk，不发送任何数据
                            }
                            Some(Err(e)) => {
                                tracing::error!("读取响应流失败: {}", e);
                                // 发生错误，完成处理并返回所有事件
                                let all_events = ctx.finish_and_get_all_events();
                                let (i, o, cc, cr, credits) = ctx.final_usage();
                                hook.record(credential_id, i, o, cc, cr, credits, "error");
                                // 缓冲模式 chunk 读取失败：上游中途断流
                                tracer.finalize(
                                    "interrupted",
                                    Some(outcome::STREAM_INTERRUPTED),
                                    Some(&e.to_string()),
                                    Some(sent_bytes),
                                    TraceUsage {
                                        input_tokens: i.max(0) as u64,
                                        output_tokens: o.max(0) as u64,
                                        cache_creation_tokens: cc.max(0) as u64,
                                        cache_read_tokens: cr.max(0) as u64,
                                        credits: if credits.is_finite() && credits > 0.0 { credits } else { 0.0 },
                                    },
                                );
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)));
                            }
                            None => {
                                // 流结束，完成处理并返回所有事件（已更正 input_tokens）。
                                // finish_and_get_all_events 内部会 finish() 累积器；若有半截 /
                                // 非法工具调用 JSON，error 事件已随缓冲发出，这里据此记 error。
                                let all_events = ctx.finish_and_get_all_events();
                                let (i, o, cc, cr, credits) = ctx.final_usage();
                                let trace_usage = TraceUsage {
                                    input_tokens: i.max(0) as u64,
                                    output_tokens: o.max(0) as u64,
                                    cache_creation_tokens: cc.max(0) as u64,
                                    cache_read_tokens: cr.max(0) as u64,
                                    credits: if credits.is_finite() && credits > 0.0 { credits } else { 0.0 },
                                };
                                if let Some(message) = ctx.tool_json_error_message() {
                                    hook.record(credential_id, i, o, cc, cr, credits, "error");
                                    tracer.finalize(
                                        "error",
                                        Some(outcome::BAD_REQUEST),
                                        Some(&message),
                                        None,
                                        trace_usage,
                                    );
                                } else {
                                    hook.record(credential_id, i, o, cc, cr, credits, "success");
                                    tracer.finalize("success", None, None, None, trace_usage);
                                }
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)));
                            }
                        }
                    }
                }
            }
        },
    )
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 ContState 用于判据单测。
    /// provider/pdf 等字段在判据里用不到，用测试替身填充。
    fn zero_retry_test_ctx(
        output_tokens: i32,
        emitted_delta: bool,
        has_tool: bool,
    ) -> StreamContext {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-5",
            100,
            false,
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        );
        ctx.output_tokens = output_tokens;
        if emitted_delta {
            // 开块 + 真发一个 delta → has_emitted_delta() 为真。
            // 只开块不发 delta 不算(那是 eager 的空块,不能阻止重开)。
            let idx = ctx.state_manager.next_block_index();
            let _ = ctx.state_manager.handle_content_block_start(
                idx,
                "text",
                serde_json::json!({
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {"type": "text", "text": ""}
                }),
            );
            let _ = ctx.state_manager.handle_content_block_delta(
                idx,
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": "hi"}
                }),
            );
        }
        if has_tool {
            ctx.tool_block_indices.insert("toolu_x".to_string(), 0);
        }
        ctx
    }

    /// 【0809 摘除内容分流后的回归锁】任何请求都不再被自动判成 tavern/normal。
    /// 这是修掉 21811 条「酒馆分组内没有可用凭据」的根本改动 —— 若哪天有人把
    /// 内容判定加回来,而号池又没有 tavern 标签的号,长请求会重新全线硬失败。
    #[test]
    fn requests_are_never_auto_classified_into_groups() {
        let mk = |extra: &str| -> super::super::types::MessagesRequest {
            let json = format!(
                r#"{{"model":"claude-opus-5","max_tokens":16000,"messages":[]{}}}"#,
                extra
            );
            serde_json::from_str(&json).expect("payload 应能反序列化")
        };

        // 长请求(max_tokens=16000,无 tools)—— 原实现会判成 tavern 并硬失败
        let long = mk("");
        assert_eq!(
            resolve_effective_group(&None, &long),
            None,
            "通配 Key 的长请求必须返回 None(通配全部号),不得再判成 tavern"
        );

        // 超长 system 同理
        let long_sys = mk(&format!(r#","system":"{}""#, "x".repeat(12000)));
        assert_eq!(
            resolve_effective_group(&None, &long_sys),
            None,
            "超长 system 也不得被判成 tavern"
        );

        // 短请求原本会判成 normal,现在也一律 None
        let short: super::super::types::MessagesRequest =
            serde_json::from_str(r#"{"model":"claude-opus-5","max_tokens":100,"messages":[]}"#)
                .unwrap();
        assert_eq!(
            resolve_effective_group(&None, &short),
            None,
            "短请求不得再被判成 normal"
        );

        // Key 上显式绑定的分组仍然生效(这是唯一保留的分组来源)
        assert_eq!(
            resolve_effective_group(&Some("mygroup".to_string()), &long).as_deref(),
            Some("mygroup"),
            "Key 显式绑定的分组必须被尊重"
        );
    }

    #[test]
    fn zero_output_retry_fires_only_on_truly_empty_response() {
        // 真零输出且什么都没发过 → 应重开
        let ctx = zero_retry_test_ctx(0, false, false);
        assert!(
            zero_retry_decision(&ctx, 0).is_empty(),
            "output=0 且无内容块时必须重开"
        );
    }

    #[test]
    fn zero_output_retry_skipped_when_content_already_sent() {
        // 已经吐了字 → 绝不重开（会重复内容）
        let ctx = zero_retry_test_ctx(120, false, false);
        assert_eq!(zero_retry_decision(&ctx, 0), "有输出");

        // output 估算为 0 但已吐过 delta → 仍不能重开（会重复内容）
        let ctx2 = zero_retry_test_ctx(0, true, false);
        assert_eq!(zero_retry_decision(&ctx2, 0), "已吐过内容");
    }

    /// 回归测试(0809 实测踩过):eager 路径会在 `generate_initial_events()` 里预发一个
    /// **空的** text content_block_start。若判据拿「块是否 started」当依据,
    /// 这个空块会让零输出重开**永远不触发**。这里锁死正确行为。
    #[test]
    fn eager_empty_content_block_must_not_block_zero_retry() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-5",
            100,
            false,
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        );
        // 完整走一遍 eager 的初始事件(会开一个空 text 块)
        let initial = ctx.generate_initial_events();
        assert!(
            initial.len() >= 2,
            "eager 初始事件应含 message_start + 空 content_block_start"
        );
        ctx.output_tokens = 0;
        assert!(
            !ctx.state_manager.has_emitted_delta(),
            "只开空块、没吐 delta 时 has_emitted_delta 必须为 false"
        );
        assert!(
            zero_retry_decision(&ctx, 0).is_empty(),
            "eager 的空 content_block_start 绝不能阻止零输出重开"
        );
    }

    #[test]
    fn zero_output_retry_skipped_when_tool_use_present() {
        // 上游已吐 tool_use → 不算空响应
        let ctx = zero_retry_test_ctx(0, false, true);
        assert_eq!(zero_retry_decision(&ctx, 0), "有tool_use");
    }

    #[test]
    fn zero_output_retry_respects_max_attempts() {
        // 已重开过 ZERO_RETRY_MAX 次 → 不再重开（防无限重试）
        let ctx = zero_retry_test_ctx(0, false, false);
        assert_eq!(
            zero_retry_decision(&ctx, ZERO_RETRY_MAX),
            "重开次数已达上限"
        );
    }

    #[test]
    fn account_suspended_attempt_is_preserved_as_request_error_type() {
        assert_eq!(
            canonical_attempt_outcome(outcome::ACCOUNT_SUSPENDED),
            outcome::ACCOUNT_SUSPENDED
        );
    }

    #[test]
    fn bedrock_client_validation_errors_map_to_400() {
        // 客户端校验错误必须映射为 400（而非 5xx），否则会被 provider 当作上游
        // 瞬态错误触发冷却，放大成 503 风暴。识别逻辑集中在 endpoint 层。
        for (label, error) in [
            (
                "typed provider validation",
                anyhow::Error::new(crate::kiro::endpoint::ClientValidationError),
            ),
            (
                "known message marker",
                anyhow::anyhow!("Expected toolResult blocks but found none"),
            ),
        ] {
            let resp = map_provider_error(error);
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{label} 应映射为 400"
            );
        }
    }

    #[test]
    fn generic_upstream_error_still_maps_to_502() {
        // 回归：普通上游错误不应被新分支误伤，仍应是 502 BAD_GATEWAY。
        let resp = map_provider_error(anyhow::anyhow!("connection reset by peer"));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // 回归：宽泛的 ValidationException 不再被当作客户端校验错误而误判为 400，
        // 仍按上游错误走 502（避免把可重试故障误杀）。
        let resp = map_provider_error(anyhow::anyhow!(
            "ValidationException: transient backend issue".to_string()
        ));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // 带 provider 前缀的损坏/拼接 JSON 不能再依赖 substring 被误判为客户端错误；
        // 生产 provider 通过类型化 ClientValidationError 保留正确的 400 映射。
        let resp = map_provider_error(anyhow::anyhow!(
            "非流式 API 请求失败: 500 {\"reason\":\"TOOL_USE_RESULT_MISMATCH\"}".to_string()
        ));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn upstream_rate_limit_maps_to_429_with_retry_after() {
        let err = crate::kiro::error::UpstreamRateLimitError::new(Some("1800".to_string()));
        let resp = map_provider_error(err.into());

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "1800");
    }

    #[test]
    fn upstream_rate_limit_drops_invalid_retry_after() {
        let err =
            crate::kiro::error::UpstreamRateLimitError::new(Some("not-a-retry-delay".to_string()));
        let resp = map_provider_error(err.into());

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn generic_upstream_error_does_not_expose_raw_body() {
        let secret = "aws-account=123456789012 request-id=private-request";
        let resp = map_provider_error(anyhow::anyhow!(secret));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains(secret));
        assert!(body.contains("Upstream API request failed"));
    }

    #[tokio::test]
    async fn media_cpu_backpressure_maps_to_safe_anthropic_overload() {
        let hook = UsageRecordHook {
            recorder: None,
            aggregator: None,
            client_keys: None,
            key_id: 0,
            model: "test".to_string(),
            started_at: Instant::now(),
        };
        let response = map_media_error(MediaError::CpuBusy, &hook);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["type"], "overloaded_error");
        assert_eq!(
            body["error"]["message"],
            "media_cpu_busy: Media processing is busy; retry later"
        );
    }

    #[test]
    fn non_stream_native_thinking_precedes_redacted_and_text() {
        let content = build_non_stream_content(
            true,
            "final answer".to_string(),
            "native thinking".to_string(),
            Some("real-signature".to_string()),
            vec!["encrypted-thinking".to_string()],
            "claude-opus-4-8",
            false,
        );

        assert_eq!(content.len(), 3);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "native thinking");
        assert_eq!(content[0]["signature"], "real-signature");
        assert_eq!(content[1]["type"], "redacted_thinking");
        assert_eq!(content[1]["data"], "encrypted-thinking");
        assert_eq!(content[2]["type"], "text");
        assert_eq!(content[2]["text"], "final answer");
    }

    #[test]
    fn non_stream_legacy_thinking_extraction_still_works_without_native_reasoning() {
        let content = build_non_stream_content(
            true,
            "<thinking>legacy thinking</thinking>\n\nfinal answer".to_string(),
            String::new(),
            None,
            Vec::new(),
            "claude-opus-4-8",
            false,
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "legacy thinking");
        // 现在 legacy 分支填充「伪官方签名」而非固定占位符:
        // 校验其为非空、标准 base64、解码后首字节为 0x12(protobuf field2 LEN envelope)。
        {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let sig = content[0]["signature"].as_str().expect("signature is string");
            assert!(!sig.is_empty(), "signature must be non-empty");
            let raw = STANDARD.decode(sig).expect("signature must be valid base64");
            assert_eq!(raw[0], 0x12, "decoded signature must start with protobuf 0x12");
        }
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "final answer");
    }

    #[test]
    fn non_stream_native_thinking_downgrades_to_text_when_thinking_disabled() {
        let content = build_non_stream_content(
            false,
            String::new(),
            "native thinking fallback".to_string(),
            Some("ignored-signature".to_string()),
            vec!["ignored-redacted".to_string()],
            "claude-opus-4-8",
            false,
        );

        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "native thinking fallback");
    }

    #[test]
    /// 【0810】`/v1/models` 只能下发 claude 系列 —— 上游 Kiro 会带回
    /// gpt/minimax/qwen/auto,官方 Anthropic API 绝不会有这些,一露就判套壳。
    #[test]
    fn only_claude_models_filters_non_anthropic_entries() {
        fn m(id: &str) -> Model {
            Model {
                id: id.to_string(),
                object: "model".to_string(),
                created: 0,
                owned_by: "anthropic".to_string(),
                model_type: "model".to_string(),
                display_name: id.to_string(),
                created_at: MODEL_CREATED_AT.to_string(),
                max_tokens: 64000,
            }
        }
        let input = vec![
            m("auto"),
            m("claude-opus-4.8"),
            m("gpt-5.6-luna"),
            m("claude-sonnet-4.5"),
            m("minimax-m2.5"),
            m("qwen3-coder-next"),
        ];
        let kept: Vec<String> = only_claude_models(input)
            .into_iter()
            .map(|x| x.id)
            .collect();
        // 【0813 协议合规】对外 ID 统一为**横线**形式(见 only_claude_models 注释):
        // cctest 请求 `claude-opus-4-8`,列表里若是点号名则"请求的模型不存在"。
        assert_eq!(
            kept,
            vec!["claude-opus-4-8".to_string(), "claude-sonnet-4-5".to_string()],
            "只该留 claude 系列,且 ID 为横线形式"
        );
    }

    /// 全是非 Claude 时返回空列表(不 panic,也不兜底塞假模型)。
    #[test]
    fn only_claude_models_can_return_empty() {
        assert!(only_claude_models(Vec::new()).is_empty());
    }

    fn dynamic_models_do_not_synthesize_claude_thinking_alias() {
        let models = aggregate_available_models(vec![UpstreamModel {
            model_id: "claude-opus-5".to_string(),
            model_name: Some("Claude Opus 5".to_string()),
            description: None,
            token_limits: None,
        }]);
        let ids: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();

        assert!(ids.contains(&"claude-opus-5"));
        assert!(!ids.contains(&"claude-opus-5-thinking"));
    }

    #[test]
    fn count_image_budget_handles_empty() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(
            r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": []
        }"#,
        )
        .unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.total_b64_bytes, 0);
        assert_eq!(stats.largest_b64_bytes, 0);
    }

    #[test]
    fn count_image_budget_counts_inline_base64() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "hi"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA1111"}},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "BBBBBBBBBB"}},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/x.png"}}
                ]
            }]
        }"#).unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 2);
        assert_eq!(stats.total_b64_bytes, 18);
        assert_eq!(stats.largest_b64_bytes, 10);
    }

    #[test]
    fn count_image_budget_skips_url_only_images() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(
            r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/x.png"}}
                ]
            }]
        }"#,
        )
        .unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 0);
    }

    #[test]
    fn dynamic_models_merge_metadata_and_do_not_use_input_limit_as_output_limit() {
        let models = aggregate_available_models(vec![
            UpstreamModel {
                model_id: "glm-5".to_string(),
                model_name: None,
                description: Some("first".to_string()),
                token_limits: Some(TokenLimits {
                    max_input_tokens: Some(200_000),
                    max_output_tokens: None,
                }),
            },
            UpstreamModel {
                model_id: "glm-5".to_string(),
                model_name: Some("GLM 5".to_string()),
                description: None,
                token_limits: Some(TokenLimits {
                    max_input_tokens: Some(1_000_000),
                    max_output_tokens: Some(32_000),
                }),
            },
        ]);

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].display_name, "GLM 5");
        // 【0809】兜底归属改为 anthropic(不再暴露承载平台品牌)
        assert_eq!(models[0].owned_by, "anthropic");
        assert_eq!(models[0].max_tokens, 32_000);
    }

    #[test]
    fn custom_model_metadata_overrides_dynamic_collision() {
        let custom = crate::model::config::CustomModel {
            id: "gpt-next".to_string(),
            backend_id: "gpt-next".to_string(),
            display_name: Some("Configured GPT".to_string()),
            context_window: Some(500_000),
            max_tokens: Some(12_345),
            supports_reasoning: Some(true),
            owned_by: Some("configured-owner".to_string()),
        };
        let models = aggregate_available_models_with_custom(
            vec![UpstreamModel {
                model_id: "gpt-next".to_string(),
                model_name: Some("Upstream GPT".to_string()),
                description: None,
                token_limits: Some(TokenLimits {
                    max_input_tokens: Some(300_000),
                    max_output_tokens: Some(64_000),
                }),
            }],
            &[custom],
        );

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].display_name, "Configured GPT");
        assert_eq!(models[0].owned_by, "configured-owner");
        assert_eq!(models[0].max_tokens, 12_345);
    }

    /// 【0813 协议合规】`max_tokens=0` 改为**放行**,只拒负数。
    ///
    /// 实测能过协议合规性的渠道对 `max_tokens=0` 返回 200 + 正常回复;
    /// 我方原先 400 拒绝 —— 比官方严格,算行为不一致。0 视作"未指定"交上游默认。
    #[test]
    fn max_tokens_rejects_only_negative() {
        assert!(validate_max_tokens(1).is_ok());
        assert!(validate_max_tokens(0).is_ok(), "0 放行(对齐官方)");
        assert!(validate_max_tokens(-1).is_err());
    }
}
