//! Anthropic API Handler 函数

use std::collections::HashMap;
use std::convert::Infallible;

use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::token;
use anyhow::Error;
use axum::{
    Json as JsonExtractor,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::interval;
use uuid::Uuid;

use super::cache;
use super::cache::CacheProfile;
use super::converter::{
    ConversionError, convert_request_with_mappings, get_context_window_size_with_mappings,
};
use super::identity_guard;
use super::middleware::AppState;
use super::multimodal::normalize_multimodal_sources;
use super::stream::normalize_tool_use_id;
use super::stream::{BufferedStreamContext, SseEvent, StreamContext};
use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking,
};
use super::websearch;

fn consumed_tokens(input_tokens: i32, output_tokens: i32) -> u64 {
    input_tokens.max(0) as u64 + output_tokens.max(0) as u64
}

fn structured_output_requested(payload: &MessagesRequest) -> bool {
    payload
        .output_config
        .as_ref()
        .and_then(|config| config.format.as_ref())
        .and_then(|format| {
            format
                .get("type")
                .and_then(serde_json::Value::as_str)
                .or_else(|| format.as_str())
        })
        .is_some_and(|format_type| matches!(format_type, "json_schema" | "json_object"))
}

/// Keep non-stream structured responses parseable if the model adds Markdown
/// fences or a short lead-in sentence despite the injected output constraint.
fn normalize_structured_output_text(text: &str) -> String {
    let trimmed = text.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```JSON"))
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|value| value.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);

    if serde_json::from_str::<serde_json::Value>(unfenced).is_ok() {
        return unfenced.to_string();
    }

    for (open, close) in [(b'{', b'}'), (b'[', b']')] {
        let Some(start) = unfenced.as_bytes().iter().position(|byte| *byte == open) else {
            continue;
        };
        let Some(end) = unfenced.as_bytes().iter().rposition(|byte| *byte == close) else {
            continue;
        };
        if start <= end {
            let candidate = &unfenced[start..=end];
            if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
                return candidate.to_string();
            }
        }
    }

    tracing::warn!("结构化输出未生成可解析 JSON，保留上游原文");
    text.to_string()
}

/// Normalize text deltas after a buffered stream completes. Structured output
/// must remain valid when the upstream model emits fences or a short preface.
fn normalize_structured_output_events(events: &mut [SseEvent]) {
    let mut text_by_index: HashMap<i64, String> = HashMap::new();
    for event in events.iter() {
        if event.event != "content_block_delta" || event.data["delta"]["type"] != "text_delta" {
            continue;
        }
        let Some(index) = event.data["index"].as_i64() else {
            continue;
        };
        let Some(text) = event.data["delta"]["text"].as_str() else {
            continue;
        };
        text_by_index.entry(index).or_default().push_str(text);
    }

    for (index, text) in text_by_index {
        let normalized = normalize_structured_output_text(&text);
        let mut emitted = false;
        for event in events.iter_mut() {
            if event.event != "content_block_delta"
                || event.data["delta"]["type"] != "text_delta"
                || event.data["index"].as_i64() != Some(index)
            {
                continue;
            }
            event.data["delta"]["text"] = if emitted {
                serde_json::Value::String(String::new())
            } else {
                emitted = true;
                serde_json::Value::String(normalized.clone())
            };
        }
    }
}

/// 将 KiroProvider 错误映射为 HTTP 响应
fn map_provider_error(err: Error) -> Response {
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
    tracing::error!("Kiro API 调用失败: {}", err);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(
            "api_error",
            format!("上游 API 调用失败: {}", err),
        )),
    )
        .into_response()
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models(State(state): State<AppState>) -> impl IntoResponse {
    tracing::info!("Received GET /v1/models request");
    let model_mappings = state.model_mappings.read().clone();
    Json(ModelsResponse {
        object: "list".to_string(),
        data: list_models_with_mappings(&model_mappings),
    })
}

pub fn list_models_with_mappings(model_mappings: &HashMap<String, String>) -> Vec<Model> {
    let mut models = vec![
        Model {
            id: "claude-sonnet-4-6".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929-thinking".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-8".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-4-8-thinking".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-4-7".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-7-thinking".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101-thinking".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001-thinking".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
    ];

    for model_id in model_mappings.keys() {
        if !models
            .iter()
            .any(|model| model.id.eq_ignore_ascii_case(model_id))
        {
            models.push(Model {
                id: model_id.clone(),
                object: "model".to_string(),
                created: 0,
                owned_by: "custom".to_string(),
                display_name: model_id.clone(),
                model_type: "chat".to_string(),
                max_tokens: 128_000,
            });
        }
    }

    models
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    let stream = payload
        .stream
        .unwrap_or_else(|| state.default_stream.load(Ordering::Relaxed));
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %stream,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages request"
    );
    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
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
    let protection_ttl = provider.cache_account_protection_duration();

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);

    if identity_guard::enabled() {
        identity_guard::inject_identity_prompt(&mut payload);
        let input_tokens = token::count_billable_input_tokens(
            payload.model.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;
        if let Some(response) = identity_guard::scripted_response(&payload, stream, input_tokens) {
            return response;
        }
    }

    if let Err(e) = normalize_multimodal_sources(&mut payload).await {
        tracing::warn!("多模态请求归一化失败: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("invalid_request_error", e.to_string())),
        )
            .into_response();
    }

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_billable_input_tokens(
            payload.model.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        return websearch::handle_websearch_request(provider, &payload, input_tokens).await;
    }

    let model_mappings = state.model_mappings.read().clone();

    // 转换请求
    let conversion_result = match convert_request_with_mappings(&payload, &model_mappings) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 构建 Kiro 请求（profile_arn 由 provider 层根据实际凭据注入）
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
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

    tracing::debug!("Kiro request body: {}", request_body);

    // 估算输入 tokens
    let input_tokens = token::count_billable_input_tokens(
        payload.model.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;
    let cache_profile = cache::build_profile(&payload, input_tokens);
    let preferred_account_ids = cache::preferred_account_ids(cache_profile.as_ref());
    let reserved_account_ids = cache::active_account_ids(protection_ttl);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;
    let structured_output = structured_output_requested(&payload);

    if stream {
        // 结构化输出需要等完整响应后归一化，普通流式请求保持实时返回。
        if structured_output {
            handle_stream_request_buffered(
                provider,
                &request_body,
                &payload.model,
                input_tokens,
                thinking_enabled,
                structured_output,
                tool_name_map,
                cache_profile,
                preferred_account_ids,
                reserved_account_ids,
                get_context_window_size_with_mappings(&payload.model, &model_mappings),
            )
            .await
        } else {
            handle_stream_request(
                provider,
                &request_body,
                &payload.model,
                input_tokens,
                thinking_enabled,
                tool_name_map,
                cache_profile,
                preferred_account_ids,
                reserved_account_ids,
                get_context_window_size_with_mappings(&payload.model, &model_mappings),
            )
            .await
        }
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking.load(Ordering::Relaxed) && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            payload.max_tokens,
            input_tokens,
            extract_thinking,
            structured_output,
            tool_name_map,
            cache_profile,
            payload.stop_sequences.clone(),
            preferred_account_ids,
            reserved_account_ids,
            get_context_window_size_with_mappings(&payload.model, &model_mappings),
        )
        .await
    }
}

/// 处理流式请求
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    cache_profile: Option<CacheProfile>,
    preferred_account_ids: Vec<String>,
    reserved_account_ids: Vec<String>,
    context_window_size: i32,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let (response, account_id, request_lease) = match provider
        .call_api_stream_with_account_and_cache_accounts(
            request_body,
            &preferred_account_ids,
            &reserved_account_ids,
        )
        .await
    {
        Ok(result) => result,
        Err(e) => return map_provider_error(e),
    };
    let cache_usage = cache::compute(&account_id, cache_profile.as_ref());

    // 创建流处理上下文
    let mut ctx = StreamContext::new_with_thinking(
        model,
        input_tokens,
        thinking_enabled,
        tool_name_map,
        cache_usage,
    );
    ctx.set_context_window_size(context_window_size);

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 创建 SSE 流
    let stream = create_sse_stream(
        provider,
        response,
        ctx,
        initial_events,
        account_id,
        cache_profile,
        request_lease,
    );

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
const PING_INTERVAL_SECS: u64 = 25;

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

/// 创建 SSE 事件流
fn create_sse_stream(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
    account_id: String,
    cache_profile: Option<CacheProfile>,
    request_lease: crate::kiro::token_manager::RequestLease,
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
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            interval(Duration::from_secs(PING_INTERVAL_SECS)),
            provider,
            account_id,
            cache_profile,
            request_lease,
        ),
        |(
            mut body_stream,
            mut ctx,
            mut decoder,
            finished,
            mut ping_interval,
            provider,
            account_id,
            cache_profile,
            request_lease,
        )| async move {
            if finished {
                return None;
            }

            // 使用 select! 同时等待数据和 ping 定时器
            tokio::select! {
                // 处理数据流
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
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

                            Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, provider, account_id, cache_profile, request_lease)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            let (input_tokens, output_tokens) = ctx.token_totals();
                            provider.record_token_usage_for_account(
                                &account_id,
                                consumed_tokens(input_tokens, output_tokens),
                            );
                            // 发送最终事件并结束
                            let final_events = ctx.generate_final_events();
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, provider, account_id, cache_profile, request_lease)))
                        }
                        None => {
                            let (input_tokens, output_tokens) = ctx.token_totals();
                            provider.record_token_usage_for_account(
                                &account_id,
                                consumed_tokens(input_tokens, output_tokens),
                            );
                            // 流结束，发送最终事件
                            let final_events = ctx.generate_final_events();
                            cache::update(&account_id, cache_profile.as_ref());
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, provider, account_id, cache_profile, request_lease)))
                        }
                    }
                }
                // 发送 ping 保活
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                    Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, provider, account_id, cache_profile, request_lease)))
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}

/// 处理非流式请求
async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    max_tokens: i32,
    input_tokens: i32,
    thinking_enabled: bool,
    structured_output: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    cache_profile: Option<CacheProfile>,
    stop_sequences: Option<Vec<String>>,
    preferred_account_ids: Vec<String>,
    reserved_account_ids: Vec<String>,
    context_window_size: i32,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let (response, account_id, _request_lease) = match provider
        .call_api_with_account_and_cache_accounts(
            request_body,
            &preferred_account_ids,
            &reserved_account_ids,
        )
        .await
    {
        Ok(result) => result,
        Err(e) => return map_provider_error(e),
    };
    let cache_usage = cache::compute(&account_id, cache_profile.as_ref());

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("读取响应体失败: {}", e);
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
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    let mut stop_sequence: Option<String> = None;
    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(tool_use.tool_use_id.clone())
                                .or_insert_with(String::new);
                            buffer.push_str(&tool_use.input);

                            // 如果是完整的工具调用，添加到列表
                            if tool_use.stop {
                                let input: serde_json::Value = if buffer.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::from_str(buffer).unwrap_or_else(|e| {
                                        tracing::warn!(
                                            "工具输入 JSON 解析失败: {}, tool_use_id: {}",
                                            e,
                                            tool_use.tool_use_id
                                        );
                                        serde_json::json!({})
                                    })
                                };

                                let original_name = tool_name_map
                                    .get(&tool_use.name)
                                    .cloned()
                                    .unwrap_or_else(|| tool_use.name.clone());
                                let tool_use_id = normalize_tool_use_id(&tool_use.tool_use_id);

                                tool_uses.push(json!({
                                    "type": "tool_use",
                                    "id": tool_use_id,
                                    "name": original_name,
                                    "input": input
                                }));
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 从上下文使用百分比计算实际的 input_tokens
                            let window_size = context_window_size;
                            let actual_input_tokens =
                                (context_usage.context_usage_percentage * (window_size as f64)
                                    / 100.0) as i32;
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

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 构建响应内容
    let response_id = format!("msg_{}", Uuid::new_v4().to_string().replace('-', ""));
    let mut content: Vec<serde_json::Value> = Vec::new();

    if thinking_enabled {
        // 从完整文本中提取 thinking 块
        let (thinking, mut remaining_text) =
            super::stream::extract_thinking_from_complete_text(&text_content);

        if stop_reason == "end_turn" {
            if let Some(matched) =
                apply_stop_sequences(&mut remaining_text, stop_sequences.as_deref())
            {
                stop_reason = "stop_sequence".to_string();
                stop_sequence = Some(matched);
            }
        }

        if let Some(thinking_text) = thinking {
            let thinking_index = content.len() as i32;
            let signature = super::stream::create_thinking_signature(
                &response_id,
                model,
                thinking_index,
                &thinking_text,
            );
            content.push(json!({
                "type": "thinking",
                "thinking": thinking_text,
                "signature": signature
            }));
        }

        if !remaining_text.is_empty() {
            if structured_output && stop_reason == "end_turn" {
                remaining_text = normalize_structured_output_text(&remaining_text);
            }
            content.push(json!({
                "type": "text",
                "text": remaining_text
            }));
        }
    } else if !text_content.is_empty() {
        if stop_reason == "end_turn" {
            if let Some(matched) =
                apply_stop_sequences(&mut text_content, stop_sequences.as_deref())
            {
                stop_reason = "stop_sequence".to_string();
                stop_sequence = Some(matched);
            }
        }
        if structured_output && stop_reason == "end_turn" {
            text_content = normalize_structured_output_text(&text_content);
        }
        content.push(json!({
            "type": "text",
            "text": text_content
        }));
    }

    content.extend(tool_uses);

    // 估算输出 tokens
    let mut output_tokens = token::estimate_output_tokens(&content);
    if stop_reason == "end_turn"
        && output_tokens > 0
        && (output_tokens >= max_tokens.max(1) || max_tokens <= 5)
    {
        output_tokens = max_tokens.max(1);
        stop_reason = "max_tokens".to_string();
    }

    // 计费输入 tokens 已排除 system；contextUsageEvent 是完整上下文占用量，不能用于计费。
    let final_input_tokens = input_tokens;

    // 构建 Anthropic 响应
    let mut response_body = json!({
        "id": response_id,
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": stop_sequence,
        "usage": {
            "input_tokens": final_input_tokens,
            "output_tokens": output_tokens
        }
    });
    cache::apply_usage(&mut response_body["usage"], cache_usage);
    cache::update(&account_id, cache_profile.as_ref());
    provider.record_token_usage_for_account(
        &account_id,
        consumed_tokens(final_input_tokens, output_tokens),
    );

    (StatusCode::OK, Json(response_body)).into_response()
}

fn apply_stop_sequences(text: &mut String, stop_sequences: Option<&[String]>) -> Option<String> {
    let sequences = stop_sequences?;
    let mut earliest: Option<(usize, &str)> = None;

    for sequence in sequences {
        if sequence.is_empty() {
            continue;
        }
        if let Some(pos) = text.find(sequence) {
            if earliest.map_or(true, |(current_pos, _)| pos < current_pos) {
                earliest = Some((pos, sequence.as_str()));
            }
        }
    }

    if let Some((pos, matched)) = earliest {
        text.truncate(pos);
        Some(matched.to_string())
    } else {
        None
    }
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
    JsonExtractor(mut payload): JsonExtractor<CountTokensRequest>,
) -> impl IntoResponse {
    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );

    if identity_guard::enabled() {
        let model = payload.model.clone();
        identity_guard::inject_system_prompt(&mut payload.system, &model);
    }

    let total_tokens = token::count_all_tokens(
        payload.model,
        payload.system,
        payload.messages,
        payload.tools,
    ) as i32;

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1) as i32,
    })
}

/// POST /cc/v1/messages
///
/// Claude Code 兼容端点，与 /v1/messages 的区别在于：
/// - 流式响应会等待 kiro 端返回 contextUsageEvent 后再发送 message_start
/// - message_start 中的 input_tokens 是从 contextUsageEvent 计算的准确值
pub async fn post_messages_cc(
    State(state): State<AppState>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    let stream = payload
        .stream
        .unwrap_or_else(|| state.default_stream.load(Ordering::Relaxed));
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %stream,
        message_count = %payload.messages.len(),
        "Received POST /cc/v1/messages request"
    );

    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
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
    let protection_ttl = provider.cache_account_protection_duration();

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);

    if identity_guard::enabled() {
        identity_guard::inject_identity_prompt(&mut payload);
        let input_tokens = token::count_billable_input_tokens(
            payload.model.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;
        if let Some(response) = identity_guard::scripted_response(&payload, stream, input_tokens) {
            return response;
        }
    }

    if let Err(e) = normalize_multimodal_sources(&mut payload).await {
        tracing::warn!("多模态请求归一化失败: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("invalid_request_error", e.to_string())),
        )
            .into_response();
    }

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_billable_input_tokens(
            payload.model.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        return websearch::handle_websearch_request(provider, &payload, input_tokens).await;
    }

    let model_mappings = state.model_mappings.read().clone();

    // 转换请求
    let conversion_result = match convert_request_with_mappings(&payload, &model_mappings) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 构建 Kiro 请求（profile_arn 由 provider 层根据实际凭据注入）
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
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

    tracing::debug!("Kiro request body: {}", request_body);

    // 估算输入 tokens
    let input_tokens = token::count_billable_input_tokens(
        payload.model.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;
    let cache_profile = cache::build_profile(&payload, input_tokens);
    let preferred_account_ids = cache::preferred_account_ids(cache_profile.as_ref());
    let reserved_account_ids = cache::active_account_ids(protection_ttl);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;

    if stream {
        // 流式响应（缓冲模式）
        handle_stream_request_buffered(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            thinking_enabled,
            structured_output_requested(&payload),
            tool_name_map,
            cache_profile,
            preferred_account_ids,
            reserved_account_ids,
            get_context_window_size_with_mappings(&payload.model, &model_mappings),
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking.load(Ordering::Relaxed) && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            payload.max_tokens,
            input_tokens,
            extract_thinking,
            structured_output_requested(&payload),
            tool_name_map,
            cache_profile,
            payload.stop_sequences.clone(),
            preferred_account_ids,
            reserved_account_ids,
            get_context_window_size_with_mappings(&payload.model, &model_mappings),
        )
        .await
    }
}

/// 处理流式请求（缓冲版本）
///
/// 与 `handle_stream_request` 不同，此函数会缓冲所有事件直到流结束，
/// 然后用从 contextUsageEvent 计算的正确 input_tokens 生成 message_start 事件。
async fn handle_stream_request_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    estimated_input_tokens: i32,
    thinking_enabled: bool,
    structured_output: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    cache_profile: Option<CacheProfile>,
    preferred_account_ids: Vec<String>,
    reserved_account_ids: Vec<String>,
    context_window_size: i32,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let (response, account_id, request_lease) = match provider
        .call_api_stream_with_account_and_cache_accounts(
            request_body,
            &preferred_account_ids,
            &reserved_account_ids,
        )
        .await
    {
        Ok(result) => result,
        Err(e) => return map_provider_error(e),
    };
    let cache_usage = cache::compute(&account_id, cache_profile.as_ref());

    // 创建缓冲流处理上下文
    let mut ctx = BufferedStreamContext::new(
        model,
        estimated_input_tokens,
        thinking_enabled,
        tool_name_map,
        cache_usage,
    );
    ctx.set_context_window_size(context_window_size);

    // 创建缓冲 SSE 流
    let stream = create_buffered_sse_stream(
        provider,
        response,
        ctx,
        structured_output,
        account_id,
        cache_profile,
        request_lease,
    );

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
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
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    response: reqwest::Response,
    ctx: BufferedStreamContext,
    structured_output: bool,
    account_id: String,
    cache_profile: Option<CacheProfile>,
    request_lease: crate::kiro::token_manager::RequestLease,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();

    stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            interval(Duration::from_secs(PING_INTERVAL_SECS)),
            provider,
            account_id,
            cache_profile,
            request_lease,
        ),
        move |(
            mut body_stream,
            mut ctx,
            mut decoder,
            finished,
            mut ping_interval,
            provider,
            account_id,
            cache_profile,
            request_lease,
        )| async move {
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
                        return Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, provider, account_id, cache_profile, request_lease)));
                    }

                    // 然后处理数据流
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
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
                                let (input_tokens, output_tokens) = ctx.token_totals();
                                provider.record_token_usage_for_account(
                                    &account_id,
                                    consumed_tokens(input_tokens, output_tokens),
                                );
                                // 发生错误，完成处理并返回所有事件
                                let mut all_events = ctx.finish_and_get_all_events();
                                if structured_output {
                                    normalize_structured_output_events(&mut all_events);
                                }
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, provider, account_id, cache_profile, request_lease)));
                            }
                            None => {
                                // 流结束，完成处理并返回所有事件（已更正 input_tokens）
                                let (input_tokens, output_tokens) = ctx.token_totals();
                                provider.record_token_usage_for_account(
                                    &account_id,
                                    consumed_tokens(input_tokens, output_tokens),
                                );
                                let mut all_events = ctx.finish_and_get_all_events();
                                if structured_output {
                                    normalize_structured_output_events(&mut all_events);
                                }
                                cache::update(&account_id, cache_profile.as_ref());
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, provider, account_id, cache_profile, request_lease)));
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
    use super::{
        apply_stop_sequences, normalize_structured_output_events, normalize_structured_output_text,
    };
    use crate::anthropic::stream::SseEvent;
    use serde_json::json;

    #[test]
    fn test_apply_stop_sequences_truncates_at_earliest_match() {
        let mut text = "one two three HALT and never more".to_string();
        let matched =
            apply_stop_sequences(&mut text, Some(&["never".to_string(), "HALT".to_string()]));

        assert_eq!(matched.as_deref(), Some("HALT"));
        assert_eq!(text, "one two three ");
    }

    #[test]
    fn test_apply_stop_sequences_ignores_empty_sequences() {
        let mut text = "complete response".to_string();
        let matched = apply_stop_sequences(&mut text, Some(&["".to_string()]));

        assert_eq!(matched, None);
        assert_eq!(text, "complete response");
    }

    #[test]
    fn test_normalize_structured_output_text_removes_fence() {
        assert_eq!(
            normalize_structured_output_text("```json\n{\"ok\":true}\n```"),
            "{\"ok\":true}"
        );
    }

    #[test]
    fn test_normalize_structured_output_events_collapses_streamed_text() {
        let mut events = vec![
            SseEvent::new(
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "```json\n{\"ok\":true}"}
                }),
            ),
            SseEvent::new(
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "\n```"}
                }),
            ),
        ];

        normalize_structured_output_events(&mut events);

        assert_eq!(events[0].data["delta"]["text"], "{\"ok\":true}");
        assert_eq!(events[1].data["delta"]["text"], "");
    }
}
