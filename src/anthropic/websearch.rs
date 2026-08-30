//! WebSearch 工具处理模块
//!
//! 实现 Anthropic WebSearch 请求到 Kiro MCP 的转换和响应生成

use std::convert::Infallible;

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use base64::Engine as _;
use bytes::Bytes;
use futures::{Stream, stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::stream::SseEvent;
use super::types::{ErrorResponse, MessagesRequest};

/// MCP 请求
#[derive(Debug, Serialize)]
pub struct McpRequest {
    pub id: String,
    pub jsonrpc: String,
    pub method: String,
    pub params: McpParams,
}

/// MCP 请求参数
#[derive(Debug, Serialize)]
pub struct McpParams {
    pub name: String,
    pub arguments: McpArguments,
}

/// MCP 参数
#[derive(Debug, Serialize)]
pub struct McpArguments {
    pub query: String,
}

/// MCP 响应
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResponse {
    pub error: Option<McpError>,
    pub id: String,
    pub jsonrpc: String,
    pub result: Option<McpResult>,
}

/// MCP 错误
#[derive(Debug, Deserialize)]
pub struct McpError {
    pub code: Option<i32>,
    pub message: Option<String>,
}

/// MCP 结果
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

/// MCP 内容
#[derive(Debug, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// WebSearch 搜索结果
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WebSearchResults {
    #[serde(default)]
    pub results: Vec<WebSearchResult>,
    #[serde(rename = "totalResults")]
    pub total_results: Option<i32>,
    pub query: Option<String>,
    pub error: Option<String>,
}

/// 单个搜索结果
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct WebSearchResult {
    pub title: String,
    pub url: String,
    pub snippet: Option<String>,
    #[serde(rename = "publishedDate")]
    pub published_date: Option<i64>,
    pub id: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "maxVerbatimWordLimit")]
    pub max_verbatim_word_limit: Option<i32>,
    #[serde(rename = "publicDomain")]
    pub public_domain: Option<bool>,
}

fn is_web_search_tool(tool: &super::types::Tool) -> bool {
    tool.name == "web_search"
        || tool
            .tool_type
            .as_deref()
            .is_some_and(|tool_type| tool_type.starts_with("web_search_"))
}

/// 检查请求是否只包含 WebSearch 服务端工具。
pub fn has_web_search_tool(req: &MessagesRequest) -> bool {
    req.tools
        .as_ref()
        .is_some_and(|tools| !tools.is_empty() && tools.iter().all(is_web_search_tool))
}

/// 从消息中提取搜索查询
///
/// 读取 messages 的第一条消息的第一个内容块
/// 并去除 "Perform a web search for the query: " 前缀
pub fn extract_search_query(req: &MessagesRequest) -> Option<String> {
    let text = req
        .messages
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .and_then(|message| match &message.content {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Array(blocks) => Some(
                blocks
                    .iter()
                    .filter(|block| {
                        block.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    })
                    .filter_map(|block| block.get("text").and_then(serde_json::Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            _ => None,
        })?;

    let trimmed = text.trim();
    let prefixes = [
        "Perform a web search for the query:",
        "Search the web for:",
        "Search the web for",
        "Search for:",
        "Search for",
        "Query:",
    ];
    let query = prefixes
        .iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix).map(str::trim))
        .unwrap_or(trimmed);

    (!query.is_empty()).then(|| query.to_string())
}

/// 生成22位大小写字母和数字的随机字符串
fn generate_random_id_22() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..22)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 生成8位小写字母和数字的随机字符串
fn generate_random_id_8() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..8)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 创建 MCP 请求
///
/// ID 格式: web_search_tooluse_{22位随机}_{毫秒时间戳}_{8位随机}
pub fn create_mcp_request(query: &str) -> (String, McpRequest) {
    let random_22 = generate_random_id_22();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let random_8 = generate_random_id_8();

    let request_id = format!(
        "web_search_tooluse_{}_{}_{}",
        random_22, timestamp, random_8
    );

    // tool_use_id 使用相同格式
    let tool_use_id = format!(
        "srvtoolu_{}",
        Uuid::new_v4().to_string().replace('-', "")[..32].to_string()
    );

    let request = McpRequest {
        id: request_id,
        jsonrpc: "2.0".to_string(),
        method: "tools/call".to_string(),
        params: McpParams {
            name: "web_search".to_string(),
            arguments: McpArguments {
                query: query.to_string(),
            },
        },
    };

    (tool_use_id, request)
}

/// 解析 MCP 响应中的搜索结果
pub fn parse_search_results(mcp_response: &McpResponse) -> Option<WebSearchResults> {
    let result = mcp_response.result.as_ref()?;
    for content in &result.content {
        if content.content_type != "text" {
            continue;
        }
        let text = content
            .text
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();
        if let Ok(results) = serde_json::from_str::<WebSearchResults>(text) {
            return Some(results);
        }
        if let Ok(items) = serde_json::from_str::<Vec<WebSearchResult>>(text) {
            return Some(WebSearchResults {
                total_results: Some(items.len() as i32),
                query: None,
                error: None,
                results: items,
            });
        }
    }
    None
}

/// 生成 WebSearch SSE 响应流
pub fn create_websearch_sse_stream(
    model: String,
    query: String,
    tool_use_id: String,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let events =
        generate_websearch_events(&model, &query, &tool_use_id, search_results, input_tokens);

    stream::iter(
        events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    )
}

/// 生成 WebSearch SSE 事件序列
fn generate_websearch_events(
    model: &str,
    query: &str,
    tool_use_id: &str,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let message_id = format!(
        "msg_{}",
        Uuid::new_v4().to_string().replace('-', "")[..24].to_string()
    );

    // 1. message_start
    events.push(SseEvent::new(
        "message_start",
        json!({
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0
                }
            }
        }),
    ));

    // 2. content_block_start (text - 搜索决策说明, index 0)
    let decision_text = format!("I'll search for \"{}\".", query);
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "text",
                "text": ""
            }
        }),
    ));
    events.push(SseEvent::new(
        "content_block_delta",
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": decision_text
            }
        }),
    ));
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 0
        }),
    ));

    // 3. content_block_start (server_tool_use, index 1)
    // server_tool_use 是服务端工具，input 在 content_block_start 中一次性完整发送，
    // 不像客户端 tool_use 需要通过 input_json_delta 增量传输。
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "id": tool_use_id,
                "type": "server_tool_use",
                "name": "web_search"
            }
        }),
    ));

    // Anthropic streams server-tool arguments as input_json_delta rather than
    // embedding the complete input in content_block_start.
    events.push(SseEvent::new(
        "content_block_delta",
        json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {
                "type": "input_json_delta",
                "partial_json": serde_json::to_string(&json!({"query": query}))
                    .expect("web search query is serializable")
            }
        }),
    ));

    // 4. content_block_stop (server_tool_use)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 1
        }),
    ));

    // 5. content_block_start (web_search_tool_result, index 2)
    let search_content = if let Some(ref results) = search_results {
        results
            .results
            .iter()
            .map(|r| {
                let page_age = r.published_date.and_then(|ms| {
                    chrono::DateTime::from_timestamp_millis(ms)
                        .map(|dt| dt.format("%B %-d, %Y").to_string())
                });
                let encrypted_content = base64::engine::general_purpose::STANDARD.encode(
                    r.snippet
                        .as_deref()
                        .filter(|snippet| !snippet.is_empty())
                        .unwrap_or(&r.title),
                );
                json!({
                    "type": "web_search_result",
                    "title": r.title,
                    "url": r.url,
                    "encrypted_content": encrypted_content,
                    "page_age": page_age
                })
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 2,
            "content_block": {
                "type": "web_search_tool_result",
                "tool_use_id": tool_use_id,
                "content": search_content
            }
        }),
    ));

    // 6. content_block_stop (web_search_tool_result)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 2
        }),
    ));

    // 7. content_block_start (text, index 3)
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 3,
            "content_block": {
                "type": "text",
                "text": ""
            }
        }),
    ));

    // 8. content_block_delta (text_delta) - 生成搜索结果摘要
    let summary = generate_search_summary(query, &search_results);

    // 分块发送文本
    let chunk_size = 100;
    for chunk in summary.chars().collect::<Vec<_>>().chunks(chunk_size) {
        let text: String = chunk.iter().collect();
        events.push(SseEvent::new(
            "content_block_delta",
            json!({
            "type": "content_block_delta",
                "index": 3,
                "delta": {
                    "type": "text_delta",
                    "text": text
                }
            }),
        ));
    }

    // Citations are emitted after the text delta they support, matching the
    // Anthropic streaming protocol for web search result locations.
    if let Some(ref results) = search_results {
        for (index, result) in results.results.iter().enumerate() {
            events.push(SseEvent::new(
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": 3,
                    "delta": {
                        "type": "citations_delta",
                        "citation": websearch_citation(result, index)
                    }
                }),
            ));
        }
    }

    // 9. content_block_stop (text)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 3
        }),
    ));

    // 10. message_delta
    // 官方 API 的 message_delta.delta 中没有 stop_sequence 字段
    let output_tokens = (summary.len() as i32 + 3) / 4; // 简单估算
    events.push(SseEvent::new(
        "message_delta",
        json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": "end_turn"
            },
            "usage": {
                "output_tokens": output_tokens,
                "server_tool_use": {
                    "web_search_requests": 1
                }
            }
        }),
    ));

    // 11. message_stop
    events.push(SseEvent::new(
        "message_stop",
        json!({
            "type": "message_stop"
        }),
    ));

    events
}

fn websearch_citation(result: &WebSearchResult, index: usize) -> serde_json::Value {
    let mut digest = Sha256::new();
    digest.update(index.to_string().as_bytes());
    digest.update([0]);
    digest.update(result.url.as_bytes());
    digest.update([0]);
    digest.update(result.snippet.as_deref().unwrap_or_default().as_bytes());
    let encrypted_index = base64::engine::general_purpose::STANDARD.encode(digest.finalize());
    let cited_text = result
        .snippet
        .as_deref()
        .unwrap_or(&result.title)
        .chars()
        .take(150)
        .collect::<String>();

    json!({
        "type": "web_search_result_location",
        "url": result.url,
        "title": result.title,
        "encrypted_index": encrypted_index,
        "cited_text": cited_text
    })
}

/// 生成搜索结果摘要
fn generate_search_summary(query: &str, results: &Option<WebSearchResults>) -> String {
    let mut summary = format!("Here are the search results for \"{}\":\n\n", query);

    if let Some(results) = results {
        for (i, result) in results.results.iter().enumerate() {
            summary.push_str(&format!("{}. **{}**\n", i + 1, result.title));
            if let Some(ref snippet) = result.snippet {
                // 截断过长的摘要（安全处理 UTF-8 多字节字符）
                let truncated = match snippet.char_indices().nth(200) {
                    Some((idx, _)) => format!("{}...", &snippet[..idx]),
                    None => snippet.clone(),
                };
                summary.push_str(&format!("   {}\n", truncated));
            }
            summary.push_str(&format!("   Source: {}\n\n", result.url));
        }
    } else {
        summary.push_str("No results found.\n");
    }

    summary.push_str("\nPlease note that these are web search results and may not be fully accurate or up-to-date.");

    summary
}

/// 处理 WebSearch 请求
pub async fn handle_websearch_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    payload: &MessagesRequest,
    input_tokens: i32,
) -> Response {
    // 1. 提取搜索查询
    let query = match extract_search_query(payload) {
        Some(q) => q,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    "无法从消息中提取搜索查询",
                )),
            )
                .into_response();
        }
    };

    tracing::info!(query = %query, "处理 WebSearch 请求");

    // 2. 创建 MCP 请求
    let (tool_use_id, mcp_request) = create_mcp_request(&query);

    // 3. 调用 Kiro MCP API
    let (response, account_id) = match call_mcp_api(&provider, &mcp_request).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "WebSearch MCP API 调用失败");
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    format!("WebSearch 上游调用失败: {e}"),
                )),
            )
                .into_response();
        }
    };
    if response
        .result
        .as_ref()
        .is_some_and(|result| result.is_error)
    {
        tracing::error!("WebSearch MCP 返回 isError=true");
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(
                "api_error",
                "WebSearch 搜索服务返回错误",
            )),
        )
            .into_response();
    }
    let search_results = match parse_search_results(&response) {
        Some(results) if results.error.is_none() => Some(results),
        Some(results) => {
            let message = results
                .error
                .unwrap_or_else(|| "搜索服务返回错误".to_string());
            tracing::error!(error = %message, "WebSearch MCP 返回错误");
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    format!("WebSearch 搜索失败: {message}"),
                )),
            )
                .into_response();
        }
        None => {
            tracing::error!("WebSearch MCP 返回无法解析的结果");
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "WebSearch 上游返回了无法解析的结果",
                )),
            )
                .into_response();
        }
    };
    let account_id = Some(account_id);

    if let Some(account_id) = account_id {
        let summary = generate_search_summary(&query, &search_results);
        let output_tokens = estimate_websearch_output_tokens(&summary);
        provider.record_token_usage_for_account(
            &account_id,
            (input_tokens.max(0) as u64) + (output_tokens.max(0) as u64),
        );
    }

    // 4. 生成 SSE 响应
    let model = payload.model.clone();
    let stream =
        create_websearch_sse_stream(model, query, tool_use_id, search_results, input_tokens);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 调用 Kiro MCP API
async fn call_mcp_api(
    provider: &crate::kiro::provider::KiroProvider,
    request: &McpRequest,
) -> anyhow::Result<(McpResponse, String)> {
    let request_body = serde_json::to_string(request)?;

    tracing::debug!("MCP request: {}", request_body);

    let (response, account_id, _request_lease) =
        provider.call_mcp_with_account(&request_body).await?;

    let body = response.text().await?;
    tracing::debug!("MCP response: {}", body);

    let mcp_response: McpResponse = serde_json::from_str(&body)?;

    if let Some(ref error) = mcp_response.error {
        anyhow::bail!(
            "MCP error: {} - {}",
            error.code.unwrap_or(-1),
            error.message.as_deref().unwrap_or("Unknown error")
        );
    }

    Ok((mcp_response, account_id))
}

fn estimate_websearch_output_tokens(summary: &str) -> i32 {
    ((summary.len() as i32) + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_web_search_tool_only_one() {
        use crate::anthropic::types::{Message, Tool};

        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
                cache_control: None,
            }],
            stream: Some(true),
            system: None,
            tools: Some(vec![Tool {
                tool_type: Some("web_search_20250305".to_string()),
                name: "web_search".to_string(),
                description: String::new(),
                input_schema: Default::default(),
                max_uses: Some(8),
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        assert!(has_web_search_tool(&req));
    }

    #[test]
    fn test_has_web_search_tool_multiple_tools() {
        use crate::anthropic::types::{Message, Tool};

        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
                cache_control: None,
            }],
            stream: Some(true),
            system: None,
            tools: Some(vec![
                Tool {
                    tool_type: Some("web_search_20250305".to_string()),
                    name: "web_search".to_string(),
                    description: String::new(),
                    input_schema: Default::default(),
                    max_uses: Some(8),
                    cache_control: None,
                },
                Tool {
                    tool_type: None,
                    name: "other_tool".to_string(),
                    description: "Other tool".to_string(),
                    input_schema: Default::default(),
                    max_uses: None,
                    cache_control: None,
                },
            ]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        // 多个工具时不应该被识别为纯 websearch 请求
        assert!(!has_web_search_tool(&req));
    }

    #[test]
    fn test_generate_websearch_events_use_anthropic_block_indexes() {
        let events = generate_websearch_events(
            "claude-sonnet-4-5",
            "rust latest version",
            "srvtoolu_test",
            Some(WebSearchResults {
                results: vec![WebSearchResult {
                    title: "Rust".to_string(),
                    url: "https://www.rust-lang.org".to_string(),
                    snippet: Some("Rust language".to_string()),
                    published_date: None,
                    id: None,
                    domain: None,
                    max_verbatim_word_limit: None,
                    public_domain: None,
                }],
                total_results: Some(1),
                query: Some("rust latest version".to_string()),
                error: None,
            }),
            12,
        );

        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.event == "content_block_start")
            .collect();
        assert_eq!(starts.len(), 4);
        assert_eq!(starts[0].data["index"], 0);
        assert_eq!(starts[0].data["content_block"]["type"], "text");
        assert_eq!(starts[1].data["index"], 1);
        assert_eq!(starts[1].data["content_block"]["type"], "server_tool_use");
        let input_delta = events
            .iter()
            .find(|event| event.data["delta"]["type"] == "input_json_delta")
            .expect("should emit server tool input as a delta");
        assert_eq!(input_delta.data["index"], 1);
        assert_eq!(
            input_delta.data["delta"]["partial_json"],
            "{\"query\":\"rust latest version\"}"
        );
        assert_eq!(starts[2].data["index"], 2);
        assert_eq!(
            starts[2].data["content_block"]["type"],
            "web_search_tool_result"
        );
        assert_eq!(
            starts[2].data["content_block"]["tool_use_id"],
            "srvtoolu_test"
        );
        let result = &starts[2].data["content_block"]["content"][0];
        assert_ne!(result["encrypted_content"], "Rust language");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(result["encrypted_content"].as_str().unwrap())
                .unwrap(),
            b"Rust language"
        );
        assert_eq!(starts[3].data["index"], 3);
        assert_eq!(starts[3].data["content_block"]["type"], "text");

        let citation = events
            .iter()
            .find(|event| event.data["delta"]["type"] == "citations_delta")
            .expect("should emit a citation delta");
        assert_eq!(citation.data["index"], 3);
        assert_eq!(
            citation.data["delta"]["citation"]["type"],
            "web_search_result_location"
        );
        assert!(
            !citation.data["delta"]["citation"]["encrypted_index"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[test]
    fn test_extract_search_query_with_prefix() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!([{
                    "type": "text",
                    "text": "Perform a web search for the query: rust latest version 2026"
                }]),
                cache_control: None,
            }],
            stream: Some(true),
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        let query = extract_search_query(&req);
        // 前缀应该被去除
        assert_eq!(query, Some("rust latest version 2026".to_string()));
    }

    #[test]
    fn test_extract_search_query_plain_text() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("What is the weather today?"),
                cache_control: None,
            }],
            stream: Some(true),
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        let query = extract_search_query(&req);
        assert_eq!(query, Some("What is the weather today?".to_string()));
    }

    #[test]
    fn test_extract_search_query_uses_last_user_text_blocks() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: serde_json::json!("old query"),
                    cache_control: None,
                },
                Message {
                    role: "assistant".to_string(),
                    content: serde_json::json!("ack"),
                    cache_control: None,
                },
                Message {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "text", "text": "Search the web for:"},
                        {"type": "text", "text": "Rust 2026 release"}
                    ]),
                    cache_control: None,
                },
            ],
            stream: Some(true),
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        assert_eq!(
            extract_search_query(&req),
            Some("Rust 2026 release".to_string())
        );
    }

    #[test]
    fn test_parse_search_results_accepts_array_payload() {
        let response = McpResponse {
            error: None,
            id: "test_id".to_string(),
            jsonrpc: "2.0".to_string(),
            result: Some(McpResult {
                content: vec![McpContent {
                    content_type: "text".to_string(),
                    text: r#"[{"title":"Test","url":"https://example.com"}]"#.to_string(),
                }],
                is_error: false,
            }),
        };

        let results = parse_search_results(&response).unwrap();
        assert_eq!(results.total_results, Some(1));
        assert_eq!(results.results[0].url, "https://example.com");
    }

    #[test]
    fn test_create_mcp_request() {
        let (tool_use_id, request) = create_mcp_request("test query");

        assert!(tool_use_id.starts_with("srvtoolu_"));
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "tools/call");
        assert_eq!(request.params.name, "web_search");
        assert_eq!(request.params.arguments.query, "test query");

        // 验证 ID 格式: web_search_tooluse_{22位}_{时间戳}_{8位}
        assert!(request.id.starts_with("web_search_tooluse_"));
    }

    #[test]
    fn test_mcp_request_id_format() {
        let (_, request) = create_mcp_request("test");

        // 格式: web_search_tooluse_{22位}_{毫秒时间戳}_{8位}
        let id = &request.id;
        assert!(id.starts_with("web_search_tooluse_"));

        let suffix = &id["web_search_tooluse_".len()..];
        let parts: Vec<&str> = suffix.split('_').collect();
        assert_eq!(parts.len(), 3, "应该有3个部分: 22位随机_时间戳_8位随机");

        // 第一部分: 22位大小写字母和数字
        assert_eq!(parts[0].len(), 22);
        assert!(parts[0].chars().all(|c| c.is_ascii_alphanumeric()));

        // 第二部分: 毫秒时间戳
        assert!(parts[1].parse::<i64>().is_ok());

        // 第三部分: 8位小写字母和数字
        assert_eq!(parts[2].len(), 8);
        assert!(
            parts[2]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_parse_search_results() {
        let response = McpResponse {
            error: None,
            id: "test_id".to_string(),
            jsonrpc: "2.0".to_string(),
            result: Some(McpResult {
                content: vec![McpContent {
                    content_type: "text".to_string(),
                    text: r#"{"results":[{"title":"Test","url":"https://example.com","snippet":"Test snippet"}],"totalResults":1}"#.to_string(),
                }],
                is_error: false,
            }),
        };

        let results = parse_search_results(&response);
        assert!(results.is_some());
        let results = results.unwrap();
        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].title, "Test");
    }

    #[test]
    fn test_generate_search_summary() {
        let results = WebSearchResults {
            results: vec![WebSearchResult {
                title: "Test Result".to_string(),
                url: "https://example.com".to_string(),
                snippet: Some("This is a test snippet".to_string()),
                published_date: None,
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("test".to_string()),
            error: None,
        };

        let summary = generate_search_summary("test", &Some(results));

        assert!(summary.contains("Test Result"));
        assert!(summary.contains("https://example.com"));
        assert!(summary.contains("This is a test snippet"));
    }
}
