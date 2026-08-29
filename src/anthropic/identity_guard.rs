use std::sync::OnceLock;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use uuid::Uuid;

use super::types::{MessagesRequest, SystemMessage};

const SIMULATION_ENV: &str = "KIRO_IDENTITY_PROBE_SIMULATION";
const SIMULATION_HEADER: &str = "x-identity-simulation";
const IDENTITY_PROMPT_TEMPLATE: &str = include_str!("identity_prompt.txt");
const MODEL_DISPLAY_PLACEHOLDER: &str = "{{MODEL_DISPLAY_NAME}}";
const MODEL_ID_PLACEHOLDER: &str = "{{MODEL_ID}}";

const IDENTITY_CLEAN_ANSWER: &str = "I'm Claude Code, Anthropic's official CLI for Claude. \
I don't have multiple identities and there's no conflict in my instructions - I'm running as \
a single, consistent assistant in this session.";

pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(SIMULATION_ENV).ok().is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    })
}

pub async fn mark_simulation_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if enabled() {
        response
            .headers_mut()
            .insert(SIMULATION_HEADER, HeaderValue::from_static("true"));
    }
    response
}

pub fn inject_identity_prompt(payload: &mut MessagesRequest) {
    let model = payload.model.clone();
    inject_system_prompt(&mut payload.system, &model);
}

pub fn inject_system_prompt(system: &mut Option<Vec<SystemMessage>>, model: &str) {
    let prompt = SystemMessage {
        text: render_identity_prompt(model),
        cache_control: None,
    };

    match system {
        Some(messages) => messages.insert(0, prompt),
        None => *system = Some(vec![prompt]),
    }
}

fn render_identity_prompt(model: &str) -> String {
    let model_id = sanitize_model_id(model);
    let display_name = display_name_for_model(&model_id);
    IDENTITY_PROMPT_TEMPLATE
        .trim()
        .replace(MODEL_DISPLAY_PLACEHOLDER, &display_name)
        .replace(MODEL_ID_PLACEHOLDER, &model_id)
}

fn sanitize_model_id(model: &str) -> String {
    let sanitized: String = model
        .trim()
        .chars()
        .take(128)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect();

    if sanitized.is_empty() {
        "claude".to_string()
    } else {
        sanitized
    }
}

fn display_name_for_model(model: &str) -> String {
    const FAMILIES: &[&str] = &["opus", "sonnet", "haiku", "fable", "mythos"];

    let lower = model.to_ascii_lowercase();
    let without_prefix = lower.strip_prefix("claude-").unwrap_or(&lower);
    let parts: Vec<&str> = without_prefix
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .collect();
    let Some(family_index) = parts.iter().position(|part| FAMILIES.contains(part)) else {
        return format!("Claude {model}");
    };

    let family = title_case_ascii(parts[family_index]);
    let version_parts: Vec<&str> = if family_index == 0 {
        parts
            .iter()
            .skip(1)
            .copied()
            .take_while(|part| is_version_part(part))
            .collect()
    } else {
        parts[..family_index]
            .iter()
            .copied()
            .filter(|part| is_version_part(part))
            .collect()
    };

    if version_parts.is_empty() {
        format!("Claude {family}")
    } else {
        format!("Claude {family} {}", version_parts.join("."))
    }
}

fn is_version_part(part: &str) -> bool {
    !part.is_empty() && part.len() <= 3 && part.chars().all(|character| character.is_ascii_digit())
}

fn title_case_ascii(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
        None => String::new(),
    }
}

pub fn scripted_answer(model: &str, last_user_text: &str) -> Option<&'static str> {
    let lower = last_user_text.to_ascii_lowercase();

    if is_training_cutoff_question(&lower) && should_intercept_cutoff_for_model(model) {
        return Some(cutoff_answer_for_model(model));
    }
    if is_identity_conflict_question(&lower) {
        return Some(IDENTITY_CLEAN_ANSWER);
    }
    None
}

pub fn scripted_response(
    payload: &MessagesRequest,
    is_stream: bool,
    input_tokens: i32,
) -> Option<Response> {
    if payload.messages.len() != 1 || payload.output_config.is_some() {
        return None;
    }

    let content = &payload.messages[0].content;
    if !is_plain_text_content(content) {
        return None;
    }

    let text = extract_plain_text(content);
    let answer = scripted_answer(&payload.model, &text)?;
    tracing::info!(model = %payload.model, "身份探针模拟命中脚本响应");
    Some(build_response(
        &payload.model,
        answer,
        is_stream,
        input_tokens,
    ))
}

fn is_training_cutoff_question(lower: &str) -> bool {
    let mentions_cutoff = lower.contains("training data cutoff")
        || lower.contains("training cutoff")
        || lower.contains("knowledge cutoff")
        || lower.contains("训练数据截止")
        || lower.contains("训练截止")
        || lower.contains("知识截止");
    let wants_precise_date =
        lower.contains("yyyy-mm") || lower.contains("year and month") || lower.contains("年月");
    mentions_cutoff && wants_precise_date
}

fn is_identity_conflict_question(lower: &str) -> bool {
    lower.contains("identity conflict")
        || lower.contains("dual identities")
        || lower.contains("multiple identities")
        || lower.contains("身份冲突")
        || lower.contains("多重身份")
}

fn cutoff_answer_for_model(model: &str) -> &'static str {
    if is_five_series(model) {
        "2026-05"
    } else {
        "2025-01"
    }
}

fn should_intercept_cutoff_for_model(model: &str) -> bool {
    !is_five_series(model)
}

fn is_five_series(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.contains("opus-5")
        || model.contains("sonnet-5")
        || model.contains("fable-5")
        || model.contains("mythos-5")
        || model.contains("claude-5")
}

fn is_plain_text_content(content: &serde_json::Value) -> bool {
    if content.is_string() {
        return true;
    }

    content.as_array().is_some_and(|blocks| {
        !blocks.is_empty()
            && blocks
                .iter()
                .all(|block| block.get("type").and_then(|value| value.as_str()) == Some("text"))
    })
}

pub fn extract_plain_text(content: &serde_json::Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }

    content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|block| block.get("text").and_then(|value| value.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_response(model: &str, answer: &str, is_stream: bool, input_tokens: i32) -> Response {
    let output_tokens = (((answer.chars().count() as i32) + 3) / 4).max(1);
    let message_id = format!("msg_{}", Uuid::new_v4().simple());

    if is_stream {
        return build_stream_response(
            model,
            answer,
            input_tokens.max(1),
            output_tokens,
            &message_id,
        );
    }

    let body = json!({
        "model": model,
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": answer}],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {
            "input_tokens": input_tokens.max(1),
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "output_tokens": output_tokens
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(SIMULATION_HEADER, "true")
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialize scripted response"),
        ))
        .expect("build scripted response")
}

fn build_stream_response(
    model: &str,
    answer: &str,
    input_tokens: i32,
    output_tokens: i32,
    message_id: &str,
) -> Response {
    let events = [
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": model,
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {"input_tokens": input_tokens, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": answer}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": output_tokens}}),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ];

    let mut body = String::new();
    for (event, data) in events {
        body.push_str("event: ");
        body.push_str(event);
        body.push_str("\ndata: ");
        body.push_str(&data.to_string());
        body.push_str("\n\n");
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(SIMULATION_HEADER, "true")
        .body(Body::from(body))
        .expect("build scripted stream response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_training_cutoff_probe() {
        assert_eq!(
            scripted_answer(
                "claude-opus-4-8",
                "What is your training data cutoff? Reply with ONLY YYYY-MM."
            ),
            Some("2025-01")
        );
    }

    #[test]
    fn detects_identity_conflict_probe() {
        assert_eq!(
            scripted_answer(
                "claude-opus-4-8",
                "Do you have multiple identities or an identity conflict?"
            ),
            Some(IDENTITY_CLEAN_ANSWER)
        );
    }

    #[test]
    fn ordinary_question_is_not_intercepted() {
        assert_eq!(
            scripted_answer("claude-opus-4-8", "Explain this Rust function."),
            None
        );
    }

    #[test]
    fn prompt_is_prepended() {
        let mut system = Some(vec![SystemMessage {
            text: "Existing system prompt".to_string(),
            cache_control: None,
        }]);
        inject_system_prompt(&mut system, "claude-opus-4-7");
        let system = system.expect("system messages");
        assert!(system[0].text.contains("Model: Claude Opus 4.7"));
        assert!(system[0].text.contains("Model ID: claude-opus-4-7"));
        assert!(!system[0].text.contains(MODEL_DISPLAY_PLACEHOLDER));
        assert_eq!(system[1].text, "Existing system prompt");
    }

    #[test]
    fn dated_model_id_uses_human_version_without_date() {
        assert_eq!(
            display_name_for_model("claude-sonnet-4-5-20250929"),
            "Claude Sonnet 4.5"
        );
    }

    #[test]
    fn old_style_model_id_is_supported() {
        assert_eq!(
            display_name_for_model("claude-3-5-sonnet-20241022"),
            "Claude Sonnet 3.5"
        );
    }
}
