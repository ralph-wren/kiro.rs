//! Default prompt cache policy for requests without explicit cache controls.
//!
//! Explicit Anthropic `cache_control` markers always win. These helpers only add
//! conservative cache breakpoints for long, stable request prefixes when the
//! client did not provide any cache controls.

use serde_json::Value;

use crate::token;

use super::types::{MessagesRequest, Tool};

pub(crate) const DEFAULT_MIN_AUTO_CACHE_TOKENS: i32 = 1024;

pub(crate) fn has_explicit_cache_control(req: &MessagesRequest) -> bool {
    if req
        .tools
        .as_ref()
        .is_some_and(|tools| tools.iter().any(|tool| tool.cache_control.is_some()))
    {
        return true;
    }

    if req
        .system
        .as_ref()
        .is_some_and(|system| system.iter().any(|block| block.cache_control.is_some()))
    {
        return true;
    }

    req.messages
        .iter()
        .any(|message| message.cache_control.is_some() || value_has_cache_control(&message.content))
}

pub(crate) fn should_auto_cache_system(req: &MessagesRequest) -> bool {
    req.system.as_ref().is_some_and(|system| {
        let tokens: i32 = system
            .iter()
            .map(|block| token::count_tokens(&block.text) as i32)
            .sum();
        tokens >= DEFAULT_MIN_AUTO_CACHE_TOKENS
    })
}

pub(crate) fn should_auto_cache_message(req: &MessagesRequest, index: usize) -> bool {
    if index >= req.messages.len() {
        return false;
    }

    // Only historical messages are stable enough for automatic cache points.
    // The current user turn commonly changes between calls, so auto-caching it
    // makes cache creation grow on every request and skews Anthropic usage.
    if req.messages.len().saturating_sub(1) <= index {
        return false;
    }

    count_message_tokens(&req.messages[index].content) >= DEFAULT_MIN_AUTO_CACHE_TOKENS
}

pub(crate) fn should_auto_cache_tool(req: &MessagesRequest, index: usize) -> bool {
    let Some(tools) = &req.tools else {
        return false;
    };
    if index >= tools.len() {
        return false;
    }

    count_tools_tokens(&tools[..=index]) >= DEFAULT_MIN_AUTO_CACHE_TOKENS
}

pub(crate) fn should_use_default_cache(req: &MessagesRequest) -> bool {
    !has_explicit_cache_control(req)
}

fn value_has_cache_control(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("cache_control"),
        Value::Array(items) => items.iter().any(value_has_cache_control),
        _ => false,
    }
}

fn count_tools_tokens(tools: &[Tool]) -> i32 {
    tools
        .iter()
        .map(|tool| {
            token::count_tokens(&stable_json(&serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            }))) as i32
        })
        .sum()
}

pub(crate) fn count_message_tokens(value: &Value) -> i32 {
    match value {
        Value::String(text) => token::count_tokens(text) as i32,
        Value::Array(parts) => parts
            .iter()
            .map(|part| {
                part.get("text")
                    .or_else(|| part.get("thinking"))
                    .and_then(Value::as_str)
                    .map(|text| token::count_tokens(text) as i32)
                    .unwrap_or_else(|| token::count_tokens(&stable_json(part)) as i32)
            })
            .sum(),
        other => token::count_tokens(&stable_json(other)) as i32,
    }
}

fn stable_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => value.to_string(),
        Value::Array(items) => {
            let rendered = items.iter().map(stable_json).collect::<Vec<_>>().join(",");
            format!("[{}]", rendered)
        }
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let rendered = keys
                .into_iter()
                .filter_map(|key| {
                    let value = stable_json(map.get(key)?);
                    Some(format!("{}:{}", serde_json::to_string(key).ok()?, value))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", rendered)
        }
    }
}
