//! Anthropic prompt cache usage simulation.
//!
//! Kiro accepts `cachePoint` in requests, but its event stream does not expose
//! Claude-compatible cache read/write token counters. This tracker mirrors the
//! request-side `cache_control` breakpoints so `/v1/messages` can return the
//! expected Anthropic usage fields.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::token;

use super::cache_policy;
use super::types::{CacheControl, MessagesRequest, Tool};

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const ONE_HOUR_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_MIN_CACHEABLE_TOKENS: i32 = 1024;
const OPUS_MIN_CACHEABLE_TOKENS: i32 = 4096;
const MAX_CACHE_RATIO: f64 = 0.85;
const MAX_ENTRIES_PER_ACCOUNT: usize = 200;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct CacheBreakpoint {
    fingerprint: String,
    cumulative_tokens: i32,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheProfile {
    breakpoints: Vec<CacheBreakpoint>,
    total_input_tokens: i32,
    model: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CacheUsage {
    pub(crate) cache_creation_input_tokens: i32,
    pub(crate) cache_creation_5m_input_tokens: i32,
    pub(crate) cache_creation_1h_input_tokens: i32,
    pub(crate) cache_read_input_tokens: i32,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    expires_at: Instant,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CacheableBlock {
    value: String,
    tokens: i32,
    ttl: Option<Duration>,
}

#[derive(Debug)]
struct PromptCacheTracker {
    entries_by_account: HashMap<String, HashMap<String, CacheEntry>>,
    last_prune: Instant,
}

impl PromptCacheTracker {
    fn new() -> Self {
        Self {
            entries_by_account: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    fn build_profile(
        &self,
        req: &MessagesRequest,
        total_input_tokens: i32,
    ) -> Option<CacheProfile> {
        let blocks = flatten_cache_blocks(req);
        if blocks.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        let mut breakpoints = Vec::new();
        let mut cumulative_tokens = 0;

        for block in blocks {
            hash_chunk(&mut hasher, &block.value);
            cumulative_tokens += block.tokens;

            if let Some(ttl) = block.ttl {
                breakpoints.push(CacheBreakpoint {
                    fingerprint: hex::encode(hasher.clone().finalize()),
                    cumulative_tokens,
                    ttl,
                });
            }
        }

        if breakpoints.is_empty() {
            return None;
        }

        Some(CacheProfile {
            breakpoints,
            total_input_tokens: total_input_tokens.max(cumulative_tokens).max(1),
            model: req.model.clone(),
        })
    }

    fn compute(&mut self, account_id: &str, profile: Option<&CacheProfile>) -> CacheUsage {
        let Some(profile) = profile else {
            return CacheUsage::default();
        };
        if profile.breakpoints.is_empty() || account_id.is_empty() {
            return CacheUsage::default();
        }

        let now = Instant::now();
        self.prune_if_needed(now);

        let min_tokens = min_cacheable_tokens(&profile.model);
        let last = profile.breakpoints.last().expect("profile has breakpoints");
        let mut last_tokens = last.cumulative_tokens.min(profile.total_input_tokens);
        let max_cacheable = (profile.total_input_tokens as f64 * MAX_CACHE_RATIO).floor() as i32;
        if last_tokens > max_cacheable {
            last_tokens = max_cacheable;
        }

        let Some(entries) = self.entries_by_account.get_mut(account_id) else {
            let creation = if last_tokens >= min_tokens {
                last_tokens
            } else {
                0
            };
            let (creation_5m, creation_1h) = split_cache_creation_tokens(profile, 0, creation);
            return CacheUsage {
                cache_creation_input_tokens: creation,
                cache_creation_5m_input_tokens: creation_5m,
                cache_creation_1h_input_tokens: creation_1h,
                cache_read_input_tokens: 0,
            };
        };

        let mut matched_tokens = 0;
        for bp in profile.breakpoints.iter().rev() {
            if bp.cumulative_tokens < min_tokens {
                continue;
            }
            let Some(entry) = entries.get_mut(&bp.fingerprint) else {
                continue;
            };
            if entry.expires_at < now {
                continue;
            }

            entry.expires_at = now + entry.ttl;
            matched_tokens = bp
                .cumulative_tokens
                .min(profile.total_input_tokens)
                .min(last_tokens);
            break;
        }

        let creation = (last_tokens - matched_tokens).max(0);
        let (creation_5m, creation_1h) =
            split_cache_creation_tokens(profile, matched_tokens, creation);

        CacheUsage {
            cache_creation_input_tokens: creation,
            cache_creation_5m_input_tokens: creation_5m,
            cache_creation_1h_input_tokens: creation_1h,
            cache_read_input_tokens: matched_tokens,
        }
    }

    fn update(&mut self, account_id: &str, profile: Option<&CacheProfile>) {
        let Some(profile) = profile else {
            return;
        };
        if profile.breakpoints.is_empty() || account_id.is_empty() {
            return;
        }

        let min_tokens = min_cacheable_tokens(&profile.model);
        let now = Instant::now();
        let entries = self
            .entries_by_account
            .entry(account_id.to_string())
            .or_default();

        for bp in &profile.breakpoints {
            if bp.cumulative_tokens < min_tokens {
                continue;
            }
            entries.insert(
                bp.fingerprint.clone(),
                CacheEntry {
                    expires_at: now + bp.ttl,
                    ttl: bp.ttl,
                },
            );
        }

        if entries.len() > MAX_ENTRIES_PER_ACCOUNT {
            let mut sorted: Vec<_> = entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.expires_at))
                .collect();
            sorted.sort_by_key(|(_, expires_at)| *expires_at);
            for (key, _) in sorted
                .into_iter()
                .take(entries.len() - MAX_ENTRIES_PER_ACCOUNT)
            {
                entries.remove(&key);
            }
        }
    }

    fn prune_if_needed(&mut self, now: Instant) {
        if now.duration_since(self.last_prune) < PRUNE_INTERVAL {
            return;
        }
        self.last_prune = now;

        self.entries_by_account.retain(|_, entries| {
            entries.retain(|_, entry| entry.expires_at >= now);
            !entries.is_empty()
        });
    }
}

static TRACKER: OnceLock<Mutex<PromptCacheTracker>> = OnceLock::new();

fn tracker() -> &'static Mutex<PromptCacheTracker> {
    TRACKER.get_or_init(|| Mutex::new(PromptCacheTracker::new()))
}

pub(crate) fn build_profile(
    req: &MessagesRequest,
    total_input_tokens: i32,
) -> Option<CacheProfile> {
    tracker().lock().build_profile(req, total_input_tokens)
}

pub(crate) fn compute(account_id: &str, profile: Option<&CacheProfile>) -> CacheUsage {
    tracker().lock().compute(account_id, profile)
}

pub(crate) fn update(account_id: &str, profile: Option<&CacheProfile>) {
    tracker().lock().update(account_id, profile)
}

fn flatten_cache_blocks(req: &MessagesRequest) -> Vec<CacheableBlock> {
    let mut blocks = Vec::new();
    let use_default_cache = cache_policy::should_use_default_cache(req);

    if let Some(tools) = &req.tools {
        for (index, tool) in tools.iter().enumerate() {
            append_tool_block(
                &mut blocks,
                tool,
                use_default_cache && cache_policy::should_auto_cache_tool(req, index),
            );
        }
    }

    if let Some(system) = &req.system {
        let auto_cache_system = use_default_cache && cache_policy::should_auto_cache_system(req);
        for block in system {
            let value = stable_json(&serde_json::json!({
                "kind": "system",
                "type": "text",
                "text": block.text,
            }));
            blocks.push(CacheableBlock {
                value,
                tokens: token::count_tokens(&block.text) as i32,
                ttl: ttl_from_control(&block.cache_control).or_else(|| {
                    if auto_cache_system {
                        Some(DEFAULT_CACHE_TTL)
                    } else {
                        None
                    }
                }),
            });
        }
    }

    for (index, message) in req.messages.iter().enumerate() {
        let auto_cache_message =
            use_default_cache && cache_policy::should_auto_cache_message(req, index);
        match &message.content {
            Value::String(text) => {
                let value = stable_json(&serde_json::json!({
                    "kind": "message",
                    "role": message.role,
                    "index": index,
                    "type": "text",
                    "text": text,
                }));
                blocks.push(CacheableBlock {
                    value,
                    tokens: token::count_tokens(text) as i32,
                    ttl: ttl_from_control(&message.cache_control).or_else(|| {
                        if auto_cache_message {
                            Some(DEFAULT_CACHE_TTL)
                        } else {
                            None
                        }
                    }),
                });
            }
            Value::Array(parts) => {
                let last_idx = parts.len().saturating_sub(1);
                let message_ttl = ttl_from_control(&message.cache_control).or_else(|| {
                    if auto_cache_message {
                        Some(DEFAULT_CACHE_TTL)
                    } else {
                        None
                    }
                });
                for (block_index, part) in parts.iter().enumerate() {
                    let text = part
                        .get("text")
                        .or_else(|| part.get("thinking"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let value = stable_json(&serde_json::json!({
                        "kind": "message",
                        "role": message.role,
                        "index": index,
                        "blockIndex": block_index,
                        "block": part,
                    }));
                    blocks.push(CacheableBlock {
                        value,
                        tokens: if text.is_empty() {
                            token::count_tokens(&stable_json(part)) as i32
                        } else {
                            token::count_tokens(text) as i32
                        },
                        ttl: ttl_from_value(part).or_else(|| {
                            if block_index == last_idx {
                                message_ttl
                            } else {
                                None
                            }
                        }),
                    });
                }
            }
            other => {
                let value = stable_json(&serde_json::json!({
                    "kind": "message",
                    "role": message.role,
                    "index": index,
                    "content": other,
                }));
                blocks.push(CacheableBlock {
                    tokens: token::count_tokens(&value) as i32,
                    value,
                    ttl: ttl_from_control(&message.cache_control).or_else(|| {
                        if auto_cache_message {
                            Some(DEFAULT_CACHE_TTL)
                        } else {
                            None
                        }
                    }),
                });
            }
        }
    }

    blocks
}

fn append_tool_block(blocks: &mut Vec<CacheableBlock>, tool: &Tool, auto_cache: bool) {
    let value = stable_json(&serde_json::json!({
        "kind": "tool",
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }));
    blocks.push(CacheableBlock {
        tokens: token::count_tokens(&value) as i32,
        value,
        ttl: ttl_from_control(&tool.cache_control).or_else(|| {
            if auto_cache {
                Some(DEFAULT_CACHE_TTL)
            } else {
                None
            }
        }),
    });
}

fn ttl_from_value(value: &Value) -> Option<Duration> {
    let cache_control = value.get("cache_control")?;
    let cache_type = cache_control.get("type")?.as_str()?;
    if !cache_type.eq_ignore_ascii_case("ephemeral") {
        return None;
    }

    ttl_from_ttl_value(cache_control.get("ttl"))
}

fn ttl_from_control(cache_control: &Option<CacheControl>) -> Option<Duration> {
    let cache_control = cache_control.as_ref()?;
    if !cache_control.cache_type.eq_ignore_ascii_case("ephemeral") {
        return None;
    }

    match cache_control.ttl.as_deref() {
        Some("1h") | Some("1H") => Some(ONE_HOUR_CACHE_TTL),
        Some(ttl) => ttl
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .or(Some(DEFAULT_CACHE_TTL)),
        None => Some(DEFAULT_CACHE_TTL),
    }
}

fn ttl_from_ttl_value(value: Option<&Value>) -> Option<Duration> {
    match value {
        Some(Value::String(ttl)) if ttl == "1h" || ttl == "1H" => Some(ONE_HOUR_CACHE_TTL),
        Some(Value::Number(ttl)) => ttl
            .as_u64()
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .or(Some(DEFAULT_CACHE_TTL)),
        _ => Some(DEFAULT_CACHE_TTL),
    }
}

fn min_cacheable_tokens(model: &str) -> i32 {
    if model.to_lowercase().contains("opus") {
        OPUS_MIN_CACHEABLE_TOKENS
    } else {
        DEFAULT_MIN_CACHEABLE_TOKENS
    }
}

fn split_cache_creation_tokens(
    profile: &CacheProfile,
    matched_tokens: i32,
    creation_tokens: i32,
) -> (i32, i32) {
    if creation_tokens <= 0 {
        return (0, 0);
    }

    let creation_end = (matched_tokens + creation_tokens).min(profile.total_input_tokens);
    let mut previous_cumulative = 0;
    let mut creation_5m = 0;
    let mut creation_1h = 0;

    for bp in &profile.breakpoints {
        let upper = bp
            .cumulative_tokens
            .min(profile.total_input_tokens)
            .min(creation_end);
        if upper <= previous_cumulative {
            continue;
        }

        let lower = previous_cumulative.max(matched_tokens);
        if upper > lower {
            let segment_tokens = upper - lower;
            if is_one_hour_ttl(bp.ttl) {
                creation_1h += segment_tokens;
            } else {
                creation_5m += segment_tokens;
            }
        }

        previous_cumulative = previous_cumulative.max(upper);
        if previous_cumulative >= creation_end {
            break;
        }
    }

    let split_total = creation_5m + creation_1h;
    if split_total < creation_tokens {
        creation_5m += creation_tokens - split_total;
    }

    (creation_5m, creation_1h)
}

fn is_one_hour_ttl(ttl: Duration) -> bool {
    ttl >= ONE_HOUR_CACHE_TTL
}

fn hash_chunk(hasher: &mut Sha256, chunk: &str) {
    hasher.update(chunk.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(chunk.as_bytes());
    hasher.update(b"\0");
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

pub(crate) fn apply_usage(usage: &mut Value, cache_usage: CacheUsage) {
    let Some(usage_obj) = usage.as_object_mut() else {
        return;
    };

    let input_tokens = usage_obj
        .get("input_tokens")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let billed_input_tokens = (input_tokens
        - cache_usage.cache_creation_input_tokens as i64
        - cache_usage.cache_read_input_tokens as i64)
        .max(0);

    usage_obj.insert(
        "input_tokens".to_string(),
        Value::Number(billed_input_tokens.into()),
    );
    usage_obj.insert(
        "cache_creation_input_tokens".to_string(),
        Value::Number((cache_usage.cache_creation_input_tokens as i64).into()),
    );
    usage_obj.insert(
        "cache_read_input_tokens".to_string(),
        Value::Number((cache_usage.cache_read_input_tokens as i64).into()),
    );

    let mut cache_creation_5m = cache_usage.cache_creation_5m_input_tokens;
    let cache_creation_1h = cache_usage.cache_creation_1h_input_tokens;
    let split_cache_creation_tokens = cache_creation_5m + cache_creation_1h;
    if cache_usage.cache_creation_input_tokens > split_cache_creation_tokens {
        cache_creation_5m += cache_usage.cache_creation_input_tokens - split_cache_creation_tokens;
    }

    if cache_creation_5m > 0 || cache_creation_1h > 0 {
        let mut cache_creation = serde_json::Map::new();
        cache_creation.insert(
            "ephemeral_5m_input_tokens".to_string(),
            Value::Number((cache_creation_5m as i64).into()),
        );
        cache_creation.insert(
            "ephemeral_1h_input_tokens".to_string(),
            Value::Number((cache_creation_1h as i64).into()),
        );
        usage_obj.insert("cache_creation".to_string(), Value::Object(cache_creation));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::types::{CacheControl, Message, MessagesRequest};

    fn cached_request(text: String) -> MessagesRequest {
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!([
                    {
                        "type": "text",
                        "text": text,
                        "cache_control": { "type": "ephemeral" }
                    }
                ]),
                cache_control: None,
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: Some("test-cache-conversation".to_string()),
        }
    }

    #[test]
    fn test_prompt_cache_tracker_reports_creation_then_read() {
        let req = cached_request("stable prefix ".repeat(500));
        let profile = build_profile(&req, 2000);
        let first = compute("account-a", profile.as_ref());
        update("account-a", profile.as_ref());
        let second = compute("account-a", profile.as_ref());

        assert!(first.cache_creation_input_tokens > 0);
        assert_eq!(first.cache_read_input_tokens, 0);
        assert_eq!(second.cache_creation_input_tokens, 0);
        assert!(second.cache_read_input_tokens > 0);
    }

    #[test]
    fn test_message_level_cache_control_on_array_content_is_cacheable() {
        let mut req = cached_request("stable prefix ".repeat(500));
        req.messages[0].content = serde_json::json!([
            {
                "type": "text",
                "text": "stable prefix ".repeat(500)
            }
        ]);
        req.messages[0].cache_control = Some(CacheControl {
            cache_type: "ephemeral".to_string(),
            ttl: None,
        });

        let profile = build_profile(&req, 2000);
        let usage = compute("account-message-level", profile.as_ref());

        assert!(usage.cache_creation_input_tokens > 0);
    }

    #[test]
    fn test_long_system_without_cache_control_gets_default_cache_profile() {
        let mut req = cached_request("Hello".to_string());
        req.system = Some(vec![super::super::types::SystemMessage {
            text: "stable system prefix ".repeat(500),
            cache_control: None,
        }]);
        req.messages[0].content = serde_json::json!("Hello");

        let profile = build_profile(&req, 2000);
        let usage = compute("account-auto-system", profile.as_ref());

        assert!(usage.cache_creation_input_tokens > 0);
    }

    #[test]
    fn test_short_request_without_cache_control_does_not_get_default_cache_profile() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("short"),
                cache_control: None,
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
            conversation_id: None,
        };

        assert!(build_profile(&req, 32).is_none());
    }

    #[test]
    fn test_apply_usage_reports_cache_read_and_creation_separately() {
        let mut usage = serde_json::json!({
            "input_tokens": 2000,
            "output_tokens": 12
        });

        apply_usage(
            &mut usage,
            CacheUsage {
                cache_creation_input_tokens: 1200,
                cache_creation_5m_input_tokens: 400,
                cache_creation_1h_input_tokens: 800,
                cache_read_input_tokens: 300,
            },
        );

        assert_eq!(usage["input_tokens"], 500);
        assert_eq!(usage["output_tokens"], 12);
        assert_eq!(usage["cache_read_input_tokens"], 300);
        assert_eq!(usage["cache_creation_input_tokens"], 1200);
        assert_eq!(usage["cache_creation"]["ephemeral_5m_input_tokens"], 400);
        assert_eq!(usage["cache_creation"]["ephemeral_1h_input_tokens"], 800);
    }
}
