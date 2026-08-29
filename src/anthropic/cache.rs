//! Anthropic prompt cache usage simulation.
//!
//! Kiro accepts `cachePoint` in requests, but its event stream does not expose
//! Claude-compatible cache read/write token counters. This tracker mirrors the
//! request-side `cache_control` breakpoints so `/v1/messages` can return the
//! expected Anthropic usage fields.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use parking_lot::Mutex;
use rusqlite::{Connection, params};
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
    fingerprint: String,
    expires_at: Instant,
    protected_at: Instant,
    model: String,
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
    persistence: Option<PromptCachePersistence>,
}

#[derive(Debug)]
struct PromptCachePersistence {
    tx: Sender<PersistenceCommand>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
enum PersistenceCommand {
    Upsert {
        account_id: String,
        fingerprint: String,
        model: String,
        ttl_seconds: u64,
    },
    Delete {
        account_id: String,
        fingerprint: String,
        model: String,
    },
    DeleteExpired {
        now: i64,
    },
    Shutdown,
}

impl PromptCacheTracker {
    fn new() -> Self {
        Self {
            entries_by_account: HashMap::new(),
            last_prune: Instant::now(),
            persistence: None,
        }
    }

    fn init_persistence(&mut self, cache_dir: &Path) -> anyhow::Result<usize> {
        let (persistence, entries) = PromptCachePersistence::open(cache_dir)?;
        let count = entries.len();
        for (account_id, fingerprint, entry) in entries {
            let key = cache_entry_key(&entry.model, &fingerprint);
            self.entries_by_account
                .entry(account_id)
                .or_default()
                .insert(key, entry);
        }
        self.persistence = Some(persistence);
        Ok(count)
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

        let Some(entries) = self.entries_by_account.get(account_id) else {
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
            let entry_key = cache_entry_key(&profile.model, &bp.fingerprint);
            let Some(entry) = entries.get(&entry_key) else {
                continue;
            };
            if entry.expires_at < now || entry.model != profile.model {
                continue;
            }

            matched_tokens = bp
                .cumulative_tokens
                .min(profile.total_input_tokens)
                .min(last_tokens);
            break;
        }

        let creation = if matched_tokens > 0 {
            0
        } else {
            last_tokens.max(0)
        };
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
                cache_entry_key(&profile.model, &bp.fingerprint),
                CacheEntry {
                    fingerprint: bp.fingerprint.clone(),
                    expires_at: now + bp.ttl,
                    protected_at: now,
                    model: profile.model.clone(),
                },
            );
            if let Some(persistence) = &self.persistence {
                if let Err(error) =
                    persistence.upsert(account_id, &bp.fingerprint, &profile.model, bp.ttl)
                {
                    tracing::warn!("保存 Prompt Cache 亲和记录失败: {}", error);
                }
            }
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
                if let Some(removed) = entries.remove(&key)
                    && let Some(persistence) = &self.persistence
                    && let Err(error) =
                        persistence.delete(account_id, &removed.fingerprint, &removed.model)
                {
                    tracing::warn!("淘汰 Prompt Cache 亲和记录失败: {}", error);
                }
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
        if let Some(persistence) = &self.persistence
            && let Err(error) = persistence.delete_expired()
        {
            tracing::warn!("清理过期 Prompt Cache 亲和记录失败: {}", error);
        }
    }

    fn active_entry_counts(&self, now: Instant) -> HashMap<String, u64> {
        self.entries_by_account
            .iter()
            .filter_map(|(account_id, entries)| {
                let count = entries
                    .values()
                    .filter(|entry| entry.expires_at >= now)
                    .count() as u64;
                (count > 0).then(|| (account_id.clone(), count))
            })
            .collect()
    }
}

impl PromptCachePersistence {
    fn open(cache_dir: &Path) -> anyhow::Result<(Self, Vec<(String, String, CacheEntry)>)> {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("创建 Prompt Cache 亲和目录失败: {}", cache_dir.display()))?;
        let path = cache_dir.join("prompt_cache_affinity.sqlite3");
        let connection = Connection::open(&path)
            .with_context(|| format!("打开 Prompt Cache 亲和数据库失败: {}", path.display()))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .context("设置 Prompt Cache SQLite busy_timeout 失败")?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                CREATE TABLE IF NOT EXISTS prompt_cache_affinity (
                    account_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    model TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    protected_at INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    PRIMARY KEY (account_id, fingerprint, model)
                );
                CREATE INDEX IF NOT EXISTS idx_prompt_cache_affinity_expires_at
                    ON prompt_cache_affinity(expires_at);
                "#,
            )
            .context("初始化 Prompt Cache 亲和数据库失败")?;
        let entries = load_active(&connection)?;
        let (tx, rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("kiro-prompt-cache-sqlite".to_string())
            .spawn(move || run_persistence_worker(connection, rx))
            .context("启动 Prompt Cache SQLite 持久化线程失败")?;
        Ok((
            Self {
                tx,
                worker: Some(worker),
            },
            entries,
        ))
    }

    fn upsert(
        &self,
        account_id: &str,
        fingerprint: &str,
        model: &str,
        ttl: Duration,
    ) -> anyhow::Result<()> {
        self.tx
            .send(PersistenceCommand::Upsert {
                account_id: account_id.to_string(),
                fingerprint: fingerprint.to_string(),
                model: model.to_string(),
                ttl_seconds: ttl.as_secs().max(1),
            })
            .context("发送 Prompt Cache upsert 任务失败")
    }

    fn delete_expired(&self) -> anyhow::Result<()> {
        self.tx
            .send(PersistenceCommand::DeleteExpired {
                now: unix_timestamp(),
            })
            .context("发送 Prompt Cache 清理任务失败")
    }

    fn delete(&self, account_id: &str, fingerprint: &str, model: &str) -> anyhow::Result<()> {
        self.tx
            .send(PersistenceCommand::Delete {
                account_id: account_id.to_string(),
                fingerprint: fingerprint.to_string(),
                model: model.to_string(),
            })
            .context("发送 Prompt Cache 删除任务失败")
    }
}

impl Drop for PromptCachePersistence {
    fn drop(&mut self) {
        let _ = self.tx.send(PersistenceCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn load_active(connection: &Connection) -> anyhow::Result<Vec<(String, String, CacheEntry)>> {
    let now_epoch = unix_timestamp();
    connection.execute(
        "DELETE FROM prompt_cache_affinity WHERE expires_at <= ?1",
        params![now_epoch],
    )?;
    let now = Instant::now();
    let mut statement = connection.prepare(
        "SELECT account_id, fingerprint, model, expires_at, protected_at \
             FROM prompt_cache_affinity WHERE expires_at > ?1",
    )?;
    let rows = statement.query_map(params![now_epoch], |row| {
        let expires_at_epoch: i64 = row.get(3)?;
        let protected_at_epoch: i64 = row.get(4)?;
        let remaining = expires_at_epoch.saturating_sub(now_epoch) as u64;
        let protected_elapsed = now_epoch.saturating_sub(protected_at_epoch) as u64;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            CacheEntry {
                fingerprint: row.get(1)?,
                expires_at: now + Duration::from_secs(remaining),
                protected_at: now
                    .checked_sub(Duration::from_secs(protected_elapsed))
                    .unwrap_or(now),
                model: row.get(2)?,
            },
        ))
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("读取 Prompt Cache 亲和记录失败")
}

fn run_persistence_worker(connection: Connection, rx: Receiver<PersistenceCommand>) {
    while let Ok(command) = rx.recv() {
        match command {
            PersistenceCommand::Upsert {
                account_id,
                fingerprint,
                model,
                ttl_seconds,
            } => {
                let now = unix_timestamp();
                if let Err(error) = connection.execute(
                    "INSERT INTO prompt_cache_affinity \
             (account_id, fingerprint, model, expires_at, protected_at, ttl_seconds) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(account_id, fingerprint, model) DO UPDATE SET \
             expires_at=excluded.expires_at, protected_at=excluded.protected_at, \
             ttl_seconds=excluded.ttl_seconds",
                    params![
                        account_id,
                        fingerprint,
                        model,
                        now.saturating_add(ttl_seconds as i64),
                        now,
                        ttl_seconds,
                    ],
                ) {
                    tracing::warn!("保存 Prompt Cache 亲和记录失败: {}", error);
                }
            }
            PersistenceCommand::Delete {
                account_id,
                fingerprint,
                model,
            } => {
                if let Err(error) = connection.execute(
                    "DELETE FROM prompt_cache_affinity \
             WHERE account_id = ?1 AND fingerprint = ?2 AND model = ?3",
                    params![account_id, fingerprint, model],
                ) {
                    tracing::warn!("删除 Prompt Cache 亲和记录失败: {}", error);
                }
            }
            PersistenceCommand::DeleteExpired { now } => {
                if let Err(error) = connection.execute(
                    "DELETE FROM prompt_cache_affinity WHERE expires_at <= ?1",
                    params![now],
                ) {
                    tracing::warn!("清理 Prompt Cache 亲和记录失败: {}", error);
                }
            }
            PersistenceCommand::Shutdown => break,
        }
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn cache_entry_key(model: &str, fingerprint: &str) -> String {
    format!("{}\0{}", model, fingerprint)
}

static TRACKER: OnceLock<Mutex<PromptCacheTracker>> = OnceLock::new();
static CACHE_CREATION_USAGE_MULTIPLIER_BITS: AtomicU64 = AtomicU64::new(1.0f64.to_bits());
static CACHE_READ_USAGE_MULTIPLIER_BITS: AtomicU64 = AtomicU64::new(1.0f64.to_bits());

fn tracker() -> &'static Mutex<PromptCacheTracker> {
    TRACKER.get_or_init(|| Mutex::new(PromptCacheTracker::new()))
}

pub(crate) fn build_profile(
    req: &MessagesRequest,
    total_input_tokens: i32,
) -> Option<CacheProfile> {
    tracker().lock().build_profile(req, total_input_tokens)
}

pub(crate) fn init_persistence(cache_dir: &Path) -> anyhow::Result<usize> {
    tracker().lock().init_persistence(cache_dir)
}

/// 返回当前请求可能命中的账号，按缓存前缀长度从高到低排序。
///
/// 这里只做只读探测，不会刷新缓存 TTL；请求成功完成后由 `update`
/// 统一续期缓存与账号保护窗口。
pub(crate) fn preferred_account_ids(profile: Option<&CacheProfile>) -> Vec<String> {
    let Some(profile) = profile else {
        return Vec::new();
    };
    if profile.breakpoints.is_empty() {
        return Vec::new();
    }

    let now = Instant::now();
    let min_tokens = min_cacheable_tokens(&profile.model);
    let last = profile.breakpoints.last().expect("profile has breakpoints");
    let last_tokens = last.cumulative_tokens.min(profile.total_input_tokens);
    let max_cacheable = (profile.total_input_tokens as f64 * MAX_CACHE_RATIO).floor() as i32;
    let last_tokens = last_tokens.min(max_cacheable);

    let mut tracker = tracker().lock();
    tracker.prune_if_needed(now);

    let mut matches = Vec::new();
    for (account_id, entries) in &tracker.entries_by_account {
        let mut matched_tokens = 0;
        for breakpoint in profile.breakpoints.iter().rev() {
            if breakpoint.cumulative_tokens < min_tokens {
                continue;
            }
            let entry_key = cache_entry_key(&profile.model, &breakpoint.fingerprint);
            let Some(entry) = entries.get(&entry_key) else {
                continue;
            };
            if entry.expires_at < now || entry.model != profile.model {
                continue;
            }

            matched_tokens = breakpoint
                .cumulative_tokens
                .min(profile.total_input_tokens)
                .min(last_tokens);
            break;
        }

        if matched_tokens > 0 {
            matches.push((account_id.clone(), matched_tokens));
        }
    }

    matches.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    matches
        .into_iter()
        .map(|(account_id, _)| account_id)
        .collect()
}

/// 返回当前仍有有效 Prompt Cache 的账号。
///
/// 这些账号默认只保留给能命中其缓存前缀的请求使用；真正的缓存命中
/// 仍由 `preferred_account_ids` 决定。
pub(crate) fn active_account_ids(protection_ttl: Duration) -> Vec<String> {
    if protection_ttl.is_zero() {
        return Vec::new();
    }

    let now = Instant::now();
    let mut tracker = tracker().lock();
    tracker.prune_if_needed(now);
    tracker
        .entries_by_account
        .iter()
        .filter(|(_, entries)| {
            entries.values().any(|entry| {
                entry.expires_at >= now && now.duration_since(entry.protected_at) < protection_ttl
            })
        })
        .map(|(account_id, _)| account_id.clone())
        .collect()
}

pub(crate) fn active_entry_counts() -> HashMap<String, u64> {
    let now = Instant::now();
    let mut tracker = tracker().lock();
    tracker.prune_if_needed(now);
    tracker.active_entry_counts(now)
}

pub(crate) fn compute(account_id: &str, profile: Option<&CacheProfile>) -> CacheUsage {
    tracker().lock().compute(account_id, profile)
}

pub(crate) fn update(account_id: &str, profile: Option<&CacheProfile>) {
    tracker().lock().update(account_id, profile)
}

pub(crate) fn set_usage_multipliers(cache_creation_multiplier: f64, cache_read_multiplier: f64) {
    CACHE_CREATION_USAGE_MULTIPLIER_BITS.store(
        sanitize_multiplier(cache_creation_multiplier).to_bits(),
        Ordering::Relaxed,
    );
    CACHE_READ_USAGE_MULTIPLIER_BITS.store(
        sanitize_multiplier(cache_read_multiplier).to_bits(),
        Ordering::Relaxed,
    );
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
        Some(ttl) if ttl.eq_ignore_ascii_case("1h") => Some(ONE_HOUR_CACHE_TTL),
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
        Some(Value::String(ttl)) if ttl.eq_ignore_ascii_case("1h") => Some(ONE_HOUR_CACHE_TTL),
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
    let cache_creation_multiplier =
        f64::from_bits(CACHE_CREATION_USAGE_MULTIPLIER_BITS.load(Ordering::Relaxed));
    let cache_read_multiplier =
        f64::from_bits(CACHE_READ_USAGE_MULTIPLIER_BITS.load(Ordering::Relaxed));
    apply_usage_with_multipliers(
        usage,
        cache_usage,
        cache_creation_multiplier,
        cache_read_multiplier,
    );
}

fn apply_usage_with_multipliers(
    usage: &mut Value,
    cache_usage: CacheUsage,
    cache_creation_multiplier: f64,
    cache_read_multiplier: f64,
) {
    let Some(usage_obj) = usage.as_object_mut() else {
        return;
    };

    let cache_creation_input_tokens = scale_tokens(
        cache_usage.cache_creation_input_tokens,
        cache_creation_multiplier,
    );
    let cache_creation_5m_input_tokens = scale_tokens(
        cache_usage.cache_creation_5m_input_tokens,
        cache_creation_multiplier,
    );
    let cache_creation_1h_input_tokens = scale_tokens(
        cache_usage.cache_creation_1h_input_tokens,
        cache_creation_multiplier,
    );
    let cache_read_input_tokens =
        scale_tokens(cache_usage.cache_read_input_tokens, cache_read_multiplier);

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
        Value::Number((cache_creation_input_tokens as i64).into()),
    );
    usage_obj.insert(
        "cache_read_input_tokens".to_string(),
        Value::Number((cache_read_input_tokens as i64).into()),
    );

    let mut cache_creation_5m = cache_creation_5m_input_tokens;
    let cache_creation_1h = cache_creation_1h_input_tokens;
    let split_cache_creation_tokens = cache_creation_5m + cache_creation_1h;
    if cache_creation_input_tokens > split_cache_creation_tokens {
        cache_creation_5m += cache_creation_input_tokens - split_cache_creation_tokens;
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

fn sanitize_multiplier(multiplier: f64) -> f64 {
    if multiplier.is_finite() && multiplier >= 0.0 {
        multiplier
    } else {
        1.0
    }
}

fn scale_tokens(tokens: i32, multiplier: f64) -> i32 {
    if tokens <= 0 {
        return 0;
    }
    ((tokens as f64) * sanitize_multiplier(multiplier))
        .round()
        .clamp(0.0, i32::MAX as f64) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::types::{CacheControl, Message, MessagesRequest};

    fn cached_request(text: String) -> MessagesRequest {
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
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
            stream: Some(false),
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
    fn test_active_entry_counts_tracks_live_cache_writes_without_duplicates() {
        let req = cached_request("active cache prefix ".repeat(500));
        let mut tracker = PromptCacheTracker::new();
        let profile = tracker.build_profile(&req, 2000);

        tracker.update("account-a", profile.as_ref());
        tracker.update("account-a", profile.as_ref());
        assert_eq!(tracker.active_entry_counts(Instant::now())["account-a"], 1);

        for entry in tracker
            .entries_by_account
            .get_mut("account-a")
            .unwrap()
            .values_mut()
        {
            entry.expires_at = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        }
        assert!(tracker.active_entry_counts(Instant::now()).is_empty());
    }

    #[test]
    fn test_prompt_cache_affinity_persists_and_restores() {
        let cache_dir = tempfile::tempdir().unwrap();
        let req = cached_request("persistent cache prefix ".repeat(500));

        let mut writer = PromptCacheTracker::new();
        assert_eq!(writer.init_persistence(cache_dir.path()).unwrap(), 0);
        let profile = writer.build_profile(&req, 2500);
        let first = writer.compute("persistent-account", profile.as_ref());
        assert!(first.cache_creation_input_tokens > 0);
        writer.update("persistent-account", profile.as_ref());
        drop(writer);

        let mut reader = PromptCacheTracker::new();
        assert_eq!(reader.init_persistence(cache_dir.path()).unwrap(), 1);
        let restored_profile = reader.build_profile(&req, 2500);
        let restored = reader.compute("persistent-account", restored_profile.as_ref());

        assert_eq!(restored.cache_creation_input_tokens, 0);
        assert!(restored.cache_read_input_tokens > 0);
    }

    #[test]
    fn test_prompt_cache_affinity_isolated_by_model() {
        let text = "same prefix different model ".repeat(1000);
        let req = cached_request(text.clone());
        let mut tracker = PromptCacheTracker::new();
        let sonnet_profile = tracker.build_profile(&req, 2500);
        tracker.update("model-account", sonnet_profile.as_ref());

        let mut opus_req = cached_request(text);
        opus_req.model = "claude-opus-4-1-20250805".to_string();
        let opus_profile = tracker.build_profile(&opus_req, 8000);
        let opus_usage = tracker.compute("model-account", opus_profile.as_ref());

        assert_eq!(opus_usage.cache_read_input_tokens, 0);
        assert!(opus_usage.cache_creation_input_tokens > 0);
    }

    #[test]
    fn test_compute_does_not_refresh_affinity_before_success() {
        let req = cached_request("success only affinity ".repeat(500));
        let mut tracker = PromptCacheTracker::new();
        let profile = tracker.build_profile(&req, 2500);
        tracker.update("success-account", profile.as_ref());

        let profile = profile.unwrap();
        let breakpoint = profile.breakpoints.last().unwrap();
        let key = cache_entry_key(&profile.model, &breakpoint.fingerprint);
        tracker
            .entries_by_account
            .get_mut("success-account")
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .protected_at = Instant::now() - Duration::from_secs(1);
        let before = tracker.entries_by_account["success-account"][&key].protected_at;

        let usage = tracker.compute("success-account", Some(&profile));
        let after_compute = tracker.entries_by_account["success-account"][&key].protected_at;
        assert!(usage.cache_read_input_tokens > 0);
        assert_eq!(after_compute, before);

        tracker.update("success-account", Some(&profile));
        let after_success = tracker.entries_by_account["success-account"][&key].protected_at;
        assert!(after_success > before);
    }

    #[test]
    fn test_preferred_account_ids_returns_cached_accounts() {
        let req = cached_request("preferred account ".repeat(500));
        let profile = build_profile(&req, 2000);
        let account_id = "account-preferred-cache";

        let first = compute(account_id, profile.as_ref());
        assert!(first.cache_creation_input_tokens > 0);
        update(account_id, profile.as_ref());

        let preferred = preferred_account_ids(profile.as_ref());
        assert_eq!(preferred, vec![account_id.to_string()]);
        assert!(active_account_ids(Duration::from_secs(300)).contains(&account_id.to_string()));
        assert!(active_account_ids(Duration::ZERO).is_empty());
    }

    #[test]
    fn test_prompt_cache_tracker_does_not_create_changing_suffix_after_hit() {
        fn request_with_suffix(suffix: &str) -> MessagesRequest {
            MessagesRequest {
                model: "claude-sonnet-4-5-20250929".to_string(),
                max_tokens: 1024,
                stop_sequences: None,
                messages: vec![Message {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {
                            "type": "text",
                            "text": "stable prefix ".repeat(500),
                            "cache_control": { "type": "ephemeral" }
                        },
                        {
                            "type": "text",
                            "text": suffix,
                            "cache_control": { "type": "ephemeral" }
                        }
                    ]),
                    cache_control: None,
                }],
                stream: Some(false),
                system: None,
                tools: None,
                tool_choice: None,
                thinking: None,
                output_config: None,
                metadata: None,
                conversation_id: Some("test-cache-changing-suffix".to_string()),
            }
        }

        let first_req = request_with_suffix(&"first tail ".repeat(160));
        let first_profile = build_profile(&first_req, 2500);
        let first = compute("account-changing-suffix", first_profile.as_ref());
        update("account-changing-suffix", first_profile.as_ref());

        let second_req = request_with_suffix(&"second tail ".repeat(180));
        let second_profile = build_profile(&second_req, 2700);
        let second = compute("account-changing-suffix", second_profile.as_ref());

        assert!(first.cache_creation_input_tokens > 0);
        assert!(second.cache_read_input_tokens > 0);
        assert_eq!(second.cache_creation_input_tokens, 0);
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
    fn test_one_hour_cache_control_reports_1h_creation_tokens() {
        let mut req = cached_request("stable one hour prefix ".repeat(500));
        req.messages[0].content = serde_json::json!([
            {
                "type": "text",
                "text": "stable one hour prefix ".repeat(500),
                "cache_control": { "type": "ephemeral", "ttl": "1h" }
            }
        ]);

        let profile = build_profile(&req, 3000);
        let usage = compute("account-one-hour-cache", profile.as_ref());

        assert!(usage.cache_creation_input_tokens > 0);
        assert_eq!(usage.cache_creation_5m_input_tokens, 0);
        assert_eq!(
            usage.cache_creation_1h_input_tokens,
            usage.cache_creation_input_tokens
        );
    }

    #[test]
    fn test_mixed_cache_control_reports_5m_and_1h_creation_tokens() {
        let mut req = cached_request("unused".to_string());
        req.messages[0].content = serde_json::json!([
            {
                "type": "text",
                "text": "stable five minute prefix ".repeat(300),
                "cache_control": { "type": "ephemeral" }
            },
            {
                "type": "text",
                "text": "stable one hour suffix ".repeat(300),
                "cache_control": { "type": "ephemeral", "ttl": "1H" }
            }
        ]);

        let profile = build_profile(&req, 5000);
        let usage = compute("account-mixed-cache", profile.as_ref());

        assert!(usage.cache_creation_5m_input_tokens > 0);
        assert!(usage.cache_creation_1h_input_tokens > 0);
        assert_eq!(
            usage.cache_creation_input_tokens,
            usage.cache_creation_5m_input_tokens + usage.cache_creation_1h_input_tokens
        );
    }

    #[test]
    fn test_short_request_without_cache_control_does_not_get_default_cache_profile() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            stop_sequences: None,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("short"),
                cache_control: None,
            }],
            stream: Some(false),
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

    #[test]
    fn test_apply_usage_deducts_unscaled_cache_tokens_from_input() {
        let mut usage = serde_json::json!({
            "input_tokens": 2000,
            "output_tokens": 12
        });

        apply_usage_with_multipliers(
            &mut usage,
            CacheUsage {
                cache_creation_input_tokens: 1200,
                cache_creation_5m_input_tokens: 1200,
                cache_creation_1h_input_tokens: 0,
                cache_read_input_tokens: 300,
            },
            5.0,
            5.0,
        );

        assert_eq!(usage["input_tokens"], 500);
        assert_eq!(usage["cache_creation_input_tokens"], 6000);
        assert_eq!(usage["cache_read_input_tokens"], 1500);
        assert_eq!(usage["cache_creation"]["ephemeral_5m_input_tokens"], 6000);
    }

    #[test]
    fn test_scale_tokens_applies_multiplier() {
        assert_eq!(scale_tokens(1000, 1.5), 1500);
        assert_eq!(scale_tokens(1001, 0.5), 501);
        assert_eq!(scale_tokens(1000, 0.0), 0);
    }
}
