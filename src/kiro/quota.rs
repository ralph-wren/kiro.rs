//! 真实上游余额快照及本服务的 credit 计费账本。两者不混用、不从 Token 推算。
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::model::events::{Event, MeteringEvent};
use super::model::usage_limits::UsageLimitsResponse;
use crate::admin::types::BalanceResponse;

pub const BALANCE_CACHE_TTL_SECS: f64 = 300.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedBalance {
    #[serde(alias = "cached_at")]
    pub cached_at: f64,
    pub data: BalanceResponse,
    #[serde(default)]
    pub schema_version: u8,
    #[serde(default)]
    pub request_count: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<f64>,
}

impl CachedBalance {
    pub fn from_usage(
        id: u64,
        usage: &UsageLimitsResponse,
        request_count: Option<u64>,
    ) -> anyhow::Result<Self> {
        let now = Utc::now().timestamp() as f64;
        let q = usage.quota_at(now)?;
        Ok(Self {
            cached_at: now,
            schema_version: 2,
            request_count,
            valid_until: q.valid_until,
            data: BalanceResponse {
                id,
                subscription_title: usage.subscription_title().map(str::to_owned),
                current_usage: q.usage,
                usage_limit: q.limit,
                remaining: q.remaining,
                usage_percentage: if q.limit > 0.0 {
                    (100.0 * (1.0 - q.remaining / q.limit)).clamp(0.0, 100.0)
                } else {
                    0.0
                },
                next_reset_at: usage.next_date_reset,
            },
        })
    }

    pub fn is_fresh(&self, now: f64, request_count: u64, in_flight: usize) -> bool {
        self.schema_version == 2
            && self.cached_at.is_finite()
            && (0.0..BALANCE_CACHE_TTL_SECS).contains(&(now - self.cached_at))
            && self
                .valid_until
                .is_none_or(|expiry| expiry.is_finite() && expiry > now)
            && self.request_count == Some(request_count)
            && in_flight == 0
            && [
                self.data.remaining,
                self.data.current_usage,
                self.data.usage_limit,
            ]
            .iter()
            .all(|v| v.is_finite() && *v >= 0.0)
    }
}

fn day_key(timestamp: i64) -> String {
    (chrono::DateTime::from_timestamp(timestamp, 0).unwrap() + Duration::hours(8))
        .format("%Y-%m-%d")
        .to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreditDay {
    credits: f64,
    pending: u64,
    missing: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreditLedger {
    tracking_started_at: i64,
    total_credits: f64,
    days: BTreeMap<String, CreditDay>,
}

impl CreditLedger {
    fn valid(&self) -> bool {
        chrono::DateTime::from_timestamp(self.tracking_started_at, 0).is_some()
            && self.total_credits.is_finite()
            && self.total_credits >= 0.0
            && self.days.iter().all(|(key, day)| {
                chrono::NaiveDate::parse_from_str(key, "%Y-%m-%d").is_ok()
                    && day.credits.is_finite()
                    && day.credits >= 0.0
            })
    }
}

pub struct CreditStats {
    pub today: Option<f64>,
    pub today_confirmed: f64,
    pub total_confirmed: f64,
    pub missing_requests: u64,
    pub pending_requests: u64,
    pub tracking_started_at: i64,
    pub persistence_ok: bool,
}

/// 每次变更即时、原子落盘；不能把断流或缺失计费事件当作零消耗。
pub struct CreditLedgerStore {
    path: Option<PathBuf>,
    ledger: Mutex<CreditLedger>,
    persistence_ok: Mutex<bool>,
}

impl CreditLedgerStore {
    pub fn load(path: Option<PathBuf>) -> Arc<Self> {
        let mut persistence_ok = true;
        let loaded = path.as_ref().and_then(|p| match std::fs::read(p) {
            Ok(bytes) => match serde_json::from_slice::<CreditLedger>(&bytes) {
                Ok(ledger) if ledger.valid() => Some(ledger),
                Ok(_) => {
                    tracing::warn!("credit 账本数值无效，保留原文件");
                    persistence_ok = false;
                    None
                }
                Err(error) => {
                    tracing::warn!("credit 账本解析失败，保留原文件: {error}");
                    persistence_ok = false;
                    None
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!("credit 账本读取失败: {error}");
                persistence_ok = false;
                None
            }
        });
        let store = Arc::new(Self {
            path,
            persistence_ok: Mutex::new(persistence_ok),
            ledger: Mutex::new(loaded.unwrap_or_else(|| CreditLedger {
                tracking_started_at: Utc::now().timestamp(),
                total_credits: 0.0,
                days: BTreeMap::new(),
            })),
        });
        let mut ledger = store.ledger.lock();
        // 上次进程退出时仍未完成的调用不能判作零费用。
        let today = day_key(Utc::now().timestamp());
        let mut previous_pending = 0;
        for (key, day) in &mut ledger.days {
            if key != &today {
                previous_pending += day.pending;
            }
            day.missing += day.pending;
            day.pending = 0;
        }
        // 跨天未完成调用可能在今天计费，不能仅标记昨天缺失。
        ledger.days.entry(today).or_default().missing += previous_pending;
        store.save(&ledger);
        drop(ledger);
        store
    }

    fn save(&self, ledger: &CreditLedger) {
        let Some(path) = &self.path else {
            return;
        };
        if !*self.persistence_ok.lock() {
            return;
        }
        let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> anyhow::Result<()> {
            use std::io::Write;
            let bytes = serde_json::to_vec(ledger)?;
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            Ok(())
        })();
        if let Err(error) = result {
            *self.persistence_ok.lock() = false;
            tracing::warn!("credit 账本持久化失败，完整性标记已取消: {error}");
            let _ = std::fs::remove_file(&temp);
        }
    }

    pub fn stats(&self) -> CreditStats {
        self.stats_at(Utc::now().timestamp())
    }

    fn stats_at(&self, now: i64) -> CreditStats {
        let ledger = self.ledger.lock();
        let key = day_key(now);
        let credits = ledger.days.get(&key).map_or(0.0, |d| d.credits);
        let missing = ledger.days.get(&key).map_or(0, |d| d.missing);
        let pending = ledger.days.values().map(|d| d.pending).sum();
        let persistence_ok = *self.persistence_ok.lock();
        // 安装当天的旧请求无法追溯；次日起才可能提供完整本服务日消费。
        let complete = day_key(ledger.tracking_started_at) < key
            && missing == 0
            && pending == 0
            && persistence_ok
            && self.path.is_some();
        CreditStats {
            today: complete.then_some(credits),
            today_confirmed: credits,
            total_confirmed: ledger.total_credits,
            missing_requests: missing,
            pending_requests: pending,
            tracking_started_at: ledger.tracking_started_at,
            persistence_ok,
        }
    }

    pub fn begin(self: &Arc<Self>) -> CreditMeter {
        self.begin_at(Utc::now().timestamp())
    }

    fn begin_at(self: &Arc<Self>, now: i64) -> CreditMeter {
        let key = day_key(now);
        let mut ledger = self.ledger.lock();
        ledger.days.entry(key.clone()).or_default().pending += 1;
        self.save(&ledger);
        CreditMeter {
            store: self.clone(),
            key,
            has_metering: false,
            complete: false,
            invalid: false,
        }
    }
}

pub struct CreditMeter {
    store: Arc<CreditLedgerStore>,
    key: String,
    has_metering: bool,
    complete: bool,
    invalid: bool,
}

impl CreditMeter {
    pub fn observe(&mut self, event: &Event) {
        if let Event::Metering(event) = event {
            self.observe_metering(event);
        }
    }

    fn observe_metering(&mut self, event: &MeteringEvent) {
        let Some(usage) = event.credit_usage() else {
            self.invalid = true;
            return;
        };
        // 每个已解码 meteringEvent 是上游实际计费量；多个计费事件逐笔累加。
        self.has_metering = true;
        let mut ledger = self.store.ledger.lock();
        ledger.total_credits += usage;
        ledger
            .days
            .entry(day_key(Utc::now().timestamp()))
            .or_default()
            .credits += usage;
        self.store.save(&ledger);
    }

    pub fn invalidate(&mut self) {
        self.invalid = true;
    }

    pub fn finish(&mut self) {
        self.complete = true;
    }
}

impl Drop for CreditMeter {
    fn drop(&mut self) {
        let mut ledger = self.store.ledger.lock();
        let day = ledger.days.entry(self.key.clone()).or_default();
        day.pending = day.pending.saturating_sub(1);
        if !self.complete || !self.has_metering || self.invalid {
            day.missing += 1;
            let today = day_key(Utc::now().timestamp());
            if today != self.key {
                ledger.days.entry(today).or_default().missing += 1;
            }
        }
        self.store.save(&ledger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meters_each_real_credit_event_and_survives_restart() {
        let path = std::env::temp_dir().join(format!("kiro-credit-{}.json", uuid::Uuid::new_v4()));
        let store = CreditLedgerStore::load(Some(path.clone()));
        {
            let mut meter = store.begin();
            let event: MeteringEvent =
                serde_json::from_str(r#"{"unit":"credit","usage":0.0169543708291874}"#).unwrap();
            meter.observe_metering(&event);
            meter.observe_metering(&event);
            meter.finish();
        }
        let stats = store.stats();
        assert!((stats.today_confirmed - 2.0 * 0.0169543708291874).abs() < 1e-12);
        assert_eq!(stats.missing_requests, 0);
        assert!(stats.today.is_none()); // 部署当天不能补造凌晨到部署前的费用。
        drop(store);
        let store = CreditLedgerStore::load(Some(path.clone()));
        assert_eq!(store.stats().today_confirmed, stats.today_confirmed);
        assert_eq!(store.stats().total_confirmed, stats.total_confirmed);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_or_aborted_metering_is_unknown_not_zero() {
        let store = CreditLedgerStore::load(None);
        drop(store.begin());
        assert_eq!(store.stats().missing_requests, 1);
        assert!(store.stats().today.is_none());
    }

    fn metering_frame(payload: &[u8]) -> Vec<u8> {
        use crate::kiro::parser::crc::crc32;
        let mut headers = Vec::new();
        for (key, value) in [(":message-type", "event"), (":event-type", "meteringEvent")] {
            headers.push(key.len() as u8);
            headers.extend_from_slice(key.as_bytes());
            headers.push(7);
            headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
            headers.extend_from_slice(value.as_bytes());
        }
        let mut frame = Vec::new();
        frame.extend_from_slice(&((16 + headers.len() + payload.len()) as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame.extend_from_slice(&headers);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame
    }

    #[test]
    fn metering_frames_survive_chunk_boundaries_and_truncation_is_not_complete() {
        use crate::kiro::parser::decoder::EventStreamDecoder;
        let frame = metering_frame(br#"{"unit":"credit","usage":0.0123456789}"#);
        let mut decoder = EventStreamDecoder::new();
        let store = CreditLedgerStore::load(None);
        let mut meter = store.begin();
        for chunk in frame.chunks(3) {
            decoder.feed(chunk).unwrap();
            for result in decoder.decode_iter() {
                meter.observe(&Event::from_frame(result.unwrap()).unwrap());
            }
        }
        assert!(decoder.is_complete());
        meter.finish();
        drop(meter);
        assert_eq!(store.stats().today_confirmed, 0.0123456789);
        assert_eq!(store.stats().missing_requests, 0);

        let meter = store.begin();
        decoder.feed(&frame[..frame.len() - 1]).unwrap();
        assert_eq!(decoder.decode_iter().count(), 0);
        assert!(!decoder.is_complete());
        drop(meter);
        assert_eq!(store.stats().missing_requests, 1);
    }

    #[test]
    fn complete_day_requires_full_coverage_and_no_missing_or_pending_requests() {
        let path = std::env::temp_dir().join(format!("kiro-credit-{}.json", uuid::Uuid::new_v4()));
        let store = CreditLedgerStore::load(Some(path.clone()));
        let now = Utc::now().timestamp();
        store.ledger.lock().tracking_started_at = now - 86_400;
        assert_eq!(store.stats().today, Some(0.0));
        {
            let mut meter = store.begin();
            assert!(store.stats().today.is_none());
            meter.observe_metering(&MeteringEvent {
                unit: Some("credit".into()),
                usage: Some(0.42),
            });
            meter.finish();
        }
        assert_eq!(store.stats().today, Some(0.42));
        drop(store.begin());
        assert!(store.stats().today.is_none());
        assert_eq!(store.stats().today_confirmed, 0.42);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn aborted_cross_day_request_marks_both_days_incomplete() {
        let store = CreditLedgerStore::load(None);
        let now = Utc::now().timestamp();
        drop(store.begin_at(now - 86_400));
        assert_eq!(store.stats().missing_requests, 1);
        assert_eq!(store.ledger.lock().days[&day_key(now - 86_400)].missing, 1);
    }

    #[test]
    fn invalid_metering_is_unknown_but_explicit_zero_is_real() {
        for (unit, usage) in [
            (None, Some(0.0)),
            (Some("credit"), None),
            (Some("tokens"), Some(10.0)),
            (Some("credit"), Some(-1.0)),
        ] {
            let store = CreditLedgerStore::load(None);
            {
                let mut meter = store.begin();
                meter.observe_metering(&MeteringEvent {
                    unit: unit.map(str::to_owned),
                    usage,
                });
                meter.finish();
            }
            assert_eq!(store.stats().missing_requests, 1);
            assert_eq!(store.stats().total_confirmed, 0.0);
        }
        let store = CreditLedgerStore::load(None);
        {
            let mut meter = store.begin();
            meter.observe_metering(&MeteringEvent {
                unit: Some("credit".into()),
                usage: Some(0.0),
            });
            meter.finish();
        }
        assert_eq!(store.stats().missing_requests, 0);
    }

    #[test]
    fn crash_and_corrupt_ledger_cannot_claim_complete_usage() {
        let path = std::env::temp_dir().join(format!("kiro-credit-{}.json", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let mut days = BTreeMap::new();
        days.insert(
            day_key(now - 86_400),
            CreditDay {
                pending: 1,
                ..Default::default()
            },
        );
        let ledger = CreditLedger {
            tracking_started_at: now - 172_800,
            total_credits: 0.0,
            days,
        };
        std::fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        let store = CreditLedgerStore::load(Some(path.clone()));
        assert_eq!(store.stats().missing_requests, 1);
        assert!(store.stats().today.is_none());
        drop(store);
        std::fs::write(&path, b"corrupt").unwrap();
        let store = CreditLedgerStore::load(Some(path.clone()));
        assert!(!store.stats().persistence_ok);
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn balance_snapshot_expires_on_requests_ttl_and_pool_expiry() {
        let now = Utc::now().timestamp() as f64;
        let usage: UsageLimitsResponse = serde_json::from_value(serde_json::json!({
            "subscriptionInfo":{"subscriptionTitle":"KIRO FREE"},
            "usageBreakdownList":[{"currentUsageWithPrecision":12.345,
                "usageLimitWithPrecision":50,
                "freeTrialInfo":{"freeTrialStatus":"ACTIVE","freeTrialExpiry":now+60.0,
                    "currentUsageWithPrecision":100,"usageLimitWithPrecision":500}}]
        }))
        .unwrap();
        let cached = CachedBalance::from_usage(7, &usage, Some(3)).unwrap();
        assert_eq!(cached.data.subscription_title.as_deref(), Some("KIRO FREE"));
        assert_eq!(cached.data.usage_limit, 550.0);
        assert!((cached.data.remaining - 437.655).abs() < 1e-9);
        assert!(cached.is_fresh(now, 3, 0));
        assert!(!cached.is_fresh(now, 4, 0));
        assert!(!cached.is_fresh(now, 3, 1));
        assert!(!cached.is_fresh(now + 61.0, 3, 0));
        assert!(!cached.is_fresh(now + 301.0, 3, 0));
    }
}
