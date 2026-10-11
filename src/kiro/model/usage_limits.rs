//! 上游额度：缺失值不能当作零，只统计仍有效的额度池。
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageLimitsResponse {
    #[serde(default)]
    pub next_date_reset: Option<f64>,
    #[serde(default)]
    pub subscription_info: Option<SubscriptionInfo>,
    #[serde(default)]
    pub usage_breakdown_list: Vec<UsageBreakdown>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInfo {
    #[serde(default)]
    pub subscription_title: Option<String>,
}
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageBreakdown {
    pub resource_type: Option<String>,
    pub current_usage: Option<i64>,
    pub current_usage_with_precision: Option<f64>,
    #[serde(default)]
    pub bonuses: Vec<Bonus>,
    pub free_trial_info: Option<FreeTrialInfo>,
    pub next_date_reset: Option<f64>,
    pub usage_limit: Option<i64>,
    pub usage_limit_with_precision: Option<f64>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bonus {
    pub current_usage: Option<f64>,
    pub usage_limit: Option<f64>,
    pub status: Option<String>,
    pub expires_at: Option<f64>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeTrialInfo {
    pub current_usage: Option<i64>,
    pub current_usage_with_precision: Option<f64>,
    pub free_trial_expiry: Option<f64>,
    pub free_trial_status: Option<String>,
    pub usage_limit: Option<i64>,
    pub usage_limit_with_precision: Option<f64>,
}
#[derive(Debug, Clone)]
pub struct QuotaTotals {
    pub usage: f64,
    pub limit: f64,
    pub remaining: f64,
    // 重置或任一额度池过期后必须重新查询。
    pub valid_until: Option<f64>,
}
fn amount(precise: Option<f64>, integer: Option<i64>) -> anyhow::Result<f64> {
    precise
        .or_else(|| integer.map(|v| v as f64))
        .filter(|v| v.is_finite() && *v >= 0.0)
        .ok_or_else(|| anyhow::anyhow!("上游额度字段缺失或无效"))
}
fn not_expired(expiry: Option<f64>, now: f64) -> bool {
    expiry.is_none_or(|expiry| expiry.is_finite() && expiry > now)
}
impl UsageLimitsResponse {
    pub fn subscription_title(&self) -> Option<&str> {
        self.subscription_info
            .as_ref()?
            .subscription_title
            .as_deref()
    }
    pub fn quota_at(&self, now: f64) -> anyhow::Result<QuotaTotals> {
        // 请求参数为 AGENTIC_REQUEST，当前上游响应使用 CREDIT 表示计费额度。
        // 兼容旧响应的 AGENTIC_REQUEST；不能误取其它资源的限额。
        let breakdown = self
            .usage_breakdown_list
            .iter()
            .find(|b| b.resource_type.as_deref() == Some("CREDIT"))
            .or_else(|| {
                self.usage_breakdown_list
                    .iter()
                    .find(|b| b.resource_type.as_deref() == Some("AGENTIC_REQUEST"))
            })
            .or_else(|| {
                (self.usage_breakdown_list.len() == 1
                    && self.usage_breakdown_list[0].resource_type.is_none())
                .then(|| &self.usage_breakdown_list[0])
            })
            .ok_or_else(|| anyhow::anyhow!("上游未返回 CREDIT/AGENTIC_REQUEST 额度明细"))?;
        let mut totals = QuotaTotals {
            usage: 0.0,
            limit: 0.0,
            remaining: 0.0,
            valid_until: breakdown.next_date_reset.or(self.next_date_reset),
        };
        if totals
            .valid_until
            .is_some_and(|v| !v.is_finite() || v <= now)
        {
            anyhow::bail!("上游额度周期已到期，等待上游更新");
        }
        let mut add = |usage: f64, limit: f64, expiry: Option<f64>| {
            totals.usage += usage;
            totals.limit += limit;
            totals.remaining += (limit - usage).max(0.0);
            if let Some(expiry) = expiry {
                totals.valid_until = Some(totals.valid_until.map_or(expiry, |v| v.min(expiry)));
            }
        };
        add(
            amount(
                breakdown.current_usage_with_precision,
                breakdown.current_usage,
            )?,
            amount(breakdown.usage_limit_with_precision, breakdown.usage_limit)?,
            None,
        );
        if let Some(trial) = &breakdown.free_trial_info {
            if trial.free_trial_status.as_deref() == Some("ACTIVE")
                && not_expired(trial.free_trial_expiry, now)
            {
                add(
                    amount(trial.current_usage_with_precision, trial.current_usage)?,
                    amount(trial.usage_limit_with_precision, trial.usage_limit)?,
                    trial.free_trial_expiry,
                );
            }
        }
        for bonus in &breakdown.bonuses {
            if bonus.status.as_deref() == Some("ACTIVE") && not_expired(bonus.expires_at, now) {
                add(
                    amount(bonus.current_usage, None)?,
                    amount(bonus.usage_limit, None)?,
                    bonus.expires_at,
                );
            }
        }
        Ok(totals)
    }
    pub fn usage_limit(&self) -> f64 {
        self.quota_at(chrono::Utc::now().timestamp() as f64)
            .map_or(0.0, |q| q.limit)
    }
    pub fn current_usage(&self) -> f64 {
        self.quota_at(chrono::Utc::now().timestamp() as f64)
            .map_or(0.0, |q| q.usage)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn live_credit_resource_uses_precise_quota_instead_of_request_parameter_name() {
        let response: UsageLimitsResponse = serde_json::from_value(json!({
            "usageBreakdownList": [
                {"resourceType":"OTHER", "currentUsage":0, "usageLimit":99999},
                {"resourceType":"CREDIT", "currentUsage":35,
                    "currentUsageWithPrecision":35.91,"usageLimit":50,
                    "usageLimitWithPrecision":50.0,"freeTrialInfo":null,"bonuses":[]},
                {"resourceType":"AGENTIC_REQUEST", "currentUsage":0,"usageLimit":999}
            ]
        }))
        .unwrap();
        let q = response.quota_at(100.0).unwrap();
        assert_eq!(q.limit, 50.0);
        assert_eq!(q.usage, 35.91);
        assert!((q.remaining - 14.09).abs() < 1e-9);
    }
    #[test]
    fn real_pools_use_precision_fallback_expiry_and_independent_balances() {
        let response: UsageLimitsResponse = serde_json::from_value(json!({
            "usageBreakdownList": [{"resourceType":"OTHER", "usageLimit":99999}, {
                "resourceType":"AGENTIC_REQUEST", "currentUsage":60, "usageLimit":50,
                "freeTrialInfo":{"freeTrialStatus":"ACTIVE","freeTrialExpiry":90,
                    "currentUsageWithPrecision":0,"usageLimitWithPrecision":500},
                "bonuses":[{"status":"ACTIVE","currentUsage":2.5,"usageLimit":10},
                    {"status":"EXPIRED","currentUsage":0,"usageLimit":1000}]
            }]
        }))
        .unwrap();
        let q = response.quota_at(100.0).unwrap();
        assert_eq!(q.limit, 60.0);
        assert_eq!(q.usage, 62.5);
        assert_eq!(q.remaining, 7.5);
    }
    #[test]
    fn explicit_precise_zero_does_not_fall_back_and_missing_is_error() {
        let response: UsageLimitsResponse = serde_json::from_value(json!({
            "usageBreakdownList":[{"currentUsage":30,"currentUsageWithPrecision":0,
                "usageLimit":50,"usageLimitWithPrecision":50}]
        }))
        .unwrap();
        assert_eq!(response.quota_at(100.0).unwrap().remaining, 50.0);
        for value in [json!({}), json!({"usageBreakdownList":[{"usageLimit":50}]})] {
            let response: UsageLimitsResponse = serde_json::from_value(value).unwrap();
            assert!(response.quota_at(100.0).is_err());
        }
    }
}
