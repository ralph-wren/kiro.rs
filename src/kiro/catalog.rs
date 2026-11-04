//! Live Kiro model discovery. Metadata requests share authentication and proxy
//! settings with inference, but never count as a successful inference call.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::endpoint::RequestContext;
use super::machine_id;
use super::provider::KiroProvider;
use crate::anthropic::types::Model;
use crate::anthropic::{
    get_context_window_size_with_mappings, list_models_with_mappings, map_model_with_mappings,
};

const CACHE_TTL: Duration = Duration::from_secs(300);
const FAILURE_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpstreamModel {
    pub model_id: String,
    #[serde(default)]
    model_name: String,
    #[serde(default)]
    token_limits: TokenLimits,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenLimits {
    max_input_tokens: Option<i32>,
    max_output_tokens: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelsPage {
    models: Vec<UpstreamModel>,
    next_token: Option<String>,
}

#[derive(Default)]
pub(super) struct ModelCache {
    models: Vec<UpstreamModel>,
    refreshed_at: Option<Instant>,
    failed_at: Option<Instant>,
}

impl KiroProvider {
    pub(super) async fn available_models(&self) -> anyhow::Result<Vec<UpstreamModel>> {
        // One refresh at a time. A failed discovery does not block every message
        // on another upstream attempt, and a previously loaded catalog survives.
        let _refresh = self.model_refresh.lock().await;
        {
            let cache = self.model_cache.lock();
            if cache
                .refreshed_at
                .is_some_and(|at| at.elapsed() < CACHE_TTL)
            {
                return Ok(cache.models.clone());
            }
            if cache
                .failed_at
                .is_some_and(|at| at.elapsed() < FAILURE_BACKOFF)
            {
                anyhow::ensure!(!cache.models.is_empty(), "上游模型列表暂时不可用");
                return Ok(cache.models.clone());
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(20), self.fetch_models()).await;
        let mut cache = self.model_cache.lock();
        match result {
            Ok(Ok(models)) => {
                cache.models = models;
                cache.refreshed_at = Some(Instant::now());
                cache.failed_at = None;
            }
            _ => {
                cache.failed_at = Some(Instant::now());
                tracing::warn!("上游模型列表刷新失败，保留已有模型缓存");
                anyhow::ensure!(!cache.models.is_empty(), "上游模型列表暂时不可用");
            }
        }
        Ok(cache.models.clone())
    }

    async fn fetch_models(&self) -> anyhow::Result<Vec<UpstreamModel>> {
        let ctx = self.token_manager.acquire_context(None).await?;
        let config = self.token_manager.config();
        let machine = machine_id::generate_from_credentials(&ctx.credentials, config);
        let rctx = RequestContext {
            credentials: &ctx.credentials,
            token: &ctx.token,
            machine_id: &machine,
            config,
        };
        let endpoint = self.endpoint_for(&ctx.credentials)?;
        let mut url = reqwest::Url::parse(&endpoint.api_url(&rctx))?;
        url.set_path("/ListAvailableModels");
        url.set_query(None);
        let client = self.client_for(&ctx.credentials)?;
        let mut next = None;
        let mut seen_tokens = HashSet::new();
        let mut models = Vec::new();
        // Bound pagination even when an upstream returns malformed tokens.
        for _ in 0..20 {
            let mut page_url = url.clone();
            {
                let mut query = page_url.query_pairs_mut();
                query
                    .append_pair("origin", "AI_EDITOR")
                    .append_pair("maxResults", "50");
                if let Some(profile) = ctx.credentials.request_profile_arn() {
                    query.append_pair("profileArn", profile);
                }
                if let Some(token) = next.as_deref() {
                    query.append_pair("nextToken", token);
                }
            }
            let response = endpoint
                .decorate_api(client.get(page_url), &rctx)
                .header("accept", "application/json")
                .timeout(Duration::from_secs(10))
                .send()
                .await?;
            // Do not include response bodies or authenticated URLs in errors.
            anyhow::ensure!(
                response.status().is_success(),
                "获取模型列表失败: {}",
                response.status()
            );
            let page: ModelsPage = response.json().await?;
            models.extend(
                page.models
                    .into_iter()
                    .filter(|model| !model.model_id.trim().is_empty()),
            );
            next = page.next_token.filter(|token| !token.is_empty());
            if let Some(token) = &next {
                anyhow::ensure!(seen_tokens.insert(token.clone()), "模型列表分页标记重复");
            } else {
                let mut ids = HashSet::new();
                models.retain(|model| ids.insert(model.model_id.clone()));
                anyhow::ensure!(!models.is_empty(), "上游返回空模型列表");
                return Ok(models);
            }
        }
        anyhow::bail!("模型列表分页超过上限")
    }

    pub async fn effective_model_mappings(
        &self,
        configured: HashMap<String, String>,
    ) -> HashMap<String, String> {
        match self.available_models().await {
            Ok(models) => merge_mappings(&models, configured),
            Err(_) => configured,
        }
    }

    pub fn context_window_size(&self, model: &str, mappings: &HashMap<String, String>) -> i32 {
        let mapped = map_model_with_mappings(model, mappings);
        self.model_cache
            .lock()
            .models
            .iter()
            .find(|entry| Some(entry.model_id.as_str()) == mapped.as_deref())
            .and_then(|entry| entry.token_limits.max_input_tokens)
            .filter(|limit| *limit > 0)
            .unwrap_or_else(|| get_context_window_size_with_mappings(model, mappings))
    }

    pub async fn models_with_mappings(
        &self,
        configured: &HashMap<String, String>,
    ) -> anyhow::Result<Vec<Model>> {
        let upstream = self.available_models().await?;
        let mappings = merge_mappings(&upstream, configured.clone());
        let mut models: Vec<Model> = upstream
            .iter()
            .map(|entry| Model {
                id: entry.model_id.clone(),
                object: "model".into(),
                created: 0,
                owned_by: "kiro".into(),
                display_name: if entry.model_name.is_empty() {
                    entry.model_id.clone()
                } else {
                    entry.model_name.clone()
                },
                model_type: "chat".into(),
                max_tokens: entry
                    .token_limits
                    .max_output_tokens
                    .filter(|limit| *limit > 0)
                    .unwrap_or(64000),
            })
            .collect();
        // Keep supported legacy aliases for clients already using dated IDs.
        for mut alias in list_models_with_mappings(&mappings) {
            if models
                .iter()
                .any(|model| model.id.eq_ignore_ascii_case(&alias.id))
            {
                continue;
            }
            let mapped = map_model_with_mappings(&alias.id, &mappings);
            if let Some(target) = upstream
                .iter()
                .find(|entry| Some(entry.model_id.as_str()) == mapped.as_deref())
            {
                alias.max_tokens = target
                    .token_limits
                    .max_output_tokens
                    .filter(|limit| *limit > 0)
                    .unwrap_or(64000);
                models.push(alias);
            }
        }
        Ok(models)
    }
}

fn merge_mappings(
    models: &[UpstreamModel],
    configured: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut mappings = HashMap::new();
    for model in models {
        mappings.insert(model.model_id.clone(), model.model_id.clone());
        if model.model_id.starts_with("claude-") {
            mappings.insert(model.model_id.replace('.', "-"), model.model_id.clone());
        }
    }
    // Explicit aliases retain precedence, including case-insensitive overrides.
    for (source, target) in configured {
        mappings.retain(|key, _| !key.trim().eq_ignore_ascii_case(source.trim()));
        mappings.insert(source, target);
    }
    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_enables_upstream_ids_without_accepting_unknown_models() {
        let models: Vec<UpstreamModel> = serde_json::from_value(serde_json::json!([
            {"modelId":"claude-sonnet-5.5","modelName":"Sonnet", "tokenLimits":{"maxInputTokens":1000000,"maxOutputTokens":64000}},
            {"modelId":"gpt-5.6-sol"}
        ])).unwrap();
        let mappings = merge_mappings(&models, HashMap::new());
        assert_eq!(
            map_model_with_mappings("claude-sonnet-5-5-thinking", &mappings).as_deref(),
            Some("claude-sonnet-5.5")
        );
        assert_eq!(
            map_model_with_mappings("gpt-5.6-sol", &mappings).as_deref(),
            Some("gpt-5.6-sol")
        );
        assert_eq!(map_model_with_mappings("invented-model", &mappings), None);
        assert_eq!(models[0].token_limits.max_input_tokens, Some(1000000));
        let mappings = merge_mappings(
            &models,
            HashMap::from([("CLAUDE-SONNET-5-5".into(), "custom-target".into())]),
        );
        assert_eq!(
            map_model_with_mappings("claude-sonnet-5-5", &mappings).as_deref(),
            Some("custom-target")
        );
    }
}
