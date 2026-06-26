//! Anthropic multimodal input normalization.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Url;
use serde_json::{Value, json};
use std::time::Duration;

use super::types::MessagesRequest;

const MAX_REMOTE_BYTES: usize = 10 * 1024 * 1024;
const MAX_DOCUMENT_TEXT_CHARS: usize = 120_000;

#[derive(Debug)]
pub struct MultimodalError {
    message: String,
}

impl MultimodalError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MultimodalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for MultimodalError {}

pub async fn normalize_multimodal_sources(
    payload: &mut MessagesRequest,
) -> Result<(), MultimodalError> {
    for message in &mut payload.messages {
        let Some(blocks) = message.content.as_array_mut() else {
            continue;
        };

        for block in blocks {
            normalize_block(block).await?;
        }
    }

    Ok(())
}

async fn normalize_block(block: &mut Value) -> Result<(), MultimodalError> {
    match block.get("type").and_then(Value::as_str) {
        Some("image") => normalize_image_block(block).await,
        Some("document") => normalize_document_block(block).await,
        _ => Ok(()),
    }
}

async fn normalize_image_block(block: &mut Value) -> Result<(), MultimodalError> {
    let Some(source) = block.get_mut("source").and_then(Value::as_object_mut) else {
        return Ok(());
    };

    let source_type = source
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if source_type == "base64" {
        return Ok(());
    }

    if source_type != "url" {
        return Ok(());
    }

    let Some(url) = source
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Err(MultimodalError::new("image source.url is required"));
    };

    let media = load_media_from_url(&url, Some("image")).await?;
    source.insert("type".to_string(), json!("base64"));
    source.insert("media_type".to_string(), json!(media.media_type));
    source.insert("data".to_string(), json!(STANDARD.encode(media.bytes)));
    source.remove("url");

    Ok(())
}

async fn normalize_document_block(block: &mut Value) -> Result<(), MultimodalError> {
    let title = block
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("document")
        .to_string();

    let Some(source) = block.get("source").and_then(Value::as_object) else {
        return Ok(());
    };

    let source_type = source
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let (media_type, bytes) = match source_type {
        "base64" => {
            let media_type = source
                .get("media_type")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream")
                .to_string();
            let data = source
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| MultimodalError::new("document source.data is required"))?;
            let bytes = STANDARD
                .decode(data)
                .map_err(|e| MultimodalError::new(format!("invalid document base64 data: {e}")))?;
            (media_type, bytes)
        }
        "url" => {
            let url = source
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| MultimodalError::new("document source.url is required"))?;
            let media = load_media_from_url(url, None).await?;
            (media.media_type, media.bytes)
        }
        _ => return Ok(()),
    };

    let Some(text) = document_bytes_to_text(&media_type, &bytes)? else {
        return Ok(());
    };

    let text = truncate_chars(&text, MAX_DOCUMENT_TEXT_CHARS);
    *block = json!({
        "type": "text",
        "text": format!("<document title=\"{}\" media_type=\"{}\">\n{}\n</document>", title, media_type, text)
    });

    Ok(())
}

struct LoadedMedia {
    media_type: String,
    bytes: Vec<u8>,
}

async fn load_media_from_url(
    url: &str,
    expected_prefix: Option<&str>,
) -> Result<LoadedMedia, MultimodalError> {
    if let Some(media) = parse_data_url(url)? {
        if let Some(prefix) = expected_prefix {
            if !media.media_type.starts_with(prefix) {
                return Err(MultimodalError::new(format!(
                    "expected {prefix}/* data URL, got {}",
                    media.media_type
                )));
            }
        }
        return Ok(media);
    }

    let parsed =
        Url::parse(url).map_err(|e| MultimodalError::new(format!("invalid media URL: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(MultimodalError::new(
            "only http, https, and data URLs are supported for multimodal sources",
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| MultimodalError::new(format!("failed to build HTTP client: {e}")))?;
    let response = client
        .get(parsed)
        .send()
        .await
        .map_err(|e| MultimodalError::new(format!("failed to download media URL: {e}")))?;

    if !response.status().is_success() {
        return Err(MultimodalError::new(format!(
            "media URL returned HTTP {}",
            response.status()
        )));
    }

    if response
        .content_length()
        .is_some_and(|len| len > MAX_REMOTE_BYTES as u64)
    {
        return Err(MultimodalError::new(format!(
            "media URL body is too large: {} bytes",
            response.content_length().unwrap_or_default()
        )));
    }

    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| mime_guess::from_path(url).first_raw().map(str::to_string))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    if let Some(prefix) = expected_prefix {
        if !media_type.starts_with(prefix) {
            return Err(MultimodalError::new(format!(
                "expected {prefix}/* media URL, got {media_type}"
            )));
        }
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| MultimodalError::new(format!("failed to read media URL body: {e}")))?;
    if bytes.len() > MAX_REMOTE_BYTES {
        return Err(MultimodalError::new(format!(
            "media URL body is too large: {} bytes",
            bytes.len()
        )));
    }

    Ok(LoadedMedia {
        media_type,
        bytes: bytes.to_vec(),
    })
}

fn parse_data_url(url: &str) -> Result<Option<LoadedMedia>, MultimodalError> {
    let Some(rest) = url.strip_prefix("data:") else {
        return Ok(None);
    };
    let Some((meta, data)) = rest.split_once(',') else {
        return Err(MultimodalError::new("invalid data URL"));
    };

    let mut meta_parts = meta.split(';');
    let media_type = meta_parts
        .next()
        .filter(|v| !v.is_empty())
        .unwrap_or("text/plain")
        .to_string();
    let is_base64 = meta_parts.any(|part| part.eq_ignore_ascii_case("base64"));
    if !is_base64 {
        return Err(MultimodalError::new("only base64 data URLs are supported"));
    }

    let bytes = STANDARD
        .decode(data)
        .map_err(|e| MultimodalError::new(format!("invalid data URL base64 payload: {e}")))?;

    Ok(Some(LoadedMedia { media_type, bytes }))
}

fn document_bytes_to_text(
    media_type: &str,
    bytes: &[u8],
) -> Result<Option<String>, MultimodalError> {
    match media_type {
        "text/plain" | "text/markdown" | "text/csv" | "application/json" => {
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|e| MultimodalError::new(format!("document is not valid UTF-8: {e}")))?;
            Ok(Some(text))
        }
        "application/pdf" => {
            let text = pdf_extract::extract_text_from_mem(bytes)
                .map_err(|e| MultimodalError::new(format!("failed to extract PDF text: {e}")))?;
            Ok(Some(text))
        }
        _ => Ok(None),
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut truncated: String = text.chars().take(max_chars).collect();
    truncated.push_str("\n...[truncated]");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_normalize_data_url_image_source_to_base64() {
        let mut payload: MessagesRequest = serde_json::from_value(serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 32,
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image",
                    "source": {
                        "type": "url",
                        "url": "data:image/png;base64,aGVsbG8="
                    }
                }]
            }]
        }))
        .unwrap();

        normalize_multimodal_sources(&mut payload).await.unwrap();

        let source = &payload.messages[0].content[0]["source"];
        assert_eq!(source["type"], "base64");
        assert_eq!(source["media_type"], "image/png");
        assert_eq!(source["data"], "aGVsbG8=");
    }

    #[tokio::test]
    async fn test_normalize_plain_text_document_to_text_block() {
        let mut payload: MessagesRequest = serde_json::from_value(serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 32,
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "document",
                    "title": "sample.txt",
                    "source": {
                        "type": "base64",
                        "media_type": "text/plain",
                        "data": "SGVsbG8gZnJvbSBkb2N1bWVudA=="
                    }
                }]
            }]
        }))
        .unwrap();

        normalize_multimodal_sources(&mut payload).await.unwrap();

        let block = &payload.messages[0].content[0];
        assert_eq!(block["type"], "text");
        assert!(
            block["text"]
                .as_str()
                .unwrap()
                .contains("Hello from document")
        );
    }
}
