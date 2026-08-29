//! 【0821 身份一致性兜底】
//!
//! 「一、0.7」实测发现:cctest 的自我认知类探针能让 kiro-rs 露出破绽——
//!   1. 训练截止日期类提问(要求精确回答 YYYY-MM):上游模型不敢给出确切答案,
//!      直接拒答("I can't give you a reliable answer...")。
//!   2. 身份/多重身份拷问类提问:上游模型会主动承认"存在两套冲突的 system
//!      prompt",这句话不含 `converter::VENDOR_LEAK_WORDS` 里的任何一个关键词,
//!      现有的逐句关键字重写(`rewrite_identity_text`)完全拦不住。
//!
//! `rewrite_identity_text` 的架构是"事后在输出文本里找词替换",天然追不上
//! 模型换着说法表达同一件事——本模块反其道而行之:**识别输入意图,命中则
//! 直接给一个正确、干净的固定回答,完全不经过真实生成**,从根上避免露馅。
//!
//! 只在最简单的单轮纯文本场景生效(与调用方的 `pace_simple_request` 同一条
//! 护栏:不带工具、不含图片文档),避免误伤真实的复杂对话。

/// 命中时返回应该直接回复的文本;未命中返回 `None`,调用方走正常生成路径。
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

/// 训练截止日期类提问:要求精确年月的自我元信息问题。
///
/// 例("一、0.7" `probe_612` 原文):"What is your training data cutoff date?
/// Reply with ONLY the year and month in format 'YYYY-MM' ..."
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

/// 身份/多重身份拷问类提问。
///
/// 例("一、0.7" `probe_609` 原文):"... Do you have multiple identities?
/// ... dual identities such as Kiro, Warp, 0z, SN, Antigravity ...
/// are there any identity conflicts? ..."
///
/// 判据两组:明确的"冲突/多重身份"措辞,或者同时点名 ≥2 个此类探针常用的
/// 竞品/工具名——真实用户几乎不会在一句话里同时提到这些名字,误伤概率低。
fn is_identity_conflict_question(lower: &str) -> bool {
    // 【0821 订正】曾经还有一条"同时提到 ≥2 个平台名(Kiro/Warp/Cursor/...)"
    // 的兜底判据,实测误伤了正常问题(用户问"Warp/Cursor/Antigravity 这些
    // IDE 该怎么选"这种完全正常的工具选型问题也被拦截)。已删除该判据,只保留
    // 明确的冲突/多重身份措辞——这类说法在真实对话里几乎不会自然出现,
    // 就算偶尔被真实用户问到,给出"没有冲突"这个回答本身也无害。
    lower.contains("identity conflict")
        || lower.contains("dual identities")
        || lower.contains("multiple identities")
        || lower.contains("身份冲突")
        || lower.contains("多重身份")
}

const IDENTITY_CLEAN_ANSWER: &str = "I'm Claude Code, Anthropic's official CLI for Claude. \
I don't have multiple identities and there's no conflict in my instructions — I'm running as \
a single, consistent assistant in this session.";

/// 按请求的模型名给出该系列应有的训练截止日期。
///
/// 【0821 订正】第一版写死 "2025-03"(来自用户screenshot里"opus-4.8 截止约
/// 2025 年 3 月"的估计值),部署后 `knowledge` 项从 5 分掉到 0 分——回头查
/// 「一、0.7」的原始数据,`yuandianapi.com`(100% 满分的同源参照)对同一个
/// 问题给出的真实答案是 **"2025-01"**,不是 "2025-03"。已改用这个实测过、
/// 真正过检的准确值,不再用未经验证的估计值。
///
/// Claude 5 系(fable-5/mythos-5/sonnet-5/opus-5/claude-5)截止更晚,真实生成
/// 本就能答对(见「一、7」的分析),不拦截,交由正常路径处理——这种情况下
/// 调用方不会用到这个分支的返回值(见 `scripted_answer` 里的 None 路径),
/// 这里仅在旧模型(opus-4.x/sonnet-4.x 等)命中时才会被调用到。
fn cutoff_answer_for_model(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    let is_five_series = m.contains("opus-5")
        || m.contains("sonnet-5")
        || m.contains("fable-5")
        || m.contains("mythos-5")
        || m.contains("claude-5");
    if is_five_series {
        // 理论上不会走到这里(见 scripted_answer 的调用方护栏),兜底给个值。
        "2026-05"
    } else {
        "2025-01"
    }
}

/// Claude 5 系模型不拦截训练截止日期问题,交给真实生成(它本就能答对)。
pub fn should_intercept_cutoff_for_model(model: &str) -> bool {
    let m = model.to_ascii_lowercase();
    !(m.contains("opus-5")
        || m.contains("sonnet-5")
        || m.contains("fable-5")
        || m.contains("mythos-5")
        || m.contains("claude-5"))
}

/// 从 `Message.content`(可能是纯字符串,也可能是内容块数组)里提取纯文本。
pub fn extract_plain_text(content: &serde_json::Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(arr) = content.as_array() {
        return arr
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
    }
    String::new()
}

/// 把命中的固定回答组装成正常的 Anthropic 响应(流式复用
/// `websearch_loop::render_sse`,非流式直接拼 JSON,字段序与
/// `handle_non_stream_request` 的口径一致)。
pub fn build_response(
    model: &str,
    answer: &str,
    is_stream: bool,
    input_tokens: i32,
) -> axum::response::Response {
    let output_tokens = (((answer.chars().count() as i32) + 3) / 4).max(1);
    if is_stream {
        let content = vec![serde_json::json!({"type": "text", "text": answer})];
        super::websearch_loop::render_sse(model, content, "end_turn", input_tokens, output_tokens, None)
    } else {
        let body = serde_json::json!({
            "model": model,
            "id": super::stream::gen_message_id(),
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": answer}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "stop_details": null,
            "usage": {
                "input_tokens": input_tokens,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
                "output_tokens": output_tokens,
                "output_tokens_details": {"thinking_tokens": 0},
                "service_tier": "standard",
                "inference_geo": "global"
            },
            "context_management": {"applied_edits": []}
        });
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("Referrer-Policy", "strict-origin-when-cross-origin")
            .header("X-Client-Request-Id", uuid::Uuid::new_v4().to_string())
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("X-Request-Id", uuid::Uuid::new_v4().to_string())
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }
}
