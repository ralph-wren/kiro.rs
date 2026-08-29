//! Admin API 错误类型定义

use std::fmt;

use axum::http::StatusCode;

use super::types::AdminErrorResponse;

/// Admin 服务错误类型
#[derive(Debug)]
pub enum AdminServiceError {
    /// 凭据不存在
    NotFound { id: u64 },

    /// 上游服务调用失败（网络、API 错误等）
    UpstreamError(String),

    /// 内部状态错误
    InternalError(String),

    /// 凭据无效（验证失败）
    InvalidCredential(String),
}

impl fmt::Display for AdminServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminServiceError::NotFound { id } => {
                write!(f, "凭据不存在: {}", id)
            }
            AdminServiceError::UpstreamError(msg) => write!(f, "上游服务错误: {}", msg),
            AdminServiceError::InternalError(msg) => write!(f, "内部错误: {}", msg),
            AdminServiceError::InvalidCredential(msg) => write!(f, "凭据无效: {}", msg),
        }
    }
}

impl std::error::Error for AdminServiceError {}

impl AdminServiceError {
    /// 获取对应的 HTTP 状态码
    pub fn status_code(&self) -> StatusCode {
        match self {
            AdminServiceError::NotFound { .. } => StatusCode::NOT_FOUND,
            AdminServiceError::UpstreamError(message) => {
                upstream_status_code(message).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            AdminServiceError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AdminServiceError::InvalidCredential(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// 转换为 API 错误响应
    pub fn into_response(self) -> AdminErrorResponse {
        match &self {
            AdminServiceError::NotFound { .. } => AdminErrorResponse::not_found(self.to_string()),
            AdminServiceError::UpstreamError(_) => AdminErrorResponse::api_error(self.to_string()),
            AdminServiceError::InternalError(_) => {
                AdminErrorResponse::internal_error(self.to_string())
            }
            AdminServiceError::InvalidCredential(_) => {
                AdminErrorResponse::invalid_request(self.to_string())
            }
        }
    }
}

fn upstream_status_code(message: &str) -> Option<StatusCode> {
    for marker in ["HTTP ", "status code "] {
        if let Some(rest) = message.split_once(marker).map(|(_, rest)| rest) {
            if let Some(status) = parse_status_token(rest.split_whitespace().next()?) {
                return Some(status);
            }
        }
    }

    message.split_whitespace().find_map(parse_status_token)
}

fn parse_status_token(token: &str) -> Option<StatusCode> {
    let digits = token.trim_matches(|character: char| !character.is_ascii_digit());
    if digits.len() != 3 {
        return None;
    }

    let code = digits.parse::<u16>().ok()?;
    if !(100..600).contains(&code) {
        return None;
    }

    StatusCode::from_u16(code).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_http_status_is_preserved() {
        let error = AdminServiceError::UpstreamError(
            "指定凭据 API 请求失败（#13198）: 429 Too Many Requests".to_string(),
        );
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn upstream_without_http_status_remains_bad_gateway() {
        let error = AdminServiceError::UpstreamError("连接上游超时".to_string());
        assert_eq!(error.status_code(), StatusCode::BAD_GATEWAY);
    }
}
