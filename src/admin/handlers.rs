//! Admin API HTTP 处理器

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use tokio::time::{Duration, sleep};

use super::{
    middleware::AdminState,
    types::{
        AddCredentialRequest, AdminErrorResponse, CredentialsQuery, ServiceTestRequest,
        SetDisabledRequest, SetLoadBalancingModeRequest, SetPriorityRequest, SuccessResponse,
    },
};
use crate::model::config::Config;

const ADD_CREDENTIAL_TIMEOUT: Duration = Duration::from_secs(75);

/// GET /api/admin/credentials
/// 获取所有凭据状态
pub async fn get_all_credentials(
    State(state): State<AdminState>,
    Query(query): Query<CredentialsQuery>,
) -> impl IntoResponse {
    let response = state.service.get_all_credentials(query);
    Json(response)
}

/// POST /api/admin/credentials/:id/disabled
/// 设置凭据禁用状态
pub async fn set_credential_disabled(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetDisabledRequest>,
) -> impl IntoResponse {
    match state.service.set_disabled(id, payload.disabled) {
        Ok(_) => {
            let action = if payload.disabled { "禁用" } else { "启用" };
            Json(SuccessResponse::new(format!("凭据 #{} 已{}", id, action))).into_response()
        }
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/priority
/// 设置凭据优先级
pub async fn set_credential_priority(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetPriorityRequest>,
) -> impl IntoResponse {
    match state.service.set_priority(id, payload.priority) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 优先级已设置为 {}",
            id, payload.priority
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/reset
/// 重置失败计数并重新启用
pub async fn reset_failure_count(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.reset_and_enable(id) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 失败计数已重置并重新启用",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/credentials/:id/balance
/// 获取指定凭据的余额
pub async fn get_credential_balance(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.get_balance(id).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials
/// 添加新凭据
pub async fn add_credential(
    State(state): State<AdminState>,
    Json(payload): Json<AddCredentialRequest>,
) -> impl IntoResponse {
    match tokio::time::timeout(
        ADD_CREDENTIAL_TIMEOUT,
        state.service.add_credential(payload),
    )
    .await
    {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => {
            tracing::warn!("添加凭据失败: {}", e);
            (e.status_code(), Json(e.into_response())).into_response()
        }
        Err(_) => {
            tracing::warn!(
                "添加凭据超时：超过 {} 秒未完成",
                ADD_CREDENTIAL_TIMEOUT.as_secs()
            );
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(AdminErrorResponse::api_error(format!(
                    "添加凭据超时：超过 {} 秒未完成，请稍后重试",
                    ADD_CREDENTIAL_TIMEOUT.as_secs()
                ))),
            )
                .into_response()
        }
    }
}

/// DELETE /api/admin/credentials/:id
/// 删除凭据
pub async fn delete_credential(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.delete_credential(id) {
        Ok(_) => Json(SuccessResponse::new(format!("凭据 #{} 已删除", id))).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/refresh
/// 强制刷新凭据 Token
pub async fn force_refresh_token(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.force_refresh_token(id).await {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} Token 已强制刷新",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/load-balancing
/// 获取负载均衡模式
pub async fn get_load_balancing_mode(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_load_balancing_mode();
    Json(response)
}

/// PUT /api/admin/config/load-balancing
/// 设置负载均衡模式
pub async fn set_load_balancing_mode(
    State(state): State<AdminState>,
    Json(payload): Json<SetLoadBalancingModeRequest>,
) -> impl IntoResponse {
    match state.service.set_load_balancing_mode(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config
/// 获取完整服务配置
pub async fn get_config(State(state): State<AdminState>) -> impl IntoResponse {
    match state.service.get_config() {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// PUT /api/admin/config
/// 保存完整服务配置
pub async fn update_config(
    State(state): State<AdminState>,
    Json(payload): Json<Config>,
) -> impl IntoResponse {
    match state.service.update_config(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/models
/// 获取 Admin 测试弹窗可选模型列表
pub async fn get_models(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_models()).into_response()
}

/// POST /api/admin/service/test
/// 使用指定模型发送最小消息，验证服务链路是否可用
pub async fn test_service(
    State(state): State<AdminState>,
    Json(payload): Json<ServiceTestRequest>,
) -> impl IntoResponse {
    match state
        .service
        .test_service(payload.prompt, payload.model, payload.credential_id)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/service/restart
/// 请求当前进程退出，由 Docker/systemd 等进程管理器负责重新拉起
pub async fn restart_service() -> impl IntoResponse {
    tokio::spawn(async {
        sleep(Duration::from_millis(800)).await;
        tracing::warn!("Admin 请求重启服务，当前进程即将退出");
        std::process::exit(0);
    });

    Json(SuccessResponse::new(
        "重启请求已接受，服务将在约 800ms 后重启",
    ))
}
