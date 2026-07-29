import axios from 'axios'
import { storage } from '@/lib/storage'
import type {
  CredentialsStatusResponse,
  BalanceResponse,
  SuccessResponse,
  SetDisabledRequest,
  SetPriorityRequest,
  AddCredentialRequest,
  AddCredentialResponse,
  AdminConfig,
  AdminConfigResponse,
  LoadBalancingMode,
  ModelsResponse,
  ServiceTestRequest,
  ServiceTestResponse,
} from '@/types/api'

export interface CredentialsQuery {
  page?: number
  pageSize?: number
  sortField?: 'priority' | 'success' | 'lastUsed' | 'remaining'
  sortDirection?: 'asc' | 'desc'
  status?: 'all' | 'enabled' | 'disabled'
  disabledReason?: string
}

const ADD_CREDENTIAL_TIMEOUT_MS = 75_000
const BALANCE_QUERY_TIMEOUT_MS = 45_000
const SERVICE_TEST_TIMEOUT_MS = 60_000

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

// 请求拦截器添加 API Key
api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})

// 获取所有凭据状态
export async function getCredentials(
  query?: CredentialsQuery
): Promise<CredentialsStatusResponse> {
  const { data } = await api.get<CredentialsStatusResponse>('/credentials', {
    params: query,
  })
  return data
}

// 设置凭据禁用状态
export async function setCredentialDisabled(
  id: number,
  disabled: boolean
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/disabled`,
    { disabled } as SetDisabledRequest
  )
  return data
}

// 设置凭据优先级
export async function setCredentialPriority(
  id: number,
  priority: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/priority`,
    { priority } as SetPriorityRequest
  )
  return data
}

// 重置失败计数
export async function resetCredentialFailure(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/reset`)
  return data
}

// 强制刷新 Token
export async function forceRefreshToken(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/refresh`)
  return data
}

// 获取凭据余额
export async function getCredentialBalance(id: number): Promise<BalanceResponse> {
  const { data } = await api.get<BalanceResponse>(`/credentials/${id}/balance`, {
    timeout: BALANCE_QUERY_TIMEOUT_MS,
  })
  return data
}

// 添加新凭据
export async function addCredential(
  req: AddCredentialRequest
): Promise<AddCredentialResponse> {
  const { data } = await api.post<AddCredentialResponse>('/credentials', req, {
    timeout: ADD_CREDENTIAL_TIMEOUT_MS,
  })
  return data
}

// 删除凭据
export async function deleteCredential(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/credentials/${id}`)
  return data
}

// 获取负载均衡模式
export async function getLoadBalancingMode(): Promise<{ mode: LoadBalancingMode }> {
  const { data } = await api.get<{ mode: LoadBalancingMode }>('/config/load-balancing')
  return data
}

// 设置负载均衡模式
export async function setLoadBalancingMode(mode: LoadBalancingMode): Promise<{ mode: LoadBalancingMode }> {
  const { data } = await api.put<{ mode: LoadBalancingMode }>('/config/load-balancing', { mode })
  return data
}

// 获取完整服务配置
export async function getAdminConfig(): Promise<AdminConfigResponse> {
  const { data } = await api.get<AdminConfigResponse>('/config')
  return data
}

// 保存完整服务配置
export async function updateAdminConfig(config: AdminConfig): Promise<AdminConfigResponse> {
  const { data } = await api.put<AdminConfigResponse>('/config', config)
  return data
}

export async function testService(
  req: ServiceTestRequest
): Promise<ServiceTestResponse> {
  const { data } = await api.post<ServiceTestResponse>('/service/test', req, {
    timeout: SERVICE_TEST_TIMEOUT_MS,
  })
  return data
}

export async function getModels(): Promise<ModelsResponse> {
  const { data } = await api.get<ModelsResponse>('/models')
  return data
}

// 请求重启服务
export async function restartService(): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/service/restart')
  return data
}
