// 凭据状态响应
export interface CredentialsStatusResponse {
  total: number
  available: number
  filteredTotal: number
  quotaExceeded: number
  statusCounts: CredentialStatusCounts
  currentId: number
  stats: RequestStatsSummary
  credentials: CredentialStatusItem[]
  disabledIds?: number[]
}

export interface CredentialStatusCounts {
  total: number
  enabled: number
  disabled: number
  disabledReasons: DisabledReasonCount[]
}

export interface DisabledReasonCount {
  reason: string
  count: number
}

// 单个凭据状态
export interface CredentialStatusItem {
  id: number
  priority: number
  disabled: boolean
  failureCount: number
  isCurrent: boolean
  expiresAt: string | null
  authMethod: string | null
  hasProfileArn: boolean
  email?: string
  refreshTokenHash?: string
  apiKeyHash?: string
  maskedApiKey?: string
  successCount: number
  lastUsedAt: string | null
  hasProxy: boolean
  proxyUrl?: string
  refreshFailureCount: number
  disabledReason?: string
  endpoint: string
  balance?: BalanceResponse
}

// 余额响应
export interface BalanceResponse {
  id: number
  subscriptionTitle: string | null
  currentUsage: number
  usageLimit: number
  remaining: number
  usagePercentage: number
  nextResetAt: number | null
}

export interface RequestStatsSummary {
  rpm: number
  totalRequestCount: number
  totalTokenCount: number
  totalSuccessCount: number
  totalSuccessRate: number
  todayRequestCount: number
  todayTokenCount: number
  todaySuccessCount: number
  todaySuccessRate: number
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

export type TlsBackend = 'rustls' | 'native-tls'
export type LoadBalancingMode = 'priority' | 'balanced'
export type CountTokensAuthType = 'x-api-key' | 'bearer'

export interface AdminConfig {
  host: string
  port: number
  region: string
  authRegion: string | null
  apiRegion: string | null
  kiroVersion: string
  machineId: string | null
  apiKey: string | null
  systemVersion: string
  nodeVersion: string
  tlsBackend: TlsBackend
  countTokensApiUrl: string | null
  countTokensApiKey: string | null
  countTokensAuthType: CountTokensAuthType
  proxyUrl: string | null
  proxyUsername: string | null
  proxyPassword: string | null
  adminApiKey: string | null
  loadBalancingMode: LoadBalancingMode
  maxConcurrentRequestsPerCredential: number
  disabledCredentialRecoveryIntervalSeconds: number
  disabledCredentialRecoveryBatchSize: number
  batchImportConcurrency: number
  usageRequestConcurrency: number
  extractThinking: boolean
  defaultEndpoint: string
  endpoints: Record<string, unknown>
  modelMappings: Record<string, string>
}

export interface AdminConfigResponse {
  config: AdminConfig
  changedFields: string[]
  restartRequiredFields: string[]
  restartRequired: boolean
}

// 错误响应
export interface AdminErrorResponse {
  error: {
    type: string
    message: string
  }
}

// 请求类型
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
}

// 添加凭据请求
export interface AddCredentialRequest {
  refreshToken?: string
  authMethod?: 'social' | 'idc' | 'api_key'
  clientId?: string
  clientSecret?: string
  priority?: number
  authRegion?: string
  apiRegion?: string
  machineId?: string
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  kiroApiKey?: string
  endpoint?: string
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
}
