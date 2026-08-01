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
  filteredIds?: number[]
  filteredDisabledIds?: number[]
  filteredFailedIds?: number[]
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
  currentConcurrentRequests: number
  upstreamHeaderLatencyEmaMs?: number
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
  remainingQuota: number
  todayConsumedQuota: number
  totalConsumedQuota: number
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

export type TlsBackend = 'rustls' | 'native-tls'
export type LoadBalancingMode = 'priority' | 'balanced'
export type CountTokensAuthType = 'x-api-key' | 'bearer'
export type CredentialStorageBackend = 'file' | 'sqlite'

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
  credentialStorage: CredentialStorageBackend
  credentialDatabasePath: string | null
  loadBalancingMode: LoadBalancingMode
  cacheAccountProtectionSeconds: number
  cacheAccountWaitSeconds: number
  rateLimitCooldownSeconds: number
  maxConcurrentRequestsPerCredential: number
  perCredentialRateLimitMaxRequests: number
  perCredentialRateLimitWindowSeconds: number
  globalRateLimitMaxRequests: number
  globalRateLimitWindowSeconds: number
  disabledCredentialRecoveryIntervalSeconds: number
  disabledCredentialRecoveryBatchSize: number
  batchImportConcurrency: number
  usageRequestConcurrency: number
  proactiveTokenRefreshIntervalSeconds: number
  proactiveTokenRefreshBatchSize: number
  proactiveTokenRefreshConcurrency: number
  usageQueryIntervalSeconds: number
  usageQueryDisableRemainingThreshold: number
  cacheCreationUsageMultiplier: number
  cacheReadUsageMultiplier: number
  extractThinking: boolean
  defaultStream: boolean
  testDefaultModel: string
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

export interface SetCredentialEmailRequest {
  email?: string | null
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
  email?: string
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
}

export interface ServiceTestRequest {
  prompt: string
  model: string
  credentialId?: number
}

export interface ServiceTestResponse {
  success: boolean
  model: string
  prompt: string
  status: number
  latencyMs: number
  credentialId: number | null
  email: string | null
  replyText: string | null
  responsePreview: string
}

export interface ModelItem {
  id: string
  object: string
  created: number
  owned_by: string
  display_name: string
  type: string
  max_tokens: number
}

export interface ModelsResponse {
  object: string
  data: ModelItem[]
}
