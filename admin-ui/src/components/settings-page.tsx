import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, AlertTriangle, CheckCircle2, Plus, RotateCcw, Save, Settings, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { getAdminConfig, restartService, updateAdminConfig } from '@/api/credentials'
import type {
  AdminConfig,
  AdminConfigResponse,
  CountTokensAuthType,
  CredentialStorageBackend,
  LoadBalancingMode,
  TlsBackend,
} from '@/types/api'
import { extractErrorMessage } from '@/lib/utils'

interface SettingsPageProps {
  onBack: () => void
}

interface ModelMappingRow {
  source: string
  target: string
}

interface SettingsFormState {
  host: string
  port: string
  region: string
  authRegion: string
  apiRegion: string
  kiroVersion: string
  machineId: string
  apiKey: string
  systemVersion: string
  nodeVersion: string
  tlsBackend: TlsBackend
  countTokensApiUrl: string
  countTokensApiKey: string
  countTokensAuthType: CountTokensAuthType
  proxyUrl: string
  proxyUsername: string
  proxyPassword: string
  adminApiKey: string
  credentialStorage: CredentialStorageBackend
  credentialDatabasePath: string
  loadBalancingMode: LoadBalancingMode
  maxConcurrentRequestsPerCredential: string
  disabledCredentialRecoveryIntervalSeconds: string
  disabledCredentialRecoveryBatchSize: string
  batchImportConcurrency: string
  usageRequestConcurrency: string
  proactiveTokenRefreshIntervalSeconds: string
  proactiveTokenRefreshBatchSize: string
  proactiveTokenRefreshConcurrency: string
  usageQueryIntervalSeconds: string
  usageQueryDisableRemainingThreshold: string
  extractThinking: boolean
  defaultStream: boolean
  defaultEndpoint: string
  endpointsJson: string
  modelMappings: ModelMappingRow[]
}

const RESTART_FIELD_LABELS: Record<string, string> = {
  host: '监听地址',
  port: '监听端口',
  region: '默认区域',
  authRegion: '认证区域',
  apiRegion: 'API 区域',
  kiroVersion: 'Kiro 版本',
  machineId: '机器码',
  apiKey: 'API Key',
  systemVersion: '系统版本标识',
  nodeVersion: 'Node.js 版本标识',
  tlsBackend: 'TLS 后端',
  countTokensApiUrl: 'Token 计数 API 地址',
  countTokensApiKey: 'Token 计数 API Key',
  countTokensAuthType: 'Token 计数认证类型',
  proxyUrl: '全局代理地址',
  proxyUsername: '代理用户名',
  proxyPassword: '代理密码',
  adminApiKey: 'Admin API Key',
  credentialStorage: '凭据存储后端',
  credentialDatabasePath: 'SQLite 数据库路径',
  maxConcurrentRequestsPerCredential: '单账号并发数',
  disabledCredentialRecoveryIntervalSeconds: '禁用账号恢复检查间隔',
  disabledCredentialRecoveryBatchSize: '禁用账号恢复批量数',
  batchImportConcurrency: '批量导入并发数',
  usageRequestConcurrency: '额度查询并发数',
  proactiveTokenRefreshIntervalSeconds: 'Token 预刷新间隔',
  proactiveTokenRefreshBatchSize: 'Token 预刷新批量数',
  proactiveTokenRefreshConcurrency: 'Token 预刷新并发数',
  usageQueryIntervalSeconds: '额度查询间隔',
  usageQueryDisableRemainingThreshold: '低余额禁用阈值',
  extractThinking: 'Thinking 提取',
  defaultStream: '默认流式响应',
  defaultEndpoint: '默认端点',
  endpoints: '端点配置',
}

function nullableToString(value: string | null): string {
  return value ?? ''
}

function toFormState(config: AdminConfig): SettingsFormState {
  return {
    host: config.host,
    port: String(config.port),
    region: config.region,
    authRegion: nullableToString(config.authRegion),
    apiRegion: nullableToString(config.apiRegion),
    kiroVersion: config.kiroVersion,
    machineId: nullableToString(config.machineId),
    apiKey: nullableToString(config.apiKey),
    systemVersion: config.systemVersion,
    nodeVersion: config.nodeVersion,
    tlsBackend: config.tlsBackend,
    countTokensApiUrl: nullableToString(config.countTokensApiUrl),
    countTokensApiKey: nullableToString(config.countTokensApiKey),
    countTokensAuthType: config.countTokensAuthType,
    proxyUrl: nullableToString(config.proxyUrl),
    proxyUsername: nullableToString(config.proxyUsername),
    proxyPassword: nullableToString(config.proxyPassword),
    adminApiKey: nullableToString(config.adminApiKey),
    credentialStorage: config.credentialStorage,
    credentialDatabasePath: nullableToString(config.credentialDatabasePath),
    loadBalancingMode: config.loadBalancingMode,
    maxConcurrentRequestsPerCredential: String(config.maxConcurrentRequestsPerCredential),
    disabledCredentialRecoveryIntervalSeconds: String(config.disabledCredentialRecoveryIntervalSeconds),
    disabledCredentialRecoveryBatchSize: String(config.disabledCredentialRecoveryBatchSize),
    batchImportConcurrency: String(config.batchImportConcurrency),
    usageRequestConcurrency: String(config.usageRequestConcurrency),
    proactiveTokenRefreshIntervalSeconds: String(config.proactiveTokenRefreshIntervalSeconds),
    proactiveTokenRefreshBatchSize: String(config.proactiveTokenRefreshBatchSize),
    proactiveTokenRefreshConcurrency: String(config.proactiveTokenRefreshConcurrency),
    usageQueryIntervalSeconds: String(config.usageQueryIntervalSeconds),
    usageQueryDisableRemainingThreshold: String(config.usageQueryDisableRemainingThreshold ?? 1),
    extractThinking: config.extractThinking,
    defaultStream: config.defaultStream,
    defaultEndpoint: config.defaultEndpoint,
    endpointsJson: JSON.stringify(config.endpoints ?? {}, null, 2),
    modelMappings: Object.entries(config.modelMappings ?? {})
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([source, target]) => ({ source, target })),
  }
}

function emptyToNull(value: string): string | null {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function toConfig(form: SettingsFormState): AdminConfig {
  let endpoints: Record<string, unknown>
  try {
    const parsed = JSON.parse(form.endpointsJson || '{}')
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('端点配置必须是 JSON 对象')
    }
    endpoints = parsed as Record<string, unknown>
  } catch {
    throw new Error('端点配置 JSON 格式不正确')
  }

  const modelMappings: Record<string, string> = {}
  for (const mapping of form.modelMappings) {
    const source = mapping.source.trim()
    const target = mapping.target.trim()
    if (!source && !target) {
      continue
    }
    if (!source || !target) {
      throw new Error('模型映射的请求模型名和目标模型 ID 不能只填写一项')
    }
    if (Object.keys(modelMappings).some(key => key.toLowerCase() === source.toLowerCase())) {
      throw new Error(`模型映射重复：${source}`)
    }
    modelMappings[source] = target
  }

  return {
    host: form.host.trim(),
    port: Number(form.port),
    region: form.region.trim(),
    authRegion: emptyToNull(form.authRegion),
    apiRegion: emptyToNull(form.apiRegion),
    kiroVersion: form.kiroVersion.trim(),
    machineId: emptyToNull(form.machineId),
    apiKey: emptyToNull(form.apiKey),
    systemVersion: form.systemVersion.trim(),
    nodeVersion: form.nodeVersion.trim(),
    tlsBackend: form.tlsBackend,
    countTokensApiUrl: emptyToNull(form.countTokensApiUrl),
    countTokensApiKey: emptyToNull(form.countTokensApiKey),
    countTokensAuthType: form.countTokensAuthType,
    proxyUrl: emptyToNull(form.proxyUrl),
    proxyUsername: emptyToNull(form.proxyUsername),
    proxyPassword: emptyToNull(form.proxyPassword),
    adminApiKey: emptyToNull(form.adminApiKey),
    credentialStorage: form.credentialStorage,
    credentialDatabasePath: emptyToNull(form.credentialDatabasePath),
    loadBalancingMode: form.loadBalancingMode,
    maxConcurrentRequestsPerCredential: Number(form.maxConcurrentRequestsPerCredential),
    disabledCredentialRecoveryIntervalSeconds: Number(form.disabledCredentialRecoveryIntervalSeconds),
    disabledCredentialRecoveryBatchSize: Number(form.disabledCredentialRecoveryBatchSize),
    batchImportConcurrency: Number(form.batchImportConcurrency),
    usageRequestConcurrency: Number(form.usageRequestConcurrency),
    proactiveTokenRefreshIntervalSeconds: Number(form.proactiveTokenRefreshIntervalSeconds),
    proactiveTokenRefreshBatchSize: Number(form.proactiveTokenRefreshBatchSize),
    proactiveTokenRefreshConcurrency: Number(form.proactiveTokenRefreshConcurrency),
    usageQueryIntervalSeconds: Number(form.usageQueryIntervalSeconds),
    usageQueryDisableRemainingThreshold: Number(form.usageQueryDisableRemainingThreshold),
    extractThinking: form.extractThinking,
    defaultStream: form.defaultStream,
    defaultEndpoint: form.defaultEndpoint.trim(),
    endpoints,
    modelMappings,
  }
}

function FieldLabel({
  label,
  restartRequired = false,
}: {
  label: string
  restartRequired?: boolean
}) {
  return (
    <div className="mb-1.5 flex items-center justify-between gap-2">
      <label className="text-sm font-medium">{label}</label>
      {restartRequired ? (
        <span className="text-xs text-amber-600 dark:text-amber-400">需重启</span>
      ) : (
        <span className="text-xs text-emerald-600 dark:text-emerald-400">立即生效</span>
      )}
    </div>
  )
}

export function SettingsPage({ onBack }: SettingsPageProps) {
  const [form, setForm] = useState<SettingsFormState | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const [lastResponse, setLastResponse] = useState<AdminConfigResponse | null>(null)

  const restartFieldLabels = useMemo(
    () => (lastResponse?.restartRequiredFields ?? []).map(field => RESTART_FIELD_LABELS[field] ?? field),
    [lastResponse?.restartRequiredFields]
  )
  const loadConfig = async () => {
    setLoading(true)
    try {
      const response = await getAdminConfig()
      setForm(toFormState(response.config))
      setLastResponse(response)
    } catch (error) {
      toast.error(`加载设置失败: ${extractErrorMessage(error)}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadConfig()
  }, [])

  const updateField = <K extends keyof SettingsFormState>(field: K, value: SettingsFormState[K]) => {
    setForm(previous => previous ? { ...previous, [field]: value } : previous)
  }

  const updateModelMapping = (index: number, field: keyof ModelMappingRow, value: string) => {
    setForm(previous => {
      if (!previous) return previous
      const modelMappings = previous.modelMappings.map((mapping, mappingIndex) =>
        mappingIndex === index ? { ...mapping, [field]: value } : mapping
      )
      return { ...previous, modelMappings }
    })
  }

  const addModelMapping = () => {
    if (!form) return
    updateField('modelMappings', [...form.modelMappings, { source: '', target: '' }])
  }

  const removeModelMapping = (index: number) => {
    if (!form) return
    updateField(
      'modelMappings',
      form.modelMappings.filter((_, mappingIndex) => mappingIndex !== index)
    )
  }

  const handleSave = async () => {
    if (!form) return

    let config: AdminConfig
    try {
      config = toConfig(form)
    } catch (error) {
      toast.error((error as Error).message)
      return
    }

    setSaving(true)
    try {
      const response = await updateAdminConfig(config)
      setForm(toFormState(response.config))
      setLastResponse(response)

      if (response.restartRequired) {
        toast.warning(`配置已保存，${response.restartRequiredFields.length} 项设置需要重启后生效`)
      } else {
        toast.success('设置已保存并立即生效')
      }
    } catch (error) {
      toast.error(`保存设置失败: ${extractErrorMessage(error)}`)
    } finally {
      setSaving(false)
    }
  }

  const handleRestart = async () => {
    if (!confirm('确定要重启 kiro-rs 服务吗？当前请求会被中断，Docker 会自动拉起新进程。')) {
      return
    }

    setRestarting(true)
    try {
      const response = await restartService()
      toast.success(response.message)
    } catch (error) {
      setRestarting(false)
      toast.error(`重启失败: ${extractErrorMessage(error)}`)
    }
  }

  if (loading || !form) {
    return (
      <div className="flex min-h-[24rem] items-center justify-center">
        <div className="text-center">
          <Settings className="mx-auto mb-3 h-8 w-8 animate-pulse text-muted-foreground" />
          <p className="text-sm text-muted-foreground">加载服务设置...</p>
        </div>
      </div>
    )
  }

  if (restarting) {
    return (
      <div className="flex min-h-[24rem] items-center justify-center">
        <div className="max-w-md text-center">
          <RotateCcw className="mx-auto mb-4 h-10 w-10 animate-spin text-primary" />
          <h2 className="text-lg font-semibold">服务正在重启</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            页面会在服务恢复后重新连接。Docker 或进程管理器需要保持自动重启策略开启。
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={onBack} title="返回凭据管理">
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-2xl font-semibold">服务设置</h1>
            <p className="text-sm text-muted-foreground">修改 config.json 中的运行参数</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => void loadConfig()} disabled={saving}>
            <RotateCcw className="h-4 w-4" />
            重新读取
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            <Save className="h-4 w-4" />
            {saving ? '保存中...' : '保存设置'}
          </Button>
          <Button variant="destructive" onClick={handleRestart} disabled={saving}>
            <RotateCcw className="h-4 w-4" />
            重启服务
          </Button>
        </div>
      </div>

      {lastResponse?.restartRequired && (
        <div className="flex items-start gap-3 rounded-md border border-amber-300 bg-amber-50 p-4 text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="space-y-1 text-sm">
            <p className="font-medium">部分配置需要重启后生效</p>
            <p>
              {restartFieldLabels.length > 0 ? restartFieldLabels.join('、') : '已修改的启动配置'}
              。保存已经完成，确认无进行中的重要请求后再点击“重启服务”。
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>服务基础</CardTitle>
            <CardDescription>监听地址、区域和默认端点。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <FieldLabel label="监听地址" restartRequired />
              <Input value={form.host} onChange={event => updateField('host', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="监听端口" restartRequired />
              <Input type="number" min={1} value={form.port} onChange={event => updateField('port', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="默认区域" restartRequired />
              <Input value={form.region} onChange={event => updateField('region', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="认证区域" restartRequired />
              <Input value={form.authRegion} placeholder="留空则跟随默认区域" onChange={event => updateField('authRegion', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="API 区域" restartRequired />
              <Input value={form.apiRegion} placeholder="留空则跟随默认区域" onChange={event => updateField('apiRegion', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="默认端点" restartRequired />
              <Input value={form.defaultEndpoint} onChange={event => updateField('defaultEndpoint', event.target.value)} />
            </div>
            <div className="flex items-center justify-between rounded-md border p-3 sm:col-span-2">
              <div>
                <p className="text-sm font-medium">默认流式响应</p>
                <p className="text-xs text-muted-foreground">请求未显式传入 stream 时使用此设置。</p>
                <p className="mt-1 text-xs text-emerald-600 dark:text-emerald-400">修改后立即生效</p>
              </div>
              <Switch checked={form.defaultStream} onCheckedChange={checked => updateField('defaultStream', checked)} />
            </div>
            <div>
              <FieldLabel label="TLS 后端" restartRequired />
              <select
                value={form.tlsBackend}
                onChange={event => updateField('tlsBackend', event.target.value as TlsBackend)}
                className="h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="rustls">rustls</option>
                <option value="native-tls">native-tls</option>
              </select>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>凭据存储</CardTitle>
            <CardDescription>默认使用 SQLite；切换存储后需要重启服务。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <FieldLabel label="存储后端" restartRequired />
              <select
                value={form.credentialStorage}
                onChange={event => updateField('credentialStorage', event.target.value as CredentialStorageBackend)}
                className="h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="sqlite">SQLite</option>
                <option value="file">JSON 文件</option>
              </select>
            </div>
            <div>
              <FieldLabel label="SQLite 数据库路径" restartRequired />
              <Input
                value={form.credentialDatabasePath}
                placeholder="留空则使用凭据文件目录/credentials.sqlite3"
                onChange={event => updateField('credentialDatabasePath', event.target.value)}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle>模型映射</CardTitle>
                <CardDescription>
                  精确匹配请求模型名并转换为 Kiro 模型 ID；未配置的模型继续使用内置规则。
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={addModelMapping}>
                <Plus className="h-4 w-4" />
                添加映射
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {form.modelMappings.length === 0 ? (
              <div className="rounded-md border border-dashed p-5 text-center text-sm text-muted-foreground">
                暂无自定义映射，当前使用内置模型映射。
              </div>
            ) : (
              <>
                <div className="hidden grid-cols-[minmax(0,1fr)_minmax(0,1fr)_2.5rem] gap-3 px-1 text-xs text-muted-foreground sm:grid">
                  <span>请求模型名</span>
                  <span>Kiro 模型 ID</span>
                  <span />
                </div>
                {form.modelMappings.map((mapping, index) => (
                  <div key={`${index}-${mapping.source}`} className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_2.5rem]">
                    <Input
                      value={mapping.source}
                      placeholder="例如 claude-sonnet-4-6"
                      onChange={event => updateModelMapping(index, 'source', event.target.value)}
                    />
                    <Input
                      value={mapping.target}
                      placeholder="例如 claude-sonnet-4.5"
                      onChange={event => updateModelMapping(index, 'target', event.target.value)}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="justify-self-end text-destructive hover:text-destructive sm:justify-self-center"
                      onClick={() => removeModelMapping(index)}
                      title="删除映射"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </>
            )}
            <p className="text-xs text-muted-foreground">
              带 <code>-thinking</code> 后缀的请求会自动继承基础模型映射。修改后立即生效。
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>客户端标识</CardTitle>
            <CardDescription>这些字段会影响上游请求头和服务认证。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <FieldLabel label="API Key" restartRequired />
              <Input type="password" value={form.apiKey} onChange={event => updateField('apiKey', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Admin API Key" restartRequired />
              <Input type="password" value={form.adminApiKey} onChange={event => updateField('adminApiKey', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Kiro 版本" restartRequired />
              <Input value={form.kiroVersion} onChange={event => updateField('kiroVersion', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Node.js 版本标识" restartRequired />
              <Input value={form.nodeVersion} onChange={event => updateField('nodeVersion', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="系统版本标识" restartRequired />
              <Input value={form.systemVersion} onChange={event => updateField('systemVersion', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="机器码" restartRequired />
              <Input value={form.machineId} placeholder="留空则自动生成" onChange={event => updateField('machineId', event.target.value)} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>代理与 Token 计数</CardTitle>
            <CardDescription>全局代理和外部 count_tokens 服务配置。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <FieldLabel label="全局代理地址" restartRequired />
              <Input value={form.proxyUrl} placeholder="http://host:port 或 socks5://host:port" onChange={event => updateField('proxyUrl', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="代理用户名" restartRequired />
              <Input value={form.proxyUsername} onChange={event => updateField('proxyUsername', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="代理密码" restartRequired />
              <Input type="password" value={form.proxyPassword} onChange={event => updateField('proxyPassword', event.target.value)} />
            </div>
            <div className="sm:col-span-2">
              <FieldLabel label="Token 计数 API 地址" restartRequired />
              <Input value={form.countTokensApiUrl} onChange={event => updateField('countTokensApiUrl', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Token 计数 API Key" restartRequired />
              <Input type="password" value={form.countTokensApiKey} onChange={event => updateField('countTokensApiKey', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Token 计数认证类型" restartRequired />
              <select
                value={form.countTokensAuthType}
                onChange={event => updateField('countTokensAuthType', event.target.value as CountTokensAuthType)}
                className="h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="x-api-key">x-api-key</option>
                <option value="bearer">bearer</option>
              </select>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>调度与恢复</CardTitle>
            <CardDescription>账号调度、并发和禁用账号自动恢复。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <FieldLabel label="负载均衡模式" />
              <select
                value={form.loadBalancingMode}
                onChange={event => updateField('loadBalancingMode', event.target.value as LoadBalancingMode)}
                className="h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="priority">优先级模式</option>
                <option value="balanced">均衡模式</option>
              </select>
            </div>
            <div>
              <FieldLabel label="单账号最大并发" />
              <Input type="number" min={1} value={form.maxConcurrentRequestsPerCredential} onChange={event => updateField('maxConcurrentRequestsPerCredential', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="恢复检查间隔（秒）" />
              <Input type="number" min={0} value={form.disabledCredentialRecoveryIntervalSeconds} onChange={event => updateField('disabledCredentialRecoveryIntervalSeconds', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="每轮检查账号数" />
              <Input type="number" min={1} value={form.disabledCredentialRecoveryBatchSize} onChange={event => updateField('disabledCredentialRecoveryBatchSize', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="批量导入并发数" />
              <Input type="number" min={1} value={form.batchImportConcurrency} onChange={event => updateField('batchImportConcurrency', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="额度查询并发数" />
              <Input type="number" min={1} value={form.usageRequestConcurrency} onChange={event => updateField('usageRequestConcurrency', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Token 预刷新间隔（秒）" />
              <Input type="number" min={0} value={form.proactiveTokenRefreshIntervalSeconds} onChange={event => updateField('proactiveTokenRefreshIntervalSeconds', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="每轮预刷新账号数" />
              <Input type="number" min={1} value={form.proactiveTokenRefreshBatchSize} onChange={event => updateField('proactiveTokenRefreshBatchSize', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="Token 预刷新并发数" />
              <Input type="number" min={1} value={form.proactiveTokenRefreshConcurrency} onChange={event => updateField('proactiveTokenRefreshConcurrency', event.target.value)} />
            </div>
            <div>
              <FieldLabel label="额度查询间隔（秒）" />
              <Input type="number" min={0} value={form.usageQueryIntervalSeconds} onChange={event => updateField('usageQueryIntervalSeconds', event.target.value)} />
              <p className="mt-1 text-xs text-muted-foreground">0 关闭；每轮账号数与并发数复用上方 Token 预刷新参数。定期查用量并提前禁用已耗尽账号。</p>
            </div>
            <div>
              <FieldLabel label="低余额禁用阈值" />
              <Input
                type="number"
                min={0}
                step="0.1"
                value={form.usageQueryDisableRemainingThreshold}
                onChange={event => updateField('usageQueryDisableRemainingThreshold', event.target.value)}
              />
              <p className="mt-1 text-xs text-muted-foreground">查询到剩余额度小于该值时禁用账号；默认 1，设为 0 关闭。</p>
            </div>
            <div className="flex items-center justify-between rounded-md border p-3 sm:col-span-2">
              <div>
                <p className="text-sm font-medium">提取 Thinking 块</p>
                <p className="text-xs text-muted-foreground">非流式响应中解析 thinking 内容。</p>
                <p className="mt-1 text-xs text-emerald-600 dark:text-emerald-400">修改后立即生效</p>
              </div>
              <Switch checked={form.extractThinking} onCheckedChange={checked => updateField('extractThinking', checked)} />
            </div>
          </CardContent>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>端点扩展配置</CardTitle>
            <CardDescription>填写 JSON 对象；当前已注册端点主要由服务内置实现提供。</CardDescription>
          </CardHeader>
          <CardContent>
            <FieldLabel label="endpoints JSON" restartRequired />
            <textarea
              value={form.endpointsJson}
              onChange={event => updateField('endpointsJson', event.target.value)}
              className="min-h-40 w-full rounded-md border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
              spellCheck={false}
            />
          </CardContent>
        </Card>
      </div>

      <div className="flex items-start gap-3 rounded-md border bg-muted/30 p-4 text-sm text-muted-foreground">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
        <div className="space-y-1">
          <p className="font-medium text-foreground">保存策略</p>
          <p>配置会立即写入 config.json。调度与恢复、模型映射等运行时参数可以热更新，其余启动配置需要重启服务。</p>
          <p className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="h-4 w-4" />
            修改敏感字段后请确认当前页面仍使用有效的 Admin API Key。
          </p>
        </div>
      </div>
    </div>
  )
}
