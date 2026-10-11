import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { ChevronDown, ChevronUp, Loader2, Play, RefreshCw, Trash2, Wallet } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { cn, extractErrorMessage } from '@/lib/utils'
import type { BalanceResponse, CredentialStatusItem, ModelItem, ServiceTestResponse } from '@/types/api'
import { getAdminConfig, getModels, testService } from '@/api/credentials'
import {
  useDeleteCredential,
  useForceRefreshToken,
  useResetFailure,
  useSetDisabled,
  useSetPriority,
} from '@/hooks/use-credentials'
import { formatLastUsed, formatLatency, formatTokenExpiration } from '@/components/credential-card'

export type CredentialListColumn =
  | 'id'
  | 'account'
  | 'status'
  | 'priority'
  | 'failures'
  | 'success'
  | 'activeCacheEntries'
  | 'concurrency'
  | 'latency'
  | 'lastUsed'
  | 'tokenExpires'
  | 'usage'
  | 'enabled'

export const CREDENTIAL_LIST_COLUMNS: Array<{ id: CredentialListColumn; label: string }> = [
  { id: 'id', label: 'ID' },
  { id: 'account', label: '账号' },
  { id: 'status', label: '状态' },
  { id: 'priority', label: '优先级' },
  { id: 'failures', label: '失败' },
  { id: 'success', label: '成功' },
  { id: 'activeCacheEntries', label: '有效缓存' },
  { id: 'concurrency', label: '并发' },
  { id: 'latency', label: '响应头' },
  { id: 'lastUsed', label: '最后调用' },
  { id: 'tokenExpires', label: 'Token过期' },
  { id: 'usage', label: '用量' },
  { id: 'enabled', label: '启用' },
]

interface CredentialListProps {
  credentials: CredentialStatusItem[]
  onViewBalance: (id: number) => void
  selectedIds: Set<number>
  onToggleSelect: (id: number) => void
  balanceMap: Map<number, BalanceResponse>
  loadingBalanceIds: Set<number>
  visibleColumns: Set<CredentialListColumn>
}

function authMethodLabel(value: string | null): string {
  if (!value) return '-'
  if (value === 'api_key') return 'API Key'
  if (value === 'idc') return 'IdC'
  if (value === 'social') return 'Social'
  return value
}

interface CredentialRowProps {
  credential: CredentialStatusItem
  onViewBalance: (id: number) => void
  selected: boolean
  onToggleSelect: () => void
  balance: BalanceResponse | null
  loadingBalance: boolean
  visibleColumns: Set<CredentialListColumn>
}

interface CredentialTestDialogProps {
  credential: CredentialStatusItem
  open: boolean
  onOpenChange: (open: boolean) => void
}

const FALLBACK_TEST_MODEL_ID = 'claude-sonnet-4-5-20250929'

function CredentialTestDialog({ credential, open, onOpenChange }: CredentialTestDialogProps) {
  const [models, setModels] = useState<ModelItem[]>([])
  const [selectedModel, setSelectedModel] = useState('')
  const [prompt, setPrompt] = useState('hi')
  const [loadingModels, setLoadingModels] = useState(false)
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<ServiceTestResponse | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return

    setPrompt('hi')
    setResult(null)
    setError('')
    setLoadingModels(true)
    Promise.all([
      getModels(),
      getAdminConfig().catch(() => ({
        config: { testDefaultModel: FALLBACK_TEST_MODEL_ID },
      })),
    ])
      .then(([response, configResponse]) => {
        const nextModels = response.data
        const configuredModel = configResponse.config.testDefaultModel || FALLBACK_TEST_MODEL_ID
        const selected = nextModels.some(model => model.id === configuredModel)
          ? configuredModel
          : nextModels[0]?.id || ''

        setModels(nextModels)
        setSelectedModel(selected)
      })
      .catch((err) => {
        const message = extractErrorMessage(err)
        setError(`模型列表加载失败: ${message}`)
        toast.error(`模型列表加载失败: ${message}`)
      })
      .finally(() => setLoadingModels(false))
  }, [open])

  const handleTest = async () => {
    if (!selectedModel) {
      setError('请选择模型')
      return
    }
    if (!prompt.trim()) {
      setError('请输入测试内容')
      return
    }

    setTesting(true)
    setResult(null)
    setError('')
    try {
      const response = await testService({
        credentialId: credential.id,
        model: selectedModel,
        prompt: prompt.trim(),
      })
      setResult(response)
    } catch (err) {
      setError(extractErrorMessage(err))
    } finally {
      setTesting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>测试凭据 #{credential.id}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="mb-1.5 block text-sm font-medium">模型</label>
            <select
              value={selectedModel}
              onChange={event => setSelectedModel(event.target.value)}
              disabled={loadingModels || models.length === 0}
              className="h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              {loadingModels ? (
                <option value="">加载中...</option>
              ) : (
                models.map(model => (
                  <option key={model.id} value={model.id}>
                    {model.display_name || model.id}
                  </option>
                ))
              )}
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium">输入</label>
            <Input value={prompt} onChange={event => setPrompt(event.target.value)} />
          </div>
          {result && (
            <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-950 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-100">
              <div className="mb-2 font-medium">
                测试成功 · {result.latencyMs} ms · {result.model}
              </div>
              <div className="whitespace-pre-wrap break-words">
                {result.replyText || result.responsePreview}
              </div>
            </div>
          )}
          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300">
              {error}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button
            onClick={() => void handleTest()}
            disabled={testing || loadingModels || !selectedModel}
          >
            {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            测试
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CredentialRow({
  credential,
  onViewBalance,
  selected,
  onToggleSelect,
  balance,
  loadingBalance,
  visibleColumns,
}: CredentialRowProps) {
  const [testDialogOpen, setTestDialogOpen] = useState(false)
  const setDisabled = useSetDisabled()
  const setPriority = useSetPriority()
  const resetFailure = useResetFailure()
  const forceRefresh = useForceRefreshToken()
  const deleteCredential = useDeleteCredential()

  const credentialName = credential.email || `凭据 #${credential.id}`
  const hasFailures = credential.failureCount > 0 || credential.refreshFailureCount > 0
  const tokenExpiration = formatTokenExpiration(credential.expiresAt, credential.authMethod)
  const showColumn = (column: CredentialListColumn) => visibleColumns.has(column)

  const handleToggleDisabled = () => {
    setDisabled.mutate(
      { id: credential.id, disabled: !credential.disabled },
      {
        onSuccess: (res) => toast.success(res.message),
        onError: (err) => toast.error('操作失败: ' + (err as Error).message),
      }
    )
  }

  const handlePriorityChange = (priority: number) => {
    setPriority.mutate(
      { id: credential.id, priority: Math.max(0, priority) },
      {
        onSuccess: (res) => toast.success(res.message),
        onError: (err) => toast.error('操作失败: ' + (err as Error).message),
      }
    )
  }

  const handleReset = () => {
    resetFailure.mutate(credential.id, {
      onSuccess: (res) => toast.success(res.message),
      onError: (err) => toast.error('操作失败: ' + (err as Error).message),
    })
  }

  const handleForceRefresh = () => {
    forceRefresh.mutate(credential.id, {
      onSuccess: (res) => toast.success(res.message),
      onError: (err) => toast.error('刷新失败: ' + (err as Error).message),
    })
  }

  const handleDelete = () => {
    if (!credential.disabled) {
      toast.error('请先禁用凭据再删除')
      return
    }

    if (!confirm(`确定要删除凭据 #${credential.id} 吗？此操作无法撤销。`)) {
      return
    }

    deleteCredential.mutate(credential.id, {
      onSuccess: (res) => toast.success(res.message),
      onError: (err) => toast.error('删除失败: ' + (err as Error).message),
    })
  }

  return (
    <>
      <tr className={cn('border-b transition-colors hover:bg-muted/50', credential.isCurrent && 'bg-primary/5')}>
        <td className="w-10 px-3 py-2">
          <Checkbox checked={selected} onCheckedChange={onToggleSelect} />
        </td>
      {showColumn('id') && (
        <td className="w-16 px-3 py-2 font-mono text-xs text-muted-foreground">#{credential.id}</td>
      )}
      {showColumn('account') && (
        <td className="min-w-[13rem] px-3 py-2">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-medium" title={credentialName}>
              {credentialName}
            </span>
            {credential.isCurrent && <Badge variant="success">当前</Badge>}
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>{authMethodLabel(credential.authMethod)}</span>
            {credential.endpoint && (
              <>
                <span>/</span>
                <span className="max-w-[7rem] truncate" title={credential.endpoint}>{credential.endpoint}</span>
              </>
            )}
            {credential.maskedApiKey && (
              <>
                <span>/</span>
                <span className="max-w-[9rem] truncate font-mono" title={credential.maskedApiKey}>
                  {credential.maskedApiKey}
                </span>
              </>
            )}
          </div>
        </td>
      )}
      {showColumn('status') && (
        <td className="px-3 py-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {credential.disabled ? (
              <Badge variant="destructive">已禁用</Badge>
            ) : (
              <Badge variant="success">启用</Badge>
            )}
            {credential.disabledReason && (
              <Badge className="max-w-[8rem] truncate" variant="outline" title={credential.disabledReason}>
                {credential.disabledReason}
              </Badge>
            )}
          </div>
        </td>
      )}
      {showColumn('priority') && (
        <td className="px-3 py-2">
          <div className="flex items-center gap-1">
            <Button
              className="h-7 w-7 p-0"
              size="sm"
              variant="ghost"
              onClick={() => handlePriorityChange(credential.priority - 1)}
              disabled={setPriority.isPending || credential.priority === 0}
              title="提高优先级"
            >
              <ChevronUp className="h-4 w-4" />
            </Button>
            <span className="w-8 text-center font-medium">{credential.priority}</span>
            <Button
              className="h-7 w-7 p-0"
              size="sm"
              variant="ghost"
              onClick={() => handlePriorityChange(credential.priority + 1)}
              disabled={setPriority.isPending}
              title="降低优先级"
            >
              <ChevronDown className="h-4 w-4" />
            </Button>
          </div>
        </td>
      )}
      {showColumn('failures') && (
        <td className="px-3 py-2">
          <div className={cn('font-medium', hasFailures && 'text-red-500')}>
            {credential.failureCount} / {credential.refreshFailureCount}
          </div>
        </td>
      )}
      {showColumn('success') && (
        <td className="px-3 py-2 font-medium">{credential.successCount}</td>
      )}
      {showColumn('activeCacheEntries') && (
        <td className="px-3 py-2 font-medium">{credential.activeCacheEntryCount}</td>
      )}
      {showColumn('concurrency') && (
        <td className="px-3 py-2">
          <span className={cn('font-medium', credential.currentConcurrentRequests > 0 && 'text-blue-600')}>
            {credential.currentConcurrentRequests}
          </span>
        </td>
      )}
      {showColumn('latency') && (
        <td className="px-3 py-2 font-medium">{formatLatency(credential.upstreamHeaderLatencyEmaMs)}</td>
      )}
      {showColumn('lastUsed') && (
        <td className="px-3 py-2 text-muted-foreground">{formatLastUsed(credential.lastUsedAt)}</td>
      )}
      {showColumn('tokenExpires') && (
        <td className="min-w-[13rem] px-3 py-2">
          <span
            className={cn(
              'font-medium',
              tokenExpiration.tone === 'danger' && 'text-red-500',
              tokenExpiration.tone === 'warning' && 'text-amber-600',
              tokenExpiration.tone === 'muted' && 'font-normal text-muted-foreground'
            )}
            title={tokenExpiration.title}
          >
            {tokenExpiration.text}
          </span>
        </td>
      )}
      {showColumn('usage') && (
        <td className="min-w-[11rem] px-3 py-2">
          {loadingBalance ? (
            <span className="inline-flex items-center gap-1 text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              查询中
            </span>
          ) : balance ? (
            <div className="leading-5">
              <div className="font-medium">{balance.remaining.toLocaleString('zh-CN', { maximumFractionDigits: 8 })} / {balance.usageLimit.toLocaleString('zh-CN', { maximumFractionDigits: 8 })}</div>
              <div className="text-xs text-muted-foreground">{balance.subscriptionTitle || '未知'}</div>
            </div>
          ) : (
            <span className="text-muted-foreground">未知</span>
          )}
        </td>
      )}
      {showColumn('enabled') && (
        <td className="px-3 py-2">
          <Switch checked={!credential.disabled} onCheckedChange={handleToggleDisabled} disabled={setDisabled.isPending} />
        </td>
      )}
      <td className="px-3 py-2">
        <div className="flex items-center justify-end gap-1">
          <Button
            className="h-8 w-8 p-0"
            size="sm"
            variant="ghost"
            onClick={() => setTestDialogOpen(true)}
            disabled={credential.disabled}
            title="测试账号"
          >
            <Play className="h-4 w-4" />
          </Button>
          <Button
            className="h-8 w-8 p-0"
            size="sm"
            variant="ghost"
            onClick={handleReset}
            disabled={resetFailure.isPending || !hasFailures}
            title="重置失败"
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            className="h-8 w-8 p-0"
            size="sm"
            variant="ghost"
            onClick={handleForceRefresh}
            disabled={forceRefresh.isPending || credential.disabled || credential.authMethod === 'api_key'}
            title="刷新 Token"
          >
            <RefreshCw className={cn('h-4 w-4', forceRefresh.isPending && 'animate-spin')} />
          </Button>
          <Button
            className="h-8 w-8 p-0"
            size="sm"
            variant="ghost"
            onClick={() => onViewBalance(credential.id)}
            title="查看余额"
          >
            <Wallet className="h-4 w-4" />
          </Button>
          <Button
            className="h-8 w-8 p-0"
            size="sm"
            variant="ghost"
            onClick={handleDelete}
            disabled={deleteCredential.isPending || !credential.disabled}
            title="删除"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </td>
      </tr>
      <CredentialTestDialog
        credential={credential}
        open={testDialogOpen}
        onOpenChange={setTestDialogOpen}
      />
    </>
  )
}

export function CredentialList({
  credentials,
  onViewBalance,
  selectedIds,
  onToggleSelect,
  balanceMap,
  loadingBalanceIds,
  visibleColumns,
}: CredentialListProps) {
  const showColumn = (column: CredentialListColumn) => visibleColumns.has(column)

  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full min-w-[1200px] text-left text-sm">
        <thead className="border-b bg-muted/50 text-xs text-muted-foreground">
          <tr>
            <th className="w-10 px-3 py-2"></th>
            {showColumn('id') && <th className="w-16 whitespace-nowrap px-3 py-2">ID</th>}
            {showColumn('account') && <th className="whitespace-nowrap px-3 py-2">账号</th>}
            {showColumn('status') && <th className="whitespace-nowrap px-3 py-2">状态</th>}
            {showColumn('priority') && <th className="whitespace-nowrap px-3 py-2">优先级</th>}
            {showColumn('failures') && <th className="whitespace-nowrap px-3 py-2">失败</th>}
            {showColumn('success') && <th className="whitespace-nowrap px-3 py-2">成功</th>}
            {showColumn('activeCacheEntries') && <th className="whitespace-nowrap px-3 py-2">有效缓存</th>}
            {showColumn('concurrency') && <th className="whitespace-nowrap px-3 py-2">并发</th>}
            {showColumn('lastUsed') && <th className="whitespace-nowrap px-3 py-2">最后调用</th>}
            {showColumn('tokenExpires') && <th className="whitespace-nowrap px-3 py-2">Token过期</th>}
            {showColumn('usage') && <th className="whitespace-nowrap px-3 py-2">用量</th>}
            {showColumn('enabled') && <th className="whitespace-nowrap px-3 py-2">启用</th>}
            <th className="whitespace-nowrap px-3 py-2 text-right">操作</th>
          </tr>
        </thead>
        <tbody>
          {credentials.map((credential) => (
            <CredentialRow
              key={credential.id}
              credential={credential}
              onViewBalance={onViewBalance}
              selected={selectedIds.has(credential.id)}
              onToggleSelect={() => onToggleSelect(credential.id)}
              balance={balanceMap.get(credential.id) || null}
              loadingBalance={loadingBalanceIds.has(credential.id)}
              visibleColumns={visibleColumns}
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}
