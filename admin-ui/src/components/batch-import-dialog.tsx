import { useState } from 'react'
import { toast } from 'sonner'
import { CheckCircle2, XCircle, AlertCircle, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { useCredentials, useAddCredential } from '@/hooks/use-credentials'
import { getAdminConfig } from '@/api/credentials'
import { extractErrorMessage, sha256Hex } from '@/lib/utils'

interface BatchImportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

interface CredentialInput {
  refreshToken?: string
  clientId?: string
  clientSecret?: string
  region?: string
  authRegion?: string
  apiRegion?: string
  priority?: number
  machineId?: string
  kiroApiKey?: string
  authMethod?: string
  endpoint?: string
}

interface VerificationResult {
  index: number
  status: 'pending' | 'checking' | 'verifying' | 'verified' | 'duplicate' | 'failed'
  error?: string
  usage?: string
  email?: string
  credentialId?: number
}

const DEFAULT_BATCH_IMPORT_CONCURRENCY = 50

async function getBatchImportConcurrency(): Promise<number> {
  try {
    const response = await getAdminConfig()
    const configured = Number(response.config.batchImportConcurrency)
    return Number.isFinite(configured) ? Math.max(1, Math.floor(configured)) : DEFAULT_BATCH_IMPORT_CONCURRENCY
  } catch {
    return DEFAULT_BATCH_IMPORT_CONCURRENCY
  }
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<void>
) {
  let cursor = 0
  const workerCount = Math.min(concurrency, items.length)

  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (cursor < items.length) {
      const index = cursor
      cursor += 1
      await worker(items[index], index)
    }
  }))
}

export function BatchImportDialog({ open, onOpenChange }: BatchImportDialogProps) {
  const [jsonInput, setJsonInput] = useState('')
  const [importing, setImporting] = useState(false)
  const [progress, setProgress] = useState({ current: 0, total: 0 })
  const [currentProcessing, setCurrentProcessing] = useState<string>('')
  const [results, setResults] = useState<VerificationResult[]>([])

  const { data: existingCredentials } = useCredentials({ enabled: open })
  const { mutateAsync: addCredential } = useAddCredential()

  const resetForm = () => {
    setJsonInput('')
    setProgress({ current: 0, total: 0 })
    setCurrentProcessing('')
    setResults([])
  }

  const handleBatchImport = async () => {
    // 先单独解析 JSON，给出精准的错误提示
    let credentials: CredentialInput[]
    try {
      const parsed = JSON.parse(jsonInput)
      credentials = Array.isArray(parsed) ? parsed : [parsed]
    } catch (error) {
      toast.error('JSON 格式错误: ' + extractErrorMessage(error))
      return
    }

    if (credentials.length === 0) {
      toast.error('没有可导入的凭据')
      return
    }

    try {
      setImporting(true)
      setProgress({ current: 0, total: credentials.length })
      const importConcurrency = await getBatchImportConcurrency()

      // 2. 初始化结果
      const initialResults: VerificationResult[] = credentials.map((_, i) => ({
        index: i + 1,
        status: 'pending'
      }))
      setResults(initialResults)

      // 3. 检测重复：OAuth 与 API Key 分别使用对应的 hash 集合
      const existingOauthHashes = new Set(
        existingCredentials?.credentials
          .map(c => c.refreshTokenHash)
          .filter((hash): hash is string => Boolean(hash)) || []
      )
      const existingApiKeyHashes = new Set(
        existingCredentials?.credentials
          .map(c => c.apiKeyHash)
          .filter((hash): hash is string => Boolean(hash)) || []
      )

      let successCount = 0
      let duplicateCount = 0
      let failCount = 0
      let completedCount = 0
      const reservedOauthHashes = new Set(existingOauthHashes)
      const reservedApiKeyHashes = new Set(existingApiKeyHashes)

      const completeOne = () => {
        completedCount++
        setProgress({ current: completedCount, total: credentials.length })
        setCurrentProcessing(`并发导入中... ${completedCount}/${credentials.length}`)
      }

      // 4. 并发导入。添加成功即完成，不在导入阶段查询额度。
      await runWithConcurrency(credentials, importConcurrency, async (cred, i) => {
        const isApiKeyCred = !!(cred.kiroApiKey?.trim()) || cred.authMethod === 'api_key'

        // 更新状态为检查中
        setCurrentProcessing(`并发导入中... ${completedCount}/${credentials.length}`)
        setResults(prev => {
          const newResults = [...prev]
          newResults[i] = { ...newResults[i], status: 'checking' }
          return newResults
        })

        // 客户端去重：OAuth 基于 refreshToken hash，API Key 基于 kiroApiKey hash
        let credHash = ''
        if (isApiKeyCred) {
          const apiKey = cred.kiroApiKey?.trim() || ''
          if (!apiKey) {
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = {
                ...newResults[i],
                status: 'failed',
                error: '缺少 kiroApiKey',
              }
              return newResults
            })
            failCount++
            completeOne()
            return
          }
          credHash = await sha256Hex(apiKey)
          if (reservedApiKeyHashes.has(credHash)) {
            duplicateCount++
            const existingCred = existingCredentials?.credentials.find(c => c.apiKeyHash === credHash)
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = {
                ...newResults[i],
                status: 'duplicate',
                error: '该凭据已存在',
                email: existingCred?.email || undefined
              }
              return newResults
            })
            completeOne()
            return
          }
          reservedApiKeyHashes.add(credHash)
        } else {
          const token = cred.refreshToken?.trim() || ''
          if (!token) {
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = {
                ...newResults[i],
                status: 'failed',
                error: '缺少 refreshToken',
              }
              return newResults
            })
            failCount++
            completeOne()
            return
          }
          credHash = await sha256Hex(token)
          if (reservedOauthHashes.has(credHash)) {
            duplicateCount++
            const existingCred = existingCredentials?.credentials.find(c => c.refreshTokenHash === credHash)
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = {
                ...newResults[i],
                status: 'duplicate',
                error: '该凭据已存在',
                email: existingCred?.email || undefined
              }
              return newResults
            })
            completeOne()
            return
          }
          reservedOauthHashes.add(credHash)
        }

        // 更新状态为导入中
        setResults(prev => {
          const newResults = [...prev]
          newResults[i] = { ...newResults[i], status: 'verifying' }
          return newResults
        })

        try {
          // 添加凭据
          if (isApiKeyCred) {
            // API Key 凭据
            const addedCred = await addCredential({
              authMethod: 'api_key',
              kiroApiKey: cred.kiroApiKey?.trim(),
              priority: cred.priority || 0,
              authRegion: cred.authRegion?.trim() || cred.region?.trim() || undefined,
              apiRegion: cred.apiRegion?.trim() || undefined,
              machineId: cred.machineId?.trim() || undefined,
              endpoint: cred.endpoint?.trim() || undefined,
            })

            successCount++
            setCurrentProcessing(addedCred.email ? `导入成功: ${addedCred.email}` : `导入成功: 凭据 ${i + 1}`)
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = {
                ...newResults[i],
                status: 'verified',
                email: addedCred.email || undefined,
                credentialId: addedCred.credentialId
              }
              return newResults
            })
            completeOne()
            return
          }

          // OAuth 凭据
          const token = cred.refreshToken!.trim()
          const clientId = cred.clientId?.trim() || undefined
          const clientSecret = cred.clientSecret?.trim() || undefined
          const authMethod = clientId && clientSecret ? 'idc' : 'social'

          // idc 模式下必须同时提供 clientId 和 clientSecret
          if (authMethod === 'social' && (clientId || clientSecret)) {
            throw new Error('idc 模式需要同时提供 clientId 和 clientSecret')
          }

          const addedCred = await addCredential({
            refreshToken: token,
            authMethod,
            authRegion: cred.authRegion?.trim() || cred.region?.trim() || undefined,
            apiRegion: cred.apiRegion?.trim() || undefined,
            clientId,
            clientSecret,
            priority: cred.priority || 0,
            machineId: cred.machineId?.trim() || undefined,
            endpoint: cred.endpoint?.trim() || undefined,
          })

          // 导入成功
          successCount++
          setCurrentProcessing(addedCred.email ? `导入成功: ${addedCred.email}` : `导入成功: 凭据 ${i + 1}`)
          setResults(prev => {
            const newResults = [...prev]
            newResults[i] = {
              ...newResults[i],
              status: 'verified',
              email: addedCred.email || undefined,
              credentialId: addedCred.credentialId
            }
            return newResults
          })
        } catch (error) {
          failCount++
          setResults(prev => {
            const newResults = [...prev]
            newResults[i] = {
              ...newResults[i],
              status: 'failed',
              error: extractErrorMessage(error),
              email: undefined,
            }
            return newResults
          })
        }

        completeOne()
      })

      // 显示结果
      if (failCount === 0 && duplicateCount === 0) {
        toast.success(`成功导入 ${successCount} 个凭据`)
      } else {
        const failureSummary = failCount > 0 ? `，失败 ${failCount} 个` : ''
        toast.info(`导入完成：成功 ${successCount} 个，重复 ${duplicateCount} 个${failureSummary}`)
      }
    } catch (error) {
      toast.error('导入失败: ' + extractErrorMessage(error))
    } finally {
      setImporting(false)
    }
  }

  const getStatusIcon = (status: VerificationResult['status']) => {
    switch (status) {
      case 'pending':
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
      case 'checking':
      case 'verifying':
        return <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
      case 'verified':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />
      case 'duplicate':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-500" />
    }
  }

  const getStatusText = (result: VerificationResult) => {
    switch (result.status) {
      case 'pending':
        return '等待中'
      case 'checking':
        return '检查重复...'
      case 'verifying':
        return '导入中...'
      case 'verified':
        return '导入成功'
      case 'duplicate':
        return '重复凭据'
      case 'failed':
        return '导入失败'
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(newOpen) => {
        // 关闭时清空表单（但不在导入过程中清空）
        if (!newOpen && !importing) {
          resetForm()
        }
        onOpenChange(newOpen)
      }}
    >
      <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>批量导入凭据</DialogTitle>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">
              JSON 格式凭据
            </label>
            <textarea
              placeholder={'粘贴 JSON 格式的凭据（支持单个对象或数组）\n\nOAuth: [{"refreshToken":"...","clientId":"...","clientSecret":"..."}]\nAPI Key: [{"kiroApiKey":"ksk_xxx"}]\n\n支持 region 字段自动映射为 authRegion'}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              disabled={importing}
              className="flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 font-mono"
            />
            <p className="text-xs text-muted-foreground">
              只导入凭据，不自动查询额度；需要额度信息时可在列表页点击“查询信息”。
            </p>
          </div>

          {(importing || results.length > 0) && (
            <>
              {/* 进度条 */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>{importing ? '导入进度' : '导入完成'}</span>
                  <span>{progress.current} / {progress.total}</span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full transition-all"
                    style={{ width: `${(progress.current / progress.total) * 100}%` }}
                  />
                </div>
                {importing && currentProcessing && (
                  <div className="text-xs text-muted-foreground">
                    {currentProcessing}
                  </div>
                )}
              </div>

              {/* 统计 */}
              <div className="flex gap-4 text-sm">
                <span className="text-green-600 dark:text-green-400">
                  ✓ 成功: {results.filter(r => r.status === 'verified').length}
                </span>
                <span className="text-yellow-600 dark:text-yellow-400">
                  ⚠ 重复: {results.filter(r => r.status === 'duplicate').length}
                </span>
                <span className="text-red-600 dark:text-red-400">
                  ✗ 失败: {results.filter(r => r.status === 'failed').length}
                </span>
              </div>

              {/* 结果列表 */}
              <div className="border rounded-md divide-y max-h-[300px] overflow-y-auto">
                {results.map((result) => (
                  <div key={result.index} className="p-3">
                    <div className="flex items-start gap-3">
                      {getStatusIcon(result.status)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {result.email || `凭据 #${result.index}`}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {getStatusText(result)}
                          </span>
                        </div>
                        {result.usage && (
                          <div className="text-xs text-muted-foreground mt-1">
                            用量: {result.usage}
                          </div>
                        )}
                        {result.error && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">
                            {result.error}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              onOpenChange(false)
              resetForm()
            }}
            disabled={importing}
          >
            {importing ? '导入中...' : results.length > 0 ? '关闭' : '取消'}
          </Button>
          {results.length === 0 && (
            <Button
              type="button"
              onClick={handleBatchImport}
              disabled={importing || !jsonInput.trim()}
            >
              开始导入
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
