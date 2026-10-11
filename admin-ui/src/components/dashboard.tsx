import { useState, useEffect, useRef } from 'react'
import { RefreshCw, LogOut, Moon, Sun, Server, Plus, Upload, FileUp, Trash2, RotateCcw, CheckCircle2, LayoutGrid, List, Columns3, Settings, Search, CheckSquare, Loader2 } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { CredentialCard } from '@/components/credential-card'
import {
  CREDENTIAL_LIST_COLUMNS,
  CredentialList,
  type CredentialListColumn,
} from '@/components/credential-list'
import { BalanceDialog } from '@/components/balance-dialog'
import { AddCredentialDialog } from '@/components/add-credential-dialog'
import { BatchImportDialog } from '@/components/batch-import-dialog'
import { KamImportDialog } from '@/components/kam-import-dialog'
import { BatchVerifyDialog, type VerifyResult } from '@/components/batch-verify-dialog'
import { SettingsPage } from '@/components/settings-page'
import { useCredentials, useDeleteCredential, useResetFailure, useLoadBalancingMode, useSetLoadBalancingMode } from '@/hooks/use-credentials'
import { getCredentialBalance, forceRefreshToken, setCredentialDisabled } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { BalanceResponse, LoadBalancingMode } from '@/types/api'

const BALANCE_QUERY_CONCURRENCY = 6
const LIST_COLUMNS_STORAGE_KEY = 'kiro-admin-list-visible-columns'
const DEFAULT_VISIBLE_LIST_COLUMNS = CREDENTIAL_LIST_COLUMNS.map(column => column.id)
const AUTO_VISIBLE_LIST_COLUMNS: CredentialListColumn[] = ['activeCacheEntries', 'concurrency', 'tokenExpires']

type SortField = 'priority' | 'success' | 'lastUsed' | 'remaining'
type SortDirection = 'asc' | 'desc'
type StatusFilter = 'all' | 'enabled' | 'disabled' | `reason:${string}`

interface DashboardProps {
  onLogout: () => void
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

export function Dashboard({ onLogout }: DashboardProps) {
  const [activeView, setActiveView] = useState<'credentials' | 'settings'>('credentials')
  const [selectedCredentialId, setSelectedCredentialId] = useState<number | null>(null)
  const [balanceDialogOpen, setBalanceDialogOpen] = useState(false)
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [batchImportDialogOpen, setBatchImportDialogOpen] = useState(false)
  const [kamImportDialogOpen, setKamImportDialogOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyProgress, setVerifyProgress] = useState({ current: 0, total: 0 })
  const [verifyResults, setVerifyResults] = useState<Map<number, VerifyResult>>(new Map())
  const [balanceMap, setBalanceMap] = useState<Map<number, BalanceResponse>>(new Map())
  const [loadingBalanceIds, setLoadingBalanceIds] = useState<Set<number>>(new Set())
  const [queryingInfo, setQueryingInfo] = useState(false)
  const [queryInfoProgress, setQueryInfoProgress] = useState({ current: 0, total: 0 })
  const [batchRefreshing, setBatchRefreshing] = useState(false)
  const [batchRefreshProgress, setBatchRefreshProgress] = useState({ current: 0, total: 0 })
  const cancelVerifyRef = useRef(false)
  const columnManagerRef = useRef<HTMLDivElement | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageInput, setPageInput] = useState('1')
  const [sortField, setSortField] = useState<SortField>('priority')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('enabled')
  const [credentialSearch, setCredentialSearch] = useState('')
  const [columnManagerOpen, setColumnManagerOpen] = useState(false)
  const [visibleListColumns, setVisibleListColumns] = useState<Set<CredentialListColumn>>(() => {
    if (typeof window === 'undefined') {
      return new Set(DEFAULT_VISIBLE_LIST_COLUMNS)
    }

    try {
      const saved = window.localStorage.getItem(LIST_COLUMNS_STORAGE_KEY)
      const parsed = saved ? JSON.parse(saved) : null
      const validIds = new Set(CREDENTIAL_LIST_COLUMNS.map(column => column.id))
      const selected = Array.isArray(parsed)
        ? parsed.filter((column): column is CredentialListColumn => validIds.has(column))
        : []

      const columns = new Set(selected.length > 0 ? selected : DEFAULT_VISIBLE_LIST_COLUMNS)
      AUTO_VISIBLE_LIST_COLUMNS.forEach(column => columns.add(column))
      return columns
    } catch {
      return new Set(DEFAULT_VISIBLE_LIST_COLUMNS)
    }
  })
  const [viewMode, setViewMode] = useState<'cards' | 'list'>(() => {
    if (typeof window === 'undefined') {
      return 'cards'
    }
    return window.localStorage.getItem('kiro-admin-view-mode') === 'list' ? 'list' : 'cards'
  })
  const itemsPerPage = viewMode === 'list' ? 50 : 12
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  const queryClient = useQueryClient()
  const disabledReasonFilter = statusFilter.startsWith('reason:')
    ? statusFilter.slice('reason:'.length)
    : undefined
  const credentialStatusFilter: 'all' | 'enabled' | 'disabled' = statusFilter.startsWith('reason:')
    ? 'disabled'
    : statusFilter === 'enabled' || statusFilter === 'disabled'
      ? statusFilter
      : 'all'
  const { data, isLoading, isFetching, error, refetch } = useCredentials({
    enabled: activeView === 'credentials',
    page: currentPage,
    pageSize: itemsPerPage,
    sortField,
    sortDirection,
    status: credentialStatusFilter,
    disabledReason: disabledReasonFilter,
    search: credentialSearch.trim() || undefined,
  })
  const { mutate: deleteCredential } = useDeleteCredential()
  const { mutate: resetFailure } = useResetFailure()
  const { data: loadBalancingData, isLoading: isLoadingMode } = useLoadBalancingMode()
  const { mutate: setLoadBalancingMode, isPending: isSettingMode } = useSetLoadBalancingMode()
  const stats = data?.stats
  const formatNumber = (value: number | undefined | null) => value == null
    ? '--'
    : new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 12 }).format(value)
  const formatRate = (value: number | undefined | null) => `${(value ?? 0).toFixed(1)}%`
  const filteredTotal = data?.filteredTotal ?? data?.total ?? 0

  const disabledReasonLabel = (reason: string) => {
    switch (reason) {
      case 'QuotaExceeded':
        return '额度用尽'
      case 'Manual':
        return '手动禁用'
      case 'TooManyFailures':
        return '失败过多'
      case 'TooManyRefreshFailures':
        return '刷新失败过多'
      case 'InvalidRefreshToken':
        return 'RefreshToken 失效'
      case 'InvalidConfig':
        return '配置无效'
      case 'AccountSuspended':
        return '账号封禁'
      case 'Unknown':
        return '未标记原因'
      default:
        return reason
    }
  }

  // 计算分页
  const totalPages = Math.ceil(filteredTotal / itemsPerPage)
  const currentCredentials = data?.credentials || []
  const currentPageIds = currentCredentials.map(credential => credential.id)
  const filteredCredentialIds = data?.filteredIds ?? currentPageIds
  const filteredDisabledIdSet = new Set(
    data?.filteredDisabledIds ?? currentCredentials.filter(credential => credential.disabled).map(credential => credential.id)
  )
  const filteredFailedIdSet = new Set(
    data?.filteredFailedIds
      ?? currentCredentials
        .filter(credential => credential.failureCount > 0 || credential.refreshFailureCount > 0)
        .map(credential => credential.id)
  )
  const currentPageAllSelected = currentPageIds.length > 0
    && currentPageIds.every(id => selectedIds.has(id))
  const disabledCredentialCount = data?.disabledIds?.length
    ?? Math.max(0, (data?.total || 0) - (data?.available || 0))
  const selectedDisabledCount = Array.from(selectedIds).filter(id => filteredDisabledIdSet.has(id)).length

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('kiro-admin-view-mode', viewMode)
    }
  }, [viewMode])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(LIST_COLUMNS_STORAGE_KEY, JSON.stringify(Array.from(visibleListColumns)))
    }
  }, [visibleListColumns])

  useEffect(() => {
    if (!columnManagerOpen || typeof window === 'undefined') {
      return
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (columnManagerRef.current?.contains(event.target as Node)) {
        return
      }
      setColumnManagerOpen(false)
    }

    window.addEventListener('pointerdown', handlePointerDown)
    return () => window.removeEventListener('pointerdown', handlePointerDown)
  }, [columnManagerOpen])

  // 当凭据列表变化时重置到第一页
  useEffect(() => {
    setCurrentPage(1)
    setSelectedIds(new Set())
  }, [sortDirection, sortField, statusFilter, viewMode, credentialSearch])

  useEffect(() => {
    setPageInput(String(currentPage))
  }, [currentPage])

  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages)
    }
  }, [currentPage, totalPages])

  const handlePageJump = () => {
    const nextPage = Number.parseInt(pageInput, 10)
    if (Number.isNaN(nextPage)) {
      toast.error('请输入有效页码')
      return
    }
    if (totalPages <= 0) {
      return
    }
    const clamped = Math.min(Math.max(1, nextPage), totalPages)
    setCurrentPage(clamped)
    setPageInput(String(clamped))
  }

  const toggleListColumn = (column: CredentialListColumn) => {
    setVisibleListColumns(prev => {
      const next = new Set(prev)
      if (next.has(column)) {
        if (next.size === 1) {
          toast.error('至少保留一列')
          return prev
        }
        next.delete(column)
      } else {
        next.add(column)
      }
      return next
    })
  }

  const resetListColumns = () => {
    setVisibleListColumns(new Set(DEFAULT_VISIBLE_LIST_COLUMNS))
  }

  // 后端未返回有效余额时清除旧值，避免继续展示已失效快照。
  useEffect(() => {
    if (!data?.credentials) {
      setBalanceMap(new Map())
      setLoadingBalanceIds(new Set())
      return
    }

    const validIds = new Set(data.credentials.map(credential => credential.id))

    setBalanceMap(prev => {
      const next = new Map<number, BalanceResponse>()
      data.credentials.forEach(credential => {
        if (credential.balance) {
          next.set(credential.id, credential.balance)
        }
      })
      if (next.size !== prev.size) {
        return next
      }
      for (const [id, value] of next) {
        if (prev.get(id) !== value) {
          return next
        }
      }
      return prev
    })

    setLoadingBalanceIds(prev => {
      if (prev.size === 0) {
        return prev
      }
      const next = new Set<number>()
      prev.forEach(id => {
        if (validIds.has(id)) {
          next.add(id)
        }
      })
      return next.size === prev.size ? prev : next
    })
  }, [data?.credentials])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
    document.documentElement.classList.toggle('dark')
  }

  const handleSortChange = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc')
      return
    }
    setSortField(field)
    setSortDirection(field === 'priority' ? 'asc' : 'desc')
  }

  const sortLabel = (field: SortField, label: string) => {
    if (sortField !== field) {
      return label
    }
    return `${label} ${sortDirection === 'asc' ? '↑' : '↓'}`
  }

  const handleViewBalance = (id: number) => {
    setSelectedCredentialId(id)
    setBalanceDialogOpen(true)
  }

  const handleRefresh = () => {
    refetch()
    toast.success('已刷新凭据列表')
  }

  const handleLogout = () => {
    storage.removeApiKey()
    queryClient.clear()
    onLogout()
  }

  // 选择管理
  const toggleSelect = (id: number) => {
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  const toggleSelectCurrentPage = () => {
    if (currentPageIds.length === 0) {
      toast.error('当前页没有可选择的凭据')
      return
    }

    setSelectedIds(prev => {
      const next = new Set(prev)
      if (currentPageAllSelected) {
        currentPageIds.forEach(id => next.delete(id))
      } else {
        currentPageIds.forEach(id => next.add(id))
      }
      return next
    })
  }

  const selectAllPages = () => {
    if (filteredCredentialIds.length === 0) {
      toast.error('没有可选择的凭据')
      return
    }
    setSelectedIds(new Set(filteredCredentialIds))
    toast.success(`已选择当前筛选条件下的 ${filteredCredentialIds.length} 个凭据`)
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  // 批量删除（仅删除已禁用项）
  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要删除的凭据')
      return
    }

    const disabledIds = Array.from(selectedIds).filter(id => filteredDisabledIdSet.has(id))

    if (disabledIds.length === 0) {
      toast.error('选中的凭据中没有已禁用项')
      return
    }

    const skippedCount = selectedIds.size - disabledIds.length
    const skippedText = skippedCount > 0 ? `（将跳过 ${skippedCount} 个未禁用凭据）` : ''

    if (!confirm(`确定要删除 ${disabledIds.length} 个已禁用凭据吗？此操作无法撤销。${skippedText}`)) {
      return
    }

    let successCount = 0
    let failCount = 0

    for (const id of disabledIds) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    const skippedResultText = skippedCount > 0 ? `，已跳过 ${skippedCount} 个未禁用凭据` : ''

    if (failCount === 0) {
      toast.success(`成功删除 ${successCount} 个已禁用凭据${skippedResultText}`)
    } else {
      toast.warning(`删除已禁用凭据：成功 ${successCount} 个，失败 ${failCount} 个${skippedResultText}`)
    }

    deselectAll()
  }

  // 批量启用（仅启用已禁用项）
  const handleBatchEnable = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要启用的凭据')
      return
    }

    const disabledIds = Array.from(selectedIds).filter(id => filteredDisabledIdSet.has(id))

    if (disabledIds.length === 0) {
      toast.error('选中的凭据中没有已禁用项')
      return
    }

    const skippedCount = selectedIds.size - disabledIds.length
    const skippedText = skippedCount > 0 ? `，跳过 ${skippedCount} 个已启用凭据` : ''

    let successCount = 0
    let failCount = 0

    for (const id of disabledIds) {
      try {
        await setCredentialDisabled(id, false)
        successCount++
      } catch {
        failCount++
      }
    }

    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功启用 ${successCount} 个凭据${skippedText}`)
    } else {
      toast.warning(`批量启用：成功 ${successCount} 个，失败 ${failCount} 个${skippedText}`)
    }

    deselectAll()
  }

  // 批量恢复异常
  const handleBatchResetFailure = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要恢复的凭据')
      return
    }

    const failedIds = Array.from(selectedIds).filter(id => filteredFailedIdSet.has(id))

    if (failedIds.length === 0) {
      toast.error('选中的凭据中没有失败的凭据')
      return
    }

    let successCount = 0
    let failCount = 0

    for (const id of failedIds) {
      try {
        await new Promise<void>((resolve, reject) => {
          resetFailure(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功恢复 ${successCount} 个凭据`)
    } else {
      toast.warning(`成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 批量刷新 Token
  const handleBatchForceRefresh = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要刷新的凭据')
      return
    }

    const enabledIds = Array.from(selectedIds).filter(id => !filteredDisabledIdSet.has(id))

    if (enabledIds.length === 0) {
      toast.error('选中的凭据中没有启用的凭据')
      return
    }

    setBatchRefreshing(true)
    setBatchRefreshProgress({ current: 0, total: enabledIds.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < enabledIds.length; i++) {
      try {
        await forceRefreshToken(enabledIds[i])
        successCount++
      } catch {
        failCount++
      }
      setBatchRefreshProgress({ current: i + 1, total: enabledIds.length })
    }

    setBatchRefreshing(false)
    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功刷新 ${successCount} 个凭据的 Token`)
    } else {
      toast.warning(`刷新 Token：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 一键清除所有已禁用凭据
  const handleClearAll = async () => {
    const disabledIds = data?.disabledIds
      ?? data?.credentials.filter(credential => credential.disabled).map(credential => credential.id)

    if (!disabledIds || disabledIds.length === 0) {
      toast.error('没有可清除的凭据')
      return
    }

    if (!confirm(`确定要清除所有 ${disabledIds.length} 个已禁用凭据吗？此操作无法撤销。`)) {
      return
    }

    let successCount = 0
    let failCount = 0

    for (const id of disabledIds) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功清除所有 ${successCount} 个已禁用凭据`)
    } else {
      toast.warning(`清除已禁用凭据：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 查询当前页凭据信息（有限并发，避免大批量串行太慢）
  const handleQueryCurrentPageInfo = async () => {
    if (currentCredentials.length === 0) {
      toast.error('当前页没有可查询的凭据')
      return
    }

    const ids = currentCredentials
      .filter(credential => !credential.disabled)
      .map(credential => credential.id)

    if (ids.length === 0) {
      toast.error('当前页没有可查询的启用凭据')
      return
    }

    setQueryingInfo(true)
    setQueryInfoProgress({ current: 0, total: ids.length })

    let completedCount = 0
    let successCount = 0
    let failCount = 0

    await runWithConcurrency(ids, BALANCE_QUERY_CONCURRENCY, async (id) => {
      setLoadingBalanceIds(prev => {
        const next = new Set(prev)
        next.add(id)
        return next
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        setBalanceMap(prev => {
          const next = new Map(prev)
          next.set(id, balance)
          return next
        })
      } catch (error) {
        failCount++
      } finally {
        setLoadingBalanceIds(prev => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
        completedCount++
        setQueryInfoProgress({ current: completedCount, total: ids.length })
      }
    })

    setQueryingInfo(false)

    void refetch()
    if (failCount === 0) {
      toast.success(`查询完成：成功 ${successCount}/${ids.length}`)
    } else {
      toast.warning(`查询完成：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
  }

  // 批量验活
  const handleBatchVerify = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要验活的凭据')
      return
    }

    // 初始化状态
    setVerifying(true)
    cancelVerifyRef.current = false
    const ids = Array.from(selectedIds)
    setVerifyProgress({ current: 0, total: ids.length })

    let successCount = 0

    // 初始化结果，所有凭据状态为 pending
    const initialResults = new Map<number, VerifyResult>()
    ids.forEach(id => {
      initialResults.set(id, { id, status: 'pending' })
    })
    setVerifyResults(initialResults)
    setVerifyDialogOpen(true)

    // 开始验活
    for (let i = 0; i < ids.length; i++) {
      // 检查是否取消
      if (cancelVerifyRef.current) {
        toast.info('已取消验活')
        break
      }

      const id = ids[i]

      // 更新当前凭据状态为 verifying
      setVerifyResults(prev => {
        const newResults = new Map(prev)
        newResults.set(id, { id, status: 'verifying' })
        return newResults
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        // 更新为成功状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'success',
            usage: `${balance.currentUsage}/${balance.usageLimit}`
          })
          return newResults
        })
      } catch (error) {
        // 更新为失败状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'failed',
            error: extractErrorMessage(error)
          })
          return newResults
        })
      }

      // 更新进度
      setVerifyProgress({ current: i + 1, total: ids.length })

      // 添加延迟防止封号（最后一个不需要延迟）
      if (i < ids.length - 1 && !cancelVerifyRef.current) {
        await new Promise(resolve => setTimeout(resolve, 2000))
      }
    }

    setVerifying(false)

    if (!cancelVerifyRef.current) {
      toast.success(`验活完成：成功 ${successCount}/${ids.length}`)
    }
  }

  // 取消验活
  const handleCancelVerify = () => {
    cancelVerifyRef.current = true
    setVerifying(false)
  }

  // 切换负载均衡模式
  const handleToggleLoadBalancing = () => {
    const currentMode = loadBalancingData?.mode || 'priority'
    const newMode: LoadBalancingMode = currentMode === 'priority' ? 'balanced' : 'priority'

    setLoadBalancingMode(newMode, {
      onSuccess: () => {
        const modeName = newMode === 'priority' ? '优先级模式' : '均衡负载模式'
        toast.success(`已切换到${modeName}`)
      },
      onError: (error) => {
        toast.error(`切换失败: ${extractErrorMessage(error)}`)
      }
    })
  }

  const isInitialLoading = activeView === 'credentials' && isLoading && !data
  const isRefreshingList = activeView === 'credentials' && isFetching && !!data

  if (isInitialLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">加载中...</p>
        </div>
      </div>
    )
  }

  if (activeView === 'credentials' && error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <div className="text-red-500 mb-4">加载失败</div>
            <p className="text-muted-foreground mb-4">{(error as Error).message}</p>
            <div className="space-x-2">
              <Button onClick={() => refetch()}>重试</Button>
              <Button variant="outline" onClick={handleLogout}>重新登录</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* 顶部导航 */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center justify-between px-4 md:px-8">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            <span className="font-semibold">Kiro Admin</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleToggleLoadBalancing}
              disabled={isLoadingMode || isSettingMode}
              title="切换负载均衡模式"
            >
              {isLoadingMode
                ? '加载中...'
                : loadBalancingData?.mode === 'priority'
                  ? '优先级模式'
                  : '均衡负载'}
            </Button>
            <Button
              variant={activeView === 'settings' ? 'secondary' : 'outline'}
              size="sm"
              onClick={() => setActiveView(view => view === 'settings' ? 'credentials' : 'settings')}
              title="服务设置"
            >
              <Settings className="h-4 w-4" />
              设置
            </Button>
            <Button variant="ghost" size="icon" onClick={toggleDarkMode}>
              {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Button variant="ghost" size="icon" onClick={handleRefresh}>
              <RefreshCw className="h-5 w-5" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleLogout}>
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      {/* 主内容 */}
      <main className="mx-auto w-full max-w-[1920px] px-4 py-6 md:px-8">
        {activeView === 'settings' ? (
          <SettingsPage onBack={() => setActiveView('credentials')} />
        ) : (
          <>
        {/* 统计卡片 */}
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 mb-6">
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                凭据总数
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{data?.total || 0}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                可用凭据
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none text-green-600">{data?.available || 0}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                额度用尽
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none text-orange-600">{data?.quotaExceeded || 0}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardContent className="pt-3 pb-3">
              <div aria-label="剩余额度" className="text-xl font-bold leading-none">{formatNumber(stats?.confirmedRemainingQuota)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardContent className="pt-3 pb-3">
              <div aria-label="当天消耗" className="text-xl font-bold leading-none">{formatNumber(stats?.todayConfirmedConsumedQuota)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                累计实计消耗（credits）
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.totalConsumedQuota)}</div>
              <div className="text-xs text-muted-foreground mt-2">
                {stats ? `自 ${new Date(stats.quotaTrackingStartedAt * 1000).toLocaleString('zh-CN')} 开始采集` : '等待采集状态'}
              </div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                RPM
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.rpm)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                历史总请求
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.totalRequestCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                历史消耗 TOKEN
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.totalTokenCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                历史成功
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.totalSuccessCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                当天总请求
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.todayRequestCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                当天消耗 TOKEN
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.todayTokenCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                历史成功率
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatRate(stats?.totalSuccessRate)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                当天成功
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatNumber(stats?.todaySuccessCount)}</div>
            </CardContent>
          </Card>
          <Card className="min-h-[96px]">
            <CardHeader className="pb-1.5 pt-3">
              <CardTitle className="text-xs font-medium text-muted-foreground leading-tight">
                当天成功率
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-3">
              <div className="text-xl font-bold leading-none">{formatRate(stats?.todaySuccessRate)}</div>
            </CardContent>
          </Card>
        </div>

        {/* 凭据列表 */}
        <div className="space-y-4">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div className="flex flex-wrap items-center gap-4">
              <h2 className="text-xl font-semibold">凭据管理</h2>
              {isRefreshingList && (
                <span className="inline-flex items-center gap-1.5 rounded-full border bg-muted/50 px-2.5 py-1 text-xs text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  更新中
                </span>
              )}
              <div className="flex rounded-md border p-1">
                <Button
                  className="h-7 px-2"
                  size="sm"
                  variant={viewMode === 'cards' ? 'secondary' : 'ghost'}
                  onClick={() => setViewMode('cards')}
                >
                  <LayoutGrid className="h-4 w-4" />
                  卡片
                </Button>
                <Button
                  className="h-7 px-2"
                  size="sm"
                  variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                  onClick={() => setViewMode('list')}
                >
                  <List className="h-4 w-4" />
                  列表
                </Button>
              </div>
              <div className="flex rounded-md border p-1">
                <Button
                  className="h-7 px-2"
                  size="sm"
                  variant={sortField === 'success' ? 'secondary' : 'ghost'}
                  onClick={() => handleSortChange('success')}
                  title="按成功调用次数全局排序"
                >
                  {sortLabel('success', '成功')}
                </Button>
                <Button
                  className="h-7 px-2"
                  size="sm"
                  variant={sortField === 'lastUsed' ? 'secondary' : 'ghost'}
                  onClick={() => handleSortChange('lastUsed')}
                  title="按最后调用时间全局排序"
                >
                  {sortLabel('lastUsed', '最后调用')}
                </Button>
                <Button
                  className="h-7 px-2"
                  size="sm"
                  variant={sortField === 'remaining' ? 'secondary' : 'ghost'}
                  onClick={() => handleSortChange('remaining')}
                  title="按剩余用量全局排序"
                >
                  {sortLabel('remaining', '用量')}
                </Button>
              </div>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                className="h-8 rounded-md border bg-background px-2 text-sm text-foreground shadow-sm outline-none focus:ring-2 focus:ring-ring"
                title="按状态或禁用原因筛选"
              >
                <option value="all">
                  全部状态（{formatNumber(data?.statusCounts?.total ?? data?.total)}）
                </option>
                <option value="enabled">
                  启用（{formatNumber(data?.statusCounts?.enabled ?? data?.available)}）
                </option>
                <option value="disabled">
                  已禁用（{formatNumber(data?.statusCounts?.disabled ?? disabledCredentialCount)}）
                </option>
                {data?.statusCounts?.disabledReasons.map(({ reason, count }) => (
                  <option key={reason} value={`reason:${reason}`}>
                    {disabledReasonLabel(reason)}（{formatNumber(count)}）
                  </option>
                ))}
              </select>
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={credentialSearch}
                  onChange={(event) => setCredentialSearch(event.target.value)}
                  placeholder="搜索账号 ID/邮箱"
                  className="h-8 w-56 pl-8"
                  aria-label="搜索账号 ID 或邮箱"
                />
              </div>
              {viewMode === 'list' && (
                <div className="relative" ref={columnManagerRef}>
                  <Button
                    className="h-8 px-2"
                    size="sm"
                    variant="outline"
                    onClick={() => setColumnManagerOpen(open => !open)}
                    title="管理列表显示列"
                  >
                    <Columns3 className="h-4 w-4" />
                    列
                  </Button>
                  {columnManagerOpen && (
                    <div className="absolute left-0 top-10 z-40 w-48 rounded-md border bg-popover p-2 text-popover-foreground shadow-md">
                      <div className="mb-2 flex items-center justify-between px-1">
                        <span className="text-sm font-medium">显示列</span>
                        <Button
                          className="h-7 px-2 text-xs"
                          size="sm"
                          variant="ghost"
                          onClick={resetListColumns}
                        >
                          默认
                        </Button>
                      </div>
                      <div className="space-y-1">
                        {CREDENTIAL_LIST_COLUMNS.map(column => (
                          <div
                            key={column.id}
                            className="flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-sm hover:bg-muted"
                            role="button"
                            tabIndex={0}
                            onClick={() => toggleListColumn(column.id)}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault()
                                toggleListColumn(column.id)
                              }
                            }}
                          >
                            <Checkbox
                              className="pointer-events-none"
                              checked={visibleListColumns.has(column.id)}
                              onCheckedChange={() => undefined}
                            />
                            <span>{column.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {filteredTotal > 0 && (
                <div className="flex items-center gap-2">
                  <Button
                    className="h-8 px-2"
                    size="sm"
                    variant="outline"
                    onClick={toggleSelectCurrentPage}
                    disabled={currentPageIds.length === 0}
                  >
                    <CheckSquare className="h-4 w-4" />
                    {currentPageAllSelected ? '取消本页' : '全选本页'}
                  </Button>
                  <Button
                    className="h-8 px-2"
                    size="sm"
                    variant="outline"
                    onClick={selectAllPages}
                    disabled={filteredCredentialIds.length === 0}
                  >
                    <CheckSquare className="h-4 w-4" />
                    全选所有页
                  </Button>
                </div>
              )}
              {selectedIds.size > 0 && (
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">已选择 {selectedIds.size} 个</Badge>
                  <Button onClick={deselectAll} size="sm" variant="ghost">
                    取消选择
                  </Button>
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2 xl:justify-end">
              {selectedIds.size > 0 && (
                <>
                  <Button onClick={handleBatchVerify} size="sm" variant="outline">
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                    批量验活
                  </Button>
                  <Button
                    onClick={handleBatchForceRefresh}
                    size="sm"
                    variant="outline"
                    disabled={batchRefreshing}
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${batchRefreshing ? 'animate-spin' : ''}`} />
                    {batchRefreshing ? `刷新中... ${batchRefreshProgress.current}/${batchRefreshProgress.total}` : '批量刷新 Token'}
                  </Button>
                  <Button onClick={handleBatchResetFailure} size="sm" variant="outline">
                    <RotateCcw className="h-4 w-4 mr-2" />
                    恢复异常
                  </Button>
                  <Button
                    onClick={handleBatchEnable}
                    size="sm"
                    variant="outline"
                    disabled={selectedDisabledCount === 0}
                    title={selectedDisabledCount === 0 ? '选中的凭据都已启用' : undefined}
                  >
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                    批量启用
                  </Button>
                  <Button
                    onClick={handleBatchDelete}
                    size="sm"
                    variant="destructive"
                    disabled={selectedDisabledCount === 0}
                    title={selectedDisabledCount === 0 ? '只能删除已禁用凭据' : undefined}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    批量删除
                  </Button>
                </>
              )}
              {verifying && !verifyDialogOpen && (
                <Button onClick={() => setVerifyDialogOpen(true)} size="sm" variant="secondary">
                  <CheckCircle2 className="h-4 w-4 mr-2 animate-spin" />
                  验活中... {verifyProgress.current}/{verifyProgress.total}
                </Button>
              )}
              {data?.total && data.total > 0 && (
                <Button
                  onClick={handleQueryCurrentPageInfo}
                  size="sm"
                  variant="outline"
                  disabled={queryingInfo}
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${queryingInfo ? 'animate-spin' : ''}`} />
                  {queryingInfo ? `查询中... ${queryInfoProgress.current}/${queryInfoProgress.total}` : '查询信息'}
                </Button>
              )}
              {data?.total && data.total > 0 && (
                <Button
                  onClick={handleClearAll}
                  size="sm"
                  variant="outline"
                  className="text-destructive hover:text-destructive"
                  disabled={disabledCredentialCount === 0}
                  title={disabledCredentialCount === 0 ? '没有可清除的已禁用凭据' : undefined}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  清除已禁用
                </Button>
              )}
              <Button onClick={() => setKamImportDialogOpen(true)} size="sm" variant="outline">
                <FileUp className="h-4 w-4 mr-2" />
                Kiro Account Manager 导入
              </Button>
              <Button onClick={() => setBatchImportDialogOpen(true)} size="sm" variant="outline">
                <Upload className="h-4 w-4 mr-2" />
                批量导入
              </Button>
              <Button onClick={() => setAddDialogOpen(true)} size="sm">
                <Plus className="h-4 w-4 mr-2" />
                添加凭据
              </Button>
            </div>
          </div>
          {filteredTotal === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                暂无匹配凭据
              </CardContent>
            </Card>
          ) : (
            <>
              {viewMode === 'cards' ? (
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {currentCredentials.map((credential) => (
                    <CredentialCard
                      key={credential.id}
                      credential={credential}
                      onViewBalance={handleViewBalance}
                      selected={selectedIds.has(credential.id)}
                      onToggleSelect={() => toggleSelect(credential.id)}
                      balance={balanceMap.get(credential.id) || null}
                      loadingBalance={loadingBalanceIds.has(credential.id)}
                    />
                  ))}
                </div>
              ) : (
                <CredentialList
                  credentials={currentCredentials}
                  onViewBalance={handleViewBalance}
                  selectedIds={selectedIds}
                  onToggleSelect={toggleSelect}
                  balanceMap={balanceMap}
                  loadingBalanceIds={loadingBalanceIds}
                  visibleColumns={visibleListColumns}
                />
              )}

              {/* 分页控件 */}
              {totalPages > 1 && (
                <div className="mt-6 flex flex-col items-center justify-center gap-3 sm:flex-row">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    上一页
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    第 {currentPage} / {totalPages} 页（每页 {itemsPerPage} 个，共 {filteredTotal} 个凭据）
                  </span>
                  <div className="flex items-center gap-2">
                    <Input
                      value={pageInput}
                      onChange={(event) => setPageInput(event.target.value.replace(/[^\d]/g, ''))}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          handlePageJump()
                        }
                      }}
                      className="h-8 w-20"
                      inputMode="numeric"
                      aria-label="页码"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handlePageJump}
                    >
                      跳转
                    </Button>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                  >
                    下一页
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
          </>
        )}
      </main>

      {/* 余额对话框 */}
      <BalanceDialog
        credentialId={selectedCredentialId}
        open={balanceDialogOpen}
        onOpenChange={setBalanceDialogOpen}
      />

      {/* 添加凭据对话框 */}
      <AddCredentialDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
      />

      {/* 批量导入对话框 */}
      <BatchImportDialog
        open={batchImportDialogOpen}
        onOpenChange={setBatchImportDialogOpen}
      />

      {/* KAM 账号导入对话框 */}
      <KamImportDialog
        open={kamImportDialogOpen}
        onOpenChange={setKamImportDialogOpen}
      />

      {/* 批量验活对话框 */}
      <BatchVerifyDialog
        open={verifyDialogOpen}
        onOpenChange={setVerifyDialogOpen}
        verifying={verifying}
        progress={verifyProgress}
        results={verifyResults}
        onCancel={handleCancelVerify}
      />
    </div>
  )
}
