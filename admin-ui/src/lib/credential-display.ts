import type { BalanceResponse, CredentialStatusItem } from '@/types/api'

// Preserve the configured account presentation without modifying real quota data.
export function credentialDisplayBalance(
  credential: CredentialStatusItem,
  balance: BalanceResponse | null,
): BalanceResponse | null {
  const title = credential.displaySubscriptionTitle
  const limit = credential.displayUsageLimit
  if (!balance || !title || limit == null) return balance
  return {
    ...balance,
    subscriptionTitle: title,
    usageLimit: limit,
    remaining: Math.max(0, limit - balance.currentUsage),
    usagePercentage: limit > 0 ? Math.min(100, balance.currentUsage / limit * 100) : 0,
  }
}
