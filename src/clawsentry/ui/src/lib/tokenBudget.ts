import type { HealthBudgetSnapshot, LLMUsageBucket, LLMUsageSnapshot } from '../api/types'

export type TokenBudgetLanguage = 'en' | 'zh'

function numberFormatter(language: TokenBudgetLanguage) {
  return new Intl.NumberFormat(language === 'zh' ? 'zh-CN' : 'en-US')
}

export function tokenTotal(bucket: Pick<LLMUsageBucket, 'input_tokens' | 'output_tokens'>): number {
  return (bucket.input_tokens || 0) + (bucket.output_tokens || 0)
}

export function formatTokenCount(value?: number | null, language: TokenBudgetLanguage = 'en'): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return language === 'zh' ? '未知' : 'unknown'
  return numberFormatter(language).format(value)
}

export function formatTokenPair(
  inputTokens?: number | null,
  outputTokens?: number | null,
  language: TokenBudgetLanguage = 'en',
): string {
  const inputLabel = language === 'zh' ? '输入' : 'in'
  const outputLabel = language === 'zh' ? '输出' : 'out'
  return `${formatTokenCount(inputTokens, language)} ${inputLabel} / ${formatTokenCount(outputTokens, language)} ${outputLabel}`
}

export function selectTopTokenUsageLabel(buckets: Record<string, LLMUsageBucket>): string | null {
  const topEntry = Object.entries(buckets).sort(([leftLabel, leftBucket], [rightLabel, rightBucket]) => {
    return (
      tokenTotal(rightBucket) - tokenTotal(leftBucket) ||
      rightBucket.calls - leftBucket.calls ||
      leftLabel.localeCompare(rightLabel)
    )
  })[0]

  return topEntry?.[0] ?? null
}

export function formatLlmUsageSummary(snapshot: LLMUsageSnapshot, language: TokenBudgetLanguage = 'en'): string {
  const totalTokens = snapshot.total_input_tokens + snapshot.total_output_tokens
  const usageScope = [
    selectTopTokenUsageLabel(snapshot.by_provider),
    selectTopTokenUsageLabel(snapshot.by_tier),
    selectTopTokenUsageLabel(snapshot.by_status),
  ]
    .filter(Boolean)
    .join('/')

  const calls = language === 'zh' ? '次调用' : 'calls'
  const total = language === 'zh' ? '总 token' : 'total tokens'
  return [
    `LLM ${formatTokenCount(snapshot.total_calls, language)} ${calls}`,
    `${formatTokenCount(totalTokens, language)} ${total}`,
    formatTokenPair(snapshot.total_input_tokens, snapshot.total_output_tokens, language),
    usageScope,
  ]
    .filter(Boolean)
    .join(' · ')
}

function scopeLabel(scope?: string, language: TokenBudgetLanguage = 'en'): string {
  switch (scope) {
    case 'input':
      return language === 'zh' ? '输入' : 'input'
    case 'output':
      return language === 'zh' ? '输出' : 'output'
    default:
      return language === 'zh' ? '总量' : 'total'
  }
}

export function formatTokenBudgetSnapshot(
  snapshot: HealthBudgetSnapshot | null | undefined,
  language: TokenBudgetLanguage = 'en',
): string {
  if (!snapshot) return language === 'zh' ? 'Token 快照不可用' : 'Token snapshot unavailable'

  const usedInput = snapshot.used_input_tokens ?? 0
  const usedOutput = snapshot.used_output_tokens ?? 0
  const usedTotal = snapshot.used_total_tokens ?? usedInput + usedOutput
  const parts = [
    `${formatTokenCount(usedTotal, language)} ${language === 'zh' ? '总 token' : 'total tokens'}`,
    formatTokenPair(usedInput, usedOutput, language),
  ]

  if (snapshot.enabled && typeof snapshot.limit_tokens === 'number' && snapshot.limit_tokens > 0) {
    parts.push(
      `${language === 'zh' ? '上限' : 'limit'} ${formatTokenCount(snapshot.limit_tokens, language)} ${scopeLabel(snapshot.scope, language)}`,
    )
    parts.push(
      `${language === 'zh' ? '剩余' : 'remaining'} ${
        snapshot.remaining_tokens === null
          ? (language === 'zh' ? '不限' : 'unlimited')
          : formatTokenCount(snapshot.remaining_tokens, language)
      }`,
    )
  } else {
    parts.push(language === 'zh' ? 'Token 上限未启用 / 不限' : 'token limit disabled / unlimited')
  }

  parts.push(snapshot.exhausted ? (language === 'zh' ? '已耗尽' : 'exhausted') : (language === 'zh' ? '可用' : 'active'))
  return parts.join(' · ')
}
