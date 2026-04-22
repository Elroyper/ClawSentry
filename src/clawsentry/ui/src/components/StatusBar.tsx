import { useState, useEffect } from 'react'
import { api } from '../api/client'
import type { HealthResponse, LLMUsageBucket, LLMUsageSnapshot } from '../api/types'
import { usePreferences } from '../lib/preferences'

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}

function formatUsd(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount)
}

function selectTopUsageLabel(buckets: Record<string, LLMUsageBucket>): string | null {
  const topEntry = Object.entries(buckets).sort(([leftLabel, leftBucket], [rightLabel, rightBucket]) => {
    return (
      rightBucket.cost_usd - leftBucket.cost_usd ||
      rightBucket.calls - leftBucket.calls ||
      leftLabel.localeCompare(rightLabel)
    )
  })[0]

  return topEntry?.[0] ?? null
}

function formatLlmUsageSummary(snapshot: LLMUsageSnapshot): string {
  const usageScope = [
    selectTopUsageLabel(snapshot.by_provider),
    selectTopUsageLabel(snapshot.by_tier),
    selectTopUsageLabel(snapshot.by_status),
  ]
    .filter(Boolean)
    .join('/')

  return [
    `LLM usage ${snapshot.total_calls.toLocaleString()} calls`,
    formatUsd(snapshot.total_cost_usd),
    usageScope,
  ]
    .filter(Boolean)
    .join(' · ')
}

export default function StatusBar() {
  const { t } = usePreferences()
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [status, setStatus] = useState<'online' | 'offline' | 'checking'>('checking')
  const budgetExhaustionEvent = health?.budget_exhaustion_event
  const llmUsageSummary = health?.llm_usage_snapshot ? formatLlmUsageSummary(health.llm_usage_snapshot) : null

  useEffect(() => {
    const check = async () => {
      try {
        const data = await api.health()
        setHealth(data)
        setStatus('online')
      } catch {
        setStatus('offline')
        setHealth(null)
      }
    }
    check()
    const timer = setInterval(check, 30_000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="statusbar">
      {health && status === 'online' && (
        <span className="status-summary text-muted mono">
          {formatUptime(health.uptime_seconds)} uptime · {health.trajectory_count.toLocaleString()} events ·
          {llmUsageSummary && (
            <>
              {' '}
              · {llmUsageSummary}
            </>
          )}
          {' '}
          Daily budget {formatUsd(health.budget.daily_budget_usd)} · Spend {formatUsd(health.budget.daily_spend_usd)} ·
          Remaining {health.budget.remaining_usd === null ? 'Unlimited' : formatUsd(health.budget.remaining_usd)} ·
          {' '}
          {health.budget.exhausted ? (
            <>
              <span className="status-budget-exhausted">BUDGET EXHAUSTED</span>
              <span className="status-budget-note"> · Operator action required</span>
              {budgetExhaustionEvent && (
                <span className="status-budget-note">
                  {' '}
                  · {budgetExhaustionEvent.provider} / {budgetExhaustionEvent.tier} / {formatUsd(budgetExhaustionEvent.cost_usd)}
                </span>
              )}
            </>
          ) : 'Active'}
        </span>
      )}
      <span
        className={`status-pill status-pill-${status}`}
        aria-label="Gateway connection status"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {status === 'online' ? t('status.connected') : status === 'offline' ? t('status.disconnected') : t('status.checking')}
      </span>
    </div>
  )
}
