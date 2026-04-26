import { useState, useEffect } from 'react'
import { api } from '../api/client'
import type { HealthResponse } from '../api/types'
import { usePreferences } from '../lib/preferences'
import { formatLlmUsageSummary, formatTokenBudgetSnapshot } from '../lib/tokenBudget'

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}

export default function StatusBar() {
  const { t, language } = usePreferences()
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [status, setStatus] = useState<'online' | 'offline' | 'checking'>('checking')
  const budgetExhaustionEvent = health?.budget_exhaustion_event
  const llmUsageSummary = health?.llm_usage_snapshot ? formatLlmUsageSummary(health.llm_usage_snapshot, language) : null

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
          {formatUptime(health.uptime_seconds)} uptime · {health.trajectory_count.toLocaleString()} events
          {llmUsageSummary && (
            <>
              {' '}
              · {llmUsageSummary}
            </>
          )}
          {' '}
          · {formatTokenBudgetSnapshot(health.budget, language)} ·
          {' '}
          {health.budget.exhausted ? (
            <>
              <span className="status-budget-exhausted">{language === 'zh' ? 'TOKEN 已耗尽' : 'TOKEN EXHAUSTED'}</span>
              <span className="status-budget-note"> · {language === 'zh' ? '需要操作员处理' : 'Operator action required'}</span>
              {budgetExhaustionEvent && (
                <span className="status-budget-note">
                  {' '}
                  · {budgetExhaustionEvent.provider} / {budgetExhaustionEvent.tier}
                </span>
              )}
            </>
          ) : language === 'zh' ? '可用' : 'Active'}
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
