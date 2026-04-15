import { useDeferredValue, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Search, Users } from 'lucide-react'
import { api } from '../api/client'
import { createManagedSSE } from '../api/sse'
import { RiskBadge } from '../components/badges'
import EmptyState from '../components/EmptyState'
import type { SessionSummary } from '../api/types'
import {
  activityState,
  formatRelativeTime,
  groupSessions,
} from '../lib/sessionGroups'
import { formatSessionL3Annotation } from '../lib/sessionL3Annotations'

const VERDICT_COLORS: Record<string, string> = {
  allow: '#32c48d',
  block: '#ef4444',
  defer: '#f59e0b',
  modify: '#5ea5ff',
}

function VerdictBar({ dist }: { dist: Record<string, number> }) {
  const total = Object.values(dist).reduce((sum, value) => sum + value, 0)
  if (total === 0) return <span className="text-muted mono">—</span>
  return (
    <div className="verdict-bar verdict-bar-wide">
      {Object.entries(dist).map(([key, count]) => (
        count > 0 ? (
          <div
            key={key}
            className="verdict-bar-segment"
            style={{
              width: `${(count / total) * 100}%`,
              background: VERDICT_COLORS[key] || '#475569',
            }}
            title={`${key}: ${count}`}
          />
        ) : null
      ))}
    </div>
  )
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 0.75 ? '#ef4444' : score >= 0.5 ? '#f97316' : score >= 0.25 ? '#f59e0b' : '#32c48d'
  return (
    <div className="score-bar-wrap">
      <div className="score-bar score-bar-wide">
        <div className="score-bar-fill" style={{ width: `${score * 100}%`, background: color }} />
      </div>
      <span className="mono" style={{ color }}>{score.toFixed(2)}</span>
    </div>
  )
}

export default function Sessions() {
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [minRisk, setMinRisk] = useState('')
  const [framework, setFramework] = useState('')
  const [query, setQuery] = useState('')
  const [budgetExhaustedOnly, setBudgetExhaustedOnly] = useState(false)
  const [refreshNonce, setRefreshNonce] = useState(0)
  const deferredQuery = useDeferredValue(query.trim().toLowerCase())
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const data = await api.sessions({
          sort: 'risk_level',
          limit: 200,
          min_risk: minRisk || undefined,
        })
        setSessions(data)
      } catch {
        // ignored: StatusBar and auth flow already expose connectivity/auth problems
      }
      setLoading(false)
    }

    load()

    const cleanup = createManagedSSE(
      ['decision', 'session_start', 'session_risk_change', 'session_enforcement_change'],
      {
        onEvent: () => {
          if (debounceRef.current) clearTimeout(debounceRef.current)
          debounceRef.current = setTimeout(() => { void load() }, 500)
        },
        onStatusChange: () => {},
      },
    )

    const timer = setInterval(load, 30_000)

    return () => {
      cleanup()
      clearInterval(timer)
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [minRisk, refreshNonce])

  const frameworks = Array.from(new Set(sessions.map(session => session.source_framework))).sort()
  const filteredSessions = sessions.filter(session => {
    if (framework && session.source_framework !== framework) return false
    if (budgetExhaustedOnly && session.evidence_summary?.toolkit_budget_exhausted !== true) return false
    if (!deferredQuery) return true
    const haystack = [
      session.session_id,
      session.agent_id,
      session.source_framework,
      session.workspace_root,
      session.caller_adapter,
    ].join(' ').toLowerCase()
    return haystack.includes(deferredQuery)
  })

  const groupedSessions = groupSessions(filteredSessions)

  return (
    <div className="sessions-shell">
      <section className="card sessions-toolbar">
        <div>
          <p className="section-kicker">Inventory</p>
          <h2 className="section-header" style={{ marginBottom: 0 }}>
            <Users size={18} style={{ color: 'var(--color-accent)' }} />
            Framework Overview
          </h2>
          <p className="toolbar-subtitle">
            Grouped by framework and workspace so concurrent agent sessions stay distinguishable.
          </p>
        </div>

        <div className="toolbar-controls">
          <label className="search-box">
            <Search size={14} />
            <input
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="Search session, framework, workspace, agent"
            />
          </label>
          <select value={framework} onChange={event => setFramework(event.target.value)}>
            <option value="">All Frameworks</option>
            {frameworks.map(item => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <select value={minRisk} onChange={event => setMinRisk(event.target.value)}>
            <option value="">All Risk Levels</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical Only</option>
          </select>
          <button
            type="button"
            className={`btn ${budgetExhaustedOnly ? 'btn-primary' : ''}`}
            onClick={() => setBudgetExhaustedOnly(value => !value)}
            aria-pressed={budgetExhaustedOnly}
          >
            Budget exhausted only
          </button>
          <button className="btn" onClick={() => setRefreshNonce(value => value + 1)} disabled={loading}>
            <RefreshCw size={13} style={loading ? { animation: 'spin 1s linear infinite' } : undefined} />
            Refresh
          </button>
        </div>
      </section>

      <div className="framework-overview-grid">
        {groupedSessions.map(group => (
          <article key={group.framework} className="framework-overview-card">
            <div className="framework-panel-top">
              <div>
                <h3>{group.framework}</h3>
                <p>{group.workspaceCount} workspaces</p>
              </div>
              <RiskBadge level={group.highestRisk} />
            </div>
            <div className="framework-panel-metrics">
              <div>
                <span>Sessions</span>
                <strong>{group.sessionCount}</strong>
              </div>
              <div>
                <span>High risk</span>
                <strong>{group.highRiskSessionCount}</strong>
              </div>
              <div>
                <span>Events</span>
                <strong>{group.totalEvents}</strong>
              </div>
            </div>
          </article>
        ))}
      </div>

      <div className="framework-stack">
        {groupedSessions.map(group => (
          <section key={group.framework} className="card framework-section">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Framework</p>
                <h2>{group.framework}</h2>
              </div>
              <div className="framework-section-meta">
                <span>{group.sessionCount} sessions</span>
                <span>{group.workspaceCount} workspaces</span>
                <span>{formatRelativeTime(group.latestActivityAt)}</span>
              </div>
            </div>

            <div className="workspace-grid">
              {group.workspaces.map(workspace => (
                <article key={workspace.key} className="workspace-section">
                  <div className="workspace-section-top">
                    <div>
                      <div className="workspace-section-title">
                        <h3>{workspace.workspaceLabel}</h3>
                        <RiskBadge level={workspace.highestRisk} />
                      </div>
                      <p className="workspace-root mono">
                        {workspace.workspaceRoot || 'workspace_root unavailable'}
                      </p>
                    </div>
                    <div className="workspace-section-meta">
                      <span className={`activity-pill activity-pill-${activityState(workspace.latestActivityAt)}`}>
                        {formatRelativeTime(workspace.latestActivityAt)}
                      </span>
                      <span>{workspace.sessionCount} sessions</span>
                    </div>
                  </div>

                  <div className="workspace-summary-row">
                    <span>{workspace.highRiskSessionCount} high-risk</span>
                    <span>{workspace.totalEvents} events</span>
                    <span>{workspace.callerAdapters.join(', ') || 'adapter n/a'}</span>
                  </div>

                  <div className="session-card-stack">
                    {workspace.sessions.map(session => {
                      const sessionL3Annotation = formatSessionL3Annotation(session)
                      return (
                        <Link
                          key={session.session_id}
                          to={`/sessions/${session.session_id}`}
                          className="session-card-row"
                        >
                          <div className="session-card-main">
                          <div className="session-card-head">
                            <span className="mono session-card-id">{session.session_id}</span>
                            <RiskBadge level={session.current_risk_level} />
                          </div>
                          <p className="session-card-meta">
                            {session.agent_id || 'unknown agent'} · {session.caller_adapter}
                          </p>
                          {sessionL3Annotation && (
                            <p className="session-card-meta mono" style={{ fontSize: '0.72rem' }}>
                              {sessionL3Annotation}
                            </p>
                          )}
                          <VerdictBar dist={session.decision_distribution} />
                          </div>
                          <div className="session-card-side">
                            <ScoreBar score={session.cumulative_score} />
                            <div className="session-card-statline">
                              <span>{session.event_count} events</span>
                              <span>{session.high_risk_event_count} high-risk</span>
                            </div>
                            <span className={`activity-pill activity-pill-${activityState(session.last_event_at)}`}>
                              {formatRelativeTime(session.last_event_at)}
                            </span>
                          </div>
                        </Link>
                      )
                    })}
                  </div>
                </article>
              ))}
            </div>
          </section>
        ))}

        {groupedSessions.length === 0 && !loading && (
          <div className="card">
            <EmptyState
              icon={<Users size={20} />}
              title="No sessions found"
              subtitle="Sessions will appear here once frameworks start sending monitored activity."
            />
          </div>
        )}
      </div>
    </div>
  )
}
