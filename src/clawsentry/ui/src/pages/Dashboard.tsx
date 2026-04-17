import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, Layers3, ShieldCheck, Siren } from 'lucide-react'
import { api } from '../api/client'
import type { HealthResponse, LLMUsageBucket, LLMUsageSnapshot, SessionSummary, SummaryResponse } from '../api/types'
import MetricCard from '../components/MetricCard'
import RuntimeFeed from '../components/RuntimeFeed'
import SkeletonCard from '../components/SkeletonCard'
import { RiskBadge } from '../components/badges'
import LLMUsageDrilldown from '../components/LLMUsageDrilldown'
import {
  activityState,
  formatRelativeTime,
  groupSessions,
  riskRank,
  workspaceLabel,
} from '../lib/sessionGroups'
import { formatSessionL3Annotation } from '../lib/sessionL3Annotations'

function formatUptime(seconds: number): string {
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
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

function FrameworkChip({ framework, count }: { framework: string; count: number }) {
  return (
    <span className="framework-chip">
      <span>{framework}</span>
      <strong>{count}</strong>
    </span>
  )
}

function hasToolkitEvidenceBudgetExhausted(session: SessionSummary): boolean {
  return session.evidence_summary?.toolkit_budget_exhausted === true
}

export default function Dashboard() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const budgetExhaustionEvent = health?.budget_exhaustion_event
  const llmUsageSnapshot = summary?.llm_usage_snapshot ?? health?.llm_usage_snapshot ?? null

  useEffect(() => {
    const load = () =>
      Promise.all([
        api.summary().then(setSummary),
        api.health().then(setHealth),
        api.sessions({ sort: 'risk_level', limit: 120 }).then(setSessions),
      ])
        .catch(() => {})
        .finally(() => setLoading(false))

    load()
    const timer = setInterval(load, 10_000)
    return () => clearInterval(timer)
  }, [])

  const groupedSessions = groupSessions(sessions)
  const totalWorkspaces = groupedSessions.reduce((sum, item) => sum + item.workspaceCount, 0)
  const criticalSessions = sessions.filter(session => session.current_risk_level === 'critical').length
  const highRiskSessions = sessions.filter(session => riskRank(session.current_risk_level) <= 1).length
  const blockRate = summary
    ? ((summary.by_decision.block || 0) / Math.max(summary.total_records, 1) * 100).toFixed(1)
    : '—'

  const prioritySessions = [...sessions]
    .sort((a, b) => {
      const rankDiff = riskRank(a.current_risk_level) - riskRank(b.current_risk_level)
      if (rankDiff !== 0) return rankDiff
      return new Date(b.last_event_at).getTime() - new Date(a.last_event_at).getTime()
    })
    .slice(0, 6)

  const toolkitEvidenceBudgetHotspots = sessions
    .filter(hasToolkitEvidenceBudgetExhausted)
    .sort((a, b) => {
      const rankDiff = riskRank(a.current_risk_level) - riskRank(b.current_risk_level)
      if (rankDiff !== 0) return rankDiff
      return new Date(b.last_event_at).getTime() - new Date(a.last_event_at).getTime()
    })
    .slice(0, 5)
  const toolkitEvidenceBudgetHotspotCount = sessions.filter(hasToolkitEvidenceBudgetExhausted).length

  const priorityWorkspaces = groupedSessions
    .flatMap(framework => framework.workspaces.map(workspace => ({ ...workspace, framework: framework.framework })))
    .sort((a, b) => {
      const rankDiff = riskRank(a.highestRisk) - riskRank(b.highestRisk)
      if (rankDiff !== 0) return rankDiff
      return new Date(b.latestActivityAt).getTime() - new Date(a.latestActivityAt).getTime()
    })
    .slice(0, 6)
  const priorityWorkspaceCount = priorityWorkspaces.filter(workspace => riskRank(workspace.highestRisk) <= 1).length

  if (loading) {
    return (
      <div className="dashboard-shell">
        <section className="dashboard-region" aria-label="Global posture">
          <section className="hero-banner" aria-hidden="true">
            <div>
              <SkeletonCard rows={4} height={220} />
            </div>
            <div className="hero-panel">
              <SkeletonCard rows={5} height={220} />
            </div>
          </section>
          <div className="metric-grid" style={{ marginBottom: 20 }}>
            {[0, 1, 2, 3].map(index => <SkeletonCard key={index} rows={2} height={104} />)}
          </div>
        </section>

        <section className="dashboard-region" aria-label="Operational scan">
          <div className="dashboard-grid dashboard-grid-primary">
            <SkeletonCard rows={8} height={430} />
            <SkeletonCard rows={8} height={430} />
          </div>
        </section>

        <section className="dashboard-region" aria-label="Deep inspection">
          <div className="dashboard-grid dashboard-grid-secondary">
            <SkeletonCard rows={8} height={360} />
            <SkeletonCard rows={8} height={360} />
            <SkeletonCard rows={8} height={360} />
          </div>
        </section>
      </div>
    )
  }

  return (
    <div className="dashboard-shell">
      <section className="dashboard-region" aria-label="Global posture">
        <section className="hero-banner">
          <div>
            <p className="eyebrow">Security Console</p>
            <h1>Cross-framework session coverage for live agent operations.</h1>
            <p className="hero-copy">
              Track every framework, every workspace, and every session from one monitoring surface.
              High-risk workspaces rise to the top automatically, while live runtime events stay visible.
            </p>
            <div className="hero-chip-row">
              {Object.entries(summary?.by_source_framework || {}).map(([framework, count]) => (
                <FrameworkChip key={framework} framework={framework} count={count} />
              ))}
            </div>
            <div className="hero-brief-grid" aria-label="Operator brief">
              <article className="hero-brief-card">
                <span className="hero-brief-label">Coverage</span>
                <strong>{sessions.length.toLocaleString()} sessions</strong>
                <p>{totalWorkspaces} workspaces across {groupedSessions.length} frameworks.</p>
              </article>
              <article className="hero-brief-card">
                <span className="hero-brief-label">Posture</span>
                <strong>{highRiskSessions.toLocaleString()} high-risk</strong>
                <p>{criticalSessions} critical sessions and {priorityWorkspaceCount} priority workspaces.</p>
              </article>
              <article className="hero-brief-card">
                <span className="hero-brief-label">Runtime Pulse</span>
                <strong>{health ? formatUptime(health.uptime_seconds) : '—'}</strong>
                <p>
                  {health
                    ? `${health.trajectory_count.toLocaleString()} live events tracked in the current uptime window.`
                    : 'Runtime status unavailable.'}
                </p>
              </article>
              <article className="hero-brief-card">
                <span className="hero-brief-label">Budget Pulse</span>
                <strong>{health ? formatUsd(health.budget.daily_spend_usd) : '—'}</strong>
                <p>
                  {health
                    ? `Remaining ${health.budget.remaining_usd === null ? 'Unlimited' : formatUsd(health.budget.remaining_usd)} this cycle.`
                    : 'Budget snapshot unavailable.'}
                </p>
              </article>
            </div>
          </div>
          <div className="hero-panel">
            <div className="hero-panel-header">
              <Siren size={14} />
              Current posture
            </div>
            <div className="hero-panel-body">
              <div>
                <span className="hero-panel-label">Critical sessions</span>
                <strong>{criticalSessions}</strong>
              </div>
              <div>
                <span className="hero-panel-label">High-risk workspaces</span>
                <strong>{priorityWorkspaceCount}</strong>
              </div>
              <div>
                <span className="hero-panel-label">Gateway uptime</span>
                <strong>{health ? formatUptime(health.uptime_seconds) : '—'}</strong>
              </div>
              <div>
                <span className="hero-panel-label">LLM usage</span>
                <strong>{llmUsageSnapshot ? `${llmUsageSnapshot.total_calls.toLocaleString()} calls` : '—'}</strong>
                <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                  {llmUsageSnapshot ? formatLlmUsageSummary(llmUsageSnapshot) : 'Usage snapshot unavailable'}
                </div>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <span className="hero-panel-label">Daily budget</span>
                <strong>{health ? formatUsd(health.budget.daily_budget_usd) : '—'}</strong>
                <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                  {health ? (
                    <>
                      Spend {formatUsd(health.budget.daily_spend_usd)} · Remaining{' '}
                      {health.budget.remaining_usd === null ? 'Unlimited' : formatUsd(health.budget.remaining_usd)} ·{' '}
                      Exhausted {health.budget.exhausted ? 'Yes' : 'No'}
                    </>
                  ) : (
                    'Budget snapshot unavailable'
                  )}
                </div>
                {health && (health.budget.exhausted || budgetExhaustionEvent) && (
                  <div
                    className="mono"
                    style={{
                      marginTop: 8,
                      padding: '8px 10px',
                      borderRadius: 10,
                      border: '1px solid rgba(239,68,68,0.3)',
                      background: 'rgba(239,68,68,0.08)',
                      color: 'var(--color-text)',
                      fontSize: '0.72rem',
                      lineHeight: 1.45,
                    }}
                  >
                    {budgetExhaustionEvent ? (
                      <>
                        <strong style={{ color: 'var(--color-block)' }}>Budget exhaustion event</strong>
                        <span> · Operator attention required</span>
                        <div style={{ color: 'var(--color-text-muted)' }}>
                          {budgetExhaustionEvent.provider} · {budgetExhaustionEvent.tier} ·{' '}
                          {formatUsd(budgetExhaustionEvent.cost_usd)}
                        </div>
                      </>
                    ) : (
                      <>
                        <strong style={{ color: 'var(--color-block)' }}>Budget exhaustion event</strong>
                        <span> · Operator attention required</span>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <div className="metric-grid" style={{ marginBottom: 20 }}>
          <MetricCard
            label="Tracked Sessions"
            value={sessions.length.toLocaleString()}
            accent="purple"
            icon={<Layers3 size={20} />}
            subtext={`${totalWorkspaces} workspaces across ${groupedSessions.length} frameworks`}
          />
          <MetricCard
            label="High-Risk Sessions"
            value={highRiskSessions.toLocaleString()}
            accent="red"
            icon={<AlertTriangle size={20} />}
            subtext={`${criticalSessions} critical right now`}
          />
          <MetricCard
            label="Toolkit Evidence Budget"
            value={toolkitEvidenceBudgetHotspotCount.toLocaleString()}
            accent="amber"
            icon={<Siren size={20} />}
            subtext="Sessions hitting toolkit evidence budget"
          />
          <MetricCard
            label="Block Rate"
            value={`${blockRate}%`}
            accent="amber"
            icon={<ShieldCheck size={20} />}
            subtext={`${summary?.by_decision?.block ?? 0} blocks in current window`}
          />
          <MetricCard
            label="Live Events"
            value={(health?.trajectory_count ?? 0).toLocaleString()}
            accent="blue"
            icon={<Activity size={20} />}
            subtext={health ? `${formatUptime(health.uptime_seconds)} uptime` : undefined}
          />
        </div>

        <LLMUsageDrilldown snapshot={llmUsageSnapshot} />
      </section>

      <section className="dashboard-region" aria-label="Operational scan">
        <div className="dashboard-grid dashboard-grid-primary">
          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Coverage</p>
                <h2>Framework Coverage</h2>
              </div>
              <Link to="/sessions" className="section-link">Open session inventory</Link>
            </div>
            <div className="framework-coverage-grid">
              {groupedSessions.map(group => (
                <article key={group.framework} className="framework-panel">
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
                  <div className="framework-workspace-list">
                    {group.workspaces.slice(0, 3).map(workspace => (
                      <div key={workspace.key} className="framework-workspace-row">
                        <div>
                          <strong>{workspace.workspaceLabel}</strong>
                          <span>{formatRelativeTime(workspace.latestActivityAt)}</span>
                        </div>
                        <RiskBadge level={workspace.highestRisk} />
                      </div>
                    ))}
                  </div>
                </article>
              ))}
              {groupedSessions.length === 0 && (
                <div className="empty-inline">No framework activity yet.</div>
              )}
            </div>
          </section>

          <RuntimeFeed />
        </div>
      </section>

      <section className="dashboard-region" aria-label="Deep inspection">
        <div className="dashboard-grid dashboard-grid-secondary">
          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Workspaces</p>
                <h2>Workspace Risk Board</h2>
              </div>
              <span className="section-meta">{priorityWorkspaces.length} prioritized</span>
            </div>
            <div className="workspace-board">
              {priorityWorkspaces.map(workspace => (
                <article key={workspace.key} className="workspace-card">
                  <div className="workspace-card-top">
                    <div>
                      <p className="workspace-framework">{workspace.framework}</p>
                      <h3>{workspace.workspaceLabel}</h3>
                    </div>
                    <RiskBadge level={workspace.highestRisk} />
                  </div>
                  <p className="workspace-root mono">{workspace.workspaceRoot || 'workspace_root unavailable'}</p>
                  <div className="workspace-stats">
                    <span>{workspace.sessionCount} sessions</span>
                    <span>{workspace.highRiskSessionCount} high risk</span>
                    <span>{workspace.totalEvents} events</span>
                  </div>
                  <div className="workspace-footer">
                    <span className={`activity-pill activity-pill-${activityState(workspace.latestActivityAt)}`}>
                      {formatRelativeTime(workspace.latestActivityAt)}
                    </span>
                    <span className="mono">{workspace.callerAdapters.join(', ') || 'adapter n/a'}</span>
                  </div>
                </article>
              ))}
              {priorityWorkspaces.length === 0 && (
                <div className="empty-inline">No workspace telemetry yet.</div>
              )}
            </div>
          </section>

          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Escalation queue</p>
                <h2>Priority Sessions</h2>
              </div>
              <Link to="/sessions" className="section-link">Review all sessions</Link>
            </div>
            <div className="priority-session-list">
              {prioritySessions.map(session => {
                const sessionL3Annotation = formatSessionL3Annotation(session)
                return (
                  <Link
                    key={session.session_id}
                    to={`/sessions/${session.session_id}`}
                    className="priority-session-row"
                  >
                    <div>
                      <div className="priority-session-top">
                        <strong>{workspaceLabel(session.workspace_root)}</strong>
                        <RiskBadge level={session.current_risk_level} />
                      </div>
                      <p className="priority-session-meta">
                        {session.source_framework} · {session.event_count} events · {session.high_risk_event_count} high-risk
                      </p>
                      {sessionL3Annotation && (
                        <p className="priority-session-meta mono" style={{ fontSize: '0.72rem' }}>
                          {sessionL3Annotation}
                        </p>
                      )}
                      <p className="priority-session-id mono">{session.session_id}</p>
                    </div>
                    <div className="priority-session-side">
                      <span className={`activity-pill activity-pill-${activityState(session.last_event_at)}`}>
                        {formatRelativeTime(session.last_event_at)}
                      </span>
                    </div>
                  </Link>
                )
              })}
              {prioritySessions.length === 0 && (
                <div className="empty-inline">No active sessions to prioritize.</div>
              )}
            </div>
          </section>

          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Evidence</p>
                <h2>Toolkit evidence budget hotspots</h2>
              </div>
              <span className="section-meta">{toolkitEvidenceBudgetHotspots.length} shown</span>
            </div>
            <div className="priority-session-list">
              {toolkitEvidenceBudgetHotspots.map(session => {
                const sessionL3Annotation = formatSessionL3Annotation(session)
                return (
                  <Link
                    key={session.session_id}
                    to={`/sessions/${session.session_id}`}
                    className="priority-session-row"
                  >
                    <div>
                      <div className="priority-session-top">
                        <strong>{workspaceLabel(session.workspace_root)}</strong>
                        <RiskBadge level={session.current_risk_level} />
                      </div>
                      <p className="priority-session-meta">
                        Toolkit evidence budget exhausted · {session.source_framework} · {session.event_count} events
                      </p>
                      {sessionL3Annotation && (
                        <p className="priority-session-meta mono" style={{ fontSize: '0.72rem' }}>
                          {sessionL3Annotation}
                        </p>
                      )}
                      <p className="priority-session-id mono">{session.session_id}</p>
                    </div>
                    <div className="priority-session-side">
                      <span className={`activity-pill activity-pill-${activityState(session.last_event_at)}`}>
                        {formatRelativeTime(session.last_event_at)}
                      </span>
                    </div>
                  </Link>
                )
              })}
              {toolkitEvidenceBudgetHotspots.length === 0 && (
                <div className="empty-inline">No sessions are currently hitting toolkit evidence budget.</div>
              )}
            </div>
          </section>
        </div>
      </section>
    </div>
  )
}
