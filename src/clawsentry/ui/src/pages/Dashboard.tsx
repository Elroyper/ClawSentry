import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Crosshair,
  Layers3,
  Radio,
  ShieldCheck,
  Siren,
  Timer,
  WalletCards,
  type LucideIcon,
} from 'lucide-react'
import { api } from '../api/client'
import type {
  ControlHealthSnapshot,
  HealthResponse,
  LLMUsageBucket,
  LLMUsageSnapshot,
  RiskVelocity,
  SessionSummary,
  SummaryResponse,
  SystemSecurityPosture,
  WindowRiskSummary,
} from '../api/types'
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
import { DEMO_FALLBACK_ENABLED, DEMO_HEALTH, DEMO_SESSIONS, DEMO_SUMMARY } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'

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

function formatMetricScore(value?: number | null): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(2) : '—'
}

function formatSignedMetric(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  return `${value >= 0 ? '+' : ''}${value.toFixed(2)}`
}

function formatRiskVelocityValue(value?: RiskVelocity | null): string {
  if (typeof value === 'number') return formatSignedMetric(value)
  if (value === 'up') return 'up'
  if (value === 'down') return 'down'
  if (value === 'flat') return 'flat'
  return '—'
}

function windowRiskDensity(windowSummary?: WindowRiskSummary | null): number | null {
  if (!windowSummary) return null
  if (typeof windowSummary.risk_density === 'number' && Number.isFinite(windowSummary.risk_density)) {
    return windowSummary.risk_density
  }
  const eventCount = windowSummary.event_count ?? 0
  const highCount = windowSummary.high_or_critical_count ?? windowSummary.high_risk_event_count ?? 0
  return eventCount > 0 ? highCount / eventCount : null
}

function postureScore(posture?: SystemSecurityPosture | null): number | null {
  if (!posture) return null
  if (typeof posture.posture_score === 'number') return posture.posture_score
  if (typeof posture.score_0_100 === 'number') return posture.score_0_100
  return null
}

function formatControlHealth(controlHealth?: ControlHealthSnapshot | null): string {
  if (!controlHealth) return 'Control health unavailable'
  return [
    `${controlHealth.enforced_sessions ?? 0} enforced`,
    `${controlHealth.released_sessions ?? 0} released`,
    `${controlHealth.l3_required_sessions ?? 0} L3 required`,
  ].join(' · ')
}

function formatRiskVelocity(posture?: SystemSecurityPosture | null, windowSummary?: WindowRiskSummary | null): string {
  const velocity = posture?.risk_velocity ?? windowSummary?.risk_velocity
  const density = windowRiskDensity(windowSummary)
  return `Risk velocity ${formatRiskVelocityValue(velocity)} · density ${formatMetricScore(density)}`
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

function CommandBriefCard({
  icon: Icon,
  label,
  value,
  body,
  to,
  tone = 'blue',
}: {
  icon: LucideIcon
  label: string
  value: string
  body: string
  to?: string
  tone?: 'blue' | 'cyan' | 'gold' | 'red'
}) {
  const content = (
    <>
      <span className={`command-brief-icon command-brief-icon-${tone}`}>
        <Icon size={16} aria-hidden="true" />
      </span>
      <span className="hero-brief-label">{label}</span>
      <strong>{value}</strong>
      <p>{body}</p>
    </>
  )

  if (to) {
    return (
      <Link className={`hero-brief-card hero-brief-link command-brief-card command-brief-card-${tone}`} to={to}>
        {content}
      </Link>
    )
  }

  return (
    <article className={`hero-brief-card command-brief-card command-brief-card-${tone}`}>
      {content}
    </article>
  )
}

function hasToolkitEvidenceBudgetExhausted(session: SessionSummary): boolean {
  return session.evidence_summary?.toolkit_budget_exhausted === true
}

function sessionsHref(params: Record<string, string | number | boolean | undefined>) {
  const qs = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== false && value !== '') qs.set(key, String(value))
  })
  return `/sessions?${qs.toString()}`
}

export default function Dashboard() {
  const { language, t } = usePreferences()
  const [summary, setSummary] = useState<SummaryResponse | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [demoMode, setDemoMode] = useState(false)
  const [loading, setLoading] = useState(true)
  const budgetExhaustionEvent = health?.budget_exhaustion_event
  const llmUsageSnapshot = summary?.llm_usage_snapshot ?? health?.llm_usage_snapshot ?? null
  const systemSecurityPosture = summary?.system_security_posture ?? null
  const postureWindowSummary = systemSecurityPosture?.window_risk_summary ?? null

  useEffect(() => {
    const load = () =>
      Promise.all([
        api.summary(),
        api.health(),
        api.sessions({ sort: 'risk_level', limit: 120 }),
      ])
        .then(([summaryResult, healthResult, sessionResult]) => {
          if (DEMO_FALLBACK_ENABLED && sessionResult.length === 0 && summaryResult.total_records === 0) {
            setSummary(DEMO_SUMMARY)
            setHealth(DEMO_HEALTH)
            setSessions(DEMO_SESSIONS)
            setDemoMode(true)
          } else {
            setSummary(summaryResult)
            setHealth(healthResult)
            setSessions(sessionResult)
            setDemoMode(false)
          }
        })
        .catch(() => {
          if (DEMO_FALLBACK_ENABLED) {
            setSummary(DEMO_SUMMARY)
            setHealth(DEMO_HEALTH)
            setSessions(DEMO_SESSIONS)
            setDemoMode(true)
          }
        })
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
  const firstCriticalSession = prioritySessions[0]
  const operatorSteps = [
    {
      label: t('dashboard.read.step1'),
      title: criticalSessions > 0 ? t('dashboard.step.criticalTitle') : t('dashboard.step.confirmTitle'),
      body: criticalSessions > 0
        ? `${criticalSessions} ${t('dashboard.step.criticalBody')}`
        : t('dashboard.step.confirmBody'),
      href: sessionsHref({ minRisk: criticalSessions > 0 ? 'critical' : 'high', action: 'high-risk' }),
    },
    {
      label: t('dashboard.read.step2'),
      title: toolkitEvidenceBudgetHotspotCount > 0 ? t('dashboard.step.evidenceTitle') : t('dashboard.step.l3Title'),
      body: toolkitEvidenceBudgetHotspotCount > 0
        ? `${toolkitEvidenceBudgetHotspotCount} ${t('dashboard.step.evidenceBody')}`
        : t('dashboard.step.l3Body'),
      href: toolkitEvidenceBudgetHotspotCount > 0
        ? sessionsHref({ action: 'budget', budget: 'exhausted' })
        : firstCriticalSession ? `/sessions/${firstCriticalSession.session_id}` : '/sessions',
    },
    {
      label: t('dashboard.read.step3'),
      title: t('dashboard.step.liveTitle'),
      body: t('dashboard.step.liveBody'),
      href: '/defer',
    },
  ]

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
          <div className="metric-grid dashboard-metric-grid">
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
        <section className="hero-banner command-center-hero command-deck-hero">
          <div className="command-center-copy">
            <div className="hero-command-topline">
              <p className="eyebrow">{t('dashboard.hero.kicker')}</p>
              {demoMode && <span className="showcase-pill">Showcase mode · demo telemetry</span>}
            </div>
            <h1>{t('dashboard.hero.title')}</h1>
            <p className="hero-copy">
              {t('dashboard.hero.copy')}
            </p>
            <div className="command-map" aria-hidden="true">
              <div className="command-map-core">
                <span>TOTAL TRAJECTORIES</span>
                <strong>{health?.trajectory_count ?? 0}</strong>
              </div>
              <span className="command-map-node command-map-node-risk">risk</span>
              <span className="command-map-node command-map-node-l3">L3 review</span>
              <span className="command-map-node command-map-node-budget">budget</span>
              <span className="command-map-node command-map-node-evidence">evidence</span>
              <span className="command-map-trace command-map-trace-a" />
              <span className="command-map-trace command-map-trace-b" />
            </div>
            <div className="hero-chip-row">
              {Object.entries(summary?.by_source_framework || {}).map(([framework, count]) => (
                <FrameworkChip key={framework} framework={framework} count={count} />
              ))}
              {Object.keys(summary?.by_source_framework || {}).length === 0 && (
                <>
                  <FrameworkChip framework="codex" count={0} />
                  <FrameworkChip framework="openclaw" count={0} />
                  <FrameworkChip framework="a3s-code" count={0} />
                </>
              )}
            </div>
            <div className="hero-brief-grid" aria-label="Operator brief">
              <CommandBriefCard
                icon={Radio}
                label={t('dashboard.brief.coverage')}
                value={`${sessions.length.toLocaleString()} sessions`}
                body={`${totalWorkspaces} workspaces across ${groupedSessions.length} frameworks.`}
                tone="blue"
              />
              <CommandBriefCard
                icon={Crosshair}
                label={t('dashboard.brief.posture')}
                value={`${highRiskSessions.toLocaleString()} high-risk`}
                body={`${criticalSessions} critical sessions and ${priorityWorkspaceCount} priority workspaces.`}
                to={sessionsHref({ minRisk: 'high', action: 'high-risk' })}
                tone={criticalSessions > 0 ? 'red' : 'cyan'}
              />
              {systemSecurityPosture && (
                <CommandBriefCard
                  icon={ShieldCheck}
                  label="System Security Posture"
                  value={`Posture score ${formatMetricScore(postureScore(systemSecurityPosture))}`}
                  body={`Control health: ${formatControlHealth(systemSecurityPosture.control_health)}`}
                  tone={systemSecurityPosture.risk_level === 'critical' || systemSecurityPosture.risk_level === 'high' ? 'red' : 'cyan'}
                />
              )}
            </div>
          </div>
          <div className="hero-panel command-status-panel">
            <div className="hero-panel-header">
              <Siren size={14} />
              {t('dashboard.panel.current')}
            </div>
            <div className="hero-panel-body">
              <div>
                <span className="hero-panel-label"><AlertTriangle size={13} aria-hidden="true" /> {t('dashboard.panel.critical')}</span>
                <strong>{criticalSessions}</strong>
                <Link className="hero-panel-link" to={sessionsHref({ minRisk: 'critical', action: 'high-risk' })}>
                  {t('dashboard.panel.inspect')}
                </Link>
              </div>
              <div>
                <span className="hero-panel-label"><Crosshair size={13} aria-hidden="true" /> {t('dashboard.panel.highRiskWorkspaces')}</span>
                <strong>{priorityWorkspaceCount}</strong>
                <Link className="hero-panel-link" to={sessionsHref({ minRisk: 'high', action: 'high-risk' })}>
                  {t('dashboard.panel.filterInventory')}
                </Link>
              </div>
              <div>
                <span className="hero-panel-label"><Timer size={13} aria-hidden="true" /> {t('dashboard.panel.gatewayUptime')}</span>
                <strong>{health ? formatUptime(health.uptime_seconds) : '—'}</strong>
              </div>
              <div>
                <span className="hero-panel-label"><BrainCircuit size={13} aria-hidden="true" /> {t('dashboard.panel.llmUsage')}</span>
                <strong>{llmUsageSnapshot ? `${llmUsageSnapshot.total_calls.toLocaleString()} calls` : '—'}</strong>
                <div className="mono hero-panel-detail">
                  {llmUsageSnapshot ? formatLlmUsageSummary(llmUsageSnapshot) : 'Usage snapshot unavailable'}
                </div>
              </div>
              {systemSecurityPosture && (
                <div>
                  <span className="hero-panel-label"><ShieldCheck size={13} aria-hidden="true" /> System Security Posture</span>
                  <strong>{formatMetricScore(systemSecurityPosture.latest_composite_score ?? postureScore(systemSecurityPosture))}</strong>
                  <div className="mono hero-panel-detail">
                    {formatRiskVelocity(systemSecurityPosture, postureWindowSummary)}
                  </div>
                </div>
              )}
              <div className="hero-panel-wide">
                <span className="hero-panel-label"><WalletCards size={13} aria-hidden="true" /> {t('dashboard.panel.dailyBudget')}</span>
                <strong>{health ? formatUsd(health.budget.daily_budget_usd) : '—'}</strong>
                <div className="mono hero-panel-detail">
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
                  <div className="mono hero-panel-budget-warning">
                    {budgetExhaustionEvent ? (
                      <>
                        <strong className="hero-panel-warning-title">{t('dashboard.panel.budgetAlert')}</strong>
                        <span> · Operator attention required</span>
                        <div className="hero-panel-warning-detail">
                          {budgetExhaustionEvent.provider} · {budgetExhaustionEvent.tier} ·{' '}
                          {formatUsd(budgetExhaustionEvent.cost_usd)}
                        </div>
                        <Link className="hero-panel-link" to={sessionsHref({ action: 'budget', budget: 'exhausted' })}>
                          Open budget evidence queue
                        </Link>
                      </>
                    ) : (
                      <>
                        <strong className="hero-panel-warning-title">{t('dashboard.panel.budgetAlert')}</strong>
                        <span> · Operator attention required</span>
                        <div>
                          <Link className="hero-panel-link" to={sessionsHref({ action: 'budget', budget: 'exhausted' })}>
                            Open budget evidence queue
                          </Link>
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="operator-priority-guide" aria-labelledby="operator-priority-guide-heading">
          <div className="operator-priority-copy">
            <p className="section-kicker">{t('dashboard.read.kicker')}</p>
            <h2 id="operator-priority-guide-heading">{t('dashboard.read.title')}</h2>
            <p>
              {t('dashboard.read.copy')}
            </p>
          </div>
          <div className="operator-priority-steps">
            {operatorSteps.map(step => (
              <Link key={step.label} to={step.href} className="operator-priority-step">
                <span>{step.label}</span>
                <strong>{step.title}</strong>
                <p>{step.body}</p>
              </Link>
            ))}
          </div>
        </section>

        <div className="metric-grid dashboard-metric-grid">
          <MetricCard
            label={t('dashboard.metric.tracked')}
            value={sessions.length.toLocaleString()}
            accent="purple"
            icon={<Layers3 size={20} />}
            subtext={`${totalWorkspaces} workspaces across ${groupedSessions.length} frameworks`}
          />
          <MetricCard
            label={t('dashboard.metric.highRisk')}
            value={highRiskSessions.toLocaleString()}
            accent="red"
            icon={<AlertTriangle size={20} />}
            subtext={`${criticalSessions} critical right now`}
          />
          <MetricCard
            label={t('dashboard.metric.evidenceBudget')}
            value={toolkitEvidenceBudgetHotspotCount.toLocaleString()}
            accent="amber"
            icon={<Siren size={20} />}
            subtext="Sessions hitting toolkit evidence budget"
          />
          <MetricCard
            label={t('dashboard.metric.blockRate')}
            value={`${blockRate}%`}
            accent="amber"
            icon={<ShieldCheck size={20} />}
            subtext={`${summary?.by_decision?.block ?? 0} blocks in current window`}
          />
          <MetricCard
            label={t('dashboard.metric.liveEvents')}
            value={(health?.trajectory_count ?? 0).toLocaleString()}
            accent="blue"
            icon={<Activity size={20} />}
            subtext={health ? `Cumulative records · ${formatUptime(health.uptime_seconds)} uptime` : undefined}
          />
        </div>

        <LLMUsageDrilldown snapshot={llmUsageSnapshot} />
      </section>

      <section className="dashboard-region dashboard-region-operational" aria-label="Operational scan">
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
                      <Link
                        key={workspace.key}
                        className="framework-workspace-row"
                        to={sessionsHref({ framework: group.framework, q: workspace.workspaceLabel })}
                      >
                        <div>
                          <strong>{workspace.workspaceLabel}</strong>
                          <span>{formatRelativeTime(workspace.latestActivityAt)}</span>
                        </div>
                        <RiskBadge level={workspace.highestRisk} />
                      </Link>
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

      <section className="dashboard-region dashboard-region-inspection" aria-label="Deep inspection">
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
              <Link to={sessionsHref({ minRisk: 'high', action: 'high-risk' })} className="section-link">Review high-risk queue</Link>
            </div>
            <div className="priority-session-list">
              {prioritySessions.map(session => {
                const sessionL3Annotation = formatSessionL3Annotation(session, language)
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
                        <p className="priority-session-meta priority-session-annotation mono">
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
              <Link to={sessionsHref({ action: 'budget', budget: 'exhausted' })} className="section-link">
                Open evidence queue
              </Link>
            </div>
            <div className="priority-session-list">
              {toolkitEvidenceBudgetHotspots.map(session => {
                const sessionL3Annotation = formatSessionL3Annotation(session, language)
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
                        <p className="priority-session-meta priority-session-annotation mono">
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
