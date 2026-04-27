import { useDeferredValue, useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { RefreshCw, Search, Users } from 'lucide-react'
import { api } from '../api/client'
import { createManagedSSE } from '../api/sse'
import { RiskBadge } from '../components/badges'
import EmptyState from '../components/EmptyState'
import type { RiskVelocity, SessionSummary, WindowRiskSummary } from '../api/types'
import {
  activityState,
  formatRelativeTime,
  groupSessions,
  workspaceTechnicalDetail,
} from '../lib/sessionGroups'
import { formatSessionL3Annotation } from '../lib/sessionL3Annotations'
import { DEMO_FALLBACK_ENABLED, DEMO_SESSIONS } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'

function verdictTone(decision: string): string {
  return ['allow', 'block', 'defer', 'modify'].includes(decision) ? decision : 'unknown'
}

function scoreTone(score: number): 'critical' | 'high' | 'medium' | 'low' {
  const normalized = Math.max(0, Math.min(score / 3, 1))
  if (normalized >= 0.75) return 'critical'
  if (normalized >= 0.5) return 'high'
  if (normalized >= 0.25) return 'medium'
  return 'low'
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

function VerdictBar({ dist }: { dist: Record<string, number> }) {
  const total = Object.values(dist).reduce((sum, value) => sum + value, 0)
  if (total === 0) return <span className="text-muted mono">—</span>
  let offset = 0
  return (
    <svg className="verdict-bar verdict-bar-wide" viewBox="0 0 100 7" role="img" aria-label="Decision distribution">
      <title>
        {Object.entries(dist).map(([key, count]) => `${key}: ${count}`).join(', ')}
      </title>
      {Object.entries(dist).map(([key, count]) => {
        if (count <= 0) return null
        const width = (count / total) * 100
        const x = offset
        offset += width
        return (
          <rect
            key={key}
            className={`verdict-bar-segment verdict-bar-segment-${verdictTone(key)}`}
            x={x}
            y={0}
            width={width}
            height={7}
          />
        )
      })}
    </svg>
  )
}

function ScoreBar({ score }: { score: number }) {
  const tone = scoreTone(score)
  const width = Math.max(0, Math.min(score / 3, 1)) * 100
  return (
    <div className="score-bar-wrap">
      <svg className="score-bar score-bar-wide" viewBox="0 0 100 6" role="img" aria-label={`Risk score ${score.toFixed(2)} of 3.00`}>
        <rect className="score-bar-track" x={0} y={0} width={100} height={6} rx={3} />
        <rect className={`score-bar-fill score-bar-fill-${tone}`} x={0} y={0} width={width} height={6} rx={3} />
      </svg>
      <span className={`mono score-value score-value-${tone}`}>{score.toFixed(2)}</span>
    </div>
  )
}

export default function Sessions() {
  const { t, language } = usePreferences()
  const [searchParams, setSearchParams] = useSearchParams()
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [demoMode, setDemoMode] = useState(false)
  const [minRisk, setMinRisk] = useState(() => searchParams.get('minRisk') || searchParams.get('min_risk') || '')
  const [framework, setFramework] = useState(() => searchParams.get('framework') || '')
  const [query, setQuery] = useState(() => searchParams.get('q') || '')
  const [actionFilter, setActionFilter] = useState(() => searchParams.get('action') || '')
  const [budgetExhaustedOnly, setBudgetExhaustedOnly] = useState(
    () => searchParams.get('budget') === 'exhausted' || searchParams.get('action') === 'budget',
  )
  const [refreshNonce, setRefreshNonce] = useState(0)
  const deferredQuery = useDeferredValue(query.trim().toLowerCase())
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const next = new URLSearchParams()
    if (minRisk) next.set('minRisk', minRisk)
    if (framework) next.set('framework', framework)
    if (query.trim()) next.set('q', query.trim())
    if (actionFilter) next.set('action', actionFilter)
    if (budgetExhaustedOnly) next.set('budget', 'exhausted')
    setSearchParams(next, { replace: true })
  }, [actionFilter, budgetExhaustedOnly, framework, minRisk, query, setSearchParams])

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const data = await api.sessions({
          sort: 'risk_level',
          limit: 200,
          min_risk: minRisk || undefined,
        })
        if (DEMO_FALLBACK_ENABLED && data.length === 0) {
          setSessions(DEMO_SESSIONS)
          setDemoMode(true)
        } else {
          setSessions(data)
          setDemoMode(false)
        }
      } catch {
        if (DEMO_FALLBACK_ENABLED) {
          setSessions(DEMO_SESSIONS)
          setDemoMode(true)
        }
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
    if (actionFilter === 'l3' && !session.l3_state && !session.l3_reason_code && !session.l3_advisory_latest) return false
    if (actionFilter === 'high-risk' && session.high_risk_event_count === 0 && session.current_risk_level !== 'critical') return false
    if (actionFilter === 'defer' && (session.decision_distribution.defer ?? 0) === 0) return false
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

  const groupedSessions = groupSessions(filteredSessions, language)

  return (
    <div className="sessions-shell">
      <section className="card sessions-toolbar" aria-labelledby="session-filters-heading">
        <div>
          <p className="section-kicker">{t('sessions.workbench')}</p>
          <h2 id="session-filters-heading" className="section-header sessions-filter-heading">
            <Users size={18} className="section-header-icon" />
            {t('sessions.filters')}
          </h2>
          {demoMode && <span className="showcase-pill">Showcase mode · demo sessions</span>}
          <p className="toolbar-subtitle">
            {t('sessions.subtitle')}
          </p>
        </div>

        <div className="toolbar-controls" role="group" aria-label={t('sessions.filters')}>
          <label className="search-box">
            <Search size={14} />
            <input
              aria-label={t('sessions.search')}
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder={t('sessions.searchPlaceholder')}
            />
          </label>
          <select aria-label={t('sessions.frameworkFilter')} value={framework} onChange={event => setFramework(event.target.value)}>
            <option value="">{t('sessions.allFrameworks')}</option>
            {frameworks.map(item => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <select aria-label={t('sessions.riskFilter')} value={minRisk} onChange={event => setMinRisk(event.target.value)}>
            <option value="">{t('sessions.allRisk')}</option>
            <option value="medium">{t('sessions.mediumPlus')}</option>
            <option value="high">{t('sessions.highPlus')}</option>
            <option value="critical">{t('sessions.criticalOnly')}</option>
          </select>
          <select
            aria-label={t('sessions.actionFilter')}
            value={actionFilter}
            onChange={event => {
              const value = event.target.value
              setActionFilter(value)
              if (value === 'budget') {
                setBudgetExhaustedOnly(true)
              }
            }}
          >
            <option value="">{t('sessions.allActions')}</option>
            <option value="high-risk">{t('sessions.highRiskActivity')}</option>
            <option value="defer">{t('sessions.deferApprovals')}</option>
            <option value="l3">{t('sessions.l3Attention')}</option>
            <option value="budget">{t('sessions.budgetEvidence')}</option>
          </select>
          <button
            type="button"
            className={`btn ${budgetExhaustedOnly ? 'btn-primary' : ''}`}
            onClick={() => {
              const next = !budgetExhaustedOnly
              setBudgetExhaustedOnly(next)
              if (!next && actionFilter === 'budget') setActionFilter('')
            }}
            aria-pressed={budgetExhaustedOnly}
          >
            {t('sessions.budgetOnly')}
          </button>
          {(minRisk || framework || query || actionFilter || budgetExhaustedOnly) && (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setMinRisk('')
                setFramework('')
                setQuery('')
                setActionFilter('')
                setBudgetExhaustedOnly(false)
              }}
            >
              {t('common.clearFilters')}
            </button>
          )}
          <button className="btn" onClick={() => setRefreshNonce(value => value + 1)} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin-icon' : undefined} />
            {t('common.refresh')}
          </button>
        </div>
      </section>

      <section className="card sessions-region" aria-labelledby="framework-overview-heading">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">{t('sessions.overview')}</p>
            <h2 id="framework-overview-heading">{t('sessions.frameworkOverview')}</h2>
            <p className="toolbar-subtitle">
              {t('sessions.groupedCopy')}
            </p>
          </div>
        </div>

        <div className="framework-overview-grid">
          {groupedSessions.map(group => (
            <article key={group.framework} className="framework-overview-card">
              <div className="framework-panel-top">
                <div>
                  <h3>{group.framework}</h3>
                  <p>{group.workspaceCount} {t('common.workspaces')}</p>
                </div>
                <RiskBadge level={group.highestRisk} />
              </div>
              <div className="framework-panel-metrics">
                <div>
                  <span>{t('sessions.sessionCount')}</span>
                  <strong>{group.sessionCount}</strong>
                </div>
                <div>
                  <span>{t('sessions.highRiskCount')}</span>
                  <strong>{group.highRiskSessionCount}</strong>
                </div>
                <div>
                  <span>{t('sessions.eventCount')}</span>
                  <strong>{group.totalEvents}</strong>
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="card sessions-region" aria-labelledby="session-inventory-heading">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">{t('sessions.inventory')}</p>
            <h2 id="session-inventory-heading">{t('sessions.sessionInventory')}</h2>
            <p className="toolbar-subtitle">
              {t('sessions.inventoryCopy')}
            </p>
          </div>
        </div>

        <div className="framework-stack">
          {groupedSessions.map(group => (
            <section key={group.framework} className="card framework-section">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">{t('sessions.framework')}</p>
                  <h2>{group.framework}</h2>
                </div>
                <div className="framework-section-meta">
                  <span>{group.sessionCount} {t('common.sessions')}</span>
                  <span>{group.workspaceCount} {t('common.workspaces')}</span>
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
                          {workspaceTechnicalDetail(workspace.workspaceRoot, language)}
                        </p>
                      </div>
                      <div className="workspace-section-meta">
                        <span className={`activity-pill activity-pill-${activityState(workspace.latestActivityAt)}`}>
                          {formatRelativeTime(workspace.latestActivityAt)}
                        </span>
                        <span>{workspace.sessionCount} {t('common.sessions')}</span>
                      </div>
                    </div>

                    <div className="workspace-summary-row">
                      <span>{workspace.highRiskSessionCount} {t('common.highRisk')}</span>
                      <span>{workspace.totalEvents} {t('common.events')}</span>
                      <span>{workspace.callerAdapters.join(', ') || t('sessions.adapterUnavailable')}</span>
                    </div>

                    <div className="session-card-stack">
                      {workspace.sessions.map(session => {
                        const sessionL3Annotation = formatSessionL3Annotation(session, language)
                        const primaryScore = session.session_risk_ewma ?? session.latest_composite_score ?? session.cumulative_score
                        const postActionScore = session.post_action_score_ewma ?? session.latest_post_action_score
                        const density = windowRiskDensity(session.window_risk_summary)
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
                                {session.agent_id || t('sessions.unknownAgent')} · {session.caller_adapter}
                              </p>
                              {sessionL3Annotation && (
                                <p className="session-card-meta session-card-annotation mono">
                                  {sessionL3Annotation}
                                </p>
                              )}
                              <p className="session-card-meta session-card-annotation mono">
                                <span>{t('sessions.latestScore')} {formatMetricScore(primaryScore)}</span>
                                {' · '}
                                <span>EWMA {formatMetricScore(session.session_risk_ewma)}</span>
                                {postActionScore !== undefined && (
                                  <>
                                    {' · '}
                                    <span>{t('sessions.postActionScore')} {formatMetricScore(postActionScore)}</span>
                                  </>
                                )}
                                {' · '}
                                <span>{t('sessions.velocity')} {formatRiskVelocityValue(session.risk_velocity ?? session.window_risk_summary?.risk_velocity)}</span>
                                {' · '}
                                <span>{t('sessions.density')} {formatMetricScore(density)}</span>
                              </p>
                              <VerdictBar dist={session.decision_distribution} />
                            </div>
                            <div className="session-card-side">
                              <ScoreBar score={primaryScore} />
                              <div className="session-card-statline">
                                <span>{session.event_count} {t('common.events')}</span>
                                <span>{session.high_risk_event_count} {t('common.highRisk')}</span>
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
                title={t('sessions.noSessionsTitle')}
                subtitle={t('sessions.noSessionsSubtitle')}
              />
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
