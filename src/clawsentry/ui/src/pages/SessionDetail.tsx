import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, FolderTree, ScrollText, ShieldAlert } from 'lucide-react'
import { api } from '../api/client'
import { DecisionBadge, RiskBadge } from '../components/badges'
import SkeletonCard from '../components/SkeletonCard'
import type {
  HealthBudgetSnapshot,
  SSEBudgetExhaustedEvent,
  SessionReplayPageResponse,
  SessionRisk,
  SessionRiskResponse,
  TrajectoryRecord,
} from '../api/types'
import {
  Area,
  AreaChart,
  CartesianGrid,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatRelativeTime, workspaceLabel } from '../lib/sessionGroups'
import { formatL3EvidenceSummary } from '../lib/l3EvidenceSummary'
import { DEMO_FALLBACK_ENABLED, DEMO_REPLAY_PAGE, DEMO_SESSION_RISK } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'
import {
  appendReadableLabel,
  formatOperatorAction,
  formatOperatorLabel,
  formatRunnerLabel,
} from '../lib/operatorLabels'

type ReportingEnvelope = {
  budget?: HealthBudgetSnapshot | null
  budget_exhaustion_event?: SSEBudgetExhaustedEvent | null
}

const DIMENSION_LABELS: Record<string, string> = {
  d1: 'Tool risk',
  d2: 'Target sensitivity',
  d3: 'Data flow',
  d4: 'Frequency',
  d5: 'Context',
}

const TOOLTIP_STYLE = {
  background: 'rgba(255, 255, 255, 0.96)',
  border: '1px solid rgba(148, 163, 184, 0.18)',
  borderRadius: 16,
  fontSize: 12,
  color: '#142133',
  boxShadow: '0 18px 40px rgba(15, 23, 42, 0.12)',
}

const RECENT_WINDOW_SECONDS = 60 * 60
const WINDOW_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: 'All', value: null },
  { label: 'Recent 1h', value: RECENT_WINDOW_SECONDS },
]
const FULL_REVIEW_RUNNERS = ['deterministic_local', 'fake_llm', 'llm_provider'] as const
type FullReviewRunner = typeof FULL_REVIEW_RUNNERS[number]

function parseWindowSeconds(value: string | null): number | null {
  if (!value || value === 'all') return null
  if (value === 'recent-1h') return RECENT_WINDOW_SECONDS
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

function classifyHint(hint: string): string {
  const normalized = hint.toLowerCase()
  if (normalized.includes('shell') || normalized.includes('command')) return 'shell'
  if (normalized.includes('file') || normalized.includes('path')) return 'file'
  if (normalized.includes('network') || normalized.includes('url')) return 'network'
  if (normalized.includes('secret') || normalized.includes('credential') || normalized.includes('data')) return 'data'
  return 'default'
}

function HintTag({ hint }: { hint: string }) {
  return <span className={`hint-tag hint-tag-${classifyHint(hint)}`}>{hint}</span>
}

function formatUsd(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount)
}

function TierBadge({ tier }: { tier: string }) {
  const normalized = tier.toUpperCase()
  const className = normalized === 'L3' ? 'badge-tier-l3' : normalized === 'L2' ? 'badge-tier-l2' : 'badge-tier-l1'
  return <span className={`badge ${className}`}>{normalized}</span>
}

function TimelineLatency({ ms }: { ms: number }) {
  const className = ms < 100 ? 'latency-fast' : ms < 3000 ? 'latency-medium' : 'latency-slow'
  return <span className={`latency-badge ${className}`}>{ms}ms</span>
}

function normalizeSessionRisk(result: SessionRisk | SessionRiskResponse): {
  risk: SessionRisk
  reporting: ReportingEnvelope
} {
  const response = result as SessionRiskResponse
  return {
    risk: response,
    reporting: {
      budget: response.budget ?? null,
      budget_exhaustion_event: response.budget_exhaustion_event ?? null,
    },
  }
}

function normalizeSessionReplayPage(result: SessionReplayPageResponse): {
  records: TrajectoryRecord[]
  nextCursor: number | null
  reporting: ReportingEnvelope
} {
  return {
    records: Array.isArray(result.records) ? result.records : [],
    nextCursor: result.next_cursor ?? null,
    reporting: {
      budget: result.budget ?? null,
      budget_exhaustion_event: result.budget_exhaustion_event ?? null,
    },
  }
}

function formatAdvisoryRecordRange(review: NonNullable<SessionRisk['l3_advisory']>['latest_review']): string {
  const range = review?.source_record_range
  if (!range) return 'Frozen boundary unavailable'
  const count = review.evidence_record_count ?? review.evidence_event_ids?.length ?? 0
  return `Records ${range.from_record_id}–${range.to_record_id} · ${count} event(s)`
}

function getOperatorRecommendation(
  risk: SessionRisk | null,
  showBudgetWarning: boolean,
  latestAdvisoryReview: NonNullable<SessionRisk['l3_advisory']>['latest_review'] | null,
) {
  if (latestAdvisoryReview?.recommended_operator_action) {
    return {
      label: latestAdvisoryReview.recommended_operator_action,
      detail: 'Follow the advisory-only recommendation while keeping the canonical decision unchanged.',
    }
  }

  if (showBudgetWarning) {
    return {
      label: 'review budget evidence',
      detail: 'Confirm LLM budget exhaustion before requesting additional L3 work.',
    }
  }

  if (risk?.current_risk_level === 'critical') {
    return {
      label: 'escalate immediately',
      detail: 'Critical posture detected; inspect replay evidence before releasing activity.',
    }
  }

  if (risk?.current_risk_level === 'high') {
    return {
      label: 'inspect replay',
      detail: 'High-risk activity is present; review recent decisions and L3 readiness.',
    }
  }

  return {
    label: 'monitor session',
    detail: 'No urgent advisory action is attached; keep observing trajectory changes.',
  }
}

function shouldUseSessionDetailDemoFallback(sessionId?: string): boolean {
  return DEMO_FALLBACK_ENABLED && Boolean(sessionId?.startsWith('demo-'))
}

export default function SessionDetail() {
  const { t, language } = usePreferences()
  const { sessionId } = useParams<{ sessionId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const [risk, setRisk] = useState<SessionRisk | null>(null)
  const [trajectory, setTrajectory] = useState<TrajectoryRecord[]>([])
  const [replayNextCursor, setReplayNextCursor] = useState<number | null>(null)
  const [replayLoadingMore, setReplayLoadingMore] = useState(false)
  const [replayLoadMoreError, setReplayLoadMoreError] = useState<string | null>(null)
  const [budget, setBudget] = useState<HealthBudgetSnapshot | null>(null)
  const [budgetExhaustionEvent, setBudgetExhaustionEvent] = useState<SSEBudgetExhaustedEvent | null>(null)
  const [initialLoadError, setInitialLoadError] = useState<string | null>(null)
  const [reloadNonce, setReloadNonce] = useState(0)
  const [sessionWindowSeconds, setSessionWindowSeconds] = useState<number | null>(
    () => parseWindowSeconds(searchParams.get('windowSeconds') || searchParams.get('window')),
  )
  const [loading, setLoading] = useState(true)
  const [demoMode, setDemoMode] = useState(false)
  const [fullReviewStatus, setFullReviewStatus] = useState<string | null>(null)
  const [fullReviewError, setFullReviewError] = useState<string | null>(null)
  const [fullReviewRunning, setFullReviewRunning] = useState(false)
  const [fullReviewRunner, setFullReviewRunner] = useState<FullReviewRunner>('deterministic_local')
  const [fullReviewQueueOnly, setFullReviewQueueOnly] = useState(false)

  useEffect(() => {
    if (!sessionId) return
    setLoading(true)
    setInitialLoadError(null)
    setRisk(null)
    setTrajectory([])
    setReplayNextCursor(null)
    setReplayLoadMoreError(null)
    setBudget(null)
    setBudgetExhaustionEvent(null)
    Promise.all([
      api.sessionRisk(sessionId, { windowSeconds: sessionWindowSeconds }),
      api.sessionReplayPage(sessionId, { windowSeconds: sessionWindowSeconds }),
    ])
      .then(([riskResult, trajectoryResult]) => {
        const normalizedRisk = normalizeSessionRisk(riskResult)
        const normalizedReplay = normalizeSessionReplayPage(trajectoryResult)

        setRisk(normalizedRisk.risk)
        setTrajectory(normalizedReplay.records)
        setReplayNextCursor(normalizedReplay.nextCursor)
        setBudget(normalizedRisk.reporting.budget ?? normalizedReplay.reporting.budget ?? null)
        setBudgetExhaustionEvent(
          normalizedRisk.reporting.budget_exhaustion_event
          ?? normalizedReplay.reporting.budget_exhaustion_event
          ?? null,
        )
        setDemoMode(false)
      })
      .catch(() => {
        if (!shouldUseSessionDetailDemoFallback(sessionId)) {
          setInitialLoadError('Could not load session detail. Try again.')
          return
        }
        const normalizedRisk = normalizeSessionRisk({
          ...DEMO_SESSION_RISK,
          session_id: sessionId,
        })
        const normalizedReplay = normalizeSessionReplayPage({
          ...DEMO_REPLAY_PAGE,
          session_id: sessionId,
        })
        setRisk(normalizedRisk.risk)
        setTrajectory(normalizedReplay.records)
        setReplayNextCursor(normalizedReplay.nextCursor)
        setBudget(normalizedRisk.reporting.budget ?? normalizedReplay.reporting.budget ?? null)
        setBudgetExhaustionEvent(
          normalizedRisk.reporting.budget_exhaustion_event
          ?? normalizedReplay.reporting.budget_exhaustion_event
          ?? null,
        )
        setDemoMode(true)
      })
      .finally(() => setLoading(false))
  }, [reloadNonce, sessionId, sessionWindowSeconds])

  async function loadMoreReplayRecords() {
    if (!sessionId || replayLoadingMore || replayNextCursor === null) return

    setReplayLoadingMore(true)
    setReplayLoadMoreError(null)
    try {
      const replayResult = await api.sessionReplayPage(sessionId, {
        cursor: replayNextCursor,
        windowSeconds: sessionWindowSeconds,
      })
      const normalizedReplay = normalizeSessionReplayPage(replayResult)
      setTrajectory(prev => [...prev, ...normalizedReplay.records])
      setReplayNextCursor(normalizedReplay.nextCursor)
      setBudget(prev => prev ?? normalizedReplay.reporting.budget ?? null)
      setBudgetExhaustionEvent(prev => prev ?? normalizedReplay.reporting.budget_exhaustion_event ?? null)
    } catch {
      setReplayLoadMoreError('Could not load older replay records. Try again.')
    } finally {
      setReplayLoadingMore(false)
    }
  }

  async function requestFullReview() {
    if (!sessionId || fullReviewRunning) return
    setFullReviewRunning(true)
    setFullReviewError(null)
    setFullReviewStatus(null)
    try {
      const result = await api.requestL3FullReview(sessionId, {
        runner: fullReviewRunner,
        run: !fullReviewQueueOnly,
      })
      const runnerLabel = formatRunnerLabel(fullReviewRunner, language)
      const reviewId = result.review?.review_id
      const state = result.review?.l3_state || result.job?.job_state || 'queued'
      if (fullReviewQueueOnly) {
        setFullReviewStatus(
          `Full review queued (${runnerLabel}): ${result.job?.job_id || 'job pending'}. Canonical decision unchanged.`,
        )
      } else {
        setFullReviewStatus(
          reviewId
            ? `Full review ${state} (${runnerLabel}): ${reviewId}. Canonical decision unchanged.`
            : `Full review queued (${runnerLabel}): ${result.job?.job_id || 'job pending'}. Canonical decision unchanged.`,
        )
      }
      setReloadNonce(value => value + 1)
    } catch {
      setFullReviewError('Could not request L3 full review. Try again.')
    } finally {
      setFullReviewRunning(false)
    }
  }

  if (loading) {
    return (
      <div>
        <div className="session-skeleton-spacer" />
        <div className="session-detail-grid">
          {[0, 1, 2].map(index => <SkeletonCard key={index} rows={4} height={220} />)}
        </div>
        <SkeletonCard rows={8} height={320} />
      </div>
    )
  }

  if (initialLoadError) {
    return (
      <div className="session-detail-shell">
        <Link to="/sessions" className="back-link">
          <ArrowLeft size={13} />
          Back to session inventory
        </Link>
        <section className="card section-card session-error-card" role="alert">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Session detail</p>
              <h2>Unable to load session data</h2>
            </div>
          </div>
          <p className="priority-session-meta session-error-copy">
            {initialLoadError}
          </p>
          <button
            type="button"
            className="secondary-button"
            onClick={() => setReloadNonce(value => value + 1)}
          >
            Retry
          </button>
        </section>
      </div>
    )
  }

  const radarData = risk
    ? Object.entries(risk.dimensions_latest).map(([key, value]) => ({
        dimension: DIMENSION_LABELS[key] || key,
        value,
        fullMark: 1,
      }))
    : []

  const timelineData = risk?.risk_timeline.map(item => ({
    time: new Date(item.occurred_at).toLocaleTimeString(),
    score: Number(item.composite_score.toFixed(3)),
  })) ?? []
  const showBudgetWarning = Boolean(budget?.exhausted || budgetExhaustionEvent)
  const workspaceName = workspaceLabel(risk?.workspace_root || '')
  const latestAdvisoryReview = risk?.l3_advisory?.latest_review ?? null
  const latestAdvisoryJob = risk?.l3_advisory?.latest_job ?? null
  const latestAdvisoryAction = risk?.l3_advisory?.latest_action ?? null
  const latestRecord = trajectory[0] ?? null
  const latestToolName = latestRecord ? String(latestRecord.event?.tool_name || 'unknown tool') : 'No tool observed'
  const latestDecisionLabel = latestRecord ? String(latestRecord.decision.decision).toUpperCase() : 'NO REPLAY'
  const workbenchWindowLabel = sessionWindowSeconds === null ? 'All recorded evidence' : 'Recent 1h replay scope'
  const operatorRecommendation = getOperatorRecommendation(risk, showBudgetWarning, latestAdvisoryReview)
  const evidenceBoundaryLabel = latestAdvisoryReview ? latestAdvisoryReview.snapshot_id : 'No frozen snapshot'
  const evidenceBoundaryDetail = latestAdvisoryReview
    ? formatAdvisoryRecordRange(latestAdvisoryReview)
    : 'Request full review to freeze a bounded advisory snapshot.'
  const capturedSummary = risk
    ? `${formatRelativeTime(risk.first_event_at)} · ${risk.source_framework}`
    : 'Waiting for session telemetry.'
  const classifiedSummary = risk
    ? `${risk.current_risk_level} posture · score ${risk.cumulative_score.toFixed(2)}`
    : 'Risk posture unavailable.'
  const replayEvidenceSummary = trajectory.length > 0
    ? `${trajectory.length} decision event(s) loaded for operator review.`
    : 'No replay records loaded yet.'
  const advisoryActionSummary = latestAdvisoryReview
    ? `L3 ${formatOperatorLabel('l3State', latestAdvisoryReview.l3_state, language)} · ${formatOperatorAction(latestAdvisoryAction?.recommended_operator_action || latestAdvisoryReview.recommended_operator_action || 'inspect', language)}.`
    : 'No advisory review attached yet.'
  const latestAdvisoryRunner = latestAdvisoryReview?.review_runner
    || latestAdvisoryReview?.worker_backend
    || latestAdvisoryJob?.runner
    || null

  function updateSessionWindow(value: number | null) {
    setSessionWindowSeconds(value)
    const next = new URLSearchParams(searchParams)
    if (value === null) {
      next.delete('windowSeconds')
      next.delete('window')
    } else {
      next.set('windowSeconds', String(value))
      next.delete('window')
    }
    setSearchParams(next, { replace: true })
  }

  return (
    <div className="session-detail-shell">
      <Link to="/sessions" className="back-link">
        <ArrowLeft size={13} />
        {t('session.back')}
      </Link>

      <section className="session-hero">
        <div className="session-overview-copy">
          <p className="section-kicker">{t('session.detail')}</p>
          {demoMode && <span className="showcase-pill">Showcase mode · demo replay</span>}
          <h1>{workspaceName}</h1>
          <p className="hero-copy">
            {risk?.source_framework || 'unknown'} · {risk?.caller_adapter || 'unknown adapter'} ·
            last seen {risk ? formatRelativeTime(risk.last_event_at) : 'recently'}
          </p>
        </div>
        <div className="hero-chip-row session-overview-chips">
          {risk && <RiskBadge level={risk.current_risk_level} />}
          {risk && <span className="framework-chip"><span>Agent</span><strong>{risk.agent_id}</strong></span>}
          {risk && <span className="framework-chip"><span>Events</span><strong>{risk.event_count}</strong></span>}
        </div>
      </section>

      <section className="session-surface session-analysis-surface" aria-labelledby="session-analysis-heading">
        <div className="section-card-header session-surface-header">
          <div>
            <p className="section-kicker">{t('session.analysis')}</p>
            <h2 id="session-analysis-heading">{t('session.analysisTitle')}</h2>
          </div>
          <div className="session-surface-actions">
            <span className="section-meta">{t('session.analysisMeta')}</span>
            <div className="full-review-controls">
              <label className="full-review-runner-select">
                <span>{t('session.fullReviewRunner')}</span>
                <select
                  aria-label={t('session.fullReviewRunner')}
                  value={fullReviewRunner}
                  onChange={event => setFullReviewRunner(event.target.value as FullReviewRunner)}
                  disabled={fullReviewRunning}
                >
                  {FULL_REVIEW_RUNNERS.map(runner => (
                    <option key={runner} value={runner}>
                      {formatRunnerLabel(runner, language)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="full-review-queue-toggle">
                <input
                  type="checkbox"
                  checked={fullReviewQueueOnly}
                  onChange={event => setFullReviewQueueOnly(event.target.checked)}
                  disabled={fullReviewRunning}
                />
                <span>{t('session.fullReviewQueueOnly')}</span>
              </label>
            </div>
            <button
              type="button"
              className="secondary-button"
              onClick={requestFullReview}
              disabled={fullReviewRunning || !sessionId}
            >
              {fullReviewRunning ? t('session.requestingReview') : t('session.requestReview')}
            </button>
          </div>
        </div>
        {(fullReviewStatus || fullReviewError) && (
          <p
            role={fullReviewError ? 'alert' : 'status'}
            className="priority-session-meta"
            data-tone={fullReviewError ? 'warning' : 'muted'}
          >
            {fullReviewError || fullReviewStatus}
          </p>
        )}
        <div className="session-analysis-grid">
          <section className="card section-card session-analysis-card-wide investigation-brief-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{t('session.workbench')}</p>
                <h3>{t('session.storyline')}</h3>
              </div>
              <span className="section-meta">{workbenchWindowLabel}</span>
            </div>
            <p className="investigation-lede">
              {workspaceName} is being reconstructed from {trajectory.length} replay event(s),{' '}
              {risk?.event_count ?? 0} tracked event(s), and {risk?.high_risk_event_count ?? 0} high-risk signal(s).
              The workbench keeps the advisory path visible without changing canonical safety decisions.
            </p>
            <div className="investigation-brief-grid">
              <div className="investigation-focus-card investigation-focus-card-primary">
                <span className="workbench-summary-label">{t('session.operatorRecommendation')}</span>
                <strong>{operatorRecommendation.label}</strong>
                <p>{operatorRecommendation.detail}</p>
              </div>
              <div className="investigation-focus-card">
                <span className="workbench-summary-label">{t('session.latestDecision')}</span>
                <strong>{latestDecisionLabel}</strong>
                <p>{latestToolName}</p>
              </div>
              <div className="investigation-focus-card">
                <span className="workbench-summary-label">{t('session.evidenceBoundary')}</span>
                <strong>{evidenceBoundaryLabel}</strong>
                <p>{evidenceBoundaryDetail}</p>
              </div>
            </div>
            <ol className="investigation-flow" aria-label="Investigation sequence">
              <li>
                <span>1</span>
                <div>
                  <strong>Session captured</strong>
                  <p>{capturedSummary}</p>
                </div>
              </li>
              <li>
                <span>2</span>
                <div>
                  <strong>Risk classified</strong>
                  <p>{classifiedSummary}</p>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <strong>Replay evidence assembled</strong>
                  <p>{replayEvidenceSummary}</p>
                </div>
              </li>
              <li>
                <span>4</span>
                <div>
                  <strong>Advisory action</strong>
                  <p>{advisoryActionSummary}</p>
                </div>
              </li>
            </ol>
          </section>

          <section className="card section-card session-analysis-card-wide session-analysis-summary-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Priority view</p>
                <h3>{t('session.currentPosture')}</h3>
              </div>
              <div className="hero-panel-header">
                <ShieldAlert size={14} />
                Analysis summary
              </div>
            </div>
            <div className="session-analysis-summary-grid">
              <div className="session-analysis-stat">
                <span>Current risk</span>
                <div className="session-analysis-stat-value">
                  {risk ? <RiskBadge level={risk.current_risk_level} /> : 'Unavailable'}
                </div>
              </div>
              <div className="session-analysis-stat">
                <span>Cumulative score</span>
                <strong className="mono">{risk?.cumulative_score.toFixed(2) ?? '0.00'}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>High-risk events</span>
                <strong className="mono">{risk?.high_risk_event_count ?? 0}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>Tracked events</span>
                <strong className="mono">{risk?.event_count ?? 0}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>First event</span>
                <strong className="mono">{risk ? formatRelativeTime(risk.first_event_at) : '—'}</strong>
              </div>
              <div className="session-analysis-stat">
                <span>Last event</span>
                <strong className="mono">{risk ? formatRelativeTime(risk.last_event_at) : '—'}</strong>
              </div>
            </div>
          </section>

          <section className="card section-card session-analysis-card-wide advisory-review-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Advisory-only</p>
                <h3>L3 advisory review</h3>
              </div>
              <span className="section-meta">Frozen evidence review, never a canonical decision rewrite</span>
            </div>
            {latestAdvisoryReview ? (
              <>
                <div className="advisory-review-grid">
                  <div className="session-analysis-stat">
                    <span>Review state</span>
                    <strong className="mono">{formatOperatorLabel('l3State', latestAdvisoryReview.l3_state, language)}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Review ID</span>
                    <strong className="mono">{latestAdvisoryReview.review_id}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Snapshot ID</span>
                    <strong className="mono">{latestAdvisoryReview.snapshot_id}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Job ID</span>
                    <strong className="mono">{latestAdvisoryJob?.job_id || 'Unavailable'}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Advisory risk</span>
                    <div className="session-analysis-stat-value">
                      <RiskBadge level={latestAdvisoryReview.risk_level} />
                    </div>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Operator action</span>
                    <strong className="mono">{formatOperatorAction(latestAdvisoryReview.recommended_operator_action || 'inspect', language)}</strong>
                  </div>
                  <div className="session-analysis-stat">
                    <span>Review runner</span>
                    <strong className="mono">{formatRunnerLabel(latestAdvisoryRunner, language)}</strong>
                  </div>
                </div>
                <p className="priority-session-meta advisory-review-boundary">
                  {formatAdvisoryRecordRange(latestAdvisoryReview)}
                </p>
                {latestAdvisoryReview.findings?.length > 0 && (
                  <p className="priority-session-meta">
                    Finding: <span className="mono">{latestAdvisoryReview.findings[0]}</span>
                  </p>
                )}
                <p className="priority-session-meta">
                  Canonical decision unchanged. Advisory-only review output is attached to the frozen snapshot.
                </p>
                {latestAdvisoryAction && (
                  <p className="priority-session-meta">
                    L3 advisory action: <span className="mono">{formatOperatorAction(latestAdvisoryAction.recommended_operator_action, language)}</span>
                    {' '}· advisory-only / canonical unchanged
                    {latestAdvisoryAction.source_record_range
                      ? ` · records ${latestAdvisoryAction.source_record_range.from_record_id}–${latestAdvisoryAction.source_record_range.to_record_id}`
                      : ''}
                  </p>
                )}
              </>
            ) : (
              <p className="empty-inline">
                No L3 advisory review has been attached to this session yet. Use the full-review action to freeze evidence and run a deterministic advisory pass.
              </p>
            )}
          </section>

          <section className="card section-card chart-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Dimensions</p>
                <h3>{t('session.riskComposition')}</h3>
              </div>
            </div>
            <div className="chart-card-body chart-card-radar">
              {radarData.length > 0 ? (
                <ResponsiveContainer>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="rgba(120, 196, 255, 0.12)" />
                    <PolarAngleAxis dataKey="dimension" tick={{ fill: '#89a4bd', fontSize: 10 }} />
                    <PolarRadiusAxis tick={{ fill: '#55708a', fontSize: 9 }} domain={[0, 1]} />
                    <Radar dataKey="value" stroke="#5ea5ff" fill="#5ea5ff" fillOpacity={0.2} strokeWidth={2} />
                  </RadarChart>
                </ResponsiveContainer>
              ) : (
                <p className="empty-inline">No dimension data yet.</p>
              )}
            </div>
          </section>

          <section className="card section-card chart-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Timeline</p>
                <h3>{t('session.riskTimeline')}</h3>
              </div>
            </div>
            <div className="chart-card-body chart-card-area">
              {timelineData.length > 0 ? (
                <ResponsiveContainer>
                  <AreaChart data={timelineData} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                    <defs>
                      <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#5ea5ff" stopOpacity={0.34} />
                        <stop offset="95%" stopColor="#5ea5ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(120, 196, 255, 0.08)" />
                    <XAxis dataKey="time" tick={{ fill: '#89a4bd', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#89a4bd', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 1]} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#5ea5ff"
                      strokeWidth={2}
                      fill="url(#riskGradient)"
                      dot={{ fill: '#5ea5ff', r: 3, strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: '#5ea5ff' }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <p className="empty-inline">No timeline data yet.</p>
              )}
            </div>
          </section>

          <section className="card section-card session-analysis-card-wide">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Replay</p>
                <h3>{t('session.decisionTimeline')}</h3>
              </div>
              <div
                role="group"
                aria-label="Session time window"
                className="session-window-controls"
              >
                {WINDOW_OPTIONS.map(option => {
                  const isSelected = sessionWindowSeconds === option.value
                  return (
                    <button
                      key={option.label}
                      type="button"
                      className="secondary-button"
                      aria-pressed={isSelected}
                      onClick={() => updateSessionWindow(option.value)}
                      data-selected={isSelected ? 'true' : 'false'}
                    >
                      {option.label}
                    </button>
                  )
                })}
              </div>
              <span className="section-meta">{trajectory.length} events</span>
            </div>
            <div className="decision-timeline">
              {trajectory.map((record, index) => {
                const input = typeof record.event?.input === 'string' ? record.event.input : ''
                const evidenceSummary = formatL3EvidenceSummary(record.l3_trace?.evidence_summary)
                return (
                  <div key={`${record.recorded_at}-${index}`} className="decision-timeline-row">
                    <span className="mono decision-timeline-time">
                      {new Date(record.recorded_at).toLocaleTimeString()}
                    </span>
                    <div className="decision-timeline-main">
                      <div className="decision-timeline-badges">
                        <DecisionBadge decision={record.decision.decision} />
                        <RiskBadge level={record.risk_snapshot.risk_level} />
                        <TierBadge tier={record.meta.actual_tier} />
                        <span className="cmd-snippet">{String(record.event?.tool_name || 'unknown')}</span>
                        <TimelineLatency ms={record.decision.decision_latency_ms} />
                      </div>
                      {input && (
                        <div className="cmd-snippet decision-command">
                          {input.slice(0, 180)}
                        </div>
                      )}
                      {record.decision.reason && (
                        <p className="priority-session-meta">{String(record.decision.reason)}</p>
                      )}
                      {record.l3_trace?.trigger_detail && (
                        <p className="priority-session-meta">
                          Trigger detail: <span className="mono">{record.l3_trace?.trigger_detail}</span>
                        </p>
                      )}
                      {record.meta.l3_requested !== undefined && (
                        <p className="priority-session-meta">
                          L3 requested: <span className="mono">{record.meta.l3_requested ? 'yes' : 'no'}</span>
                        </p>
                      )}
                      {record.meta.l3_available !== undefined && (
                        <p className="priority-session-meta">
                          L3 available: <span className="mono">{record.meta.l3_available ? 'yes' : 'no'}</span>
                        </p>
                      )}
                      {record.meta.l3_reason_code && (
                        <p className="priority-session-meta">
                          L3 reason code: <span className="mono">{appendReadableLabel('l3ReasonCode', record.meta.l3_reason_code, language)}</span>
                        </p>
                      )}
                      {record.meta.l3_state && record.meta.l3_state !== 'completed' && (
                        <p className="priority-session-meta">
                          L3 state: <span className="mono">{appendReadableLabel('l3State', record.meta.l3_state, language)}</span>
                        </p>
                      )}
                      {record.meta.l3_reason && record.meta.l3_state && record.meta.l3_state !== 'completed' && (
                        <p className="priority-session-meta">
                          L3 reason: <span className="mono">{record.meta.l3_reason}</span>
                        </p>
                      )}
                      {evidenceSummary && (
                        <p className="priority-session-meta">
                          Evidence: <span className="mono">{evidenceSummary}</span>
                        </p>
                      )}
                    </div>
                  </div>
                )
              })}
              {trajectory.length === 0 && (
                <div className="empty-inline">No trajectory records yet.</div>
              )}
            </div>
            {replayLoadMoreError && (
              <p
                className="priority-session-meta replay-load-more-error"
                role="alert"
                data-tone="warning"
              >
                {replayLoadMoreError}
              </p>
            )}
            {replayNextCursor !== null && (
              <div className="replay-footer">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={loadMoreReplayRecords}
                  disabled={replayLoadingMore}
                >
                  {replayLoadingMore ? 'Loading more…' : 'Load more'}
                </button>
              </div>
            )}
          </section>

          <section className="card section-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Signals</p>
                <h3>Observed indicators</h3>
              </div>
            </div>
            <div className="detail-pill-row tier-distribution-row">
              {Object.entries(risk?.actual_tier_distribution || {}).map(([tier, count]) => (
                <span key={tier}>
                  <TierBadge tier={tier} /> <span className="mono">{count}</span>
                </span>
              ))}
            </div>
            <div className="detail-list-block">
              <span className="detail-list-label">Tools used</span>
              <div className="detail-pill-row">
                {risk?.tools_used.length
                  ? risk.tools_used.map(tool => <span key={tool} className="cmd-snippet">{tool}</span>)
                  : <span className="empty-inline">No tool usage recorded.</span>}
              </div>
            </div>
            <div className="detail-list-block">
              <span className="detail-list-label">Risk hints</span>
              <div className="detail-pill-row">
                {risk?.risk_hints_seen.length
                  ? risk.risk_hints_seen.map(hint => <HintTag key={hint} hint={hint} />)
                  : <span className="empty-inline">No risk hints recorded.</span>}
              </div>
            </div>
          </section>

          {budget && (
            <section className="card section-card">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Budget</p>
                  <h3>Budget governance</h3>
                </div>
              </div>
              <div className="detail-meta-list">
                <div className="detail-meta-item">
                  <div>
                    <span>Daily budget</span>
                    <strong className="mono">{formatUsd(budget.daily_budget_usd)}</strong>
                  </div>
                </div>
                <div className="detail-meta-item">
                  <div>
                    <span>Current state</span>
                    <strong className="mono">
                      Spend {formatUsd(budget.daily_spend_usd)} · Remaining {budget.remaining_usd === null ? 'Unlimited' : formatUsd(budget.remaining_usd)} · Exhausted {budget.exhausted ? 'Yes' : 'No'}
                    </strong>
                  </div>
                </div>
                {showBudgetWarning && (
                  <div className="mono budget-warning-panel">
                    <strong className="budget-warning-title">Budget exhaustion event</strong>
                    <span> · Operator attention required</span>
                    {budgetExhaustionEvent && (
                      <div className="budget-warning-detail">
                        {budgetExhaustionEvent.provider || 'unknown'} · {budgetExhaustionEvent.tier || 'unknown'} · {formatUsd(budgetExhaustionEvent.cost_usd ?? 0)}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      </section>

      <section className="session-surface session-context-surface" aria-labelledby="session-context-heading">
        <div className="section-card-header session-surface-header">
          <div>
            <p className="section-kicker">{t('session.context')}</p>
            <h2 id="session-context-heading">{t('session.contextTitle')}</h2>
          </div>
          <span className="section-meta">Workspace identity and recording metadata</span>
        </div>
        <div className="session-context-grid">
          <section className="card section-card session-context-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Identity</p>
                <h3>Workspace context</h3>
              </div>
            </div>
            <div className="detail-meta-list">
              <div className="detail-meta-item">
                <FolderTree size={15} />
                <div>
                  <span>Workspace root</span>
                  <strong className="mono">{risk?.workspace_root || 'Unavailable'}</strong>
                </div>
              </div>
              <div className="detail-meta-item">
                <ScrollText size={15} />
                <div>
                  <span>Transcript path</span>
                  <strong className="mono">{risk?.transcript_path || 'Unavailable'}</strong>
                </div>
              </div>
            </div>
          </section>

          <section className="card section-card session-context-card">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Metadata</p>
                <h3>Session provenance</h3>
              </div>
            </div>
            <div className="detail-meta-list">
              <div className="detail-pill-row">
                <span className="framework-chip"><span>Framework</span><strong>{risk?.source_framework || 'unknown'}</strong></span>
                <span className="framework-chip"><span>Adapter</span><strong>{risk?.caller_adapter || 'unknown'}</strong></span>
              </div>
              <div className="detail-meta-item">
                <div>
                  <span>Session ID</span>
                  <strong className="mono">{risk?.session_id || sessionId || 'Unavailable'}</strong>
                </div>
              </div>
              <div className="detail-meta-item">
                <div>
                  <span>Agent ID</span>
                  <strong className="mono">{risk?.agent_id || 'Unavailable'}</strong>
                </div>
              </div>
            </div>
          </section>
        </div>
      </section>
    </div>
  )
}
