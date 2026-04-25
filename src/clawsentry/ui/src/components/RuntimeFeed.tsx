import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Wifi, WifiOff } from 'lucide-react'
import { createManagedSSE, type SSEStatus } from '../api/sse'
import { DecisionBadge, RiskBadge } from './badges'
import EmptyState from './EmptyState'
import type {
  RuntimeEventType,
  SSERuntimeEvent,
} from '../api/types'
import { formatL3EvidenceSummary } from '../lib/l3EvidenceSummary'
import { DEMO_FALLBACK_ENABLED, DEMO_RUNTIME_EVENTS } from '../lib/demoData'
import { usePreferences } from '../lib/preferences'
import {
  appendReadableLabel,
  formatOperatorAction,
  formatOperatorLabel,
  formatRunnerLabel,
  l3AdvisoryJobHint,
  type OperatorLanguage,
} from '../lib/operatorLabels'

const RUNTIME_EVENT_TYPES: RuntimeEventType[] = [
  'decision',
  'alert',
  'trajectory_alert',
  'post_action_finding',
  'pattern_candidate',
  'pattern_evolved',
  'defer_pending',
  'defer_resolved',
  'budget_exhausted',
  'session_enforcement_change',
  'l3_advisory_snapshot',
  'l3_advisory_review',
  'l3_advisory_job',
  'l3_advisory_action',
]

const HIGH_PRIORITY_EVENT_TYPES: RuntimeEventType[] = [
  'alert',
  'trajectory_alert',
  'post_action_finding',
  'defer_pending',
  'defer_resolved',
  'budget_exhausted',
  'session_enforcement_change',
  'l3_advisory_review',
  'l3_advisory_job',
  'l3_advisory_action',
]

const FEED_MAX_EVENTS = 80

const EVENT_LABELS: Record<RuntimeEventType, string> = {
  decision: 'Decision',
  alert: 'Alert',
  trajectory_alert: 'Trajectory',
  post_action_finding: 'Finding',
  pattern_candidate: 'Pattern Candidate',
  pattern_evolved: 'Pattern Evolved',
  defer_pending: 'Defer Pending',
  defer_resolved: 'Defer Resolved',
  budget_exhausted: 'Budget Exhausted',
  session_enforcement_change: 'Enforcement',
  l3_advisory_snapshot: 'L3 Snapshot',
  l3_advisory_review: 'L3 Advisory',
  l3_advisory_job: 'L3 Job',
  l3_advisory_action: 'L3 Action',
}

function prependWithCap<T>(items: T[], nextItem: T) {
  const next = [nextItem, ...items]
  const dropped = Math.max(0, next.length - FEED_MAX_EVENTS)
  return {
    items: next.slice(0, FEED_MAX_EVENTS),
    dropped,
  }
}

function prependManyWithCap<T>(items: T[], pendingItems: T[]) {
  const next = [...pendingItems, ...items]
  const dropped = Math.max(0, next.length - FEED_MAX_EVENTS)
  return {
    items: next.slice(0, FEED_MAX_EVENTS),
    dropped,
  }
}

function matchesRuntimeFilters(
  event: SSERuntimeEvent,
  eventTypeFilter: 'all' | RuntimeEventType,
  highPriorityOnly: boolean,
) {
  const matchesType = eventTypeFilter === 'all' || event.type === eventTypeFilter
  const matchesPriority = !highPriorityOnly || HIGH_PRIORITY_EVENT_TYPES.includes(event.type)
  return matchesType && matchesPriority
}

function isActionEvent(event: SSERuntimeEvent) {
  return HIGH_PRIORITY_EVENT_TYPES.includes(event.type)
}

function TierBadge({ tier }: { tier: string }) {
  const t = tier.toUpperCase()
  const cls = t === 'L3' ? 'badge-tier-l3' : t === 'L2' ? 'badge-tier-l2' : 'badge-tier-l1'
  return <span className={`badge ${cls}`}>{t}</span>
}

function EventBadge({ type }: { type: RuntimeEventType }) {
  return (
    <span className={`badge runtime-event-badge runtime-event-badge-${type.replace(/_/g, '-')}`}>
      {EVENT_LABELS[type]}
    </span>
  )
}

function formatCountMap(map?: Record<string, number>) {
  if (!map || Object.keys(map).length === 0) return null
  return Object.entries(map)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}:${value}`)
    .join(', ')
}

function EnterpriseRuntimeLine({ event }: { event: SSERuntimeEvent }) {
  const overview = event.live_risk_overview
  if (!overview) return null
  const tierSummary = formatCountMap(overview.by_trinityguard_tier)
  return (
    <>
      <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
        Enterprise posture:{' '}
        <span className="mono">
          {overview.active_sessions} active · {overview.high_risk_sessions} high-risk · {overview.mapped_active_sessions} mapped
        </span>
      </div>
      {tierSummary && (
        <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
          TrinityGuard tiers: <span className="mono">{tierSummary}</span>
        </div>
      )}
    </>
  )
}

function ConnectionStatus({ status, detail }: { status: SSEStatus; detail?: string }) {
  if (status === 'connected') return null
  const icon = status === 'error' ? <WifiOff size={10} /> : <Wifi size={10} />
  const label = status === 'connecting' ? 'Connecting...'
    : status === 'disconnected' ? (detail || 'Reconnecting...')
      : (detail || 'Connection failed')
  return (
    <div className={`operations-stream-connection operations-stream-connection-${status}`}>
      {icon}
      <span className="mono">{label}</span>
    </div>
  )
}

function SessionLink({ sessionId }: { sessionId?: string }) {
  if (!sessionId) return null
  return (
    <Link
      to={`/sessions/${sessionId}`}
      className="mono runtime-session-link"
    >
      {sessionId.length > 12 ? `${sessionId.slice(0, 12)}...` : sessionId}
    </Link>
  )
}

function PatternBadge({ patternId }: { patternId: string }) {
  return (
    <span className="mono runtime-pattern-id">
      {patternId}
    </span>
  )
}

function RuntimeSummary({ event, language }: { event: SSERuntimeEvent; language: OperatorLanguage }) {
  switch (event.type) {
    case 'decision': {
      const evidenceSummary = formatL3EvidenceSummary(event.evidence_summary)
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="mono runtime-tool-name">
              {event.tool_name}
            </span>
            <DecisionBadge decision={event.decision} />
            <RiskBadge level={event.risk_level} />
            <TierBadge tier={event.actual_tier} />
            <SessionLink sessionId={event.session_id} />
          </div>
          {event.command && (
            <div className="cmd-snippet runtime-command">
              {event.command}
            </div>
          )}
          {event.reason && (
            <div className="text-secondary runtime-event-detail">
              {event.reason}
            </div>
          )}
          {event.trigger_detail && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              Trigger pattern: <span className="mono">{event.trigger_detail}</span>
            </div>
          )}
          {event.l3_requested !== undefined && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              L3 requested: <span className="mono">{event.l3_requested ? 'yes' : 'no'}</span>
            </div>
          )}
          {event.l3_available !== undefined && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              L3 available: <span className="mono">{event.l3_available ? 'yes' : 'no'}</span>
            </div>
          )}
          {event.l3_reason_code && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              L3 reason code: <span className="mono">{appendReadableLabel('l3ReasonCode', event.l3_reason_code, language)}</span>
            </div>
          )}
          {event.l3_state && event.l3_state !== 'completed' && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              L3 state: <span className="mono">{appendReadableLabel('l3State', event.l3_state, language)}</span>
            </div>
          )}
          {event.l3_reason && event.l3_state && event.l3_state !== 'completed' && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              L3 reason: <span className="mono">{event.l3_reason}</span>
            </div>
          )}
          {evidenceSummary && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              Evidence: <span className="mono">{evidenceSummary}</span>
            </div>
          )}
        </>
      )
    }
    case 'alert':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="mono runtime-tool-name">
              {event.metric}
            </span>
            <span className="badge badge-block">{event.severity}</span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            {event.message}
          </div>
        </>
      )
    case 'trajectory_alert':
      return (
        <>
          <div className="runtime-event-meta-row">
            <PatternBadge patternId={event.sequence_id} />
            <RiskBadge level={event.risk_level} />
            <span className="badge badge-defer">{event.handling}</span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            {event.reason}
          </div>
        </>
      )
    case 'post_action_finding':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="badge badge-defer">{event.tier}</span>
            <span className="badge badge-modify">{event.handling}</span>
            <span className="mono runtime-mono-small">
              score {event.score.toFixed(2)}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            {event.patterns_matched.length > 0
              ? `Matched: ${event.patterns_matched.join(', ')}`
              : `Framework: ${event.source_framework}`}
          </div>
        </>
      )
    case 'pattern_candidate':
      return (
        <div className="runtime-event-meta-row">
          <PatternBadge patternId={event.pattern_id} />
          <span className="badge badge-modify">{event.status}</span>
          <span className="mono text-muted runtime-mono-xsmall">
            {event.source_framework}
          </span>
          <SessionLink sessionId={event.session_id} />
        </div>
      )
    case 'pattern_evolved':
      return (
        <div className="runtime-event-meta-row">
          <PatternBadge patternId={event.pattern_id} />
          <span className="badge badge-allow">{event.result}</span>
        </div>
      )
    case 'defer_pending':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="mono runtime-tool-name">
              {event.tool_name}
            </span>
            <span className="badge badge-defer">pending</span>
            <span className="mono text-muted runtime-mono-xsmall">
              {event.timeout_s}s
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          {event.command && (
            <div className="cmd-snippet runtime-command">
              {event.command}
            </div>
          )}
          {event.reason && (
            <div className="text-secondary runtime-event-detail">
              {event.reason}
            </div>
          )}
        </>
      )
    case 'defer_resolved':
      return (
        <div className="runtime-event-meta-row">
          <span className={`badge ${event.resolved_decision === 'allow' ? 'badge-allow' : 'badge-block'}`}>
            {event.resolved_decision}
          </span>
          <span className="mono text-muted runtime-mono-xsmall">
            {event.approval_id}
          </span>
          <SessionLink sessionId={event.session_id} />
          {event.resolved_reason && (
            <span className="text-secondary runtime-event-inline-detail">
              {event.resolved_reason}
            </span>
          )}
        </div>
      )
    case 'l3_advisory_snapshot':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="badge badge-modify">snapshot</span>
            <span className="mono runtime-mono-small">
              {event.snapshot_id}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            Trigger: <span className="mono">{event.trigger_reason}</span>
            {' '}range: <span className="mono">{event.event_range.from_record_id}→{event.event_range.to_record_id}</span>
          </div>
        </>
      )
    case 'l3_advisory_review':
      return (
        <>
          <div className="runtime-event-meta-row">
            <RiskBadge level={event.risk_level} />
            <span className="badge badge-defer">{formatOperatorAction(event.recommended_operator_action, language)}</span>
            <span className="badge badge-modify">{formatOperatorLabel('l3State', event.l3_state, language)}</span>
            <span className="mono runtime-mono-small">
              {event.review_id}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            Advisory only from snapshot <span className="mono">{event.snapshot_id}</span>
          </div>
        </>
      )
    case 'l3_advisory_job': {
      const transitionHint = l3AdvisoryJobHint(event.job_state, language)
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="badge badge-modify">{formatOperatorLabel('jobState', event.job_state, language)}</span>
            <span className="mono runtime-mono-small">
              {event.job_id}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            Runner <span className="mono">{formatRunnerLabel(event.runner, language)}</span> for snapshot <span className="mono">{event.snapshot_id}</span>
          </div>
          {transitionHint && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              Next: <span className="mono">{transitionHint}</span>
            </div>
          )}
          <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
            Frozen snapshot <span className="mono">{event.snapshot_id}</span> · frozen snapshot; explicit run only
          </div>
        </>
      )
    }
    case 'l3_advisory_action':
      return (
        <>
          <div className="runtime-event-meta-row">
            <RiskBadge level={event.risk_level} />
            <span className="badge badge-defer">{formatOperatorAction(event.recommended_operator_action, language)}</span>
            <span className="mono runtime-mono-small">
              {event.review_id}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary runtime-event-detail">
            Advisory only / canonical unchanged · snapshot <span className="mono">{event.snapshot_id}</span>
            {event.job_id ? <> · job <span className="mono">{event.job_id}</span></> : null}
          </div>
          {event.source_record_range && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              Frozen range <span className="mono">{event.source_record_range.from_record_id}→{event.source_record_range.to_record_id}</span>
            </div>
          )}
          {event.summary && (
            <div className="text-secondary runtime-event-detail runtime-event-detail-compact">
              {event.summary}
            </div>
          )}
        </>
      )
    case 'budget_exhausted':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className="badge badge-block">Budget exhausted</span>
            <span className="mono runtime-tool-name">
              Provider
            </span>
            <span className="mono text-muted runtime-mono-small">
              {event.provider}
            </span>
            <span className="mono runtime-tool-name">
              Tier
            </span>
            <span className="badge badge-defer">{event.tier}</span>
            <span className="mono runtime-tool-name">
              Cost
            </span>
            <span className="mono text-muted runtime-mono-small">
              ${event.cost_usd.toFixed(2)}
            </span>
          </div>
          <div className="text-secondary runtime-event-detail">
            Budget exhausted: <span className="mono">{event.budget.exhausted ? 'yes' : 'no'}</span>
            {' · '}
            Daily spend <span className="mono">${event.budget.daily_spend_usd.toFixed(2)}</span>
            {' / '}
            <span className="mono">${event.budget.daily_budget_usd.toFixed(2)}</span>
            {event.budget.remaining_usd !== null && (
              <>
                {' · '}
                Remaining <span className="mono">${event.budget.remaining_usd.toFixed(2)}</span>
              </>
            )}
          </div>
        </>
      )
    case 'session_enforcement_change':
      return (
        <>
          <div className="runtime-event-meta-row">
            <span className={`badge ${event.state === 'released' ? 'badge-allow' : 'badge-block'}`}>
              {event.state}
            </span>
            {event.action && (
              <span className="badge badge-defer">{event.action}</span>
            )}
            <SessionLink sessionId={event.session_id} />
          </div>
          {(event.reason || event.high_risk_count !== undefined) && (
            <div className="text-secondary runtime-event-detail">
              {event.reason || `${event.high_risk_count} high-risk event(s)`}
            </div>
          )}
        </>
      )
  }
}

export default function RuntimeFeed() {
  const { t, language } = usePreferences()
  const [events, setEvents] = useState<SSERuntimeEvent[]>([])
  const [demoMode, setDemoMode] = useState(false)
  const [bufferedEvents, setBufferedEvents] = useState<SSERuntimeEvent[]>([])
  const [bufferedCount, setBufferedCount] = useState(0)
  const [droppedCount, setDroppedCount] = useState(0)
  const [paused, setPaused] = useState(false)
  const [eventTypeFilter, setEventTypeFilter] = useState<'all' | RuntimeEventType>('all')
  const [highPriorityOnly, setHighPriorityOnly] = useState(false)
  const [sseStatus, setSSEStatus] = useState<SSEStatus>('connecting')
  const [statusDetail, setStatusDetail] = useState<string>()
  const pausedRef = useRef(false)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    const cleanup = createManagedSSE(
      RUNTIME_EVENT_TYPES,
      {
        onEvent: (type, data) => {
          const nextEvent = { ...(data as Record<string, unknown>), type } as SSERuntimeEvent

          if (pausedRef.current) {
            setBufferedCount(prev => prev + 1)
            setBufferedEvents(prev => {
              const next = prependWithCap(prev, nextEvent)
              if (next.dropped > 0) {
                setDroppedCount(count => count + next.dropped)
              }
              return next.items
            })
            return
          }

          setEvents(prev => {
            const next = prependWithCap(prev, nextEvent)
            if (next.dropped > 0) {
              setDroppedCount(count => count + next.dropped)
            }
            return next.items
          })
        },
        onStatusChange: (status, detail) => {
          setSSEStatus(status)
          setStatusDetail(detail)
        },
      },
    )
    return cleanup
  }, [])

  useEffect(() => {
    if (!DEMO_FALLBACK_ENABLED) return undefined
    if (events.length > 0) return
    const timer = setTimeout(() => {
      setEvents(DEMO_RUNTIME_EVENTS)
      setDemoMode(true)
      setSSEStatus(status => status === 'connected' ? status : 'disconnected')
      setStatusDetail(detail => detail || 'Showing demo telemetry while the gateway stream is unavailable')
    }, 800)
    return () => clearTimeout(timer)
  }, [events.length])

  function togglePause() {
    if (!paused) {
      setPaused(true)
      return
    }

    if (bufferedEvents.length > 0) {
      setEvents(prev => {
        const next = prependManyWithCap(prev, bufferedEvents)
        if (next.dropped > 0) {
          setDroppedCount(count => count + next.dropped)
        }
        return next.items
      })
    }

    setBufferedEvents([])
    setBufferedCount(0)
    setPaused(false)
  }

  const filteredEvents = events.filter(event => matchesRuntimeFilters(event, eventTypeFilter, highPriorityOnly))
  const actionEventCount = events.filter(isActionEvent).length

  return (
    <section
      className="card runtime-feed operations-stream"
      aria-label={t('runtime.title')}
    >
      <div className="card-header operations-stream-header">
        <div className="operations-stream-title">
          <Activity size={12} />
          <div>
            <span>{t('runtime.title')}</span>
            <p>{demoMode ? t('runtime.demo') : t('runtime.normal')}</p>
          </div>
        </div>
        <div className="operations-stream-status">
          {sseStatus === 'connected' && <span className="stream-live-dot" aria-label="SSE connected" />}
          {events.length > 0 && (
            <span className="mono">
              {filteredEvents.length}/{events.length} events
            </span>
          )}
        </div>
      </div>
      <ConnectionStatus status={sseStatus} detail={statusDetail} />
      <div className="operations-stream-brief" aria-label="Runtime stream brief">
        <span><strong>{actionEventCount}</strong> {t('runtime.actionNeeded')}</span>
        <span><strong>{bufferedCount}</strong> {t('runtime.buffered')}</span>
        <span><strong>{droppedCount}</strong> {t('runtime.hiddenByCap')}</span>
      </div>
      <div className="operations-stream-controls">
        <label className="stream-filter-control">
          <span className="mono text-muted">{t('runtime.type')}</span>
          <select
            value={eventTypeFilter}
            onChange={(event) => setEventTypeFilter(event.target.value as 'all' | RuntimeEventType)}
            className="input"
          >
            <option value="all">{t('runtime.allEvents')}</option>
            {RUNTIME_EVENT_TYPES.map(type => (
              <option key={type} value={type}>{EVENT_LABELS[type]}</option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className={`badge ${highPriorityOnly ? 'badge-block' : ''}`}
          onClick={() => setHighPriorityOnly(prev => !prev)}
        >
          {t('runtime.highPriorityOnly')}
        </button>
        <button
          type="button"
          className={`badge ${paused ? 'badge-defer' : ''}`}
          onClick={togglePause}
        >
          {paused ? t('runtime.resume') : t('runtime.pause')}
        </button>
      </div>
      {(bufferedCount > 0 || droppedCount > 0) && (
        <div className="operations-stream-buffer">
          {bufferedCount > 0 && (
            <span className="mono">Feed paused · {bufferedCount} buffered while paused</span>
          )}
          {droppedCount > 0 && (
            <span className="mono">{droppedCount} older events hidden by feed cap</span>
          )}
        </div>
      )}
      <div className="operations-stream-list">
        {events.length === 0 ? (
          <EmptyState
            icon={<Activity size={20} />}
            title={t('runtime.waitingTitle')}
            subtitle={sseStatus === 'connected'
              ? t('runtime.waitingConnected')
              : t('runtime.waitingConnecting')}
          />
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            icon={<Activity size={20} />}
            title={t('runtime.noMatchTitle')}
            subtitle={t('runtime.noMatchSubtitle')}
          />
        ) : (
          filteredEvents.map((event, index) => (
            <div
              key={`${event.type}-${event.timestamp}-${index}`}
              className={`slide-in operations-stream-row${isActionEvent(event) ? ' operations-stream-row-priority' : ''}`}
            >
              <div className="operations-stream-row-top">
                <span className="mono text-muted operations-stream-time">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
                <EventBadge type={event.type} />
              </div>
              <RuntimeSummary event={event} language={language} />
              <EnterpriseRuntimeLine event={event} />
            </div>
          ))
        )}
      </div>
    </section>
  )
}
