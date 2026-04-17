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
]

const HIGH_PRIORITY_EVENT_TYPES: RuntimeEventType[] = [
  'alert',
  'trajectory_alert',
  'post_action_finding',
  'defer_pending',
  'defer_resolved',
  'budget_exhausted',
  'session_enforcement_change',
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
}

const EVENT_TONES: Record<RuntimeEventType, { color: string; bg: string; border: string }> = {
  decision: {
    color: 'var(--color-accent-secondary)',
    bg: 'rgba(96,165,250,0.12)',
    border: 'rgba(96,165,250,0.2)',
  },
  alert: {
    color: 'var(--color-block)',
    bg: 'rgba(239,68,68,0.12)',
    border: 'rgba(239,68,68,0.2)',
  },
  trajectory_alert: {
    color: 'var(--color-risk-high)',
    bg: 'rgba(249,115,22,0.12)',
    border: 'rgba(249,115,22,0.2)',
  },
  post_action_finding: {
    color: 'var(--color-defer)',
    bg: 'rgba(245,158,11,0.12)',
    border: 'rgba(245,158,11,0.2)',
  },
  pattern_candidate: {
    color: 'var(--color-accent)',
    bg: 'rgba(167,139,250,0.12)',
    border: 'rgba(167,139,250,0.2)',
  },
  pattern_evolved: {
    color: '#34d399',
    bg: 'rgba(52,211,153,0.12)',
    border: 'rgba(52,211,153,0.2)',
  },
  defer_pending: {
    color: 'var(--color-defer)',
    bg: 'rgba(245,158,11,0.12)',
    border: 'rgba(245,158,11,0.2)',
  },
  defer_resolved: {
    color: '#34d399',
    bg: 'rgba(52,211,153,0.12)',
    border: 'rgba(52,211,153,0.2)',
  },
  budget_exhausted: {
    color: 'var(--color-block)',
    bg: 'rgba(239,68,68,0.12)',
    border: 'rgba(239,68,68,0.2)',
  },
  session_enforcement_change: {
    color: 'var(--color-block)',
    bg: 'rgba(239,68,68,0.12)',
    border: 'rgba(239,68,68,0.2)',
  },
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

function TierBadge({ tier }: { tier: string }) {
  const t = tier.toUpperCase()
  const cls = t === 'L3' ? 'badge-tier-l3' : t === 'L2' ? 'badge-tier-l2' : 'badge-tier-l1'
  return <span className={`badge ${cls}`}>{t}</span>
}

function EventBadge({ type }: { type: RuntimeEventType }) {
  const tone = EVENT_TONES[type]
  return (
    <span
      className="badge"
      style={{
        color: tone.color,
        background: tone.bg,
        borderColor: tone.border,
      }}
    >
      {EVENT_LABELS[type]}
    </span>
  )
}

function ConnectionStatus({ status, detail }: { status: SSEStatus; detail?: string }) {
  if (status === 'connected') return null
  const color = status === 'connecting' ? 'var(--color-defer)'
    : status === 'disconnected' ? 'var(--color-defer)' : 'var(--color-block)'
  const icon = status === 'error' ? <WifiOff size={10} /> : <Wifi size={10} />
  const label = status === 'connecting' ? 'Connecting...'
    : status === 'disconnected' ? (detail || 'Reconnecting...')
      : (detail || 'Connection failed')
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 5,
      padding: '4px 10px',
      fontSize: '0.65rem',
      color,
      borderBottom: '1px solid var(--color-border)',
    }}>
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
      className="mono"
      style={{
        color: 'var(--color-accent)',
        textDecoration: 'none',
        fontSize: '0.68rem',
      }}
    >
      {sessionId.length > 12 ? `${sessionId.slice(0, 12)}...` : sessionId}
    </Link>
  )
}

function PatternBadge({ patternId }: { patternId: string }) {
  return (
    <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-secondary)' }}>
      {patternId}
    </span>
  )
}

function RuntimeSummary({ event }: { event: SSERuntimeEvent }) {
  switch (event.type) {
    case 'decision': {
      const evidenceSummary = formatL3EvidenceSummary(event.evidence_summary)
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: '0.8rem', fontWeight: 500 }}>
              {event.tool_name}
            </span>
            <DecisionBadge decision={event.decision} />
            <RiskBadge level={event.risk_level} />
            <TierBadge tier={event.actual_tier} />
            <SessionLink sessionId={event.session_id} />
          </div>
          {event.command && (
            <div className="cmd-snippet" style={{ marginTop: 6 }}>
              {event.command}
            </div>
          )}
          {event.reason && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
              {event.reason}
            </div>
          )}
          {event.trigger_detail && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              Trigger pattern: <span className="mono">{event.trigger_detail}</span>
            </div>
          )}
          {event.l3_requested !== undefined && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              L3 requested: <span className="mono">{event.l3_requested ? 'yes' : 'no'}</span>
            </div>
          )}
          {event.l3_available !== undefined && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              L3 available: <span className="mono">{event.l3_available ? 'yes' : 'no'}</span>
            </div>
          )}
          {event.l3_reason_code && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              L3 reason code: <span className="mono">{event.l3_reason_code}</span>
            </div>
          )}
          {event.l3_state && event.l3_state !== 'completed' && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              L3 state: <span className="mono">{event.l3_state}</span>
            </div>
          )}
          {event.l3_reason && event.l3_state && event.l3_state !== 'completed' && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              L3 reason: <span className="mono">{event.l3_reason}</span>
            </div>
          )}
          {evidenceSummary && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 4 }}>
              Evidence: <span className="mono">{evidenceSummary}</span>
            </div>
          )}
        </>
      )
    }
    case 'alert':
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 600 }}>
              {event.metric}
            </span>
            <span className="badge badge-block">{event.severity}</span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
            {event.message}
          </div>
        </>
      )
    case 'trajectory_alert':
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <PatternBadge patternId={event.sequence_id} />
            <RiskBadge level={event.risk_level} />
            <span className="badge badge-defer">{event.handling}</span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
            {event.reason}
          </div>
        </>
      )
    case 'post_action_finding':
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className="badge badge-defer">{event.tier}</span>
            <span className="badge badge-modify">{event.handling}</span>
            <span className="mono" style={{ fontSize: '0.72rem' }}>
              score {event.score.toFixed(2)}
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
            {event.patterns_matched.length > 0
              ? `Matched: ${event.patterns_matched.join(', ')}`
              : `Framework: ${event.source_framework}`}
          </div>
        </>
      )
    case 'pattern_candidate':
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
          <PatternBadge patternId={event.pattern_id} />
          <span className="badge badge-modify">{event.status}</span>
          <span className="mono text-muted" style={{ fontSize: '0.68rem' }}>
            {event.source_framework}
          </span>
          <SessionLink sessionId={event.session_id} />
        </div>
      )
    case 'pattern_evolved':
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
          <PatternBadge patternId={event.pattern_id} />
          <span className="badge badge-allow">{event.result}</span>
        </div>
      )
    case 'defer_pending':
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 500 }}>
              {event.tool_name}
            </span>
            <span className="badge badge-defer">pending</span>
            <span className="mono text-muted" style={{ fontSize: '0.68rem' }}>
              {event.timeout_s}s
            </span>
            <SessionLink sessionId={event.session_id} />
          </div>
          {event.command && (
            <div className="cmd-snippet" style={{ marginTop: 6 }}>
              {event.command}
            </div>
          )}
          {event.reason && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
              {event.reason}
            </div>
          )}
        </>
      )
    case 'defer_resolved':
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
          <span className={`badge ${event.resolved_decision === 'allow' ? 'badge-allow' : 'badge-block'}`}>
            {event.resolved_decision}
          </span>
          <span className="mono text-muted" style={{ fontSize: '0.68rem' }}>
            {event.approval_id}
          </span>
          <SessionLink sessionId={event.session_id} />
          {event.resolved_reason && (
            <span className="text-secondary" style={{ fontSize: '0.73rem' }}>
              {event.resolved_reason}
            </span>
          )}
        </div>
      )
    case 'budget_exhausted':
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className="badge badge-block">Budget exhausted</span>
            <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 500 }}>
              Provider
            </span>
            <span className="mono text-muted" style={{ fontSize: '0.72rem' }}>
              {event.provider}
            </span>
            <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 500 }}>
              Tier
            </span>
            <span className="badge badge-defer">{event.tier}</span>
            <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 500 }}>
              Cost
            </span>
            <span className="mono text-muted" style={{ fontSize: '0.72rem' }}>
              ${event.cost_usd.toFixed(2)}
            </span>
          </div>
          <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <span className={`badge ${event.state === 'released' ? 'badge-allow' : 'badge-block'}`}>
              {event.state}
            </span>
            {event.action && (
              <span className="badge badge-defer">{event.action}</span>
            )}
            <SessionLink sessionId={event.session_id} />
          </div>
          {(event.reason || event.high_risk_count !== undefined) && (
            <div className="text-secondary" style={{ fontSize: '0.73rem', marginTop: 6 }}>
              {event.reason || `${event.high_risk_count} high-risk event(s)`}
            </div>
          )}
        </>
      )
  }
}

export default function RuntimeFeed() {
  const [events, setEvents] = useState<SSERuntimeEvent[]>([])
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

  return (
    <section
      className="card runtime-feed"
      aria-label="Live activity feed"
      style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
    >
      <div className="card-header">
        <Activity size={12} />
        Live Activity Feed
        {sseStatus === 'connected' && (
          <span style={{ marginLeft: 4, color: '#22c55e', fontSize: '0.5rem' }}>●</span>
        )}
        {events.length > 0 && (
          <span className="mono" style={{ marginLeft: 'auto', color: 'var(--color-text-muted)', fontSize: '0.65rem' }}>
            {filteredEvents.length}/{events.length} events
          </span>
        )}
      </div>
      <ConnectionStatus status={sseStatus} detail={statusDetail} />
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 8,
        padding: '10px 14px',
        borderBottom: '1px solid var(--color-border)',
        alignItems: 'center',
      }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="mono text-muted" style={{ fontSize: '0.68rem' }}>Type</span>
          <select
            value={eventTypeFilter}
            onChange={(event) => setEventTypeFilter(event.target.value as 'all' | RuntimeEventType)}
            className="input"
            style={{ width: 'auto', minWidth: 140, padding: '6px 10px', fontSize: '0.72rem' }}
          >
            <option value="all">All events</option>
            {RUNTIME_EVENT_TYPES.map(type => (
              <option key={type} value={type}>{EVENT_LABELS[type]}</option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className={`badge ${highPriorityOnly ? 'badge-block' : ''}`}
          style={{ cursor: 'pointer', background: highPriorityOnly ? 'rgba(239,68,68,0.12)' : 'transparent' }}
          onClick={() => setHighPriorityOnly(prev => !prev)}
        >
          High priority only
        </button>
        <button
          type="button"
          className={`badge ${paused ? 'badge-defer' : ''}`}
          style={{ cursor: 'pointer', background: paused ? 'rgba(245,158,11,0.12)' : 'transparent' }}
          onClick={togglePause}
        >
          {paused ? 'Resume feed' : 'Pause feed'}
        </button>
      </div>
      {(bufferedCount > 0 || droppedCount > 0) && (
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 10,
          padding: '8px 14px',
          borderBottom: '1px solid var(--color-border)',
          fontSize: '0.7rem',
          color: 'var(--color-text-secondary)',
        }}>
          {bufferedCount > 0 && (
            <span className="mono">Feed paused · {bufferedCount} buffered while paused</span>
          )}
          {droppedCount > 0 && (
            <span className="mono">{droppedCount} older events hidden by feed cap</span>
          )}
        </div>
      )}
      <div style={{ flex: 1, overflowY: 'auto', maxHeight: 420 }}>
        {events.length === 0 ? (
          <EmptyState
            icon={<Activity size={20} />}
            title="Waiting for activity"
            subtitle={sseStatus === 'connected'
              ? 'Decisions, alerts, enforcement, defer actions, and pattern evolution events will appear here'
              : 'Establishing connection to gateway...'}
          />
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            icon={<Activity size={20} />}
            title="No events match current filters"
            subtitle="Adjust the event type filter or disable high priority only to widen the feed."
          />
        ) : (
          filteredEvents.map((event, index) => (
            <div key={`${event.type}-${event.timestamp}-${index}`} className="slide-in" style={{
              padding: '10px 14px',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              flexDirection: 'column',
              gap: 6,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                <span className="mono text-muted" style={{ fontSize: '0.65rem', minWidth: 60 }}>
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
                <EventBadge type={event.type} />
              </div>
              <RuntimeSummary event={event} />
            </div>
          ))
        )}
      </div>
    </section>
  )
}
