import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, ShieldCheck, Clock } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { connectSSE } from '../api/sse'
import CountdownTimer from '../components/CountdownTimer'
import EmptyState from '../components/EmptyState'
import type { SSEDeferPendingEvent, SSEDeferResolvedEvent } from '../api/types'

type DeferStatus = 'pending' | 'allowed' | 'denied' | 'expired'

interface DeferItem {
  approval_id: string
  session_id: string
  tool_name: string
  command: string
  reason: string
  timestamp: string
  expires_at?: number
  status: DeferStatus
}

function formatResolveActionLabel(
  action: 'Allow' | 'Deny',
  item: Pick<DeferItem, 'approval_id' | 'tool_name' | 'session_id' | 'command'>,
) {
  const command = item.command.trim()
  const commandLabel = command.length > 48 ? `${command.slice(0, 45)}...` : command
  const detail = commandLabel ? ` for command ${commandLabel}` : ''
  return `${action} approval ${item.tool_name} for session ${item.session_id}${detail} (${item.approval_id})`
}

export default function DeferPanel() {
  const [items, setItems] = useState<DeferItem[]>([])
  const [resolveAvailable, setResolveAvailable] = useState(true)

  useEffect(() => {
    const es = connectSSE(['defer_pending', 'defer_resolved'])
    es.addEventListener('defer_pending', (e: MessageEvent) => {
      try {
        const data: SSEDeferPendingEvent = JSON.parse(e.data)
        setItems(prev => {
          if (prev.some(item => item.approval_id === data.approval_id)) return prev
          const expiresAt = data.timeout_s > 0
            ? (Date.parse(data.timestamp) / 1000) + data.timeout_s
            : undefined
          return [{
            approval_id: data.approval_id,
            session_id: data.session_id,
            tool_name: data.tool_name,
            command: data.command,
            reason: data.reason,
            timestamp: data.timestamp,
            expires_at: expiresAt,
            status: 'pending',
          }, ...prev]
        })
      } catch { /* ignore */ }
    })
    es.addEventListener('defer_resolved', (e: MessageEvent) => {
      try {
        const data: SSEDeferResolvedEvent = JSON.parse(e.data)
        setItems(prev => prev.map(item =>
          item.approval_id === data.approval_id
            ? {
                ...item,
                status: data.resolved_decision === 'block' ? 'denied' : 'allowed',
                reason: data.resolved_reason || item.reason,
                timestamp: data.timestamp,
              }
            : item
        ))
      } catch { /* ignore */ }
    })
    return () => es.close()
  }, [])

  const handleResolve = useCallback(async (approvalId: string, decision: 'allow-once' | 'deny') => {
    try {
      await api.resolve(approvalId, decision, decision === 'deny' ? 'operator denied via dashboard' : '')
      setItems(prev => prev.map(item =>
        item.approval_id === approvalId
          ? { ...item, status: decision === 'allow-once' ? 'allowed' : 'denied' }
          : item
      ))
    } catch (e) {
      if (e instanceof ApiError && e.status === 503) setResolveAvailable(false)
    }
  }, [])

  const handleExpired = useCallback((approvalId: string) => {
    setItems(prev => prev.map(item => {
      if (item.approval_id !== approvalId || item.status !== 'pending') return item

      const expiredAt = item.expires_at
        ? new Date(item.expires_at * 1000).toISOString()
        : new Date().toISOString()

      return { ...item, status: 'expired', timestamp: expiredAt }
    }))
  }, [])

  const pendingItems = items.filter(i => i.status === 'pending')
  const decisionItems = items.filter(i => i.status === 'allowed' || i.status === 'denied')
  const outcomeItems = items.filter(i => i.status !== 'pending')
  const expiredItems = items.filter(i => i.status === 'expired')

  return (
    <div className="workbench-shell">
      <section className="workbench-hero defer-hero" aria-labelledby="defer-approvals-title">
        <div className="workbench-hero-copy">
          <div className="eyebrow">Operator Approval Queue</div>
          <h1 id="defer-approvals-title">
            <ShieldCheck size={20} style={{ color: 'var(--color-accent)' }} />
            Defer Approvals
          </h1>
          <p className="workbench-hero-text">
            Review pending approvals with due-time pressure, operator actions, and approval outcomes in one queue surface.
          </p>
        </div>
        <div className="workbench-hero-side">
          <span className={`badge ${pendingItems.length > 0 ? 'badge-defer' : 'badge-allow'}`}>
            {pendingItems.length} pending
          </span>
          <span className="workbench-hero-note">
            {resolveAvailable ? 'Resolve endpoint connected' : 'Resolve endpoint unavailable'}
          </span>
        </div>
      </section>

      <section className="workbench-section" aria-label="Defer approvals overview">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">Overview</div>
            <h2>Queue posture</h2>
          </div>
          <div className="section-meta">Pending decisions stream in over SSE and stay local to the operator view.</div>
        </div>
        <div className="workbench-summary-grid">
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Pending</span>
            <strong>{pendingItems.length} approvals waiting</strong>
            <p>Requests that still need an allow or deny decision.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Operator decisions</span>
            <strong>{decisionItems.length} operator decisions</strong>
            <p>Approvals explicitly allowed or denied by an operator.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Expired</span>
            <strong>{expiredItems.length} timed out</strong>
            <p>Pending requests that aged out before an operator decision.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Operator channel</span>
            <strong>{resolveAvailable ? 'Interactive' : 'Read only'}</strong>
            <p>{resolveAvailable ? 'Actions are available for incoming approvals.' : 'Actions are disabled until enforcement reconnects.'}</p>
          </div>
        </div>
      </section>

      {!resolveAvailable && (
        <div className="card workbench-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--color-defer)', fontSize: '0.83rem' }}>
            <ShieldAlert size={15} />
            Resolve not available — OpenClaw enforcement is not connected
          </div>
        </div>
      )}

      <section className="workbench-section" aria-label="Pending approvals queue">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">Pending queue</div>
            <h2>Pending approvals queue</h2>
          </div>
          <div className="section-meta">Due time, command scope, and operator actions are grouped per approval.</div>
        </div>
        {pendingItems.length === 0 ? (
          <div className="card workbench-empty-card">
            <EmptyState
              icon={<ShieldCheck size={20} />}
              title="No pending DEFER decisions"
              subtitle="DEFER decisions will appear here in real-time when agents require approval"
            />
          </div>
        ) : (
          <div className="operator-list">
            {pendingItems.map(item => {
              const remaining = item.expires_at ? item.expires_at - Date.now() / 1000 : 999
              const isUrgent = remaining < 10
              return (
                <article
                  key={item.approval_id}
                  className={`operator-card defer-card ${isUrgent ? 'defer-card-critical' : 'defer-card-pending'}`}
                >
                  <div className="operator-card-main">
                    <div className="operator-card-topline">
                      <div className="operator-card-tags">
                        <span className="badge badge-defer">pending</span>
                        <span className="badge badge-neutral">{item.tool_name}</span>
                        {isUrgent && <span className="badge badge-block">due soon</span>}
                      </div>
                      <div className="operator-time">{new Date(item.timestamp).toLocaleTimeString()}</div>
                    </div>

                    <h3 className="operator-card-title">{item.tool_name}</h3>
                    <div className="cmd-snippet operator-command">{item.command || '—'}</div>
                    {item.reason && (
                      <p className="operator-card-description">{item.reason}</p>
                    )}

                    <div className="operator-card-meta">
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Session</span>
                        <strong className="mono">{item.session_id}</strong>
                      </div>
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Pending state</span>
                        <strong>{resolveAvailable ? 'Operator decision required' : 'Awaiting reconnection'}</strong>
                      </div>
                      <div className="operator-meta-block">
                        <span className="operator-meta-label">Command</span>
                        <strong className="mono">{item.command || '—'}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="operator-card-side">
                    <div className="operator-side-panel">
                      <span className="operator-meta-label">Due time</span>
                      {item.expires_at ? (
                        <CountdownTimer
                          expiresAt={item.expires_at}
                          onExpired={() => handleExpired(item.approval_id)}
                        />
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Clock size={13} className="text-muted" />
                          <span className="mono text-muted" style={{ fontSize: '0.72rem' }}>No timeout</span>
                        </div>
                      )}
                    </div>

                    <div className="operator-action-group">
                      <button
                        className="btn btn-allow"
                        onClick={() => handleResolve(item.approval_id, 'allow-once')}
                        disabled={!resolveAvailable}
                        aria-label={formatResolveActionLabel('Allow', item)}
                      >
                        Allow
                      </button>
                      <button
                        className="btn btn-deny"
                        onClick={() => handleResolve(item.approval_id, 'deny')}
                        disabled={!resolveAvailable}
                        aria-label={formatResolveActionLabel('Deny', item)}
                      >
                        Deny
                      </button>
                    </div>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <section className="workbench-section" aria-label="Approval outcomes history">
          <div className="section-card-header workbench-section-header">
            <div>
              <div className="section-kicker">History</div>
              <h2>Approval outcomes history</h2>
            </div>
            <div className="section-meta">Operator decisions and timed-out requests stay visible for quick operator audit.</div>
          </div>
          {outcomeItems.length === 0 ? (
            <div className="card workbench-empty-card">
              <EmptyState
                icon={<ShieldCheck size={20} />}
                title="No approval outcomes yet"
                subtitle="Operator decisions and timed-out requests will appear here once approvals leave the queue"
              />
            </div>
          ) : (
            <div className="operator-history-list">
              {outcomeItems.map(item => (
                <div key={item.approval_id} className="operator-history-card">
                  <span className={`badge ${item.status === 'allowed' ? 'badge-allow' : item.status === 'denied' ? 'badge-block' : 'badge-defer'}`}>
                    {item.status}
                  </span>
                  <span className="mono">{item.tool_name}</span>
                  <span className="cmd-snippet" style={{ flex: 1 }}>{item.command || '—'}</span>
                  {item.status === 'expired' && (
                    <span className="text-muted">Timed out without an operator decision</span>
                  )}
                  <span className="text-muted mono" style={{ fontSize: '0.68rem' }}>
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
    </div>
  )
}
