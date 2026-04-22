import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, XCircle, RefreshCw, AlertTriangle, WifiOff } from 'lucide-react'
import { api } from '../api/client'
import { connectSSE } from '../api/sse'
import { RiskBadge } from '../components/badges'
import EmptyState from '../components/EmptyState'
import type { Alert, AlertSeverity, SSEAlertEvent } from '../api/types'
import { usePreferences } from '../lib/preferences'

function normalizeAlertSeverity(severity: string | undefined): AlertSeverity {
  if (severity === 'warning') return 'medium'
  if (severity === 'info') return 'low'
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') {
    return severity
  }
  return 'low'
}

function normalizeAlert(alert: Alert): Alert {
  return {
    ...alert,
    severity: normalizeAlertSeverity(alert.severity),
  }
}

function formatSessionId(sessionId: string | null | undefined) {
  if (!sessionId) return '—'
  return sessionId.length > 12 ? `${sessionId.slice(0, 12)}…` : sessionId
}

const matchesAlertFilters = (
  alert: Pick<Alert, 'severity' | 'acknowledged'>,
  severity: AlertSeverity | '',
  showAcknowledged: boolean | undefined,
) => {
  if (severity && alert.severity !== severity) return false
  if (showAcknowledged !== undefined && alert.acknowledged !== showAcknowledged) return false
  return true
}

export default function Alerts() {
  const { t } = usePreferences()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [severity, setSeverity] = useState<AlertSeverity | ''>('')
  const [showAcknowledged, setShowAcknowledged] = useState<boolean | undefined>(undefined)

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(false)
    try {
      const data = await api.alerts({ severity: severity || undefined, acknowledged: showAcknowledged, limit: 100 })
      setAlerts(data.map(normalizeAlert))
    } catch {
      setAlerts([])
      setLoadError(true)
    }
    setLoading(false)
  }, [severity, showAcknowledged])

  useEffect(() => { load() }, [load])
  useEffect(() => { const t = setInterval(load, 30_000); return () => clearInterval(t) }, [load])

  useEffect(() => {
    const es = connectSSE(['alert'])
    es.addEventListener('alert', (e: MessageEvent) => {
      try {
        const data: SSEAlertEvent = JSON.parse(e.data)
        const newAlert: Alert = {
          alert_id: data.alert_id,
          severity: normalizeAlertSeverity(data.severity),
          metric: data.metric,
          session_id: data.session_id,
          message: data.message,
          details: {},
          triggered_at: data.timestamp,
          acknowledged: false,
          acknowledged_by: null,
          acknowledged_at: null,
        }
        setAlerts(prev => matchesAlertFilters(newAlert, severity, showAcknowledged) ? [newAlert, ...prev] : prev)
      } catch { /* ignore */ }
    })
    return () => es.close()
  }, [severity, showAcknowledged])

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId)
      setAlerts(prev => prev
        .map(a => a.alert_id === alertId ? { ...a, acknowledged: true, acknowledged_by: 'dashboard', acknowledged_at: new Date().toISOString() } : a)
        .filter(alert => matchesAlertFilters(alert, severity, showAcknowledged)))
    } catch { /* ignore */ }
  }

  const openCount = alerts.filter(a => !a.acknowledged).length
  const acknowledgedCount = alerts.length - openCount
  const priorityCount = alerts.filter(a => !a.acknowledged && (a.severity === 'high' || a.severity === 'critical')).length

  return (
    <div className="workbench-shell">
      <section className="workbench-hero alerts-hero" aria-labelledby="alerts-workbench-title">
        <div className="workbench-hero-copy">
          <div className="eyebrow">{t('alerts.hero.kicker')}</div>
          <h1 id="alerts-workbench-title">
            <AlertTriangle size={20} className="alerts-title-icon" />
            {t('alerts.hero.title')}
          </h1>
          <p className="workbench-hero-text">
            {t('alerts.hero.copy')}
          </p>
        </div>
        <div className="workbench-hero-side">
          <span className={`badge ${openCount > 0 ? 'badge-defer' : 'badge-allow'}`}>
            {openCount} open
          </span>
          <span className="workbench-hero-note">
            {priorityCount > 0 ? `${priorityCount} priority incidents need review` : 'No priority incidents pending'}
          </span>
        </div>
      </section>

      <section className="workbench-section" aria-label="Alerts overview">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">{t('alerts.overview.kicker')}</div>
            <h2>{t('alerts.overview.title')}</h2>
          </div>
          <div className="section-meta">Refreshes every 30 seconds and accepts live SSE inserts.</div>
        </div>
        <div className="workbench-summary-grid">
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Queue size</span>
            <strong>{alerts.length} total alerts</strong>
            <p>All alerts matching the current server-side filters.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Needs action</span>
            <strong>{openCount} open</strong>
            <p>Unacknowledged alerts waiting for operator triage.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Resolved state</span>
            <strong>{acknowledgedCount} acknowledged</strong>
            <p>Alerts already actioned inside this filtered view.</p>
          </div>
          <div className="workbench-summary-card">
            <span className="workbench-summary-label">Priority load</span>
            <strong>{priorityCount} high priority</strong>
            <p>Open `high` or `critical` signals that should be reviewed first.</p>
          </div>
        </div>
      </section>

      <section className="workbench-section" aria-label="Alerts filters">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">{t('alerts.filters.kicker')}</div>
            <h2>{t('alerts.filters.title')}</h2>
          </div>
          <button className="btn" onClick={load} disabled={loading} aria-label="Refresh alerts">
            <RefreshCw size={13} className={loading ? 'spin-icon' : undefined} />
            {t('common.refresh')}
          </button>
        </div>
        <div className="workbench-filter-grid">
          <label className="workbench-field">
            <span className="workbench-field-label">Severity</span>
            <select
              aria-label="Severity filter"
              value={severity}
              onChange={e => setSeverity(e.target.value as AlertSeverity | '')}
            >
              <option value="">All Severities</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <label className="workbench-field">
            <span className="workbench-field-label">Status</span>
            <select
              aria-label="Alert status filter"
              value={showAcknowledged === undefined ? '' : String(showAcknowledged)}
              onChange={e => setShowAcknowledged(e.target.value === '' ? undefined : e.target.value === 'true')}
            >
              <option value="">All Status</option>
              <option value="false">Unacknowledged</option>
              <option value="true">Acknowledged</option>
            </select>
          </label>
        </div>
      </section>

      <section className="workbench-section" aria-label="Alerts triage queue">
        <div className="section-card-header workbench-section-header">
          <div>
            <div className="section-kicker">{t('alerts.queue.kicker')}</div>
            <h2>{t('alerts.queue.title')}</h2>
          </div>
          <div className="section-meta">Severity, session, and action state are grouped per alert.</div>
        </div>

        {alerts.length === 0 && !loading ? (
          <div className="card workbench-empty-card">
            {loadError ? (
              <EmptyState
                icon={<WifiOff size={20} />}
                title={t('alerts.error.title')}
                subtitle={t('alerts.error.subtitle')}
              />
            ) : (
              <EmptyState
                icon={<AlertTriangle size={20} />}
                title={t('alerts.empty.title')}
                subtitle={t('alerts.empty.subtitle')}
              />
            )}
          </div>
        ) : (
          <div className="operator-list">
            {alerts.map(alert => (
              <article
                key={alert.alert_id}
                className={`operator-card alert-card alert-card-${alert.severity}${alert.acknowledged ? ' alert-card-acknowledged' : ''}`}
              >
                <div className="operator-card-main">
                  <div className="operator-card-topline">
                    <div className="operator-card-tags">
                      <RiskBadge level={alert.severity} />
                      <span className={`badge ${alert.acknowledged ? 'badge-allow' : 'badge-defer'}`}>
                        {alert.acknowledged ? (
                          <>
                            <CheckCircle size={12} />
                            acknowledged
                          </>
                        ) : (
                          <>
                            <XCircle size={12} />
                            open
                          </>
                        )}
                      </span>
                      <span className="badge badge-neutral">{alert.metric}</span>
                    </div>
                    <div className="operator-time">{new Date(alert.triggered_at).toLocaleString()}</div>
                  </div>

                  <h3 className="operator-card-title">{alert.message}</h3>

                  <div className="operator-card-meta">
                    <div className="operator-meta-block">
                      <span className="operator-meta-label">Metric</span>
                      <strong className="mono">{alert.metric}</strong>
                    </div>
                    <div className="operator-meta-block">
                      <span className="operator-meta-label">Session</span>
                      <Link to={`/sessions/${alert.session_id}`} className="operator-session-link">
                        {formatSessionId(alert.session_id)}
                      </Link>
                    </div>
                    <div className="operator-meta-block">
                      <span className="operator-meta-label">State</span>
                      <strong>{alert.acknowledged ? 'Acknowledged' : 'Needs acknowledgement'}</strong>
                    </div>
                  </div>
                </div>

                <div className="operator-card-side">
                  <div className="operator-side-panel">
                    <span className="operator-meta-label">Severity</span>
                    <strong className={`alert-severity-text alert-severity-text-${alert.severity}`}>
                      {alert.severity}
                    </strong>
                    <span className="text-muted">
                      {alert.acknowledged
                        ? `Acknowledged by ${alert.acknowledged_by || 'dashboard'}`
                        : 'Escalate or acknowledge to clear the queue'}
                    </span>
                  </div>
                  {!alert.acknowledged ? (
                    <button
                      className="btn btn-primary"
                      onClick={() => handleAcknowledge(alert.alert_id)}
                      aria-label={`Acknowledge alert ${alert.message}`}
                    >
                      Acknowledge
                    </button>
                  ) : (
                    <span className="operator-resolution-note">
                      {alert.acknowledged_at ? `Closed ${new Date(alert.acknowledged_at).toLocaleString()}` : 'Closed'}
                    </span>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
