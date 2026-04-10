import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, FolderTree, ScrollText, ShieldAlert } from 'lucide-react'
import { api } from '../api/client'
import { DecisionBadge, RiskBadge } from '../components/badges'
import SkeletonCard from '../components/SkeletonCard'
import type { SessionRisk, TrajectoryRecord } from '../api/types'
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

const DIMENSION_LABELS: Record<string, string> = {
  d1: 'Tool risk',
  d2: 'Target sensitivity',
  d3: 'Data flow',
  d4: 'Frequency',
  d5: 'Context',
}

const TOOLTIP_STYLE = {
  background: '#101825',
  border: '1px solid rgba(96, 165, 250, 0.18)',
  borderRadius: 16,
  fontSize: 12,
  color: '#f6f8fb',
  boxShadow: '0 18px 40px rgba(3, 11, 25, 0.34)',
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

function TierBadge({ tier }: { tier: string }) {
  const normalized = tier.toUpperCase()
  const className = normalized === 'L3' ? 'badge-tier-l3' : normalized === 'L2' ? 'badge-tier-l2' : 'badge-tier-l1'
  return <span className={`badge ${className}`}>{normalized}</span>
}

function TimelineLatency({ ms }: { ms: number }) {
  const className = ms < 100 ? 'latency-fast' : ms < 3000 ? 'latency-medium' : 'latency-slow'
  return <span className={`latency-badge ${className}`}>{ms}ms</span>
}

export default function SessionDetail() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const [risk, setRisk] = useState<SessionRisk | null>(null)
  const [trajectory, setTrajectory] = useState<TrajectoryRecord[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!sessionId) return
    setLoading(true)
    Promise.all([api.sessionRisk(sessionId), api.sessionReplay(sessionId)])
      .then(([riskResult, trajectoryResult]) => {
        setRisk(riskResult)
        setTrajectory(trajectoryResult)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [sessionId])

  if (loading) {
    return (
      <div>
        <div style={{ height: 24, marginBottom: 20 }} />
        <div className="session-detail-grid">
          {[0, 1, 2].map(index => <SkeletonCard key={index} rows={4} height={220} />)}
        </div>
        <SkeletonCard rows={8} height={320} />
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

  return (
    <div className="session-detail-shell">
      <Link to="/sessions" className="back-link">
        <ArrowLeft size={13} />
        Back to session inventory
      </Link>

      <section className="session-hero">
        <div>
          <p className="section-kicker">Session detail</p>
          <h1>{workspaceLabel(risk?.workspace_root || '')}</h1>
          <p className="hero-copy">
            {risk?.source_framework || 'unknown'} · {risk?.caller_adapter || 'unknown adapter'} ·
            last seen {risk ? formatRelativeTime(risk.last_event_at) : 'recently'}
          </p>
          <div className="hero-chip-row">
            {risk && <RiskBadge level={risk.current_risk_level} />}
            {risk && <span className="framework-chip"><span>Agent</span><strong>{risk.agent_id}</strong></span>}
            {risk && <span className="framework-chip"><span>Events</span><strong>{risk.event_count}</strong></span>}
          </div>
        </div>
        <div className="hero-panel">
          <div className="hero-panel-header">
            <ShieldAlert size={14} />
            Session risk posture
          </div>
          <div className="hero-panel-body">
            <div>
              <span className="hero-panel-label">Cumulative score</span>
              <strong>{risk?.cumulative_score.toFixed(2) ?? '0.00'}</strong>
            </div>
            <div>
              <span className="hero-panel-label">High-risk events</span>
              <strong>{risk?.high_risk_event_count ?? 0}</strong>
            </div>
            <div>
              <span className="hero-panel-label">First event</span>
              <strong>{risk ? formatRelativeTime(risk.first_event_at) : '—'}</strong>
            </div>
          </div>
        </div>
      </section>

      <div className="session-detail-grid">
        <section className="card section-card">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Identity</p>
              <h2>Workspace context</h2>
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
            <div className="detail-pill-row">
              <span className="framework-chip"><span>Framework</span><strong>{risk?.source_framework || 'unknown'}</strong></span>
              <span className="framework-chip"><span>Adapter</span><strong>{risk?.caller_adapter || 'unknown'}</strong></span>
            </div>
          </div>
        </section>

        <section className="card section-card">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Dimensions</p>
              <h2>Risk composition</h2>
            </div>
          </div>
          <div style={{ height: 280 }}>
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

        <section className="card section-card">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Signals</p>
              <h2>Observed indicators</h2>
            </div>
          </div>
          <div className="detail-pill-row" style={{ marginBottom: 16 }}>
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
      </div>

      <section className="card section-card" style={{ marginBottom: 18 }}>
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Timeline</p>
            <h2>Risk score over time</h2>
          </div>
        </div>
        <div style={{ height: 240 }}>
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

      <section className="card section-card">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Replay</p>
            <h2>Decision timeline</h2>
          </div>
          <span className="section-meta">{trajectory.length} events</span>
        </div>
        <div className="decision-timeline">
          {trajectory.map((record, index) => {
            const input = typeof record.event?.input === 'string' ? record.event.input : ''
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
                    <div className="cmd-snippet" style={{ maxWidth: '100%' }}>
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
                </div>
              </div>
            )
          })}
          {trajectory.length === 0 && (
            <div className="empty-inline">No trajectory records yet.</div>
          )}
        </div>
      </section>
    </div>
  )
}
