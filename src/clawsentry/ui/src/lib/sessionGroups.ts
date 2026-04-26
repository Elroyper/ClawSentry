import type { RiskLevel, SessionSummary } from '../api/types'

export type WorkspaceLanguage = 'en' | 'zh'

const RISK_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low']

export type WorkspaceGroup = {
  key: string
  workspaceRoot: string
  workspaceLabel: string
  framework: string
  callerAdapters: string[]
  sessionCount: number
  highRiskSessionCount: number
  criticalSessionCount: number
  totalEvents: number
  latestActivityAt: string
  highestRisk: RiskLevel
  sessions: SessionSummary[]
}

export type FrameworkGroup = {
  framework: string
  sessionCount: number
  workspaceCount: number
  highRiskSessionCount: number
  totalEvents: number
  latestActivityAt: string
  highestRisk: RiskLevel
  workspaces: WorkspaceGroup[]
}

export function riskRank(level: string): number {
  const normalized = String(level || 'low').toLowerCase() as RiskLevel
  return RISK_ORDER.indexOf(normalized)
}

export function normalizeFramework(framework: string): string {
  return framework || 'unknown'
}

export function shortSessionId(sessionId?: string | null): string {
  const normalized = String(sessionId || '').trim()
  if (!normalized) return ''
  return normalized.length > 12 ? `${normalized.slice(0, 12)}…` : normalized
}

export function workspaceLabel(workspaceRoot: string, language: WorkspaceLanguage = 'en'): string {
  if (!workspaceRoot) return language === 'zh' ? '未绑定工作区' : 'Unbound workspace'
  const trimmed = workspaceRoot.replace(/\/+$/, '')
  const segments = trimmed.split('/').filter(Boolean)
  return segments[segments.length - 1] || workspaceRoot
}

export function workspaceGroupKey(session: SessionSummary): string {
  const workspaceRoot = String(session.workspace_root || '').trim()
  if (workspaceRoot) return workspaceRoot
  const framework = normalizeFramework(session.source_framework)
  const adapter = String(session.caller_adapter || 'adapter-unknown').trim() || 'adapter-unknown'
  return `unbound:${framework}:${adapter}`
}

export function workspaceDisplayLabel(session: Pick<SessionSummary, 'workspace_root' | 'source_framework' | 'caller_adapter' | 'session_id'>, language: WorkspaceLanguage = 'en'): string {
  if (session.workspace_root) return workspaceLabel(session.workspace_root, language)
  const prefix = language === 'zh' ? '未绑定工作区' : 'Unbound workspace'
  const framework = normalizeFramework(session.source_framework)
  const adapter = String(session.caller_adapter || '').trim()
  const context = [framework, adapter].filter(Boolean).join(' · ')
  return context ? `${prefix} · ${context}` : prefix
}

export function workspaceTechnicalDetail(workspaceRoot: string | undefined | null, language: WorkspaceLanguage = 'en'): string {
  if (workspaceRoot) return workspaceRoot
  return language === 'zh' ? 'workspace_root 未上报' : 'workspace_root unavailable'
}

export function formatRelativeTime(timestamp: string): string {
  if (!timestamp) return 'No activity'
  const delta = Date.now() - new Date(timestamp).getTime()
  if (!Number.isFinite(delta) || delta < 0) return 'Just now'
  const seconds = Math.floor(delta / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export function activityState(timestamp: string): 'hot' | 'warm' | 'idle' {
  if (!timestamp) return 'idle'
  const deltaMinutes = (Date.now() - new Date(timestamp).getTime()) / 60_000
  if (deltaMinutes <= 2) return 'hot'
  if (deltaMinutes <= 15) return 'warm'
  return 'idle'
}

export function groupSessions(sessions: SessionSummary[], language: WorkspaceLanguage = 'en'): FrameworkGroup[] {
  const frameworkMap = new Map<string, Map<string, SessionSummary[]>>()

  for (const session of sessions) {
    const framework = normalizeFramework(session.source_framework)
    const workspaceRoot = session.workspace_root || ''
    if (!frameworkMap.has(framework)) {
      frameworkMap.set(framework, new Map())
    }
    const workspaceMap = frameworkMap.get(framework)!
    const key = workspaceGroupKey(session)
    const existing = workspaceMap.get(key) || []
    existing.push(session)
    workspaceMap.set(key, existing)
  }

  const groupedSessions = Array.from(frameworkMap.entries())
    .map(([framework, workspaceMap]) => {
      const workspaces: WorkspaceGroup[] = Array.from(workspaceMap.entries())
        .map(([key, workspaceSessions]) => {
          const sortedSessions = [...workspaceSessions].sort((a, b) => {
            const rankDiff = riskRank(a.current_risk_level) - riskRank(b.current_risk_level)
            if (rankDiff !== 0) return rankDiff
            return new Date(b.last_event_at).getTime() - new Date(a.last_event_at).getTime()
          })
          const highestRisk = sortedSessions[0]?.current_risk_level || 'low'
          const latestActivityAt = sortedSessions
            .map(session => session.last_event_at)
            .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0] || ''
          const adapters = Array.from(
            new Set(sortedSessions.map(session => session.caller_adapter).filter(Boolean)),
          )
          const representative = sortedSessions[0]!
          return {
            key,
            workspaceRoot: representative.workspace_root || '',
            workspaceLabel: workspaceDisplayLabel(representative, language),
            framework,
            callerAdapters: adapters,
            sessionCount: sortedSessions.length,
            highRiskSessionCount: sortedSessions.filter(session => riskRank(session.current_risk_level) <= 1).length,
            criticalSessionCount: sortedSessions.filter(session => session.current_risk_level === 'critical').length,
            totalEvents: sortedSessions.reduce((sum, session) => sum + session.event_count, 0),
            latestActivityAt,
            highestRisk,
            sessions: sortedSessions,
          }
        })
        .sort((a, b) => {
          const rankDiff = riskRank(a.highestRisk) - riskRank(b.highestRisk)
          if (rankDiff !== 0) return rankDiff
          return new Date(b.latestActivityAt).getTime() - new Date(a.latestActivityAt).getTime()
        })

      const allSessions = workspaces.flatMap(workspace => workspace.sessions)
      const latestActivityAt = allSessions
        .map(session => session.last_event_at)
        .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0] || ''
      const highestRisk = workspaces[0]?.highestRisk || 'low'

      return {
        framework,
        sessionCount: allSessions.length,
        workspaceCount: workspaces.length,
        highRiskSessionCount: allSessions.filter(session => riskRank(session.current_risk_level) <= 1).length,
        totalEvents: allSessions.reduce((sum, session) => sum + session.event_count, 0),
        latestActivityAt,
        highestRisk,
        workspaces,
      }
    })
    .sort((a, b) => {
      const rankDiff = riskRank(a.highestRisk) - riskRank(b.highestRisk)
      if (rankDiff !== 0) return rankDiff
      return new Date(b.latestActivityAt).getTime() - new Date(a.latestActivityAt).getTime()
    })

  return groupedSessions
}
