import type { RiskLevel, DecisionVerdict } from '../api/types'

function BadgeShell({ className, children }: { className?: string; children: string }) {
  return <span className={className}>{children}</span>
}

export function DecisionBadge({ decision }: { decision: DecisionVerdict }) {
  return <BadgeShell className={`badge badge-${decision}`}>{decision}</BadgeShell>
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  return <BadgeShell className={`badge badge-risk-${level}`}>{level}</BadgeShell>
}
