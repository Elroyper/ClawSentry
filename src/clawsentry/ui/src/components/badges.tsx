import type { RiskLevel, DecisionVerdict } from '../api/types'
import { usePreferences } from '../lib/preferences'

function BadgeShell({ className, children }: { className?: string; children: string }) {
  return <span className={className}>{children}</span>
}

export function DecisionBadge({ decision }: { decision: DecisionVerdict }) {
  const { t } = usePreferences()
  return <BadgeShell className={`badge badge-${decision}`}>{t(`decision.${decision}` as Parameters<typeof t>[0])}</BadgeShell>
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  const { t } = usePreferences()
  return <BadgeShell className={`badge badge-risk-${level}`}>{t(`risk.${level}` as Parameters<typeof t>[0])}</BadgeShell>
}
