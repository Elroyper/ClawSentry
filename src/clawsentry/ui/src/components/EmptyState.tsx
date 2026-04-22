import type { ReactNode } from 'react'
import { usePreferences } from '../lib/preferences'

interface EmptyStateProps {
  icon: ReactNode
  title: string
  subtitle?: string
}

export default function EmptyState({ icon, title, subtitle }: EmptyStateProps) {
  const { language } = usePreferences()
  return (
    <div className="empty-state">
      <div className="empty-state-ornament" aria-hidden="true" />
      <div className="empty-state-icon">{icon}</div>
      <div className="empty-state-kicker">{language === 'zh' ? '待命' : 'Standby'}</div>
      <div className="empty-state-title">{title}</div>
      {subtitle && <div className="empty-state-subtitle">{subtitle}</div>}
    </div>
  )
}
