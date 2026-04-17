import type { ReactNode } from 'react'

type AccentColor = 'purple' | 'red' | 'amber' | 'blue' | 'green'

interface MetricCardProps {
  label: string
  value: string | number
  accent?: AccentColor
  icon?: ReactNode
  subtext?: string
}

export default function MetricCard({ label, value, accent = 'purple', icon, subtext }: MetricCardProps) {
  return (
    <div className={`card metric-card accent-${accent}`}>
      <div className="metric-card-header">
        <div className="metric-card-copy">
          <div className="metric-value">{value}</div>
          <div className="metric-label">{label}</div>
          {subtext && <div className="metric-subtext">{subtext}</div>}
        </div>
        {icon && (
          <div className="metric-icon" aria-hidden="true">
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
