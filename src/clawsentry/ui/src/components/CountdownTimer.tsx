import { useState, useEffect } from 'react'
import { usePreferences } from '../lib/preferences'

interface CountdownTimerProps {
  expiresAt: number       // Unix timestamp (seconds)
  totalSeconds?: number   // for ring progress (default 30)
  onExpired?: () => void
}

export default function CountdownTimer({ expiresAt, totalSeconds = 30, onExpired }: CountdownTimerProps) {
  const { t } = usePreferences()
  const [remaining, setRemaining] = useState(() => Math.max(0, expiresAt - Date.now() / 1000))

  useEffect(() => {
    const timer = setInterval(() => {
      const left = Math.max(0, expiresAt - Date.now() / 1000)
      setRemaining(left)
      if (left <= 0) { clearInterval(timer); onExpired?.() }
    }, 500)
    return () => clearInterval(timer)
  }, [expiresAt, onExpired])

  if (remaining <= 0) {
    return <span className="mono countdown-expired">{t('countdown.expired')}</span>
  }

  const isUrgent = remaining < 10
  const pct = Math.min(1, remaining / totalSeconds)

  // SVG ring
  const R = 16
  const C = 2 * Math.PI * R
  const dash = pct * C

  const mins = Math.floor(remaining / 60)
  const secs = Math.floor(remaining % 60)
  const display = mins > 0 ? `${mins}:${String(secs).padStart(2, '0')}` : `${secs}s`

  return (
    <div className={`countdown-timer${isUrgent ? ' countdown-timer-urgent' : ''}`}>
      <svg width={40} height={40} className="countdown-ring">
        <circle className="countdown-ring-track" cx={20} cy={20} r={R} fill="none" strokeWidth={3} />
        <circle
          className="countdown-ring-progress"
          cx={20} cy={20} r={R}
          fill="none"
          strokeWidth={3}
          strokeDasharray={`${dash} ${C}`}
          strokeLinecap="round"
        />
      </svg>
      <span className="mono countdown-value">
        {display}
      </span>
    </div>
  )
}
