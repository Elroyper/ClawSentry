import type { SessionSummary } from '../api/types'
import { formatL3EvidenceSummary } from './l3EvidenceSummary'
import { appendReadableLabel, type OperatorLanguage } from './operatorLabels'

export function formatSessionL3Annotation(
  session: SessionSummary,
  language: OperatorLanguage = 'en',
): string | null {
  const parts: string[] = []

  const reasonCode = String(session.l3_reason_code || '').trim()
  if (reasonCode) {
    parts.push(`L3 reason code: ${appendReadableLabel('l3ReasonCode', reasonCode, language)}`)
  }

  const state = String(session.l3_state || '').trim()
  if (state && state !== 'completed') {
    parts.push(`L3 state: ${appendReadableLabel('l3State', state, language)}`)
  }

  const reason = String(session.l3_reason || '').trim()
  if (reason && state && state !== 'completed') {
    parts.push(`L3 reason: ${reason}`)
  }

  const evidenceSummary = formatL3EvidenceSummary(session.evidence_summary)
  if (evidenceSummary) {
    parts.push(`Evidence: ${evidenceSummary}`)
  }

  return parts.length > 0 ? parts.join(' · ') : null
}
