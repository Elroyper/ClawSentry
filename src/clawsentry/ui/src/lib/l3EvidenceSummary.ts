import type { L3EvidenceSummary } from '../api/types'

export function formatL3EvidenceSummary(summary?: L3EvidenceSummary | null): string | null {
  if (!summary) return null

  const parts: string[] = []

  if (summary.retained_sources?.length) {
    parts.push(summary.retained_sources.filter(Boolean).join(', '))
  }

  if (typeof summary.tool_calls_count === 'number') {
    parts.push(`${summary.tool_calls_count} tool call(s)`)
  }

  if (
    typeof summary.toolkit_budget_cap === 'number'
    && typeof summary.toolkit_calls_remaining === 'number'
    && summary.toolkit_budget_cap > 0
  ) {
    const toolkitSummary = `toolkit ${summary.toolkit_calls_remaining}/${summary.toolkit_budget_cap}`
    parts.push(summary.toolkit_budget_exhausted ? `${toolkitSummary} (exhausted)` : toolkitSummary)
  } else if (summary.toolkit_budget_exhausted) {
    parts.push('toolkit exhausted')
  }

  return parts.length > 0 ? parts.join(' · ') : null
}
