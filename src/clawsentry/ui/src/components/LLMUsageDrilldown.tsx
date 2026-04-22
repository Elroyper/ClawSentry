import type { LLMUsageBucket, LLMUsageSnapshot } from '../api/types'
import { usePreferences } from '../lib/preferences'

type LLMUsageDrilldownProps = {
  snapshot: LLMUsageSnapshot | null | undefined
}

function formatUsd(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount)
}

function formatTokens(inputTokens: number, outputTokens: number, inputLabel: string, outputLabel: string): string {
  return `${inputTokens.toLocaleString()} ${inputLabel} / ${outputTokens.toLocaleString()} ${outputLabel}`
}

function selectTopBuckets(buckets: Record<string, LLMUsageBucket>): Array<[string, LLMUsageBucket]> {
  return Object.entries(buckets)
    .sort(([leftLabel, leftBucket], [rightLabel, rightBucket]) => {
      return (
        rightBucket.cost_usd - leftBucket.cost_usd ||
        rightBucket.calls - leftBucket.calls ||
        leftLabel.localeCompare(rightLabel)
      )
    })
    .slice(0, 3)
}

function hasUsageData(snapshot: LLMUsageSnapshot | null | undefined): snapshot is LLMUsageSnapshot {
  if (!snapshot) return false

  return (
    snapshot.total_calls > 0 ||
    snapshot.total_input_tokens > 0 ||
    snapshot.total_output_tokens > 0 ||
    snapshot.total_cost_usd > 0 ||
    Object.keys(snapshot.by_provider).length > 0 ||
    Object.keys(snapshot.by_tier).length > 0 ||
    Object.keys(snapshot.by_status).length > 0
  )
}

function renderBucketPanel(
  title: string,
  buckets: Record<string, LLMUsageBucket>,
  labels: { highlighted: string; noEntries: string; calls: string; input: string; output: string },
) {
  const rows = selectTopBuckets(buckets)

  return (
    <article className="framework-panel">
      <div className="framework-panel-top">
        <div>
          <h3>{title}</h3>
          <p>{rows.length ? `${rows.length} ${labels.highlighted}` : labels.noEntries}</p>
        </div>
      </div>

      <div className="framework-workspace-list">
        {rows.map(([label, bucket], index) => (
          <div key={label} className="framework-workspace-row llm-bucket-row">
            <div className="llm-bucket-copy">
              <strong>{label}</strong>
              <span>
                {bucket.calls.toLocaleString()} {labels.calls} · {formatTokens(bucket.input_tokens, bucket.output_tokens, labels.input, labels.output)} ·{' '}
                {formatUsd(bucket.cost_usd)}
              </span>
            </div>
            <span className="mono llm-bucket-rank">
              #{index + 1}
            </span>
          </div>
        ))}
      </div>
    </article>
  )
}

export default function LLMUsageDrilldown({ snapshot }: LLMUsageDrilldownProps) {
  const { t } = usePreferences()

  if (!hasUsageData(snapshot)) {
    return (
      <section className="card section-card llm-usage-section" aria-label={t('llm.title')}>
        <div className="section-card-header">
          <div>
            <p className="section-kicker">{t('llm.kicker')}</p>
            <h2>{t('llm.title')}</h2>
          </div>
          <span className="section-meta">{t('llm.snapshotUnavailable')}</span>
        </div>
        <div className="empty-inline">{t('llm.empty')}</div>
      </section>
    )
  }

  const totalTokens = snapshot.total_input_tokens + snapshot.total_output_tokens
  const bucketLabels = {
    highlighted: t('llm.highlighted'),
    noEntries: t('llm.noEntries'),
    calls: t('llm.calls'),
    input: t('llm.in'),
    output: t('llm.out'),
  }

  return (
    <section className="card section-card llm-usage-section" aria-label={t('llm.title')}>
      <div className="section-card-header">
        <div>
          <p className="section-kicker">{t('llm.kicker')}</p>
          <h2>{t('llm.title')}</h2>
        </div>
        <span className="section-meta">
          {snapshot.total_calls.toLocaleString()} {t('llm.calls')} · {formatUsd(snapshot.total_cost_usd)}
        </span>
      </div>

      <div className="framework-panel-metrics llm-metric-grid">
        <div>
          <span>{t('llm.totalCalls')}</span>
          <strong>{snapshot.total_calls.toLocaleString()}</strong>
        </div>
        <div>
          <span>{t('llm.totalTokens')}</span>
          <strong>{totalTokens.toLocaleString()}</strong>
        </div>
        <div>
          <span>{t('llm.totalCost')}</span>
          <strong>{formatUsd(snapshot.total_cost_usd)}</strong>
        </div>
      </div>

      <div className="llm-bucket-grid">
        {renderBucketPanel(t('llm.topProviders'), snapshot.by_provider, bucketLabels)}
        {renderBucketPanel(t('llm.topTiers'), snapshot.by_tier, bucketLabels)}
        {renderBucketPanel(t('llm.topStatuses'), snapshot.by_status, bucketLabels)}
      </div>
    </section>
  )
}
