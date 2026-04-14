import type { LLMUsageBucket, LLMUsageSnapshot } from '../api/types'

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

function formatTokens(inputTokens: number, outputTokens: number): string {
  return `${inputTokens.toLocaleString()} in / ${outputTokens.toLocaleString()} out`
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

function renderBucketPanel(title: string, buckets: Record<string, LLMUsageBucket>) {
  const rows = selectTopBuckets(buckets)

  return (
    <article className="framework-panel">
      <div className="framework-panel-top">
        <div>
          <h3>{title}</h3>
          <p>{rows.length ? `${rows.length} highlighted` : 'No entries'}</p>
        </div>
      </div>

      <div className="framework-workspace-list">
        {rows.map(([label, bucket], index) => (
          <div key={label} className="framework-workspace-row" style={{ alignItems: 'flex-start' }}>
            <div style={{ display: 'grid', gap: 4 }}>
              <strong>{label}</strong>
              <span>
                {bucket.calls.toLocaleString()} calls · {formatTokens(bucket.input_tokens, bucket.output_tokens)} ·{' '}
                {formatUsd(bucket.cost_usd)}
              </span>
            </div>
            <span className="mono" style={{ color: 'var(--color-text-muted)', fontSize: '0.72rem' }}>
              #{index + 1}
            </span>
          </div>
        ))}
      </div>
    </article>
  )
}

export default function LLMUsageDrilldown({ snapshot }: LLMUsageDrilldownProps) {
  if (!hasUsageData(snapshot)) {
    return (
      <section className="card section-card" style={{ marginBottom: 18 }}>
        <div className="section-card-header">
          <div>
            <p className="section-kicker">LLM telemetry</p>
            <h2>LLM usage drill-down</h2>
          </div>
          <span className="section-meta">Snapshot unavailable</span>
        </div>
        <div className="empty-inline">No LLM usage snapshot available.</div>
      </section>
    )
  }

  const totalTokens = snapshot.total_input_tokens + snapshot.total_output_tokens

  return (
    <section className="card section-card" style={{ marginBottom: 18 }}>
      <div className="section-card-header">
        <div>
          <p className="section-kicker">LLM telemetry</p>
          <h2>LLM usage drill-down</h2>
        </div>
        <span className="section-meta">
          {snapshot.total_calls.toLocaleString()} calls · {formatUsd(snapshot.total_cost_usd)}
        </span>
      </div>

      <div className="framework-panel-metrics" style={{ marginBottom: 16 }}>
        <div>
          <span>Total calls</span>
          <strong>{snapshot.total_calls.toLocaleString()}</strong>
        </div>
        <div>
          <span>Total tokens</span>
          <strong>{totalTokens.toLocaleString()}</strong>
        </div>
        <div>
          <span>Total cost</span>
          <strong>{formatUsd(snapshot.total_cost_usd)}</strong>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 14,
        }}
      >
        {renderBucketPanel('Top providers', snapshot.by_provider)}
        {renderBucketPanel('Top tiers', snapshot.by_tier)}
        {renderBucketPanel('Top statuses', snapshot.by_status)}
      </div>
    </section>
  )
}
