import type { LLMUsageBucket, LLMUsageSnapshot } from '../api/types'
import { usePreferences } from '../lib/preferences'
import { formatTokenCount, formatTokenPair, tokenTotal } from '../lib/tokenBudget'

type LLMUsageDrilldownProps = {
  snapshot: LLMUsageSnapshot | null | undefined
}

function selectTopBuckets(buckets: Record<string, LLMUsageBucket>): Array<[string, LLMUsageBucket]> {
  return Object.entries(buckets)
    .sort(([leftLabel, leftBucket], [rightLabel, rightBucket]) => {
      return (
        tokenTotal(rightBucket) - tokenTotal(leftBucket) ||
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
    Object.keys(snapshot.by_provider).length > 0 ||
    Object.keys(snapshot.by_tier).length > 0 ||
    Object.keys(snapshot.by_status).length > 0
  )
}

function renderBucketPanel(
  title: string,
  buckets: Record<string, LLMUsageBucket>,
  labels: { highlighted: string; noEntries: string; calls: string; input: string; output: string },
  language: 'en' | 'zh',
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
                {bucket.calls.toLocaleString()} {labels.calls} · {formatTokenPair(bucket.input_tokens, bucket.output_tokens, language)} ·{' '}
                {formatTokenCount(tokenTotal(bucket), language)} {language === 'zh' ? '总 token' : 'total tokens'}
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
  const { t, language } = usePreferences()

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
          {snapshot.total_calls.toLocaleString()} {t('llm.calls')} · {formatTokenCount(totalTokens, language)} {t('llm.totalTokens')}
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
          <span>{t('llm.tokenMix')}</span>
          <strong>{formatTokenPair(snapshot.total_input_tokens, snapshot.total_output_tokens, language)}</strong>
        </div>
      </div>

      <div className="llm-bucket-grid">
        {renderBucketPanel(t('llm.topProviders'), snapshot.by_provider, bucketLabels, language)}
        {renderBucketPanel(t('llm.topTiers'), snapshot.by_tier, bucketLabels, language)}
        {renderBucketPanel(t('llm.topStatuses'), snapshot.by_status, bucketLabels, language)}
      </div>
    </section>
  )
}
