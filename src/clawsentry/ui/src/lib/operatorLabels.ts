export type OperatorLanguage = 'en' | 'zh'

type LabelKind = 'l3State' | 'jobState' | 'l3ReasonCode' | 'operatorAction' | 'runner'

type LabelMap = Partial<Record<LabelKind, Record<string, Record<OperatorLanguage, string>>>>

const LABELS: LabelMap = {
  l3State: {
    pending: { en: 'Pending', zh: '待处理' },
    running: { en: 'Running', zh: '执行中' },
    completed: { en: 'Completed', zh: '已完成' },
    failed: { en: 'Failed', zh: '失败' },
    degraded: { en: 'Degraded', zh: '已降级' },
    skipped: { en: 'Skipped', zh: '已跳过' },
    enabled: { en: 'Enabled', zh: '已启用' },
    not_triggered: { en: 'Not triggered', zh: '未触发' },
  },
  jobState: {
    queued: { en: 'Queued', zh: '已排队' },
    running: { en: 'Running', zh: '执行中' },
    completed: { en: 'Completed', zh: '已完成' },
    failed: { en: 'Failed', zh: '失败' },
    degraded: { en: 'Degraded', zh: '已降级' },
  },
  l3ReasonCode: {
    toolkit_budget_exhausted: { en: 'Toolkit budget exhausted', zh: '工具证据预算耗尽' },
    budget_exhausted: { en: 'Budget exhausted', zh: '预算耗尽' },
    hard_cap_exceeded: { en: 'Hard cap exceeded', zh: '超过硬上限' },
    operator_required: { en: 'Operator required', zh: '需要人工确认' },
    local_l3_unavailable: { en: 'Local L3 unavailable', zh: '本地 L3 不可用' },
    local_l3_not_completed: { en: 'Local L3 not completed', zh: '本地 L3 未完成' },
    trigger_not_matched: { en: 'Trigger not matched', zh: '未命中触发条件' },
    provider_disabled: { en: 'Provider disabled', zh: '提供商未启用' },
    provider_missing_key: { en: 'Provider API key missing', zh: '缺少提供商密钥' },
    provider_missing_model: { en: 'Provider model missing', zh: '缺少提供商模型' },
    provider_unsupported: { en: 'Provider unsupported', zh: '不支持的提供商' },
    provider_not_implemented: { en: 'Provider dry-run / not implemented', zh: '提供商为演练或未实现' },
    provider_timeout: { en: 'Provider timeout', zh: '提供商超时' },
    provider_error: { en: 'Provider error', zh: '提供商错误' },
    provider_response_invalid: { en: 'Provider response invalid', zh: '提供商响应无效' },
    credential_access: { en: 'Credential access', zh: '凭据访问' },
    exfil_chain: { en: 'Exfiltration chain', zh: '外传链路' },
    completed: { en: 'Completed', zh: '已完成' },
  },
  operatorAction: {
    inspect: { en: 'Inspect', zh: '检查' },
    escalate: { en: 'Escalate', zh: '升级处理' },
    pause: { en: 'Pause', zh: '暂停' },
    none: { en: 'None', zh: '无需操作' },
    monitor: { en: 'Monitor', zh: '观察' },
    configure_llm_provider: { en: 'Configure LLM provider', zh: '配置 LLM 提供商' },
  },
  runner: {
    deterministic_local: { en: 'Deterministic local', zh: '本地确定性复核' },
    llm_provider: { en: 'LLM provider', zh: 'LLM 提供商' },
    demo_fixture: { en: 'Demo fixture', zh: '演示数据' },
  },
}

function normalizeId(value?: string | null): string {
  return String(value || '').trim()
}

function humanizeId(value: string): string {
  const words = value
    .replace(/[-_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (!words) return 'Unknown'
  return words.charAt(0).toUpperCase() + words.slice(1).toLowerCase()
}

export function formatOperatorLabel(
  kind: LabelKind,
  value?: string | null,
  language: OperatorLanguage = 'en',
): string {
  const normalized = normalizeId(value)
  if (!normalized) return language === 'zh' ? '未知' : 'Unknown'
  return LABELS[kind]?.[normalized]?.[language] ?? humanizeId(normalized)
}

export function formatL3ReasonCode(value?: string | null, language: OperatorLanguage = 'en'): string {
  return formatOperatorLabel('l3ReasonCode', value, language)
}

export function formatOperatorAction(value?: string | null, language: OperatorLanguage = 'en'): string {
  return formatOperatorLabel('operatorAction', value, language)
}

export function formatRunnerLabel(value?: string | null, language: OperatorLanguage = 'en'): string {
  return formatOperatorLabel('runner', value, language)
}

export function appendReadableLabel(
  kind: LabelKind,
  value?: string | null,
  language: OperatorLanguage = 'en',
): string {
  const normalized = normalizeId(value)
  if (!normalized) return formatOperatorLabel(kind, normalized, language)
  const label = formatOperatorLabel(kind, normalized, language)
  return label.toLowerCase() === normalized.toLowerCase()
    ? normalized
    : `${normalized} · ${label}`
}

export function l3AdvisoryJobHint(jobState?: string | null, language: OperatorLanguage = 'en'): string | null {
  switch (normalizeId(jobState).toLowerCase()) {
    case 'queued':
      return language === 'zh' ? '等待操作员显式运行' : 'waiting for explicit operator run'
    case 'running':
      return language === 'zh' ? 'Worker 正在复核冻结证据' : 'worker executing frozen evidence review'
    case 'completed':
      return language === 'zh' ? '复核可用；canonical decision 未改变' : 'review available; canonical decision unchanged'
    case 'failed':
      return language === 'zh' ? 'Worker 失败；检查咨询任务证据' : 'worker failed; inspect advisory job evidence'
    case 'degraded':
      return language === 'zh'
        ? '复核降级；检查 LLM provider 配置和保留证据边界'
        : 'review degraded; check LLM provider configuration and retained evidence boundary'
    default:
      return null
  }
}
