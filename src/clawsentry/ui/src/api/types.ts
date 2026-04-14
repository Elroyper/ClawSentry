export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type DecisionVerdict = 'allow' | 'block' | 'defer' | 'modify'
export type DecisionTier = 'L1' | 'L2' | 'L3'
export type AlertSeverity = RiskLevel

export interface LLMUsageBucket {
  calls: number
  input_tokens: number
  output_tokens: number
  cost_usd: number
}

export interface LLMUsageSnapshot {
  total_calls: number
  total_input_tokens: number
  total_output_tokens: number
  total_cost_usd: number
  by_provider: Record<string, LLMUsageBucket>
  by_tier: Record<string, LLMUsageBucket>
  by_status: Record<string, LLMUsageBucket>
}

export interface HealthResponse {
  status: string
  uptime_seconds: number
  cache_size: number
  trajectory_count: number
  policy_engine: string
  auth_enabled: boolean
  budget: HealthBudgetSnapshot
  budget_exhaustion_event?: SSEBudgetExhaustedEvent | null
  llm_usage_snapshot?: LLMUsageSnapshot | null
}

export interface HealthBudgetSnapshot {
  daily_budget_usd: number
  daily_spend_usd: number
  remaining_usd: number | null
  exhausted: boolean
}

export interface SummaryResponse {
  total_records: number
  by_source_framework: Record<string, number>
  by_event_type: Record<string, number>
  by_decision: Record<string, number>
  by_risk_level: Record<string, number>
  by_actual_tier: Partial<Record<DecisionTier, number>>
  by_caller_adapter: Record<string, number>
  generated_at: string
  window_seconds: number | null
  budget_exhaustion_event?: SSEBudgetExhaustedEvent | null
  llm_usage_snapshot?: LLMUsageSnapshot | null
}

export interface SessionSummary {
  session_id: string
  agent_id: string
  source_framework: string
  caller_adapter: string
  workspace_root: string
  transcript_path: string
  current_risk_level: RiskLevel
  cumulative_score: number
  event_count: number
  high_risk_event_count: number
  decision_distribution: Record<string, number>
  first_event_at: string
  last_event_at: string
}

export interface SessionRisk {
  session_id: string
  agent_id: string
  source_framework: string
  caller_adapter: string
  workspace_root: string
  transcript_path: string
  current_risk_level: RiskLevel
  cumulative_score: number
  dimensions_latest: { d1: number; d2: number; d3: number; d4: number; d5: number }
  event_count: number
  high_risk_event_count: number
  first_event_at: string
  last_event_at: string
  risk_timeline: Array<{
    event_id: string
    occurred_at: string
    risk_level: RiskLevel
    composite_score: number
    tool_name: string
    decision: DecisionVerdict
    actual_tier: DecisionTier
    classified_by: DecisionTier
    l3_reason_code?: string
  }>
  risk_hints_seen: string[]
  tools_used: string[]
  actual_tier_distribution: Partial<Record<DecisionTier, number>>
}

export interface L3EvidenceSummary {
  retained_sources?: string[]
  tool_calls_count?: number
}

export interface TrajectoryRecord {
  event: Record<string, unknown>
  decision: {
    decision: DecisionVerdict
    reason: string
    risk_level: RiskLevel
    decision_latency_ms: number
  }
  risk_snapshot: {
    risk_level: RiskLevel
    composite_score: number
    dimensions: { d1: number; d2: number; d3: number; d4: number; d5: number }
  }
  meta: {
    actual_tier: DecisionTier
    caller_adapter: string
    l3_available?: boolean
    l3_requested?: boolean
    l3_reason_code?: string
    l3_state?: string
    l3_reason?: string
  }
  l3_trace?: {
    trigger_reason?: string
    trigger_detail?: string
    evidence_summary?: L3EvidenceSummary | null
  } | null
  recorded_at: string
}

export interface Alert {
  alert_id: string
  severity: AlertSeverity
  metric: string
  session_id: string
  message: string
  details: Record<string, unknown>
  triggered_at: string
  acknowledged: boolean
  acknowledged_by: string | null
  acknowledged_at: string | null
}

export interface SSEDecisionEvent {
  session_id: string
  event_id: string
  risk_level: RiskLevel
  decision: DecisionVerdict
  tool_name: string
  actual_tier: DecisionTier
  timestamp: string
  reason: string
  command: string
  l3_available?: boolean
  l3_requested?: boolean
  trigger_detail?: string
  l3_reason_code?: string
  l3_state?: string
  l3_reason?: string
  evidence_summary?: L3EvidenceSummary | null
  approval_id?: string
  expires_at?: number
}

export interface SSEAlertEvent {
  alert_id: string
  severity: AlertSeverity
  metric: string
  session_id: string
  current_risk: string
  message: string
  timestamp: string
}

export interface SSEBudgetExhaustedEvent {
  type: 'budget_exhausted'
  timestamp: string
  provider: string
  tier: string
  status: string
  cost_usd: number
  budget: HealthBudgetSnapshot
}

export type SSEPostActionFindingEvent = {
  event_id: string
  session_id: string
  source_framework: string
  tier: 'warn' | 'escalate' | 'emergency'
  patterns_matched: string[]
  score: number
  handling: 'broadcast' | 'defer' | 'block'
  timestamp: string
}

export type SSETrajectoryAlertEvent = {
  session_id: string
  sequence_id: string
  risk_level: RiskLevel
  matched_event_ids: string[]
  reason: string
  handling: 'broadcast' | 'defer' | 'block'
  timestamp: string
}

export type SSEPatternCandidateEvent = {
  pattern_id: string
  session_id: string
  source_framework: string
  status: 'candidate'
  timestamp: string
}

export type SSEPatternEvolvedEvent = {
  pattern_id: string
  action: string
  result: string
  timestamp: string
}

export type SSEDeferPendingEvent = {
  session_id: string
  approval_id: string
  tool_name: string
  command: string
  reason: string
  timeout_s: number
  timestamp: string
}

export type SSEDeferResolvedEvent = {
  session_id: string
  approval_id: string
  resolved_decision: 'allow' | 'allow-once' | 'block'
  resolved_reason: string
  timestamp: string
}

export type SSESessionEnforcementChangeEvent = {
  session_id: string
  state: 'enforced' | 'released'
  action: 'defer' | 'block' | 'l3_require' | null
  high_risk_count?: number
  reason?: string
  timestamp: string
}

export type RuntimeEventType =
  | 'decision'
  | 'alert'
  | 'trajectory_alert'
  | 'post_action_finding'
  | 'pattern_candidate'
  | 'pattern_evolved'
  | 'defer_pending'
  | 'defer_resolved'
  | 'budget_exhausted'
  | 'session_enforcement_change'

export type SSERuntimeEvent =
  | (SSEDecisionEvent & { type: 'decision' })
  | (SSEAlertEvent & { type: 'alert' })
  | (SSEPostActionFindingEvent & { type: 'post_action_finding' })
  | (SSETrajectoryAlertEvent & { type: 'trajectory_alert' })
  | (SSEPatternCandidateEvent & { type: 'pattern_candidate' })
  | (SSEPatternEvolvedEvent & { type: 'pattern_evolved' })
  | (SSEDeferPendingEvent & { type: 'defer_pending' })
  | (SSEDeferResolvedEvent & { type: 'defer_resolved' })
  | SSEBudgetExhaustedEvent
  | (SSESessionEnforcementChangeEvent & { type: 'session_enforcement_change' })
