import { describe, expect, it } from 'vitest'

import {
  formatL3ReasonCode,
  formatOperatorAction,
  formatOperatorLabel,
  formatRunnerLabel,
} from './operatorLabels'

describe('operator label helpers', () => {
  it('adds operator-readable English labels for technical ids', () => {
    expect(formatOperatorLabel('l3State', 'completed')).toBe('Completed')
    expect(formatOperatorLabel('jobState', 'queued')).toBe('Queued')
    expect(formatOperatorLabel('runner', 'deterministic_local')).toBe('Deterministic local')
    expect(formatL3ReasonCode('toolkit_budget_exhausted')).toBe('Toolkit budget exhausted')
    expect(formatOperatorAction('escalate')).toBe('Escalate')
    expect(formatRunnerLabel('custom_worker')).toBe('Custom worker')
  })

  it('renders Chinese labels for low-level advisory states without changing ids', () => {
    expect(formatOperatorLabel('l3State', 'degraded', 'zh')).toBe('已降级')
    expect(formatOperatorLabel('jobState', 'running', 'zh')).toBe('执行中')
    expect(formatL3ReasonCode('operator_required', 'zh')).toBe('需要人工确认')
    expect(formatOperatorAction('inspect', 'zh')).toBe('检查')
  })
})
