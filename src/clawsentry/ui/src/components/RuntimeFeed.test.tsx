import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import RuntimeFeed from './RuntimeFeed'
import { createManagedSSE } from '../api/sse'

vi.mock('../api/sse', () => ({
  createManagedSSE: vi.fn(),
}))

describe('RuntimeFeed', () => {
  function expectSecondaryLine(text: string) {
    expect(
      screen.getByText((_, element) => {
        if (!element?.classList?.contains('text-secondary')) return false
        return element.textContent?.includes(text) === true
      }),
    ).toBeInTheDocument()
  }

  beforeEach(() => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('budget_exhausted', {
        timestamp: '2026-04-14T06:00:00.000Z',
        provider: 'openai',
        tier: 'L3',
        status: 'exhausted',
        cost_usd: 12.34,
        budget: {
          enabled: true,
          limit_tokens: 1000,
          scope: 'total',
          used_input_tokens: 800,
          used_output_tokens: 200,
          used_total_tokens: 1000,
          remaining_tokens: 0,
          exhausted: true,
        },
      })
      return () => {}
    })
  })

  it('renders the runtime feed shell for budget exhaustion events', async () => {
    const { container } = render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('region', { name: /live activity feed/i }),
    ).toBeInTheDocument()
    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText(/1\/1 events/i)).toBeInTheDocument()
    expect(screen.getByText('Operations stream · action-first event language')).toBeInTheDocument()
    expect(screen.getByText(/action-needed/)).toBeInTheDocument()
    expect(screen.getAllByText('Token exhausted', { selector: 'span' }).length).toBeGreaterThan(0)
    expect(container.querySelector('.runtime-event-badge-budget-exhausted')).toHaveTextContent('Token exhausted')
    expect(screen.getByText('Provider')).toBeInTheDocument()
    expect(screen.getByText('openai')).toBeInTheDocument()
    expect(screen.getByText('Tier')).toBeInTheDocument()
    expect(screen.getByText('L3')).toBeInTheDocument()
    expect(container.querySelector('.badge.badge-defer')?.textContent).toBe('L3')
    expect(
      screen.getByText((_, element) =>
        element !== null
        && element.classList.contains('text-secondary')
        && element.textContent?.includes('1,000 total tokens') === true
        && element.textContent?.includes('800 in / 200 out') === true
        && element.textContent?.includes('exhausted') === true,
      ),
    ).toBeInTheDocument()
  })

  it('renders a compact evidence summary for decision events', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('decision', {
        session_id: 'sess-001',
        event_id: 'evt-001',
        risk_level: 'high',
        decision: 'block',
        tool_name: 'bash',
        actual_tier: 'L3',
        timestamp: '2026-04-14T06:00:00.000Z',
        reason: 'L3 review completed',
        command: 'cat secrets.env',
        evidence_summary: {
          retained_sources: ['trajectory', 'file'],
          tool_calls_count: 2,
          toolkit_budget_mode: 'multi_turn',
          toolkit_budget_cap: 5,
          toolkit_calls_remaining: 0,
          toolkit_budget_exhausted: true,
        },
      })
      return () => {}
    })

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText(/1\/1 events/i)).toBeInTheDocument()
    expect(screen.getByText('Evidence:')).toBeInTheDocument()
    expect(screen.getByText('trajectory, file · 2 tool call(s) · toolkit 0/5 (exhausted)')).toBeInTheDocument()
  })

  it('renders compact enterprise live posture rows when runtime events include the enterprise contract', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('decision', {
        session_id: 'sess-enterprise',
        event_id: 'evt-enterprise',
        risk_level: 'critical',
        decision: 'block',
        tool_name: 'bash',
        actual_tier: 'L3',
        timestamp: '2026-04-14T06:00:00.000Z',
        reason: 'Enterprise stream event',
        command: 'cat secrets.env',
        live_risk_overview: {
          active_sessions: 3,
          high_risk_sessions: 2,
          mapped_active_sessions: 1,
          by_trinityguard_tier: { P1: 1, P2: 2 },
          by_trinityguard_subtype: { cascading_failure: 1 },
        },
      })
      return () => {}
    })

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expectSecondaryLine('Enterprise posture: 3 active · 2 high-risk · 1 mapped')
    expectSecondaryLine('TrinityGuard tiers: P1:1, P2:2')
  })

  it('renders L3 metadata (request, availability, state, reason code) for decision events', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('decision', {
        session_id: 'sess-002',
        event_id: 'evt-002',
        risk_level: 'high',
        decision: 'block',
        tool_name: 'bash',
        actual_tier: 'L3',
        timestamp: '2026-04-14T07:00:00.000Z',
        reason: 'Requires L3 operator review',
        command: 'cat secrets.env',
        l3_requested: true,
        l3_available: false,
        l3_reason_code: 'operator_required',
        l3_state: 'pending',
        l3_reason: 'manual approval required',
      })
      return () => {}
    })

    const { container } = render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText('Decision', { selector: 'span' })).toBeInTheDocument()

    expect(screen.getByText('block')).toHaveClass('badge-block')
    expect(screen.getByText('high')).toHaveClass('badge-risk-high')
    expect(container.querySelector('.badge-tier-l3')?.textContent).toBe('L3')

    expectSecondaryLine('L3 requested: yes')
    expectSecondaryLine('L3 available: no')
    expectSecondaryLine('L3 reason code: operator_required')
    expectSecondaryLine('L3 state: pending')
    expectSecondaryLine('L3 reason: manual approval required')
  })

  it('does not render l3_state or l3_reason when l3_state is completed', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('decision', {
        session_id: 'sess-003',
        event_id: 'evt-003',
        risk_level: 'medium',
        decision: 'allow',
        tool_name: 'bash',
        actual_tier: 'L2',
        timestamp: '2026-04-14T07:05:00.000Z',
        reason: 'Allowed after review',
        command: 'echo ok',
        l3_requested: true,
        l3_available: true,
        l3_reason_code: 'completed',
        l3_state: 'completed',
        l3_reason: 'should not render when completed',
      })
      return () => {}
    })

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expectSecondaryLine('L3 requested: yes')
    expectSecondaryLine('L3 available: yes')
    expectSecondaryLine('L3 reason code: completed')
    expect(screen.queryByText(/L3 state:/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/L3 reason:/i)).not.toBeInTheDocument()
  })

  it('renders operator-readable labels for L3 advisory job lifecycle events', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('l3_advisory_job', {
        type: 'l3_advisory_job',
        session_id: 'sess-l3',
        snapshot_id: 'snap-l3',
        job_id: 'job-l3',
        job_state: 'queued',
        runner: 'deterministic_local',
        timestamp: '2026-04-14T07:10:00.000Z',
      })
      return () => {}
    })

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText('Queued')).toHaveClass('badge-modify')
    expectSecondaryLine('Runner Deterministic local')
    expectSecondaryLine('waiting for explicit operator run')
    expectSecondaryLine('Frozen snapshot snap-l3')
  })

  it('renders L3 advisory action boundary and IDs', async () => {
    vi.mocked(createManagedSSE).mockImplementation((types, callbacks) => {
      void types
      callbacks.onStatusChange('connected')
      callbacks.onEvent('l3_advisory_action', {
        type: 'l3_advisory_action',
        action_id: 'action-l3',
        session_id: 'sess-l3',
        snapshot_id: 'snap-l3',
        job_id: 'job-l3',
        review_id: 'review-l3',
        risk_level: 'critical',
        recommended_operator_action: 'escalate',
        l3_state: 'completed',
        source_record_range: { from_record_id: 2, to_record_id: 8 },
        summary: 'L3 advisory critical risk recommends escalate; advisory only, canonical unchanged.',
        advisory_only: true,
        canonical_decision_mutated: false,
        timestamp: '2026-04-14T07:10:00.000Z',
      })
      return () => {}
    })

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expectSecondaryLine('Advisory only / canonical unchanged')
    expectSecondaryLine('Frozen range 2→8')
    expect(screen.getByText('review-l3')).toBeInTheDocument()
  })
})
