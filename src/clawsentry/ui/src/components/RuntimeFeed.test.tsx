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
          daily_budget_usd: 123.45,
          daily_spend_usd: 123.45,
          remaining_usd: 0,
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

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText(/1\/1 events/i)).toBeInTheDocument()
    expect(screen.getByText('Budget Exhausted', { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText('Budget exhausted')).toHaveClass('badge-block')
    expect(screen.getByText('Provider')).toBeInTheDocument()
    expect(screen.getByText('openai')).toBeInTheDocument()
    expect(screen.getByText('Tier')).toBeInTheDocument()
    expect(screen.getByText('L3')).toBeInTheDocument()
    expect(container.querySelector('.badge.badge-defer')?.textContent).toBe('L3')
    expect(screen.getByText('Cost')).toBeInTheDocument()
    expect(screen.getByText('$12.34')).toBeInTheDocument()
    expect(
      screen.getByText((_, element) =>
        element !== null
        && element.classList.contains('text-secondary')
        && element.textContent?.includes('Budget exhausted: yes') === true
        && element.textContent?.includes('Daily spend $123.45 / $123.45') === true
        && element.textContent?.includes('Remaining $0.00') === true,
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
})
