import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import RuntimeFeed from './RuntimeFeed'
import { createManagedSSE } from '../api/sse'

vi.mock('../api/sse', () => ({
  createManagedSSE: vi.fn(),
}))

describe('RuntimeFeed', () => {
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
    render(
      <MemoryRouter>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText(/1\/1 events/i)).toBeInTheDocument()
    expect(screen.getByText('Provider')).toBeInTheDocument()
    expect(screen.getByText('openai')).toBeInTheDocument()
    expect(screen.getByText('Tier')).toBeInTheDocument()
    expect(screen.getByText('L3')).toBeInTheDocument()
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
        },
      })
      return () => {}
    })

    render(
      <MemoryRouter>
        <RuntimeFeed />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/live activity feed/i)).toBeInTheDocument()
    expect(screen.getByText(/1\/1 events/i)).toBeInTheDocument()
    expect(screen.getByText('Evidence:')).toBeInTheDocument()
    expect(screen.getByText('trajectory, file · 2 tool call(s)')).toBeInTheDocument()
  })
})
