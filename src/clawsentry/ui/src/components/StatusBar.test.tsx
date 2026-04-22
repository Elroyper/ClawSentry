import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import StatusBar from './StatusBar'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    health: vi.fn(),
  },
}))

describe('StatusBar', () => {
  beforeEach(() => {
    vi.mocked(api.health).mockResolvedValue({
      status: 'ok',
      uptime_seconds: 3661,
      cache_size: 0,
      trajectory_count: 1234,
      policy_engine: 'default',
      auth_enabled: true,
      budget: {
        daily_budget_usd: 123.45,
        daily_spend_usd: 12.34,
        remaining_usd: 111.11,
        exhausted: false,
      },
    })
  })

  it('renders the health summary from the API', async () => {
    render(<StatusBar />)

    expect(await screen.findByText(/1h 1m uptime/i)).toBeInTheDocument()
    expect(screen.getByText(/1,234 events/i)).toBeInTheDocument()
    expect(screen.getByText(/Daily budget \$123\.45/i)).toBeInTheDocument()
    expect(screen.getByText(/Spend \$12\.34/i)).toBeInTheDocument()
    expect(screen.getByText(/Remaining \$111\.11/i)).toBeInTheDocument()
    expect(screen.getByText(/Active/i)).toBeInTheDocument()
    expect(screen.getByRole('status', { name: /gateway connection status/i })).toHaveTextContent('CONNECTED')
    expect(screen.getByRole('status', { name: /gateway connection status/i })).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByRole('status', { name: /gateway connection status/i })).toHaveAttribute('aria-atomic', 'true')
  })

  it('uses class-based styling for budget exhaustion copy', async () => {
    vi.mocked(api.health).mockResolvedValue({
      status: 'ok',
      uptime_seconds: 120,
      cache_size: 0,
      trajectory_count: 42,
      policy_engine: 'default',
      auth_enabled: true,
      budget: {
        daily_budget_usd: 10,
        daily_spend_usd: 10,
        remaining_usd: 0,
        exhausted: true,
      },
      budget_exhaustion_event: {
        type: 'budget_exhausted',
        timestamp: '2026-04-22T00:00:00Z',
        provider: 'openai',
        tier: 'L3',
        status: 'degraded',
        cost_usd: 0.25,
        budget: {
          daily_budget_usd: 10,
          daily_spend_usd: 10,
          remaining_usd: 0,
          exhausted: true,
        },
      },
    })

    render(<StatusBar />)

    expect(await screen.findByText(/BUDGET EXHAUSTED/i)).toHaveClass('status-budget-exhausted')
    expect(screen.getByText(/Operator action required/i)).toHaveClass('status-budget-note')
    expect(screen.getByText(/openai \/ L3 \/ \$0\.25/i)).toHaveClass('status-budget-note')
  })
})
