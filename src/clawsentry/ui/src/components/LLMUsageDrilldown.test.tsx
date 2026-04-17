import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import LLMUsageDrilldown from './LLMUsageDrilldown'

describe('LLMUsageDrilldown', () => {
  it('renders a compact breakdown from the snapshot', () => {
    render(
      <LLMUsageDrilldown
        snapshot={{
          total_calls: 24,
          total_input_tokens: 1200,
          total_output_tokens: 600,
          total_cost_usd: 12.34,
          by_provider: {
            openai: { calls: 20, input_tokens: 1000, output_tokens: 500, cost_usd: 10 },
            anthropic: { calls: 4, input_tokens: 200, output_tokens: 100, cost_usd: 2.34 },
          },
          by_tier: {
            L3: { calls: 18, input_tokens: 900, output_tokens: 450, cost_usd: 9 },
            L2: { calls: 6, input_tokens: 300, output_tokens: 150, cost_usd: 3.34 },
          },
          by_status: {
            ok: { calls: 22, input_tokens: 1100, output_tokens: 550, cost_usd: 11.5 },
            exhausted: { calls: 2, input_tokens: 100, output_tokens: 50, cost_usd: 0.84 },
          },
        }}
      />,
    )

    expect(screen.getByRole('region', { name: /llm usage drill-down/i })).toBeInTheDocument()
    expect(screen.getByText('LLM usage drill-down')).toBeInTheDocument()
    expect(screen.getByText(/24 calls/i)).toBeInTheDocument()
    expect(screen.getByText('$12.34')).toBeInTheDocument()
    expect(screen.getByText('Top providers')).toBeInTheDocument()
    expect(screen.getByText('openai')).toBeInTheDocument()
    expect(screen.getByText(/20 calls/i)).toBeInTheDocument()
    expect(screen.getByText(/1,000 in \/ 500 out/i)).toBeInTheDocument()
    expect(screen.getByText(/\$10\.00/i)).toBeInTheDocument()
    expect(screen.getByText('Top tiers')).toBeInTheDocument()
    expect(screen.getByText('L3')).toBeInTheDocument()
    expect(screen.getByText('Top statuses')).toBeInTheDocument()
    expect(screen.getByText('ok')).toBeInTheDocument()
  })

  it('renders an empty state when the snapshot is missing', () => {
    render(<LLMUsageDrilldown snapshot={null} />)

    expect(screen.getByRole('region', { name: /llm usage drill-down/i })).toBeInTheDocument()
    expect(screen.getByText('LLM usage drill-down')).toBeInTheDocument()
    expect(screen.getByText('No LLM usage snapshot available.')).toBeInTheDocument()
  })
})
