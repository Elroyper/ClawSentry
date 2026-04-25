import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Sessions from './Sessions'
import { api } from '../api/client'
import { createManagedSSE } from '../api/sse'

vi.mock('../api/client', () => ({
  api: {
    sessions: vi.fn(),
  },
}))

vi.mock('../api/sse', () => ({
  createManagedSSE: vi.fn(),
}))

function makeSession(overrides: Record<string, unknown> = {}) {
  return {
    session_id: 'sess-budget',
    agent_id: 'agent-1',
    source_framework: 'codex',
    caller_adapter: 'codex-http',
    workspace_root: '/workspace/demo',
    transcript_path: '/workspace/demo/session.jsonl',
    current_risk_level: 'high',
    cumulative_score: 0.9,
    latest_composite_score: 0.94,
    session_risk_ewma: 0.82,
    risk_velocity: 'up',
    window_risk_summary: {
      window_seconds: 3600,
      event_count: 12,
      high_risk_event_count: 3,
      risk_density: 0.25,
    },
    event_count: 4,
    high_risk_event_count: 1,
    decision_distribution: { allow: 2, block: 1 },
    first_event_at: '2026-04-15T08:00:00Z',
    last_event_at: '2026-04-15T08:05:00Z',
    evidence_summary: {
      retained_sources: ['trajectory', 'file'],
      tool_calls_count: 2,
      toolkit_budget_mode: 'multi_turn',
      toolkit_budget_cap: 5,
      toolkit_calls_remaining: 0,
      toolkit_budget_exhausted: true,
    },
    ...overrides,
  }
}

function renderSessions(initialEntries = ['/sessions']) {
  return render(
    <MemoryRouter initialEntries={initialEntries} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Sessions />
    </MemoryRouter>,
  )
}

describe('Sessions inventory', () => {
  beforeEach(() => {
    vi.mocked(createManagedSSE).mockReturnValue(() => {})
    vi.mocked(api.sessions).mockResolvedValue([
      makeSession({ session_id: 'sess-budget-codex', agent_id: 'agent-alpha', source_framework: 'codex' }),
      makeSession({ session_id: 'sess-normal-codex', agent_id: 'agent-beta', source_framework: 'codex', evidence_summary: null }),
      makeSession({ session_id: 'sess-budget-openclaw', agent_id: 'agent-gamma', source_framework: 'openclaw' }),
    ] as never)
  })

  it('filters to budget-exhausted sessions without breaking framework, risk, or query filtering', async () => {
    renderSessions()

    expect(screen.getByRole('region', { name: 'Session filters' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Framework Overview' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Session inventory' })).toBeInTheDocument()

    expect(await screen.findByText('sess-budget-codex')).toBeInTheDocument()
    expect(screen.getByText('sess-normal-codex')).toBeInTheDocument()
    expect(screen.getByText('sess-budget-openclaw')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Budget exhausted only' }))
    expect(screen.getByRole('button', { name: 'Budget exhausted only' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText('sess-budget-codex')).toBeInTheDocument()
    expect(screen.getByText('sess-budget-openclaw')).toBeInTheDocument()
    expect(screen.queryByText('sess-normal-codex')).not.toBeInTheDocument()

    fireEvent.change(screen.getByRole('combobox', { name: 'Framework filter' }), {
      target: { value: 'codex' },
    })
    expect(screen.getByText('sess-budget-codex')).toBeInTheDocument()
    expect(screen.queryByText('sess-budget-openclaw')).not.toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: 'Search sessions' }), {
      target: { value: 'agent-alpha' },
    })
    await waitFor(() => {
      expect(screen.getByText('sess-budget-codex')).toBeInTheDocument()
      expect(screen.queryByText('sess-normal-codex')).not.toBeInTheDocument()
    })

    fireEvent.change(screen.getByRole('combobox', { name: 'Risk filter' }), {
      target: { value: 'high' },
    })
    await waitFor(() => {
      expect(vi.mocked(api.sessions)).toHaveBeenCalledWith(
        expect.objectContaining({ min_risk: 'high' }),
      )
    })
  })

  it('hydrates URL-backed action, risk, framework, and search filters', async () => {
    renderSessions(['/sessions?minRisk=high&framework=codex&q=agent-alpha&action=budget&budget=exhausted'])

    expect(await screen.findByText('sess-budget-codex')).toBeInTheDocument()
    expect(screen.queryByText('sess-normal-codex')).not.toBeInTheDocument()
    expect(screen.queryByText('sess-budget-openclaw')).not.toBeInTheDocument()

    expect(screen.getByRole('combobox', { name: 'Risk filter' })).toHaveValue('high')
    expect(screen.getByRole('combobox', { name: 'Framework filter' })).toHaveValue('codex')
    expect(screen.getByRole('combobox', { name: 'Action filter' })).toHaveValue('budget')
    expect(screen.getByRole('textbox', { name: 'Search sessions' })).toHaveValue('agent-alpha')
    expect(screen.getByRole('button', { name: 'Budget exhausted only' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('shows latest score, EWMA, velocity, and density hints in session rows', async () => {
    renderSessions()

    expect(await screen.findByText('sess-budget-codex')).toBeInTheDocument()
    expect(screen.getAllByText('Latest 0.94').length).toBeGreaterThan(0)
    expect(screen.getAllByText('EWMA 0.82').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Velocity up').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Density 0.25').length).toBeGreaterThan(0)
  })
})
