import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Alerts from './Alerts'
import { api } from '../api/client'
import { connectSSE } from '../api/sse'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      alerts: vi.fn(),
      acknowledgeAlert: vi.fn(),
    },
  }
})

vi.mock('../api/sse', () => ({
  connectSSE: vi.fn(),
}))

class MockEventSource {
  private listeners = new Map<string, Array<(event: MessageEvent) => void>>()

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    const current = this.listeners.get(type) ?? []
    current.push(listener)
    this.listeners.set(type, current)
  }

  close = vi.fn()

  emit(type: string, payload: unknown) {
    const event = new MessageEvent(type, { data: JSON.stringify(payload) })
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event)
    }
  }
}

function makeAlert(overrides: Record<string, unknown> = {}) {
  return {
    alert_id: 'alert-1',
    severity: 'high',
    metric: 'policy_violation_rate',
    session_id: 'sess-123456789abc',
    message: 'Policy violation threshold exceeded',
    details: {},
    triggered_at: '2026-04-15T08:00:00Z',
    acknowledged: false,
    acknowledged_by: null,
    acknowledged_at: null,
    ...overrides,
  }
}

function renderAlerts() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Alerts />
    </MemoryRouter>,
  )
}

describe('Alerts workbench', () => {
  let eventSource: MockEventSource

  beforeEach(() => {
    eventSource = new MockEventSource()
    vi.mocked(connectSSE).mockReturnValue(eventSource as unknown as EventSource)
    vi.mocked(api.alerts).mockResolvedValue([
      makeAlert(),
      makeAlert({
        alert_id: 'alert-2',
        severity: 'low',
        metric: 'inactive_watch',
        message: 'Background monitor heartbeat restored',
        acknowledged: true,
        acknowledged_by: 'operator',
        acknowledged_at: '2026-04-15T08:05:00Z',
      }),
    ] as never)
    vi.mocked(api.acknowledgeAlert).mockResolvedValue({ status: 'ok' } as never)
  })

  it('renders the operator workbench hierarchy and acknowledges open alerts', async () => {
    renderAlerts()

    expect(await screen.findByRole('heading', { level: 1, name: /alerts workbench/i })).toBeInTheDocument()
    const overview = screen.getByRole('region', { name: /alerts overview/i })
    expect(overview).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /alerts filters/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /alerts triage queue/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /severity filter/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /alert status filter/i })).toBeInTheDocument()
    expect(within(overview).getByText('2 total alerts')).toBeInTheDocument()
    expect(within(overview).getByText('1 open')).toBeInTheDocument()

    const triageQueue = screen.getByRole('region', { name: /alerts triage queue/i })
    expect(within(triageQueue).getByText('Policy violation threshold exceeded')).toBeInTheDocument()
    expect(within(triageQueue).getAllByText('policy_violation_rate').length).toBeGreaterThan(0)

    fireEvent.click(screen.getByRole('button', { name: /acknowledge alert policy violation threshold exceeded/i }))

    await waitFor(() => {
      expect(api.acknowledgeAlert).toHaveBeenCalledWith('alert-1')
    })
    expect(within(overview).getByText('0 open')).toBeInTheDocument()
    expect(within(overview).getByText('2 acknowledged')).toBeInTheDocument()
  })

  it('adds live alerts into the triage queue and normalizes warning severity', async () => {
    renderAlerts()

    expect(await screen.findByRole('heading', { level: 1, name: /alerts workbench/i })).toBeInTheDocument()

    eventSource.emit('alert', {
      alert_id: 'alert-live',
      severity: 'warning',
      metric: 'risk_velocity',
      session_id: 'sess-live',
      current_risk: 'medium',
      message: 'Risk velocity increased sharply',
      timestamp: '2026-04-15T08:06:00Z',
    })

    const triageQueue = screen.getByRole('region', { name: /alerts triage queue/i })
    expect(await within(triageQueue).findByText('Risk velocity increased sharply')).toBeInTheDocument()
    expect(within(triageQueue).getAllByText('risk_velocity').length).toBeGreaterThan(0)
    expect(within(triageQueue).getAllByText('medium').length).toBeGreaterThan(0)
    expect(screen.getAllByText('2 open').length).toBeGreaterThan(0)
  })

  it('distinguishes an unavailable alerts source from an empty queue', async () => {
    vi.mocked(api.alerts).mockRejectedValueOnce(new Error('gateway unavailable') as never)

    renderAlerts()

    expect(await screen.findByText('Alerts source unavailable')).toBeInTheDocument()
    expect(screen.getByText(/gateway alerts endpoint could not be reached/i)).toBeInTheDocument()
    expect(screen.queryByText('No alerts match the current filters')).not.toBeInTheDocument()
  })
})
