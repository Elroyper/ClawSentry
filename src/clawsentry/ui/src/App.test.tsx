import { render, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

const mocks = vi.hoisted(() => ({
  setToken: vi.fn(),
  check: vi.fn(),
  login: vi.fn(),
}))

vi.mock('./api/client', () => ({
  setToken: mocks.setToken,
}))

vi.mock('./hooks/useAuth', () => ({
  useAuth: () => ({
    authenticated: false,
    checking: false,
    authFailure: null,
    check: mocks.check,
    login: mocks.login,
  }),
}))

describe('App auth bootstrap', () => {
  afterEach(() => {
    mocks.setToken.mockClear()
    mocks.check.mockClear()
    mocks.login.mockClear()
    window.history.replaceState({}, '', '/')
  })

  it('auto-logins from ?token= and removes only the token query parameter before auth check', async () => {
    window.history.replaceState({}, '', '/ui/sessions?token=secret-token&view=active')

    render(<App />)

    await waitFor(() => expect(mocks.setToken).toHaveBeenCalledWith('secret-token'))
    await waitFor(() => expect(mocks.check).toHaveBeenCalled())

    expect(window.location.pathname).toBe('/ui/sessions')
    expect(window.location.search).toBe('?view=active')
    expect(window.location.href).not.toContain('secret-token')
  })
})
