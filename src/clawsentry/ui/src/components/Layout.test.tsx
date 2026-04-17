import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import Layout from './Layout'

vi.mock('./StatusBar', () => ({
  default: () => <div data-testid="status-bar" />,
}))

describe('Layout', () => {
  it('exposes the shell landmarks and session page title', () => {
    render(
      <MemoryRouter initialEntries={['/sessions']}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/sessions" element={<div>Sessions page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByRole('complementary')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument()
    expect(screen.getByRole('banner')).toBeInTheDocument()
    expect(screen.getByRole('main')).toBeInTheDocument()
    expect(screen.getByText('Session Inventory')).toBeInTheDocument()
  })
})
