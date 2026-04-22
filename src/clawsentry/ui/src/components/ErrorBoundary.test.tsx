import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import ErrorBoundary from './ErrorBoundary'

function ThrowingChild() {
  throw new Error('render failed')
  return null
}

describe('ErrorBoundary', () => {
  it('renders a class-based fallback with a dismiss action', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)

    render(
      <ErrorBoundary>
        <ThrowingChild />
      </ErrorBoundary>,
    )

    expect(screen.getByText('Page Error')).toHaveClass('error-boundary-title')
    expect(screen.getByText('render failed')).toHaveClass('error-boundary-message')
    expect(screen.getByRole('button', { name: /dismiss/i })).toHaveClass('btn')
    consoleError.mockRestore()
  })
})
