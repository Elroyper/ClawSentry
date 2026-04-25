import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import { setToken } from './api/client'
import Layout from './components/Layout'
import LoginForm from './components/LoginForm'
import Dashboard from './pages/Dashboard'
import Sessions from './pages/Sessions'
import SessionDetail from './pages/SessionDetail'
import Alerts from './pages/Alerts'
import DeferPanel from './pages/DeferPanel'

export default function App() {
  const { authenticated, checking, authFailure, check, login } = useAuth()
  const [bootstrapped, setBootstrapped] = useState(false)

  // Auto-login from URL ?token= parameter
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const urlToken = params.get('token')
    if (urlToken) {
      setToken(urlToken)
      // Remove token from URL bar (security: don't leave it visible)
      params.delete('token')
      const cleanUrl = params.toString()
        ? `${window.location.pathname}?${params.toString()}`
        : window.location.pathname
      window.history.replaceState({}, '', cleanUrl)
    }
    setBootstrapped(true)
  }, [])

  useEffect(() => {
    if (!bootstrapped) return
    check()
  }, [bootstrapped, check])

  if (!bootstrapped || authenticated === null) {
    return (
      <div className="login-container">
        <div style={{ textAlign: 'center' }}>
          <span className="status-dot checking" style={{ width: 12, height: 12 }} />
          <p className="text-muted mono" style={{ marginTop: 12, fontSize: '0.8rem' }}>Connecting...</p>
        </div>
      </div>
    )
  }

  if (authenticated === false) {
    return <LoginForm onLogin={login} authFailure={authFailure} checking={checking} />
  }

  return (
    <BrowserRouter basename="/ui">
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="sessions/:sessionId" element={<SessionDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="defer" element={<DeferPanel />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
