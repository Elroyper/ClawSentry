import { useState, FormEvent } from 'react'

interface LoginFormProps {
  onLogin: (token: string) => void
}

export default function LoginForm({ onLogin }: LoginFormProps) {
  const [token, setToken] = useState('')

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (token.trim()) {
      onLogin(token.trim())
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <p className="eyebrow">Secure access</p>
        <h2>CLAWSENTRY</h2>
        <div className="subtitle">Enter your AHP auth token to connect</div>
        <form className="login-form" onSubmit={handleSubmit}>
          <label className="login-label" htmlFor="auth-token">
            Auth token
          </label>
          <input
            id="auth-token"
            type="password"
            className="login-input"
            placeholder="CS_AUTH_TOKEN"
            value={token}
            onChange={e => setToken(e.target.value)}
            autoFocus
          />
          <button
            type="submit"
            className="btn btn-primary login-button"
          >
            Connect
          </button>
        </form>
      </div>
    </div>
  )
}
