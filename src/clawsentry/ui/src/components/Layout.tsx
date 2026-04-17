import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { LayoutDashboard, Users, AlertTriangle, ShieldCheck } from 'lucide-react'
import StatusBar from './StatusBar'
import ErrorBoundary from './ErrorBoundary'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/sessions', icon: Users, label: 'Sessions' },
  { to: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { to: '/defer', icon: ShieldCheck, label: 'DEFER Panel' },
]

const PAGE_TITLES: Record<string, string> = {
  '/': 'Security Console',
  '/sessions': 'Session Inventory',
  '/alerts': 'Alerts',
  '/defer': 'DEFER Panel',
}

export default function Layout() {
  const location = useLocation()
  const title = Object.entries(PAGE_TITLES)
    .sort(([a], [b]) => b.length - a.length)
    .find(([path]) => location.pathname.startsWith(path))?.[1] ?? 'ClawSentry'

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">ClawSentry</div>
          <div className="subtitle">Security Operations Console</div>
        </div>
        <nav className="sidebar-nav" aria-label="Primary">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              <Icon />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          Framework / Workspace / Session
        </div>
      </aside>
      <section className="main-content">
        <header className="topbar" role="banner">
          <div className="topbar-heading">
            <p className="topbar-kicker">Operator Console</p>
            <span className="topbar-title">{title}</span>
          </div>
          <StatusBar />
        </header>
        <main className="page-content fade-in" role="main">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </section>
    </div>
  )
}
