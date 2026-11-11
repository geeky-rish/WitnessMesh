import React, { useState } from 'react'
import { Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Overview } from './pages/Overview'
import { NetworkTopology } from './pages/NetworkTopology'
import { AttackLab } from './pages/AttackLab'
import { WitnessMonitoring } from './pages/WitnessMonitoring'
import { Checkpoints } from './pages/Checkpoints'
import { EvidenceVerification } from './pages/EvidenceVerification'
import { IncidentHistory } from './pages/IncidentHistory'
import { TrustPolicies } from './pages/TrustPolicies'
import { Settings } from './pages/Settings'

const navigation = [
  { path: '/', label: 'Overview', icon: 'Home' },
  { path: '/topology', label: 'Network Topology', icon: 'Network' },
  { path: '/attack-lab', label: 'Attack Laboratory', icon: 'AlertTriangle' },
  { path: '/witnesses', label: 'Witness Monitoring', icon: 'Shield' },
  { path: '/checkpoints', label: 'Checkpoints', icon: 'FileText' },
  { path: '/evidence', label: 'Evidence Verification', icon: 'Search' },
  { path: '/incidents', label: 'Incident History', icon: 'AlertCircle' },
  { path: '/policies', label: 'Trust Policies', icon: 'Key' },
  { path: '/settings', label: 'Settings', icon: 'Settings' },
]

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="h-screen flex">
      {/* Mobile sidebar toggle */}
      <button
        className="lg:hidden fixed top-4 left-4 z-50 btn-primary p-2"
        onClick={() => setSidebarOpen(true)}
        aria-label="Open navigation"
      >
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {/* Sidebar */}
      <aside
        className={`sidebar transition-transform duration-300 ease-in-out lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="sidebar-header flex items-center justify-between">
          <h1 className="text-lg font-semibold">WitnessMesh</h1>
          <button
            className="lg:hidden p-1 text-[#E8EDF1]/60 hover:text-white"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close navigation"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <nav className="sidebar-nav" role="list">
          {navigation.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              icon={item.icon}
              label={item.label}
              onClick={() => setSidebarOpen(false)}
            />
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="flex items-center gap-3 p-2 bg-white/5 rounded-lg">
            <div className="w-2.5 h-2.5 rounded-full bg-[#328C89]" />
            <span className="text-xs text-[#E8EDF1]/80">System Operational</span>
          </div>
        </div>
      </aside>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/50 z-40"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Main content */}
      <main className="main-content flex flex-col min-h-screen">
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="topology" element={<NetworkTopology />} />
            <Route path="attack-lab" element={<AttackLab />} />
            <Route path="witnesses" element={<WitnessMonitoring />} />
            <Route path="checkpoints" element={<Checkpoints />} />
            <Route path="evidence" element={<EvidenceVerification />} />
            <Route path="incidents" element={<IncidentHistory />} />
            <Route path="policies" element={<TrustPolicies />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </main>
    </div>
  )
}

interface NavLinkProps {
  to: string
  icon: string
  label: string
  onClick: () => void
}

function NavLink({ to, icon: IconName, label, onClick }: NavLinkProps) {
  const [isActive, setIsActive] = useState(false)

  // We'll use a simpler approach for active state
  // In a real app, you'd use useLocation from react-router-dom
  // For now, we'll just handle click

  const icons: Record<string, React.ReactNode> = {
    Home: <HomeIcon />,
    Network: <NetworkIcon />,
    AlertTriangle: <AlertTriangleIcon />,
    Shield: <ShieldIcon />,
    FileText: <FileTextIcon />,
    Search: <SearchIcon />,
    AlertCircle: <AlertCircleIcon />,
    Key: <KeyIcon />,
    Settings: <SettingsIcon />,
  }

  return (
    <button
      role="listitem"
      onClick={onClick}
      className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
      aria-current={isActive ? 'page' : undefined}
    >
      {icons[IconName] || <HomeIcon />}
      <span>{label}</span>
    </button>
  )
}

// Icon components
function HomeIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
    </svg>
  )
}

function NetworkIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
    </svg>
  )
}

function AlertTriangleIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  )
}

function ShieldIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  )
}

function FileTextIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  )
}

function SearchIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
    </svg>
  )
}

function AlertCircleIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  )
}

function KeyIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
    </svg>
  )
}

function SettingsIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  )
}

export default App