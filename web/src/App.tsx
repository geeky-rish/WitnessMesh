import React, { useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { NetworkTopology } from './pages/NetworkTopology'
import { AttackLab } from './pages/AttackLab'
import { WitnessMonitoring } from './pages/WitnessMonitoring'
import { Checkpoints } from './pages/Checkpoints'
import { EvidenceVerification } from './pages/EvidenceVerification'
import { IncidentHistory } from './pages/IncidentHistory'
import { TrustPolicies } from './pages/TrustPolicies'
import { Settings } from './pages/Settings'

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
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

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

export default App
