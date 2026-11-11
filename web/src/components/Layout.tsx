import React from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Header } from './Header'
import { Sidebar } from './Sidebar'

export function Layout() {
  const location = useLocation()

  const getPageTitle = () => {
    switch (location.pathname) {
      case '/': return 'Overview'
      case '/topology': return 'Network Topology'
      case '/attack-lab': return 'Attack Laboratory'
      case '/witnesses': return 'Witness Monitoring'
      case '/checkpoints': return 'Checkpoints'
      case '/evidence': return 'Evidence Verification'
      case '/incidents': return 'Incident History'
      case '/policies': return 'Trust Policies'
      case '/settings': return 'Settings'
      default: return 'WitnessMesh'
    }
  }

  return (
    <div className="h-full flex flex-col">
      <Header title={getPageTitle()} />
      <div className="flex-1 overflow-auto">
        <div className="main-body">
          <Outlet />
        </div>
      </div>
    </div>
  )
}