import React from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Header } from './Header'

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
      <div className="flex-1 overflow-auto flex flex-col justify-between">
        <div className="main-body flex-1">
          <Outlet />
        </div>
        <footer className="py-2.5 px-6 border-t border-[#DCE1E5] bg-[#FAFBFB] flex flex-wrap items-center justify-between text-xs text-[#75818A]">
          <div className="flex items-center gap-2">
            <span>WitnessMesh CNS Trust Monitor</span>
            <span>•</span>
            <span className="font-mono text-[11px] text-[#75818A]/80">RFC 9162 / C2SP</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span>Maintained by Rishi Kulkarni</span>
            <span>•</span>
            <a
              href="https://github.com/geeky-rish"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#328C89] hover:underline flex items-center gap-1 font-mono text-[11px]"
            >
              github.com/geeky-rish
            </a>
          </div>
        </footer>
      </div>
    </div>
  )
}