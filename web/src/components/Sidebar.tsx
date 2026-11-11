import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  Home,
  GitBranch,
  AlertTriangle,
  Shield,
  FileText,
  Search,
  AlertCircle,
  Key,
  Settings,
} from 'lucide-react'

const navigation = [
  { path: '/', label: 'Overview', icon: Home },
  { path: '/topology', label: 'Network Topology', icon: GitBranch },
  { path: '/attack-lab', label: 'Attack Laboratory', icon: AlertTriangle },
  { path: '/witnesses', label: 'Witness Monitoring', icon: Shield },
  { path: '/checkpoints', label: 'Checkpoints', icon: FileText },
  { path: '/evidence', label: 'Evidence Verification', icon: Search },
  { path: '/incidents', label: 'Incident History', icon: AlertCircle },
  { path: '/policies', label: 'Trust Policies', icon: Key },
  { path: '/settings', label: 'Settings', icon: Settings },
]

export function Sidebar() {
  return (
    <aside className="sidebar" role="navigation" aria-label="Main navigation">
      <div className="sidebar-header">
        <h1 className="text-lg font-semibold">WitnessMesh</h1>
      </div>

      <nav className="sidebar-nav" role="list">
        {navigation.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `sidebar-nav-item ${isActive ? 'active' : ''}`
            }
            role="listitem"
            aria-current={({ isActive }) => isActive ? 'page' : undefined}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="flex items-center gap-3 p-2 bg-white/5 rounded-lg">
          <span className="status-dot status-healthy" />
          <span className="text-xs text-[#E8EDF1]/80">System Operational</span>
        </div>
      </div>
    </aside>
  )
}