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
  X,
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

interface SidebarProps {
  open?: boolean
  onClose?: () => void
}

export function Sidebar({ open = false, onClose }: SidebarProps) {
  return (
    <aside
      className={`sidebar transition-transform duration-300 ease-in-out lg:translate-x-0 ${
        open ? 'translate-x-0' : '-translate-x-full'
      }`}
      role="navigation"
      aria-label="Main navigation"
    >
      <div className="sidebar-header flex items-center justify-between">
        <h1 className="text-lg font-semibold">WitnessMesh</h1>
        <button
          className="lg:hidden p-1 text-[#E8EDF1]/60 hover:text-white"
          onClick={onClose}
          aria-label="Close navigation"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <nav className="sidebar-nav" role="list">
        {navigation.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            onClick={onClose}
            className={({ isActive }) =>
              `sidebar-nav-item ${isActive ? 'active' : ''}`
            }
            role="listitem"
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
        <div className="pt-2 px-2 flex items-center justify-between text-[11px] text-[#E8EDF1]/40">
          <span>v1.0.0</span>
          <a
            href="https://github.com/geeky-rish"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white/70 transition-colors font-mono"
          >
            @geeky-rish
          </a>
        </div>
      </div>
    </aside>
  )
}
