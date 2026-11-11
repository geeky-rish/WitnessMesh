import React from 'react'
import { Bell, ChevronDown, User, LogOut, Menu } from 'lucide-react'

interface HeaderProps {
  title: string
}

export function Header({ title }: HeaderProps) {
  return (
    <header className="main-header">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="text-xl font-semibold text-[#233746]">{title}</h1>
        </div>
        <div className="flex items-center gap-3">
          {/* System status indicator */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-[#F2F3F4]">
            <span className="status-dot status-healthy" />
            <span className="text-sm font-medium text-[#233746]">Operational</span>
          </div>

          {/* Notifications */}
          <button className="p-2 rounded-lg hover:bg-[#F2F3F4] text-[#75818A] transition-colors" aria-label="Notifications">
            <Bell className="w-5 h-5" />
          </button>

          {/* User menu */}
          <div className="relative">
            <button className="flex items-center gap-2 p-2 rounded-lg hover:bg-[#F2F3F4] text-[#75818A] transition-colors" aria-label="User menu">
              <div className="w-8 h-8 rounded-full bg-[#328C89] flex items-center justify-center text-white text-sm font-medium">
                A
              </div>
              <ChevronDown className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  )
}