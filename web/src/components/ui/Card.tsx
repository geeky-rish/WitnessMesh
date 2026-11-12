import React from 'react'

export interface CardProps {
  children: React.ReactNode
  className?: string
  style?: React.CSSProperties
}

export function Card({ children, className = '', style }: CardProps) {
  return (
    <div className={`card ${className}`} style={style}>
      {children}
    </div>
  )
}

export interface StatCardProps {
  label: string
  value: number | string
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
  color: string
  trend?: string
  trendColor?: string
}

export function StatCard({ label, value, icon: Icon, color, trend, trendColor }: StatCardProps) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-[#75818A] mb-1">{label}</p>
          <p className="text-3xl font-semibold text-[#233746]">{value}</p>
          {trend && (
            <p className="text-xs font-medium mt-1" style={{ color: trendColor || '#75818A' }}>
              {trend}
            </p>
          )}
        </div>
        <div
          className="w-12 h-12 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}15` }}
        >
          <Icon className="w-6 h-6" style={{ color }} />
        </div>
      </div>
    </Card>
  )
}