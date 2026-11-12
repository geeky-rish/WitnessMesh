import React, { useState, useEffect } from 'react'
import {
  Shield,
  Users,
  FileText,
  AlertTriangle,
  TrendingUp,
  Activity,
  CheckCircle,
  XCircle,
  Clock,
} from 'lucide-react'
import { Card, StatCard } from '../components/ui/Card'
import { Table } from '../components/ui/Table'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

interface Witness {
  id: string
  name: string
  status: 'healthy' | 'warning' | 'critical' | 'unknown'
  lastSeen: string
  cosignatures: number
}

interface Incident {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  logId: string
  description: string
}

interface CheckpointStat {
  time: string
  verified: number
  failed: number
}

const mockWitnesses: Witness[] = [
  { id: 'w0', name: 'witness-0', status: 'healthy', lastSeen: '2s ago', cosignatures: 47 },
  { id: 'w1', name: 'witness-1', status: 'healthy', lastSeen: '1s ago', cosignatures: 47 },
  { id: 'w2', name: 'witness-2', status: 'healthy', lastSeen: '3s ago', cosignatures: 46 },
]

const mockIncidents: Incident[] = [
  { id: 'inc-001', type: 'Log Fork', severity: 'critical', timestamp: '2024-01-15 10:23', logId: 'log-abc123', description: 'Same-size fork detected at tree size 1,234' },
  { id: 'inc-002', type: 'Witness Equivocation', severity: 'high', timestamp: '2024-01-14 14:56', logId: 'log-abc123', description: 'Witness-1 signed conflicting checkpoints' },
  { id: 'inc-003', type: 'Missing Checkpoint', severity: 'medium', timestamp: '2024-01-13 09:12', logId: 'log-abc123', description: 'No checkpoint received for 5 minutes' },
  { id: 'inc-004', type: 'Stale Checkpoint', severity: 'low', timestamp: '2024-01-12 16:45', logId: 'log-abc123', description: 'Checkpoint older than threshold' },
]

const mockCheckpointData: CheckpointStat[] = [
  { time: '00:00', verified: 45, failed: 0 },
  { time: '04:00', verified: 47, failed: 0 },
  { time: '08:00', verified: 46, failed: 1 },
  { time: '12:00', verified: 48, failed: 0 },
  { time: '16:00', verified: 47, failed: 0 },
  { time: '20:00', verified: 47, failed: 0 },
]

const mockActivityData = [
  { time: '00:00', checkpoints: 12, incidents: 0 },
  { time: '04:00', checkpoints: 15, incidents: 0 },
  { time: '08:00', checkpoints: 14, incidents: 1 },
  { time: '12:00', checkpoints: 16, incidents: 0 },
  { time: '16:00', checkpoints: 15, incidents: 0 },
  { time: '20:00', checkpoints: 14, incidents: 0 },
]

export function Overview() {
  const [stats, setStats] = useState({
    activeWitnesses: 3,
    connectedClients: 2,
    verifiedCheckpoints: 142,
    activeIncidents: 1,
  })

  const [witnesses] = useState(mockWitnesses)
  const [incidents] = useState(mockIncidents)
  const [checkpointData] = useState(mockCheckpointData)
  const [activityData] = useState(mockActivityData)

  const statCards = [
    {
      label: 'Active Witnesses',
      value: stats.activeWitnesses,
      icon: Shield,
      color: '#328C89',
      trend: '+0%',
      trendColor: '#27865B',
    },
    {
      label: 'Connected Clients',
      value: stats.connectedClients,
      icon: Users,
      color: '#328C89',
      trend: '+0%',
      trendColor: '#27865B',
    },
    {
      label: 'Verified Checkpoints',
      value: stats.verifiedCheckpoints,
      icon: FileText,
      color: '#328C89',
      trend: '+12 today',
      trendColor: '#27865B',
    },
    {
      label: 'Active Incidents',
      value: stats.activeIncidents,
      icon: AlertTriangle,
      color: '#C74747',
      trend: '1 critical',
      trendColor: '#C74747',
    },
  ]

  const witnessColumns = [
    { key: 'name', header: 'Witness', render: (w: Witness) => (
      <div className="flex items-center gap-2">
        <span className={`status-dot status-${w.status}`} />
        <span className="font-medium">{w.name}</span>
      </div>
    )},
    { key: 'status', header: 'Status', render: (w: Witness) => (
      <span className={`badge badge-${w.status === 'healthy' ? 'success' : w.status === 'warning' ? 'warning' : 'danger'}`}>
        {w.status.charAt(0).toUpperCase() + w.status.slice(1)}
      </span>
    )},
    { key: 'lastSeen', header: 'Last Seen', render: (w: Witness) => <span className="text-[#75818A]">{w.lastSeen}</span> },
    { key: 'cosignatures', header: 'Cosignatures', render: (w: Witness) => <span className="mono">{w.cosignatures}</span> },
  ]

  const incidentColumns = [
    { key: 'id', header: 'ID', render: (i: Incident) => <span className="mono">{i.id}</span> },
    { key: 'type', header: 'Type', render: (i: Incident) => <span>{i.type}</span> },
    { key: 'severity', header: 'Severity', render: (i: Incident) => (
      <span className={`incident-severity incident-severity-${i.severity}`}>
        {i.severity.charAt(0).toUpperCase() + i.severity.slice(1)}
      </span>
    )},
    { key: 'timestamp', header: 'Time', render: (i: Incident) => <span className="text-[#75818A]">{i.timestamp}</span> },
    { key: 'logId', header: 'Log', render: (i: Incident) => <span className="mono">{i.logId.slice(0, 12)}...</span> },
    { key: 'description', header: 'Description', render: (i: Incident) => <span className="text-[#75818A] max-w-xs truncate">{i.description}</span> },
  ]

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Overview</h2>
          <p className="text-[#75818A] mt-1">System health and security monitoring dashboard</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-sm text-[#75818A]">
            <Activity className="w-4 h-4 text-[#27865B]" />
            Live
          </span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="stats-grid">
        {statCards.map((stat, i) => (
          <StatCard key={i} {...stat} />
        ))}
      </div>

      {/* Main content grid */}
      <div className="section-grid">
        {/* Witness Health */}
        <Card>
          <div className="card-header flex items-center justify-between">
            <h3 className="font-medium text-[#233746]">Witness Health</h3>
            <span className="badge badge-success">All Healthy</span>
          </div>
          <div className="card-body p-0">
            <Table data={witnesses} columns={witnessColumns} />
          </div>
        </Card>

        {/* Recent Incidents */}
        <Card>
          <div className="card-header flex items-center justify-between">
            <h3 className="font-medium text-[#233746]">Recent Incidents</h3>
            <span className="badge badge-warning">{incidents.filter(i => i.severity === 'critical' || i.severity === 'high').length} High</span>
          </div>
          <div className="card-body p-0">
            <Table data={incidents} columns={incidentColumns} />
          </div>
        </Card>
      </div>

      {/* Charts */}
      <div className="section-grid">
        {/* Checkpoint Verification History */}
        <Card>
          <div className="card-header">
            <h3 className="font-medium text-[#233746]">Checkpoint Verification (24h)</h3>
          </div>
          <div className="card-body">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={checkpointData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#DCE1E5" />
                  <XAxis dataKey="time" stroke="#75818A" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#75818A" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #DCE1E5',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    }}
                    labelStyle={{ color: '#233746', fontWeight: 500 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="verified"
                    stroke="#27865B"
                    strokeWidth={2}
                    dot={false}
                    name="Verified"
                  />
                  <Line
                    type="monotone"
                    dataKey="failed"
                    stroke="#C74747"
                    strokeWidth={2}
                    dot={false}
                    name="Failed"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center gap-4 mt-4 text-sm text-[#75818A]">
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-[#27865B]" /> Verified</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-[#C74747]" /> Failed</span>
            </div>
          </div>
        </Card>

        {/* System Activity */}
        <Card>
          <div className="card-header">
            <h3 className="font-medium text-[#233746]">System Activity (24h)</h3>
          </div>
          <div className="card-body">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={activityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#DCE1E5" />
                  <XAxis dataKey="time" stroke="#75818A" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#75818A" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #DCE1E5',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    }}
                    labelStyle={{ color: '#233746', fontWeight: 500 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="checkpoints"
                    stroke="#328C89"
                    strokeWidth={2}
                    dot={false}
                    name="Checkpoints"
                  />
                  <Line
                    type="monotone"
                    dataKey="incidents"
                    stroke="#C74747"
                    strokeWidth={2}
                    dot={false}
                    name="Incidents"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center gap-4 mt-4 text-sm text-[#75818A]">
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-[#328C89]" /> Checkpoints</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-[#C74747]" /> Incidents</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Quorum Status */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Current Quorum Status</h3>
          <span className="badge badge-success">Quorum Met</span>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-[#F2F3F4] rounded-lg">
              <p className="text-xs text-[#75818A] mb-1">Policy</p>
              <p className="font-medium text-[#233746]">2-of-3 witnesses required</p>
            </div>
            <div className="p-4 bg-[#F2F3F4] rounded-lg">
              <p className="text-xs text-[#75818A] mb-1">Current Verified</p>
              <p className="font-medium text-[#233746] text-2xl text-[#27865B]">3 / 3</p>
            </div>
            <div className="p-4 bg-[#F2F3F4] rounded-lg">
              <p className="text-xs text-[#75818A] mb-1">Byzantine Tolerance</p>
              <p className="font-medium text-[#233746]">f = 1 (satisfies 2k - n &gt; f: 4 - 3 &gt; 1)</p>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-[#DCE1E5] flex justify-between items-center text-xs text-[#75818A]">
            <span>Active cryptographic mesh verification</span>
            <span className="font-mono text-[11px]">telemetry: <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="hover:text-[#328C89]">@geeky-rish</a></span>
          </div>
        </div>
      </Card>
    </div>
  )
}