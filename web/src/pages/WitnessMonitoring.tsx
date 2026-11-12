import React, { useState } from 'react'
import { Shield, CheckCircle, XCircle, AlertCircle, RefreshCw, Download, Eye, ExternalLink } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface Witness {
  id: string
  name: string
  url: string
  publicKey: string
  status: 'healthy' | 'warning' | 'critical' | 'offline'
  lastSeen: string
  cosignatures: number
  uptime: string
  latestCheckpoint: { size: number; rootHash: string }
}

const mockWitnesses: Witness[] = [
  {
    id: 'w0',
    name: 'witness-0',
    url: 'http://localhost:8082',
    publicKey: 'ed25519:abc123...',
    status: 'healthy',
    lastSeen: '2s ago',
    cosignatures: 147,
    uptime: '99.9%',
    latestCheckpoint: { size: 1234, rootHash: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=' },
  },
  {
    id: 'w1',
    name: 'witness-1',
    url: 'http://localhost:8083',
    publicKey: 'ed25519:def456...',
    status: 'healthy',
    lastSeen: '1s ago',
    cosignatures: 147,
    uptime: '99.8%',
    latestCheckpoint: { size: 1234, rootHash: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=' },
  },
  {
    id: 'w2',
    name: 'witness-2',
    url: 'http://localhost:8084',
    publicKey: 'ed25519:ghi789...',
    status: 'warning',
    lastSeen: '45s ago',
    cosignatures: 142,
    uptime: '98.5%',
    latestCheckpoint: { size: 1230, rootHash: 'DifferentRootHash...' },
  },
]

export function WitnessMonitoring() {
  const [witnesses] = useState(mockWitnesses)

  const columns = [
    { key: 'name', header: 'Witness', render: (w: Witness) => (
      <div className="flex items-center gap-2">
        <span className={`status-dot status-${w.status}`} />
        <span className="font-medium">{w.name}</span>
      </div>
    )},
    { key: 'url', header: 'Endpoint', render: (w: Witness) => (
      <span className="mono text-[#75818A]">{w.url}</span>
    )},
    { key: 'publicKey', header: 'Public Key', render: (w: Witness) => (
      <span className="mono text-xs">{w.publicKey}</span>
    )},
    { key: 'status', header: 'Status', render: (w: Witness) => (
      <span className={`badge badge-${w.status === 'healthy' ? 'success' : w.status === 'warning' ? 'warning' : w.status === 'critical' ? 'danger' : 'neutral'}`}>
        {w.status.charAt(0).toUpperCase() + w.status.slice(1)}
      </span>
    )},
    { key: 'lastSeen', header: 'Last Seen', render: (w: Witness) => <span className="text-[#75818A]">{w.lastSeen}</span> },
    { key: 'cosignatures', header: 'Cosignatures', render: (w: Witness) => <span className="mono">{w.cosignatures}</span> },
    { key: 'uptime', header: 'Uptime', render: (w: Witness) => <span className="mono">{w.uptime}</span> },
    { key: 'latestCheckpoint', header: 'Latest Checkpoint', render: (w: Witness) => (
      <div className="text-xs">
        <span className="mono">Size: {w.latestCheckpoint.size.toLocaleString()}</span>
        <br />
        <span className="mono text-[#75818A]">{w.latestCheckpoint.rootHash.slice(0, 20)}...</span>
      </div>
    )},
    { key: 'actions', header: 'Actions', render: (w: Witness) => (
      <div className="flex items-center gap-2">
        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="View Details">
          <Eye className="w-4 h-4" />
        </button>
        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="View on Witness">
          <ExternalLink className="w-4 h-4" />
        </button>
      </div>
    )},
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Witness Monitoring</h2>
          <p className="text-[#75818A] mt-1">Monitor witness health, cosignature status, and checkpoint consistency</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary btn-sm">
            <RefreshCw className="w-4 h-4 mr-1" />
            Refresh
          </button>
          <button className="btn-secondary btn-sm">
            <Download className="w-4 h-4 mr-1" />
            Export
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="stats-grid">
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Total Witnesses</p>
              <p className="text-3xl font-semibold text-[#233746]">{witnesses.length}</p>
            </div>
            <Shield className="w-8 h-8 text-[#328C89]" />
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Healthy</p>
              <p className="text-3xl font-semibold text-[#27865B]">
                {witnesses.filter(w => w.status === 'healthy').length}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-[#27865B]" />
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Warnings</p>
              <p className="text-3xl font-semibold text-[#D69A32]">
                {witnesses.filter(w => w.status === 'warning').length}
              </p>
            </div>
            <AlertCircle className="w-8 h-8 text-[#D69A32]" />
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Total Cosignatures</p>
              <p className="text-3xl font-semibold text-[#233746]">
                {witnesses.reduce((sum, w) => sum + w.cosignatures, 0).toLocaleString()}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-[#328C89]" />
          </div>
        </Card>
      </div>

      {/* Witness Table */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Witness Details</h3>
          <span className="badge badge-primary">Real-time</span>
        </div>
        <div className="card-body p-0">
          <Table data={witnesses} columns={columns} />
        </div>
      </Card>

      {/* Consistency Check */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Checkpoint Consistency</h3>
          <span className="badge badge-warning">1 Inconsistent</span>
        </div>
        <div className="card-body">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#DCE1E5]">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#75818A] uppercase">Witness</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#75818A] uppercase">Tree Size</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#75818A] uppercase">Root Hash</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#75818A] uppercase">Match</th>
                </tr>
              </thead>
              <tbody>
                {witnesses.map((w, i) => (
                  <tr key={i} className="border-b border-[#DCE1E5] last:border-0">
                    <td className="px-4 py-3 font-medium">{w.name}</td>
                    <td className="px-4 py-3 mono">{w.latestCheckpoint.size.toLocaleString()}</td>
                    <td className="px-4 py-3 mono text-xs">{w.latestCheckpoint.rootHash}</td>
                    <td className="px-4 py-3">
                      {w.latestCheckpoint.rootHash === witnesses[0].latestCheckpoint.rootHash ? (
                        <span className="badge badge-success"><CheckCircle className="w-3 h-3 mr-1" /> Match</span>
                      ) : (
                        <span className="badge badge-danger"><XCircle className="w-3 h-3 mr-1" /> Mismatch</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 pt-3 border-t border-[#DCE1E5] flex justify-between items-center text-xs text-[#75818A]">
            <span>C2SP tlog-witness protocol synchronization</span>
            <span className="font-mono text-[11px]">witness mesh: <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="hover:text-[#328C89]">@geeky-rish</a></span>
          </div>
        </div>
      </Card>
    </div>
  )
}