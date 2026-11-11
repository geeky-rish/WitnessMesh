import React, { useState } from 'react'
import { AlertCircle, AlertTriangle, Info, Clock, Eye, Download, Filter, ChevronLeft, ChevronRight, CheckCircle, XCircle } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface Incident {
  id: string
  type: 'Log Fork' | 'Witness Equivocation' | 'Missing Checkpoint' | 'Stale Checkpoint' | 'Network Failure'
  severity: 'critical' | 'high' | 'medium' | 'low'
  timestamp: string
  logId: string
  status: 'open' | 'acknowledged' | 'resolved'
  description: string
  evidenceId?: string
  acknowledgedAt?: string
  resolvedAt?: string
}

const mockIncidents: Incident[] = [
  { id: 'inc-001', type: 'Log Fork', severity: 'critical', timestamp: '2024-01-15 10:30:15', logId: 'log-abc123', status: 'open', description: 'Same-size fork detected at tree size 1,234. Two checkpoints with same size but different Merkle roots. Log signature valid on both. Witness-0 signed conflicting checkpoint after rollback.', evidenceId: 'ev-2024-001' },
  { id: 'inc-002', type: 'Witness Equivocation', severity: 'high', timestamp: '2024-01-14 14:56:30', logId: 'log-abc123', status: 'acknowledged', description: 'Witness-1 signed two conflicting checkpoints at tree size 1,235. Compromised witness detected. Quorum not met (1/3 valid). Witness excluded from policy.', evidenceId: 'ev-2024-002', acknowledgedAt: '2024-01-14 15:02:00' },
  { id: 'inc-003', type: 'Missing Checkpoint', severity: 'medium', timestamp: '2024-01-13 09:12:00', logId: 'log-abc123', status: 'resolved', description: 'No checkpoint received for 5 minutes. Log temporarily offline for maintenance. Resumed normal operation.', resolvedAt: '2024-01-13 09:17:00' },
  { id: 'inc-004', type: 'Stale Checkpoint', severity: 'low', timestamp: '2024-01-12 16:45:00', logId: 'log-abc123', status: 'resolved', description: 'Checkpoint older than 10-minute threshold. Network delay caused temporary stall. Caught up after partition healed.', resolvedAt: '2024-01-12 16:50:00' },
  { id: 'inc-005', type: 'Network Failure', severity: 'medium', timestamp: '2024-01-11 11:20:00', logId: 'log-def456', status: 'acknowledged', description: 'Witness-2 unreachable for 2 minutes. Network partition detected. Client proceeded with 2-of-3 quorum. Witness recovered.', acknowledgedAt: '2024-01-11 11:25:00' },
  { id: 'inc-006', type: 'Log Fork', severity: 'critical', timestamp: '2024-01-10 08:00:00', logId: 'log-abc123', status: 'resolved', description: 'Different-size fork attempt detected. Consistency proof verification failed. Malicious log rejected by all witnesses.', evidenceId: 'ev-2024-003', resolvedAt: '2024-01-10 08:05:00' },
]

export function IncidentHistory() {
  const [incidents] = useState(mockIncidents)
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [filterStatus, setFilterStatus] = useState<'all' | 'open' | 'acknowledged' | 'resolved'>('all')
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [page, setPage] = useState(1)
  const pageSize = 10

  const filtered = incidents.filter(inc => {
    if (filterSeverity !== 'all' && inc.severity !== filterSeverity) return false
    if (filterStatus !== 'all' && inc.status !== filterStatus) return false
    return true
  })

  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize)
  const totalPages = Math.ceil(filtered.length / pageSize)

  const columns = [
    { key: 'id', header: 'ID', render: (i: Incident) => <span className="mono text-xs">{i.id}</span> },
    { key: 'type', header: 'Type', render: (i: Incident) => (
      <span className="badge badge-primary">{i.type}</span>
    )},
    { key: 'severity', header: 'Severity', render: (i: Incident) => (
      <span className={`incident-severity incident-severity-${i.severity}`}>
        {i.severity.charAt(0).toUpperCase() + i.severity.slice(1)}
      </span>
    )},
    { key: 'timestamp', header: 'Detected', render: (i: Incident) => <span className="text-[#75818A]">{i.timestamp}</span> },
    { key: 'logId', header: 'Log', render: (i: Incident) => <span className="mono text-xs">{i.logId.slice(0, 12)}...</span> },
    { key: 'status', header: 'Status', render: (i: Incident) => (
      <span className={`badge ${i.status === 'open' ? 'badge-danger' : i.status === 'acknowledged' ? 'badge-warning' : 'badge-success'}`}>
        {i.status.charAt(0).toUpperCase() + i.status.slice(1)}
      </span>
    )},
    { key: 'description', header: 'Description', render: (i: Incident) => (
      <span className="text-[#75818A] max-w-xs truncate block">{i.description}</span>
    )},
    { key: 'actions', header: 'Actions', render: (i: Incident) => (
      <div className="flex items-center gap-1">
        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" onClick={() => setSelectedIncident(i)} title="View Details">
          <Eye className="w-4 h-4" />
        </button>
        {i.evidenceId && (
          <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#328C89]" title="View Evidence">
            <FileText className="w-4 h-4" />
          </button>
        )}
      </div>
    )},
  ]

  const severityCounts = {
    critical: incidents.filter(i => i.severity === 'critical').length,
    high: incidents.filter(i => i.severity === 'high').length,
    medium: incidents.filter(i => i.severity === 'medium').length,
    low: incidents.filter(i => i.severity === 'low').length,
  }

  const statusCounts = {
    open: incidents.filter(i => i.status === 'open').length,
    acknowledged: incidents.filter(i => i.status === 'acknowledged').length,
    resolved: incidents.filter(i => i.status === 'resolved').length,
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Incident History</h2>
          <p className="text-[#75818A] mt-1">Security incidents detected by the monitoring engine</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary btn-sm">
            <Download className="w-4 h-4 mr-1" />
            Export Report
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="stats-grid">
        <Card className="p-5 border-l-4 border-[#C74747]">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Open Incidents</p>
              <p className="text-3xl font-semibold text-[#C74747]">{statusCounts.open}</p>
            </div>
            <AlertCircle className="w-8 h-8 text-[#C74747]" />
          </div>
        </Card>
        <Card className="p-5 border-l-4 border-[#D69A32]">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Acknowledged</p>
              <p className="text-3xl font-semibold text-[#D69A32]">{statusCounts.acknowledged}</p>
            </div>
            <Clock className="w-8 h-8 text-[#D69A32]" />
          </div>
        </Card>
        <Card className="p-5 border-l-4 border-[#27865B]">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Resolved</p>
              <p className="text-3xl font-semibold text-[#27865B]">{statusCounts.resolved}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-[#27865B]" />
          </div>
        </Card>
        <Card className="p-5 border-l-4 border-[#328C89]">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Total</p>
              <p className="text-3xl font-semibold text-[#233746]">{incidents.length}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-[#328C89]" />
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <div className="card-body">
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <label className="text-sm text-[#75818A]">Severity:</label>
              <select
                className="input w-auto"
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value as any)}
              >
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-sm text-[#75818A]">Status:</label>
              <select
                className="input w-auto"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value as any)}
              >
                <option value="all">All</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Incident Table */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Incidents</h3>
          <div className="flex items-center gap-4 text-sm text-[#75818A]">
            <span>Critical: {severityCounts.critical}</span>
            <span>High: {severityCounts.high}</span>
            <span>Medium: {severityCounts.medium}</span>
            <span>Low: {severityCounts.low}</span>
          </div>
        </div>
        <div className="card-body p-0">
          <Table data={paginated} columns={columns} />
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 p-4 border-t border-[#DCE1E5]">
            <button className="btn-secondary btn-sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-4 text-sm text-[#75818A]">Page {page} of {totalPages}</span>
            <button className="btn-secondary btn-sm" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </Card>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-3xl w-full max-h-[90vh] overflow-auto">
            <div className="p-6 border-b border-[#DCE1E5] flex items-start justify-between">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`badge ${selectedIncident.severity === 'critical' ? 'badge-danger' : selectedIncident.severity === 'high' ? 'badge-warning' : 'badge-primary'}`}>
                    {selectedIncident.type}
                  </span>
                  <span className={`incident-severity incident-severity-${selectedIncident.severity}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <h3 className="text-xl font-semibold text-[#233746]">{selectedIncident.id}</h3>
              </div>
              <button className="p-2 rounded hover:bg-[#F2F3F4]" onClick={() => setSelectedIncident(null)}>
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-xs font-medium text-[#75818A] mb-1">Log ID</p>
                  <p className="mono">{selectedIncident.logId}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[#75818A] mb-1">Detected</p>
                  <p>{selectedIncident.timestamp}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[#75818A] mb-1">Status</p>
                  <p className="capitalize">{selectedIncident.status}</p>
                </div>
                {selectedIncident.acknowledgedAt && (
                  <div>
                    <p className="text-xs font-medium text-[#75818A] mb-1">Acknowledged</p>
                    <p>{selectedIncident.acknowledgedAt}</p>
                  </div>
                )}
                {selectedIncident.resolvedAt && (
                  <div>
                    <p className="text-xs font-medium text-[#75818A] mb-1">Resolved</p>
                    <p>{selectedIncident.resolvedAt}</p>
                  </div>
                )}
                <div>
                  <p className="text-xs font-medium text-[#75818A] mb-1">Evidence</p>
                  <p className="mono">{selectedIncident.evidenceId || 'None'}</p>
                </div>
              </div>

              <div className="border-t border-[#DCE1E5] pt-4">
                <h4 className="font-medium text-[#233746] mb-2">Description</h4>
                <p className="text-[#75818A] whitespace-pre-wrap">{selectedIncident.description}</p>
              </div>

              {selectedIncident.evidenceId && (
                <div className="border-t border-[#DCE1E5] pt-4">
                  <button className="btn-primary" onClick={() => window.location.href = `/evidence?id=${selectedIncident.evidenceId}`}>
                    <FileText className="w-4 h-4 mr-1" />
                    View Evidence Bundle
                  </button>
                </div>
              )}

              <div className="flex justify-end gap-2 border-t border-[#DCE1E5] pt-4">
                <button className="btn-secondary" onClick={() => setSelectedIncident(null)}>Close</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}