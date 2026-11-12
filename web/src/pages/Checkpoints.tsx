import React, { useState } from 'react'
import { FileText, Search, Download, Eye, Filter, ChevronLeft, ChevronRight } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface Checkpoint {
  id: string
  logId: string
  treeSize: number
  rootHash: string
  timestamp: string
  signature: string
  verified: boolean
  witnesses: number
  source: 'log' | 'client' | 'monitor'
}

const mockCheckpoints: Checkpoint[] = [
  { id: 'cp-001', logId: 'log-abc123', treeSize: 1234, rootHash: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=', timestamp: '2024-01-15 10:30:00', signature: 'Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=', verified: true, witnesses: 3, source: 'log' },
  { id: 'cp-002', logId: 'log-abc123', treeSize: 1230, rootHash: 'DifferentRootHash...', timestamp: '2024-01-15 10:25:00', signature: 'DifferentSignature...', verified: true, witnesses: 3, source: 'log' },
  { id: 'cp-003', logId: 'log-abc123', treeSize: 1225, rootHash: 'AnotherRootHash...', timestamp: '2024-01-15 10:20:00', signature: 'AnotherSignature...', verified: true, witnesses: 3, source: 'log' },
  { id: 'cp-004', logId: 'log-abc123', treeSize: 1220, rootHash: 'YetAnotherRootHash...', timestamp: '2024-01-15 10:15:00', signature: 'YetAnotherSignature...', verified: true, witnesses: 3, source: 'log' },
  { id: 'cp-005', logId: 'log-abc123', treeSize: 1215, rootHash: 'OneMoreRootHash...', timestamp: '2024-01-15 10:10:00', signature: 'OneMoreSignature...', verified: true, witnesses: 3, source: 'log' },
  { id: 'cp-006', logId: 'log-abc123', treeSize: 1210, rootHash: 'FinalRootHash...', timestamp: '2024-01-15 10:05:00', signature: 'FinalSignature...', verified: true, witnesses: 3, source: 'log' },
]

const mockMaliciousCheckpoints: Checkpoint[] = [
  { id: 'cp-mal-001', logId: 'log-abc123', treeSize: 1234, rootHash: 'MALICIOUS_ROOT_HASH_DIFFERENT...', timestamp: '2024-01-15 10:30:05', signature: 'VALID_SIGNATURE_BUT_DIFFERENT_ROOT', verified: false, witnesses: 1, source: 'log' },
]

export function Checkpoints() {
  const [checkpoints] = useState([...mockCheckpoints, ...mockMaliciousCheckpoints])
  const [filter, setFilter] = useState<'all' | 'verified' | 'unverified'>('all')
  const [page, setPage] = useState(1)
  const pageSize = 10

  const filtered = checkpoints.filter(cp => {
    if (filter === 'verified') return cp.verified
    if (filter === 'unverified') return !cp.verified
    return true
  })

  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize)
  const totalPages = Math.ceil(filtered.length / pageSize)

  const columns = [
    { key: 'id', header: 'ID', render: (c: Checkpoint) => <span className="mono text-xs">{c.id}</span> },
    { key: 'treeSize', header: 'Tree Size', render: (c: Checkpoint) => <span className="mono">{c.treeSize.toLocaleString()}</span> },
    { key: 'rootHash', header: 'Root Hash', render: (c: Checkpoint) => <span className="mono text-xs">{c.rootHash}</span> },
    { key: 'timestamp', header: 'Timestamp', render: (c: Checkpoint) => <span className="text-[#75818A]">{c.timestamp}</span> },
    { key: 'verified', header: 'Verified', render: (c: Checkpoint) => (
      <span className={`badge ${c.verified ? 'badge-success' : 'badge-danger'}`}>
        {c.verified ? 'Valid' : 'Invalid'}
      </span>
    )},
    { key: 'witnesses', header: 'Witnesses', render: (c: Checkpoint) => (
      <span className="mono">{c.witnesses} / 3</span>
    )},
    { key: 'source', header: 'Source', render: (c: Checkpoint) => (
      <span className={`badge badge-${c.source === 'log' ? 'primary' : c.source === 'client' ? 'success' : 'warning'}`}>
        {c.source}
      </span>
    )},
    { key: 'actions', header: 'Actions', render: (c: Checkpoint) => (
      <div className="flex items-center gap-2">
        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="View Details">
          <Eye className="w-4 h-4" />
        </button>
      </div>
    )},
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Checkpoints</h2>
          <p className="text-[#75818A] mt-1">View and verify transparency log checkpoints</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="input w-auto"
            value={filter}
            onChange={(e) => setFilter(e.target.value as any)}
          >
            <option value="all">All Checkpoints</option>
            <option value="verified">Verified Only</option>
            <option value="unverified">Unverified Only</option>
          </select>
          <button className="btn-secondary btn-sm">
            <Download className="w-4 h-4 mr-1" />
            Export
          </button>
        </div>
      </div>

      {/* Summary */}
      <div className="stats-grid">
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Total Checkpoints</p>
              <p className="text-3xl font-semibold text-[#233746]">{checkpoints.length}</p>
            </div>
            <FileText className="w-8 h-8 text-[#328C89]" />
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Verified</p>
              <p className="text-3xl font-semibold text-[#27865B]">
                {checkpoints.filter(c => c.verified).length}
              </p>
            </div>
            <span className="w-8 h-8 rounded-lg bg-[#27865B]/10 flex items-center justify-center">
              <svg className="w-5 h-5 text-[#27865B]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </span>
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Unverified</p>
              <p className="text-3xl font-semibold text-[#C74747]">
                {checkpoints.filter(c => !c.verified).length}
              </p>
            </div>
            <span className="w-8 h-8 rounded-lg bg-[#C74747]/10 flex items-center justify-center">
              <svg className="w-5 h-5 text-[#C74747]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </span>
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-[#75818A] mb-1">Latest Tree Size</p>
              <p className="text-3xl font-semibold text-[#233746]">
                {Math.max(...checkpoints.map(c => c.treeSize)).toLocaleString()}
              </p>
            </div>
            <FileText className="w-8 h-8 text-[#328C89]" />
          </div>
        </Card>
      </div>

      {/* Checkpoint Table */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Checkpoint History</h3>
          <div className="flex items-center gap-2 text-sm text-[#75818A]">
            Showing {paginated.length} of {filtered.length}
          </div>
        </div>
        <div className="card-body p-0">
          <Table data={paginated} columns={columns} />
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 p-4 border-t border-[#DCE1E5]">
            <button
              className="btn-secondary btn-sm"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-4 text-sm text-[#75818A]">Page {page} of {totalPages}</span>
            <button
              className="btn-secondary btn-sm"
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </Card>

      {/* Merkle Tree Visualization */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Merkle Tree Structure (Latest Checkpoint)</h3>
          <span className="text-xs text-[#75818A] font-mono">tree verifier: <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="text-[#328C89] hover:underline">@geeky-rish</a></span>
        </div>
        <div className="card-body">
          <div className="font-mono text-xs bg-[#1E293B] text-[#E8EDF1] p-4 rounded overflow-x-auto">
            {`Merkle Tree (size: 1234)
├── Root: CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=
├── Level 1: [HashA, HashB]
├── Level 2: [HashC, HashD, HashE, HashF]
├── ...
└── Leaves: 1234 entries`}
          </div>
        </div>
      </Card>
    </div>
  )
}