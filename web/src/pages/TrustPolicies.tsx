import React, { useState } from 'react'
import { Key, Shield, Users, Plus, Trash2, Edit, CheckCircle, XCircle, AlertTriangle, Download, Upload, Save, RotateCcw } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface Witness {
  id: string
  name: string
  publicKey: string
  url: string
  included: boolean
}

interface Log {
  id: string
  name: string
  publicKey: string
  origin: string
}

interface Policy {
  id: string
  name: string
  quorumType: 'k_of_n' | 'tree'
  k?: number
  witnesses: string[]
  logs: string[]
  createdAt: string
  updatedAt: string
  active: boolean
}

const mockWitnesses: Witness[] = [
  { id: 'w0', name: 'witness-0', publicKey: 'ed25519:abc123...', url: 'http://localhost:8082', included: true },
  { id: 'w1', name: 'witness-1', publicKey: 'ed25519:def456...', url: 'http://localhost:8083', included: true },
  { id: 'w2', name: 'witness-2', publicKey: 'ed25519:ghi789...', url: 'http://localhost:8084', included: true },
  { id: 'w3', name: 'witness-3', publicKey: 'ed25519:jkl012...', url: 'http://localhost:8085', included: false },
]

const mockLogs: Log[] = [
  { id: 'log-0', name: 'Primary Log', publicKey: 'ed25519:logkey1...', origin: 'sigsum.org/v1/logkey1...' },
  { id: 'log-1', name: 'Secondary Log', publicKey: 'ed25519:logkey2...', origin: 'sigsum.org/v1/logkey2...' },
]

const mockPolicies: Policy[] = [
  { id: 'pol-001', name: 'Default Policy', quorumType: 'k_of_n', k: 2, witnesses: ['w0', 'w1', 'w2'], logs: ['log-0'], createdAt: '2024-01-01', updatedAt: '2024-01-10', active: true },
  { id: 'pol-002', name: 'Strict Policy', quorumType: 'k_of_n', k: 3, witnesses: ['w0', 'w1', 'w2', 'w3'], logs: ['log-0'], createdAt: '2024-01-05', updatedAt: '2024-01-12', active: false },
  { id: 'pol-003', name: 'Minimal Policy', quorumType: 'k_of_n', k: 1, witnesses: ['w0'], logs: ['log-0', 'log-1'], createdAt: '2024-01-10', updatedAt: '2024-01-10', active: false },
]

export function TrustPolicies() {
  const [policies] = useState(mockPolicies)
  const [activeTab, setActiveTab] = useState<'policies' | 'witnesses' | 'logs' | 'quorum'>('policies')
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [showPolicyForm, setShowPolicyForm] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)

  const tabs = [
    { id: 'policies', label: 'Policies', icon: Key },
    { id: 'witnesses', label: 'Witnesses', icon: Shield },
    { id: 'logs', label: 'Logs', icon: FileText },
    { id: 'quorum', label: 'Quorum Calculator', icon: Users },
  ]

  const getWitnessName = (id: string) => mockWitnesses.find(w => w.id === id)?.name || id
  const getLogName = (id: string) => mockLogs.find(l => l.id === id)?.name || id

  const calculateSafety = (n: number, k: number, f: number) => {
    const safety = 2 * k - n > f
    const liveness = k <= n - f
    return { safety, liveness }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Trust Policies</h2>
          <p className="text-[#75818A] mt-1">Manage witness sets, log identities, and quorum requirements</p>
        </div>
        {activeTab === 'policies' && (
          <button className="btn-primary" onClick={() => { setEditingPolicy(null); setShowPolicyForm(true); }}>
            <Plus className="w-4 h-4 mr-1" />
            New Policy
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id as any)}
          >
            <tab.icon className="w-4 h-4 mr-2" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <div className="space-y-4">
          <Card>
            <div className="card-header flex items-center justify-between">
              <h3 className="font-medium text-[#233746]">Trust Policies</h3>
              <span className="badge badge-primary">{policies.length} policies</span>
            </div>
            <div className="card-body p-0">
              <Table
                data={policies}
                columns={[
                  { key: 'name', header: 'Policy', render: (p: Policy) => (
                    <div className="flex items-center gap-2">
                      {p.active && <span className="status-dot status-healthy" />}
                      <span className="font-medium">{p.name}</span>
                    </div>
                  )},
                  { key: 'quorumType', header: 'Quorum Type', render: (p: Policy) => (
                    <span className="badge badge-primary">{p.quorumType === 'k_of_n' ? `K-of-N (k=${p.k})` : 'Tree'}</span>
                  )},
                  { key: 'witnesses', header: 'Witnesses', render: (p: Policy) => (
                    <span className="text-sm text-[#75818A]">{p.witnesses.map(getWitnessName).join(', ')}</span>
                  )},
                  { key: 'logs', header: 'Logs', render: (p: Policy) => (
                    <span className="text-sm text-[#75818A]">{p.logs.map(getLogName).join(', ')}</span>
                  )},
                  { key: 'status', header: 'Status', render: (p: Policy) => (
                    <span className={`badge ${p.active ? 'badge-success' : 'badge-neutral'}`}>
                      {p.active ? 'Active' : 'Inactive'}
                    </span>
                  )},
                  { key: 'updatedAt', header: 'Updated', render: (p: Policy) => <span className="text-[#75818A]">{p.updatedAt}</span> },
                  { key: 'actions', header: 'Actions', render: (p: Policy) => (
                    <div className="flex items-center gap-1">
                      <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" onClick={() => { setEditingPolicy(p); setShowPolicyForm(true); }} title="Edit">
                        <Edit className="w-4 h-4" />
                      </button>
                      {p.active ? (
                        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="Set Inactive">
                          <XCircle className="w-4 h-4" />
                        </button>
                      ) : (
                        <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#27865B]" title="Activate">
                          <CheckCircle className="w-4 h-4" />
                        </button>
                      )}
                      <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#C74747]" title="Delete">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  )},
                ]}
              />
            </div>
          </Card>

          {/* Policy Details */}
          {selectedPolicy && (
            <Card>
              <div className="card-header flex items-center justify-between">
                <h3 className="font-medium text-[#233746]">Policy Details: {selectedPolicy.name}</h3>
                <button className="btn-secondary btn-sm" onClick={() => setSelectedPolicy(null)}><XCircle className="w-4 h-4" /></button>
              </div>
              <div className="card-body space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-[#F2F3F4] rounded-lg">
                    <p className="text-xs font-medium text-[#75818A] mb-1">Witness Count</p>
                    <p className="text-2xl font-semibold text-[#233746]">{selectedPolicy.witnesses.length}</p>
                  </div>
                  <div className="p-3 bg-[#F2F3F4] rounded-lg">
                    <p className="text-xs font-medium text-[#75818A] mb-1">Quorum (k)</p>
                    <p className="text-2xl font-semibold text-[#233746]">{selectedPolicy.k || 'N/A'}</p>
                  </div>
                  <div className="p-3 bg-[#F2F3F4] rounded-lg">
                    <p className="text-xs font-medium text-[#75818A] mb-1">Byzantine Tolerance</p>
                    <p className="text-2xl font-semibold text-[#233746]">f = {Math.floor((selectedPolicy.witnesses.length - 1) / 2)}</p>
                  </div>
                </div>

                <div className="border-t border-[#DCE1E5] pt-4">
                  <h4 className="font-medium text-[#233746] mb-3">Safety & Liveness Analysis</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {(() => {
                      const n = selectedPolicy.witnesses.length
                      const k = selectedPolicy.k || 1
                      const maxF = Math.floor((n - 1) / 2)
                      const results = []
                      for (let f = 0; f <= maxF; f++) {
                        const { safety, liveness } = calculateSafety(n, k, f)
                        results.push({ f, safety, liveness })
                      }
                      return results.map(r => (
                        <div key={r.f} className="p-3 rounded-lg bg-[#F2F3F4]">
                          <p className="text-xs font-medium text-[#75818A] mb-2">f = {r.f} (max Byzantine)</p>
                          <div className="flex items-center gap-3">
                            <div className="flex items-center gap-1">
                              <span className={`status-dot ${r.safety ? 'status-healthy' : 'status-critical'}`} />
                              <span className="text-sm">Safety: {r.safety ? '✓ Satisfied' : '✗ Violated'}</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <span className={`status-dot ${r.liveness ? 'status-healthy' : 'status-critical'}`} />
                              <span className="text-sm">Liveness: {r.liveness ? '✓ Satisfied' : '✗ Violated'}</span>
                            </div>
                          </div>
                        </div>
                      ))
                    })()}
                  </div>
                </div>

                <div className="border-t border-[#DCE1E5] pt-4">
                  <h4 className="font-medium text-[#233746] mb-3">Formula</h4>
                  <div className="font-mono text-sm bg-[#1E293B] text-[#E8EDF1] p-4 rounded overflow-x-auto">
                    {`Safety:  2k - n > f   →  2×${selectedPolicy.k} - ${selectedPolicy.witnesses.length} > f
Liveness: k ≤ n - f   →  ${selectedPolicy.k} ≤ ${selectedPolicy.witnesses.length} - f

For n=${selectedPolicy.witnesses.length}, k=${selectedPolicy.k}:
Max f for safety: f < ${2 * (selectedPolicy.k || 1) - selectedPolicy.witnesses.length}
Max f for liveness: f ≤ ${selectedPolicy.witnesses.length - (selectedPolicy.k || 1)}

Recommended max f: ${Math.floor((selectedPolicy.witnesses.length - 1) / 2)}`}
                  </div>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Witnesses Tab */}
      {activeTab === 'witnesses' && (
        <Card>
          <div className="card-header flex items-center justify-between">
            <h3 className="font-medium text-[#233746]">Witness Registry</h3>
            <button className="btn-secondary btn-sm"><Plus className="w-4 h-4 mr-1" /> Add Witness</button>
          </div>
          <div className="card-body p-0">
            <Table
              data={mockWitnesses}
              columns={[
                { key: 'name', header: 'Witness', render: (w: Witness) => (
                  <div className="flex items-center gap-2">
                    <span className={`status-dot ${w.included ? 'status-healthy' : 'status-unknown'}`} />
                    <span className="font-medium">{w.name}</span>
                  </div>
                )},
                { key: 'publicKey', header: 'Public Key', render: (w: Witness) => <span className="mono text-xs">{w.publicKey}</span> },
                { key: 'url', header: 'Endpoint', render: (w: Witness) => <span className="mono text-xs text-[#75818A]">{w.url}</span> },
                { key: 'included', header: 'In Policies', render: (w: Witness) => (
                  <span className={`badge ${w.included ? 'badge-success' : 'badge-neutral'}`}>
                    {w.included ? 'Included' : 'Available'}
                  </span>
                )},
                { key: 'actions', header: 'Actions', render: (w: Witness) => (
                  <div className="flex items-center gap-1">
                    <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="Edit"><Edit className="w-4 h-4" /></button>
                    <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#C74747]" title="Remove"><Trash2 className="w-4 h-4" /></button>
                  </div>
                )},
              ]}
            />
          </div>
        </Card>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <Card>
          <div className="card-header flex items-center justify-between">
            <h3 className="font-medium text-[#233746]">Log Registry</h3>
            <button className="btn-secondary btn-sm"><Plus className="w-4 h-4 mr-1" /> Add Log</button>
          </div>
          <div className="card-body p-0">
            <Table
              data={mockLogs}
              columns={[
                { key: 'name', header: 'Log', render: (l: Log) => <span className="font-medium">{l.name}</span> },
                { key: 'publicKey', header: 'Public Key', render: (l: Log) => <span className="mono text-xs">{l.publicKey}</span> },
                { key: 'origin', header: 'Origin', render: (l: Log) => <span className="mono text-xs text-[#75818A]">{l.origin}</span> },
                { key: 'actions', header: 'Actions', render: () => (
                  <div className="flex items-center gap-1">
                    <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]" title="Edit"><Edit className="w-4 h-4" /></button>
                    <button className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#C74747]" title="Remove"><Trash2 className="w-4 h-4" /></button>
                  </div>
                )},
              ]}
            />
          </div>
        </Card>
      )}

      {/* Quorum Calculator Tab */}
      {activeTab === 'quorum' && (
        <div className="section-grid">
          <Card>
            <div className="card-header"><h3 className="font-medium text-[#233746]">Quorum Calculator</h3></div>
            <div className="card-body space-y-4">
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Total Witnesses (n)</label>
                <input type="number" className="input" defaultValue={3} min={1} max={10} />
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Quorum Size (k)</label>
                <input type="number" className="input" defaultValue={2} min={1} max={10} />
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Max Byzantine (f)</label>
                <input type="number" className="input" defaultValue={1} min={0} max={10} />
              </div>
              <div className="p-4 bg-[#F2F3F4] rounded-lg space-y-2">
                <p className="font-medium text-[#233746]">Analysis</p>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1">
                    <span className="status-dot status-healthy" />
                    <span className="text-sm">Safety: 2k - n > f</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="status-dot status-healthy" />
                    <span className="text-sm">Liveness: k ≤ n - f</span>
                  </div>
                </div>
                <p className="text-xs text-[#75818A]">Configure values above to see real-time analysis</p>
              </div>
            </div>
          </Card>

          <Card>
            <div className="card-header"><h3 className="font-medium text-[#233746]">Common Configurations</h3></div>
            <div className="card-body space-y-3">
              {[
                { n: 3, k: 2, f: 1, label: '3 witnesses, 2-of-3 quorum', desc: 'Standard configuration (f=1)' },
                { n: 5, k: 3, f: 2, label: '5 witnesses, 3-of-5 quorum', desc: 'Higher availability (f=2)' },
                { n: 7, k: 4, f: 3, label: '7 witnesses, 4-of-7 quorum', desc: 'Enterprise scale (f=3)' },
                { n: 4, k: 3, f: 1, label: '4 witnesses, 3-of-4 quorum', desc: 'Stronger safety (f=1)' },
              ].map((config, i) => (
                <div key={i} className="p-3 bg-[#F2F3F4] rounded-lg">
                  <p className="font-medium text-[#233746]">{config.label}</p>
                  <p className="text-xs text-[#75818A]">{config.desc}</p>
                  <div className="flex items-center gap-3 mt-1 text-sm">
                    <span className="text-[#27865B]">✓ Safety</span>
                    <span className="text-[#27865B]">✓ Liveness</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Policy Form Modal */}
      {showPolicyForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full">
            <div className="p-6 border-b border-[#DCE1E5] flex items-center justify-between">
              <h3 className="font-semibold text-[#233746]">{editingPolicy ? 'Edit Policy' : 'New Policy'}</h3>
              <button className="p-2 rounded hover:bg-[#F2F3F4]" onClick={() => { setShowPolicyForm(false); setEditingPolicy(null); }}>
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Policy Name</label>
                <input type="text" className="input" defaultValue={editingPolicy?.name || ''} placeholder="Enter policy name" />
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Quorum Type</label>
                <select className="input">
                  <option value="k_of_n">K-of-N</option>
                  <option value="tree">Tree (advanced)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Quorum Size (k)</label>
                <input type="number" className="input" defaultValue={editingPolicy?.k || 2} min={1} />
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Witnesses</label>
                <div className="space-y-1">
                  {mockWitnesses.map(w => (
                    <label key={w.id} className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" className="w-4 h-4" defaultChecked={editingPolicy?.witnesses.includes(w.id) || (w.included && !editingPolicy)} />
                      <span className="text-sm">{w.name}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm text-[#75818A] mb-1">Logs</label>
                <div className="space-y-1">
                  {mockLogs.map(l => (
                    <label key={l.id} className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" className="w-4 h-4" defaultChecked={editingPolicy?.logs.includes(l.id)} />
                      <span className="text-sm">{l.name}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4 border-t border-[#DCE1E5]">
                <button className="btn-secondary" onClick={() => { setShowPolicyForm(false); setEditingPolicy(null); }}>Cancel</button>
                <button className="btn-primary"><Save className="w-4 h-4 mr-1" /> Save Policy</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}