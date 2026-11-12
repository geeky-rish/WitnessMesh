import React, { useState } from 'react'
import { Card } from '../components/ui/Card'
import { Sliders, Save, RefreshCw, ShieldCheck, Database, Server, Info } from 'lucide-react'

export function Settings() {
  const [logUrl, setLogUrl] = useState('http://localhost:8081')
  const [pollInterval, setPollInterval] = useState('5')
  const [quorumN, setQuorumN] = useState('3')
  const [quorumK, setQuorumK] = useState('2')
  const [quorumF, setQuorumF] = useState('1')
  const [autoVerify, setAutoVerify] = useState(true)
  const [saved, setSaved] = useState(false)

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#233746]">System Settings</h1>
          <p className="text-sm text-[#75818A]">Manage network endpoints, polling parameters, and cryptographic verification preferences</p>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        <Card>
          <div className="card-header flex items-center gap-2">
            <Server className="w-5 h-5 text-[#328C89]" />
            <h2 className="text-lg font-medium text-[#233746]">Network Endpoints</h2>
          </div>
          <div className="card-body space-y-4">
            <div>
              <label className="block text-sm font-medium text-[#233746] mb-1">
                Transparency Log URL
              </label>
              <input
                type="text"
                value={logUrl}
                onChange={(e) => setLogUrl(e.target.value)}
                className="input w-full max-w-lg"
                placeholder="http://localhost:8081"
              />
              <p className="text-xs text-[#75818A] mt-1">Default address for querying tree heads and consistency proofs</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-[#233746] mb-1">
                Monitoring Poll Interval (seconds)
              </label>
              <input
                type="number"
                value={pollInterval}
                onChange={(e) => setPollInterval(e.target.value)}
                className="input w-32"
                min="1"
                max="60"
              />
              <p className="text-xs text-[#75818A] mt-1">Frequency at which the monitor pulls checkpoints from witnesses</p>
            </div>
          </div>
        </Card>

        <Card>
          <div className="card-header flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[#328C89]" />
            <h2 className="text-lg font-medium text-[#233746]">Quorum & Security Rules</h2>
          </div>
          <div className="card-body space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-xl">
              <div>
                <label className="block text-sm font-medium text-[#233746] mb-1">Total Witnesses (n)</label>
                <input
                  type="number"
                  value={quorumN}
                  onChange={(e) => setQuorumN(e.target.value)}
                  className="input w-full"
                  min="1"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#233746] mb-1">Required Quorum (k)</label>
                <input
                  type="number"
                  value={quorumK}
                  onChange={(e) => setQuorumK(e.target.value)}
                  className="input w-full"
                  min="1"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#233746] mb-1">Max Byzantine (f)</label>
                <input
                  type="number"
                  value={quorumF}
                  onChange={(e) => setQuorumF(e.target.value)}
                  className="input w-full"
                  min="0"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-2">
              <input
                type="checkbox"
                id="autoVerify"
                checked={autoVerify}
                onChange={(e) => setAutoVerify(e.target.checked)}
                className="rounded border-[#DCE1E5] text-[#328C89] focus:ring-[#328C89]"
              />
              <label htmlFor="autoVerify" className="text-sm font-medium text-[#233746]">
                Automatically trigger offline verifier when monitor detects incident
              </label>
            </div>
          </div>
        </Card>

        <Card>
          <div className="card-header flex items-center gap-2">
            <Database className="w-5 h-5 text-[#328C89]" />
            <h2 className="text-lg font-medium text-[#233746]">Storage & Audit</h2>
          </div>
          <div className="card-body space-y-4">
            <p className="text-sm text-[#75818A]">
              SQLite backend database path: <code className="bg-[#F2F3F4] px-2 py-1 rounded text-[#233746]">data/witnessmesh.db</code>
            </p>
            <p className="text-xs text-[#75818A]">
              Tamper-evident audit chain is active and hashes all policy modifications sequentially.
            </p>
          </div>
        </Card>

        <Card>
          <div className="card-header flex items-center gap-2">
            <Info className="w-5 h-5 text-[#328C89]" />
            <h2 className="text-lg font-medium text-[#233746]">System & Support Information</h2>
          </div>
          <div className="card-body space-y-3 text-sm text-[#75818A]">
            <p>
              WitnessMesh is an open cryptographic trust monitoring and attack detection system for transparency logs.
            </p>
            <div className="p-3 bg-[#F2F3F4] rounded-lg space-y-1.5 text-xs text-[#233746]">
              <div><span className="text-[#75818A]">Version:</span> 1.0.0 (RFC 9162 / C2SP compliant)</div>
              <div><span className="text-[#75818A]">Support & Technical Inquiries:</span> Rishi Kulkarni</div>
              <div><span className="text-[#75818A]">GitHub:</span> <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="text-[#328C89] hover:underline font-mono">geeky-rish</a></div>
              <div><span className="text-[#75818A]">Email:</span> <a href="mailto:chingi11@proton.me" className="text-[#328C89] hover:underline font-mono">chingi11@proton.me</a></div>
            </div>
          </div>
        </Card>

        <div className="flex items-center gap-4">
          <button type="submit" className="btn-primary flex items-center gap-2">
            <Save className="w-4 h-4" />
            Save Configuration
          </button>
          {saved && (
            <span className="text-sm font-medium text-[#27865B]">
              Settings saved successfully!
            </span>
          )}
        </div>
      </form>
    </div>
  )
}
