import React, { useState } from 'react'
import { Search, CheckCircle, XCircle, AlertTriangle, Download, Eye, Play, Loader2, FileText, Copy, Shield } from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface EvidenceBundle {
  id: string
  version: number
  logId: string
  case: 'same-size-fork' | 'different-size-fork' | 'witness-equivocation'
  status: 'valid' | 'invalid' | 'pending'
  checkpoints: number
  cosignatures: number
  detectedAt: string
  detectorId: string
  verifiedAt?: string
}

interface EvidenceDetail {
  id: string
  version: number
  logIdentity: {
    publicKey: string
    origin: string
  }
  case: string
  checkpoints: Array<{
    treeSize: number
    rootHash: string
    signature: string
    keyId: string
  }>
  cosignatures: Array<{
    witnessId: string
    witnessName: string
    timestamp: number
    signature: string
    checkpointSize: number
  }>
  consistencyProof?: {
    oldSize: number
    newSize: number
    hashes: string[]
  }
  detectionTime: string
  detectorId: string
  metadata: Record<string, string>
}

const mockEvidence: EvidenceBundle[] = [
  { id: 'ev-2024-001', version: 1, logId: 'log-abc123', case: 'same-size-fork', status: 'valid', checkpoints: 2, cosignatures: 4, detectedAt: '2024-01-15 10:30:15', detectorId: 'monitor-1', verifiedAt: '2024-01-15 10:30:20' },
  { id: 'ev-2024-002', version: 1, logId: 'log-abc123', case: 'witness-equivocation', status: 'valid', checkpoints: 2, cosignatures: 2, detectedAt: '2024-01-14 14:56:30', detectorId: 'monitor-1', verifiedAt: '2024-01-14 14:56:35' },
  { id: 'ev-2024-003', version: 1, logId: 'log-def456', case: 'different-size-fork', status: 'invalid', checkpoints: 2, cosignatures: 3, detectedAt: '2024-01-13 09:12:00', detectorId: 'monitor-1', verifiedAt: '2024-01-13 09:12:05' },
]

const evidenceDetails: Record<string, EvidenceDetail> = {
  'ev-2024-001': {
    id: 'ev-2024-001',
    version: 1,
    logIdentity: { publicKey: 'ed25519:abc123...', origin: 'sigsum.org/v1/abc123...' },
    case: 'Same-Size Fork',
    checkpoints: [
      { treeSize: 1234, rootHash: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=', signature: 'Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=', keyId: 'a1b2' },
      { treeSize: 1234, rootHash: 'MALICIOUS_ROOT_HASH_DIFFERENT...', signature: 'VALID_SIGNATURE_BUT_DIFFERENT_ROOT', keyId: 'a1b2' },
    ],
    cosignatures: [
      { witnessId: 'witness-0', witnessName: 'witness-0', timestamp: 1705315815, signature: 'cosig1...', checkpointSize: 1234 },
      { witnessId: 'witness-1', witnessName: 'witness-1', timestamp: 1705315816, signature: 'cosig2...', checkpointSize: 1234 },
      { witnessId: 'witness-0', witnessName: 'witness-0', timestamp: 1705315820, signature: 'cosig3...', checkpointSize: 1234 },
      { witnessId: 'witness-2', witnessName: 'witness-2', timestamp: 1705315821, signature: 'cosig4...', checkpointSize: 1234 },
    ],
    detectionTime: '2024-01-15 10:30:15',
    detectorId: 'monitor-1',
    metadata: { 'quorum': '2-of-3', 'fork_type': 'same-size', 'conflicting_witnesses': 'witness-0' },
  },
  'ev-2024-002': {
    id: 'ev-2024-002',
    version: 1,
    logIdentity: { publicKey: 'ed25519:abc123...', origin: 'sigsum.org/v1/abc123...' },
    case: 'Witness Equivocation',
    checkpoints: [
      { treeSize: 1235, rootHash: 'RootHashA...', signature: 'SigA...', keyId: 'a1b2' },
      { treeSize: 1235, rootHash: 'RootHashB...', signature: 'SigB...', keyId: 'a1b2' },
    ],
    cosignatures: [
      { witnessId: 'witness-1', witnessName: 'witness-1', timestamp: 1705244190, signature: 'cosigA...', checkpointSize: 1235 },
      { witnessId: 'witness-1', witnessName: 'witness-1', timestamp: 1705244200, signature: 'cosigB...', checkpointSize: 1235 },
    ],
    detectionTime: '2024-01-14 14:56:30',
    detectorId: 'monitor-1',
    metadata: { 'quorum': '2-of-3', 'equivocating_witness': 'witness-1', 'action': 'witness_excluded' },
  },
  'ev-2024-003': {
    id: 'ev-2024-003',
    version: 1,
    logIdentity: { publicKey: 'ed25519:def456...', origin: 'sigsum.org/v1/def456...' },
    case: 'Different-Size Fork',
    checkpoints: [
      { treeSize: 1000, rootHash: 'RootHash1000...', signature: 'Sig1000...', keyId: 'c3d4' },
      { treeSize: 1050, rootHash: 'RootHash1050...', signature: 'Sig1050...', keyId: 'c3d4' },
    ],
    cosignatures: [
      { witnessId: 'witness-0', witnessName: 'witness-0', timestamp: 1705137120, signature: 'cosig1...', checkpointSize: 1050 },
      { witnessId: 'witness-1', witnessName: 'witness-1', timestamp: 1705137121, signature: 'cosig2...', checkpointSize: 1050 },
      { witnessId: 'witness-2', witnessName: 'witness-2', timestamp: 1705137122, signature: 'cosig3...', checkpointSize: 1050 },
    ],
    consistencyProof: { oldSize: 1000, newSize: 1050, hashes: ['hash1', 'hash2', 'hash3'] },
    detectionTime: '2024-01-13 09:12:00',
    detectorId: 'monitor-1',
    metadata: { 'quorum': '2-of-3', 'fork_type': 'different-size', 'consistency_proof': 'invalid' },
  },
}

export function EvidenceVerification() {
  const [evidence] = useState(mockEvidence)
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceDetail | null>(null)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [verificationResult, setVerificationResult] = useState<{ valid: boolean; message: string } | null>(null)

  const handleVerify = async (evidenceId: string) => {
    setVerifying(evidenceId)
    setVerificationResult(null)

    // Simulate offline verification
    await new Promise(r => setTimeout(r, 2000))

    const detail = evidenceDetails[evidenceId]
    const isValid = detail && (detail.id === 'ev-2024-001' || detail.id === 'ev-2024-002')

    setVerificationResult({
      valid: isValid,
      message: isValid
        ? 'VALID: Cryptographic evidence establishes the stated inconsistency. All signatures verified. Merkle proofs valid.'
        : 'INVALID: Evidence is malformed, forged, inconsistent, or insufficient. Consistency proof verification failed.',
    })
    setVerifying(null)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const formatJson = (obj: any) => JSON.stringify(obj, null, 2)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Evidence Verification</h2>
          <p className="text-[#75818A] mt-1">Cryptographically verify evidence bundles independently</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="file"
            accept=".json"
            className="hidden"
            id="evidence-upload"
            onChange={(e) => handleFileUpload(e.target.files?.[0])}
          />
          <button className="btn-secondary" onClick={() => document.getElementById('evidence-upload')?.click()}>
            <FileText className="w-4 h-4 mr-1" />
            Upload Evidence
          </button>
        </div>
      </div>

      {/* Evidence List */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Evidence Bundles</h3>
          <span className="badge badge-primary">{evidence.length} bundles</span>
        </div>
        <div className="card-body p-0">
          <Table
            data={evidence}
            columns={[
              { key: 'id', header: 'Evidence ID', render: (e: EvidenceBundle) => <span className="mono text-xs">{e.id}</span> },
              { key: 'logId', header: 'Log', render: (e: EvidenceBundle) => <span className="mono text-xs">{e.logId.slice(0, 12)}...</span> },
              { key: 'case', header: 'Case Type', render: (e: EvidenceBundle) => (
                <span className="badge badge-primary">{e.case.replace(/-/g, ' ')}</span>
              )},
              { key: 'status', header: 'Status', render: (e: EvidenceBundle) => (
                <span className={`badge ${e.status === 'valid' ? 'badge-success' : e.status === 'invalid' ? 'badge-danger' : 'badge-warning'}`}>
                  {e.status === 'valid' ? '✓ Valid' : e.status === 'invalid' ? '✗ Invalid' : '⏳ Pending'}
                </span>
              )},
              { key: 'checkpoints', header: 'Checkpoints', render: (e: EvidenceBundle) => <span className="mono">{e.checkpoints}</span> },
              { key: 'cosignatures', header: 'Cosignatures', render: (e: EvidenceBundle) => <span className="mono">{e.cosignatures}</span> },
              { key: 'detectedAt', header: 'Detected', render: (e: EvidenceBundle) => <span className="text-[#75818A] text-xs">{e.detectedAt}</span> },
              { key: 'actions', header: 'Actions', render: (e: EvidenceBundle) => (
                <div className="flex items-center gap-1">
                  <button
                    className="p-1.5 rounded hover:bg-[#F2F3F4] text-[#75818A]"
                    onClick={() => setSelectedEvidence(evidenceDetails[e.id] || null)}
                    title="View Details"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                  <button
                    className={`btn-primary btn-sm ${verifying === e.id ? 'opacity-50' : ''}`}
                    onClick={() => handleVerify(e.id)}
                    disabled={verifying !== null}
                    title="Run Offline Verifier"
                  >
                    {verifying === e.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  </button>
                </div>
              )},
            ]}
          />
        </div>
      </Card>

      {/* Verification Result */}
      {verificationResult && (
        <Card className={verificationResult.valid ? 'border-[#27865B]' : 'border-[#C74747]'} style={{ borderWidth: '2px' }}>
          <div className="card-header flex items-center justify-between" style={{ backgroundColor: verificationResult.valid ? '#27865B15' : '#C7474715' }}>
            <div className="flex items-center gap-3">
              {verificationResult.valid ? (
                <CheckCircle className="w-6 h-6 text-[#27865B]" />
              ) : (
                <XCircle className="w-6 h-6 text-[#C74747]" />
              )}
              <h3 className="font-medium" style={{ color: verificationResult.valid ? '#27865B' : '#C74747' }}>
                {verificationResult.valid ? 'Verification Passed' : 'Verification Failed'}
              </h3>
            </div>
            <button className="btn-secondary btn-sm" onClick={() => setVerificationResult(null)}>
              <XCircle className="w-4 h-4" />
            </button>
          </div>
          <div className="card-body">
            <p className="font-mono text-sm whitespace-pre-wrap">{verificationResult.message}</p>
          </div>
        </Card>
      )}

      {/* Evidence Detail View */}
      {selectedEvidence && (
        <div className="space-y-4">
          <Card>
            <div className="card-header flex items-center justify-between">
              <h3 className="font-medium text-[#233746]">Evidence Details: {selectedEvidence.id}</h3>
              <div className="flex items-center gap-2">
                <button className="btn-secondary btn-sm" onClick={() => copyToClipboard(formatJson(selectedEvidence))}>
                  <Copy className="w-4 h-4 mr-1" />
                  Copy JSON
                </button>
                <button className="btn-secondary btn-sm" onClick={() => downloadJson(selectedEvidence)}>
                  <Download className="w-4 h-4 mr-1" />
                  Download
                </button>
                <button className="btn-secondary btn-sm" onClick={() => setSelectedEvidence(null)}>
                  <XCircle className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="card-body space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="evidence-section">
                  <p className="evidence-label">Evidence ID</p>
                  <p className="evidence-value mono">{selectedEvidence.id}</p>
                </div>
                <div className="evidence-section">
                  <p className="evidence-label">Version</p>
                  <p className="evidence-value mono">{selectedEvidence.version}</p>
                </div>
                <div className="evidence-section">
                  <p className="evidence-label">Case Type</p>
                  <p className="evidence-value">{selectedEvidence.case}</p>
                </div>
                <div className="evidence-section">
                  <p className="evidence-label">Detection Time</p>
                  <p className="evidence-value">{selectedEvidence.detectionTime}</p>
                </div>
                <div className="evidence-section">
                  <p className="evidence-label">Detector</p>
                  <p className="evidence-value mono">{selectedEvidence.detectorId}</p>
                </div>
              </div>

              <div className="border-t border-[#DCE1E5] pt-4">
                <h4 className="font-medium text-[#233746] mb-3">Log Identity</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="evidence-section">
                    <p className="evidence-label">Public Key</p>
                    <p className="evidence-value mono">{selectedEvidence.logIdentity.publicKey}</p>
                  </div>
                  <div className="evidence-section">
                    <p className="evidence-label">Origin</p>
                    <p className="evidence-value mono text-xs">{selectedEvidence.logIdentity.origin}</p>
                  </div>
                </div>
              </div>

              <div className="border-t border-[#DCE1E5] pt-4">
                <h4 className="font-medium text-[#233746] mb-3">Conflicting Checkpoints ({selectedEvidence.checkpoints.length})</h4>
                <div className="space-y-3">
                  {selectedEvidence.checkpoints.map((cp, i) => (
                    <div key={i} className="p-3 bg-[#F2F3F4] rounded-lg">
                      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                        <div><p className="evidence-label">Tree Size</p><p className="evidence-value mono">{cp.treeSize.toLocaleString()}</p></div>
                        <div><p className="evidence-label">Root Hash</p><p className="evidence-value mono text-xs">{cp.rootHash}</p></div>
                        <div><p className="evidence-label">Key ID</p><p className="evidence-value mono">{cp.keyId}</p></div>
                        <div><p className="evidence-label">Signature</p><p className="evidence-value mono text-xs">{cp.signature.slice(0, 30)}...</p></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="border-t border-[#DCE1E5] pt-4">
                <h4 className="font-medium text-[#233746] mb-3">Witness Cosignatures ({selectedEvidence.cosignatures.length})</h4>
                <Table
                  data={selectedEvidence.cosignatures}
                  columns={[
                    { key: 'witnessName', header: 'Witness', render: (c: any) => <span className="font-medium">{c.witnessName}</span> },
                    { key: 'checkpointSize', header: 'Checkpoint Size', render: (c: any) => <span className="mono">{c.checkpointSize.toLocaleString()}</span> },
                    { key: 'timestamp', header: 'Timestamp', render: (c: any) => <span className="mono">{new Date(c.timestamp * 1000).toISOString()}</span> },
                    { key: 'signature', header: 'Signature', render: (c: any) => <span className="mono text-xs">{c.signature.slice(0, 40)}...</span> },
                  ]}
                />
              </div>

              {selectedEvidence.consistencyProof && (
                <div className="border-t border-[#DCE1E5] pt-4">
                  <h4 className="font-medium text-[#233746] mb-3">Consistency Proof</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="evidence-section">
                      <p className="evidence-label">Old Size</p>
                      <p className="evidence-value mono">{selectedEvidence.consistencyProof.oldSize.toLocaleString()}</p>
                    </div>
                    <div className="evidence-section">
                      <p className="evidence-label">New Size</p>
                      <p className="evidence-value mono">{selectedEvidence.consistencyProof.newSize.toLocaleString()}</p>
                    </div>
                    <div className="evidence-section">
                      <p className="evidence-label">Proof Hashes</p>
                      <p className="evidence-value mono text-xs">{selectedEvidence.consistencyProof.hashes.length} hashes</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="border-t border-[#DCE1E5] pt-4">
                <h4 className="font-medium text-[#233746] mb-3">Metadata</h4>
                <div className="font-mono text-xs bg-[#1E293B] text-[#E8EDF1] p-4 rounded overflow-x-auto">
                  {formatJson(selectedEvidence.metadata)}
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Offline Verifier Help */}
      <Card>
        <div className="card-header">
          <h3 className="font-medium text-[#233746]">Independent Offline Verifier</h3>
        </div>
        <div className="card-body">
          <p className="text-[#75818A] mb-4">The offline verifier is a standalone CLI tool that validates evidence bundles without trusting the monitoring service.</p>
          <div className="bg-[#1E293B] text-[#E8EDF1] p-4 rounded font-mono text-sm overflow-x-auto">
            {`# Verify evidence bundle
witnessmesh -mode verify -evidence ev-2024-001.json

# Output:
# Verification Result: VALID
# STATUS: VALID - Cryptographic evidence establishes the stated inconsistency`}
          </div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="p-3 bg-[#27865B]/10 rounded">
              <p className="font-medium text-[#27865B] mb-1">✓ Valid Cases</p>
              <ul className="text-xs text-[#75818A] space-y-1">
                <li>Same-size fork with valid signatures</li>
                <li>Different-size fork with valid consistency proof</li>
                <li>Witness equivocation with dual signatures</li>
              </ul>
            </div>
            <div className="p-3 bg-[#C74747]/10 rounded">
              <p className="font-medium text-[#C74747] mb-1">✗ Rejected Cases (Test Coverage)</p>
              <ul className="text-xs text-[#75818A] space-y-1">
                <li>Truncated evidence bundle</li>
                <li>Invalid log/witness signatures</li>
                <li>Mismatched log identity</li>
                <li>Incorrect tree size / altered root</li>
                <li>Missing required signatures</li>
                <li>Forged witness identity</li>
                <li>Unrelated checkpoints / malformed</li>
              </ul>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}

function handleFileUpload(file: File | undefined) {
  if (!file) return
  const reader = new FileReader()
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target?.result as string)
      console.log('Uploaded evidence:', data)
    } catch (err) {
      console.error('Invalid JSON:', err)
    }
  }
  reader.readAsText(file)
}

function downloadJson(data: any) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${data.id}.json`
  a.click()
  URL.revokeObjectURL(url)
}