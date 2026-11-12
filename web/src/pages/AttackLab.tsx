import React, { useState, useEffect } from 'react'
import {
  Play,
  Square as Stop,
  RotateCcw,
  AlertTriangle,
  Shield,
  Database,
  Users,
  WifiOff,
  Link2,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  Terminal,
  Eye,
  Download,
  Trash2,
} from 'lucide-react'
import { Card } from '../components/ui/Card'
import { Table } from '../components/ui/Table'

interface Attack {
  id: string
  name: string
  description: string
  preconditions: string[]
  category: 'split-view' | 'rollback' | 'collusion' | 'network'
  status: 'idle' | 'running' | 'prevented' | 'detected' | 'failed' | 'recovering'
  result?: string
  evidenceId?: string
  duration?: number
}

interface AttackEvent {
  timestamp: string
  level: 'info' | 'warning' | 'error' | 'success'
  message: string
  source: string
}

const attacks: Attack[] = [
  {
    id: 'split-view',
    name: 'Split-View Attack',
    description: 'Malicious log presents different histories to different clients. Honest witnesses should reject inconsistent checkpoints.',
    preconditions: ['3 honest witnesses running', '2 clients configured', 'Log in honest mode'],
    category: 'split-view',
    status: 'idle',
  },
  {
    id: 'rollback',
    name: 'Witness State Rollback',
    description: 'Snapshot witness SQLite state, advance to newer checkpoint, restore snapshot. Malicious log presents conflicting history.',
    preconditions: ['Witness-0 at checkpoint N', 'SQLite backup available', 'Malicious log mode enabled'],
    category: 'rollback',
    status: 'idle',
  },
  {
    id: 'collusion',
    name: 'Log-Witness Collusion',
    description: 'Compromised witness signs conflicting checkpoints from malicious log. Other honest witnesses should prevent quorum.',
    preconditions: ['Witness-1 configured as compromised', 'Malicious log mode enabled', 'Quorum policy 2-of-3'],
    category: 'collusion',
    status: 'idle',
  },
  {
    id: 'network-partition',
    name: 'Network Partition',
    description: 'Simulate network delay/packet loss between clients and witnesses. Test system behavior during temporary outage.',
    preconditions: ['All services running', 'tc netem available (Linux)'],
    category: 'network',
    status: 'idle',
  },
]

const categoryIcons = {
  'split-view': AlertTriangle,
  'rollback': Database,
  'collusion': Users,
  'network': WifiOff,
}

const categoryColors = {
  'split-view': '#C74747',
  'rollback': '#D69A32',
  'collusion': '#328C89',
  'network': '#75818A',
}

export function AttackLab() {
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null)
  const [events, setEvents] = useState<AttackEvent[]>([])
  const [runningAttackId, setRunningAttackId] = useState<string | null>(null)
  const [systemStatus, setSystemStatus] = useState<'ready' | 'initializing' | 'running'>('ready')

  const startAttack = async (attack: Attack) => {
    setSelectedAttack(attack)
    setRunningAttackId(attack.id)
    setEvents([])
    addEvent('info', `Starting attack: ${attack.name}`, 'system')

    // Simulate attack execution
    const steps = getAttackSteps(attack.id)
    for (const step of steps) {
      if (runningAttackId !== attack.id) break
      addEvent(step.level, step.message, step.source)
      await new Promise(r => setTimeout(r, step.delay))
    }

    // Determine result
    const result = simulateAttackResult(attack.id)
    setSelectedAttack(prev => prev ? { ...prev, status: result.status, result: result.message, evidenceId: result.evidenceId } : null)
    setRunningAttackId(null)
    addEvent(result.status === 'detected' ? 'success' : 'error', `Attack ${result.status}: ${result.message}`, 'system')
  }

  const stopAttack = () => {
    if (runningAttackId) {
      setRunningAttackId(null)
      addEvent('warning', 'Attack stopped by user', 'system')
      setSelectedAttack(prev => prev ? { ...prev, status: 'failed', result: 'Stopped by user' } : null)
    }
  }

  const resetAttack = (attack: Attack) => {
    setSelectedAttack(prev => prev?.id === attack.id ? { ...attack, status: 'idle', result: undefined, evidenceId: undefined } : prev)
    if (selectedAttack?.id === attack.id) {
      setEvents([])
    }
  }

  const downloadEvents = (attackId: string) => {
    const attack = attacks.find(a => a.id === attackId)
    const content = `Attack: ${attack?.name}\nEvents:\n${events.map(e => `[${e.timestamp}] ${e.source}: ${e.message}`).join('\n')}`
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${attackId}-events.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const addEvent = (level: AttackEvent['level'], message: string, source: string) => {
    setEvents(prev => [...prev, {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      source,
    }])
  }

  const getStatusBadge = (status: Attack['status']) => {
    const config = {
      idle: { label: 'Ready', class: 'badge-neutral', icon: Clock },
      running: { label: 'Running', class: 'attack-status-running', icon: Loader2 },
      prevented: { label: 'Prevented', class: 'attack-status-prevented', icon: Shield },
      detected: { label: 'Detected', class: 'attack-status-detected', icon: AlertTriangle },
      failed: { label: 'Failed', class: 'attack-status-failed', icon: XCircle },
      recovering: { label: 'Recovering', class: 'attack-status-recovering', icon: RotateCcw },
    }
    const c = config[status]
    return (
      <span className={c.class}>
        <c.icon className="w-3 h-3" />
        {c.label}
      </span>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Attack Laboratory</h2>
          <p className="text-[#75818A] mt-1">Controlled, reproducible attack simulations against running components</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`badge ${systemStatus === 'ready' ? 'badge-success' : 'badge-warning'}`}>
            {systemStatus === 'ready' ? 'System Ready' : 'Initializing...'}
          </span>
        </div>
      </div>

      <div className="section-grid-3">
        {attacks.map((attack) => {
          const Icon = categoryIcons[attack.category]
          const color = categoryColors[attack.category]
          const isRunning = runningAttackId === attack.id
          const isSelected = selectedAttack?.id === attack.id

          return (
            <Card
              key={attack.id}
              className={`attack-card ${isSelected ? 'ring-2' : ''} transition-all`}
              style={{ borderColor: isSelected ? color : undefined }}
            >
              <div className="attack-header">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center text-white" style={{ backgroundColor: color }}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-medium text-[#233746]">{attack.name}</h3>
                    <p className="text-xs text-[#75818A]">{attack.category}</p>
                  </div>
                </div>
                {getStatusBadge(attack.status)}
              </div>

              <div className="p-4 space-y-3">
                <p className="text-sm text-[#75818A]">{attack.description}</p>

                <div className="border-t border-[#DCE1E5] pt-3">
                  <h4 className="text-xs font-medium text-[#75818A] mb-2">Preconditions</h4>
                  <ul className="space-y-1 text-xs text-[#75818A]">
                    {attack.preconditions.map((p, i) => (
                      <li key={i} className="flex items-center gap-1">
                        <CheckCircle className="w-3 h-3 text-[#27865B]" />
                        {p}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="flex gap-2">
                  <button
                    className="btn-primary flex-1"
                    onClick={() => startAttack(attack)}
                    disabled={isRunning || systemStatus !== 'ready'}
                  >
                    {isRunning ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin mr-1" />
                        Running...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-1" />
                        Launch
                      </>
                    )}
                  </button>
                  {attack.status !== 'idle' && (
                    <button
                      className="btn-secondary"
                      onClick={() => resetAttack(attack)}
                    >
                      <RotateCcw className="w-4 h-4" />
                    </button>
                  )}
                </div>

                {attack.result && (
                  <div className={`p-3 rounded-lg text-xs ${
                    attack.status === 'detected' || attack.status === 'prevented'
                      ? 'bg-[#27865B]/10 text-[#27865B]'
                      : 'bg-[#C74747]/10 text-[#C74747]'
                  }`}>
                    <p className="font-medium mb-1">{attack.status === 'detected' || attack.status === 'prevented' ? '✓' : '✗'} {attack.result}</p>
                    {attack.evidenceId && (
                      <button className="text-xs underline mt-1 inline-block" onClick={() => viewEvidence(attack.evidenceId!)}>
                        View Evidence →
                      </button>
                    )}
                  </div>
                )}
              </div>
            </Card>
          )
        })}
      </div>

      {/* Live Event Log */}
      {selectedAttack && (
        <Card>
          <div className="card-header flex items-center justify-between">
            <h3 className="font-medium text-[#233746]">Live Event Log</h3>
            <div className="flex items-center gap-2">
              {runningAttackId && (
                <button className="btn-danger btn-sm" onClick={stopAttack}>
                  <Stop className="w-4 h-4 mr-1" />
                  Stop Attack
                </button>
              )}
              <button className="btn-secondary btn-sm" onClick={() => downloadEvents(selectedAttack!.id)}>
                <Download className="w-4 h-4 mr-1" />
                Export
              </button>
              <button className="btn-secondary btn-sm" onClick={() => setEvents([])}>
                <Trash2 className="w-4 h-4 mr-1" />
                Clear
              </button>
            </div>
          </div>
          <div className="card-body p-0 max-h-96 overflow-auto">
            <div className="font-mono text-xs p-4 bg-[#1E293B] text-[#E8EDF1]">
              {events.length === 0 ? (
                <p className="text-[#75818A]">No events yet. Launch an attack to see live output.</p>
              ) : (
                events.map((event, i) => (
                  <div
                    key={i}
                    className={`flex gap-3 py-1 border-b border-[#334155] ${
                      event.level === 'error' ? 'text-[#C74747]' :
                      event.level === 'warning' ? 'text-[#D69A32]' :
                      event.level === 'success' ? 'text-[#27865B]' :
                      'text-[#94A3B8]'
                    }`}
                  >
                    <span className="text-[#64748B] min-w-[80px]">{event.timestamp}</span>
                    <span className="text-[#64748B] min-w-[80px]">{event.source}</span>
                    <span>{event.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </Card>
      )}

      {/* Attack History / Results */}
      <Card>
        <div className="card-header flex items-center justify-between">
          <h3 className="font-medium text-[#233746]">Attack History</h3>
          <span className="text-xs text-[#75818A] font-mono">suite author: <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="text-[#328C89] hover:underline">@geeky-rish</a></span>
        </div>
        <div className="card-body p-0">
          <Table
            data={attacks.filter(a => a.status !== 'idle')}
            columns={[
              { key: 'name', header: 'Attack', render: (a: Attack) => {
                const IconComp = categoryIcons[a.category];
                return (
                  <div className="flex items-center gap-2">
                    {IconComp && <IconComp className="w-4 h-4" style={{ color: categoryColors[a.category] }} />}
                    <span>{a.name}</span>
                  </div>
                );
              }},
              { key: 'status', header: 'Status', render: (a: Attack) => getStatusBadge(a.status) },
              { key: 'result', header: 'Result', render: (a: Attack) => (
                <span className={`text-sm ${a.status === 'detected' || a.status === 'prevented' ? 'text-[#27865B]' : 'text-[#C74747]'}`}>
                  {a.result || '—'}
                </span>
              )},
              { key: 'evidenceId', header: 'Evidence', render: (a: Attack) => a.evidenceId ? (
                <button className="text-sm text-[#328C89] hover:underline" onClick={() => viewEvidence(a.evidenceId!)}>
                  <Eye className="w-3 h-3 inline mr-1" />
                  View
                </button>
              ) : <span className="text-[#75818A]">—</span> },
            ]}
          />
        </div>
      </Card>
    </div>
  )
}

function getAttackSteps(attackId: string) {
  const steps: { level: AttackEvent['level']; message: string; source: string; delay: number }[] = []

  switch (attackId) {
    case 'split-view':
      steps.push(
        { level: 'info', message: 'Enabling malicious mode on transparency log', source: 'log', delay: 500 },
        { level: 'info', message: 'Creating alternative history with different Merkle root', source: 'log', delay: 800 },
        { level: 'info', message: 'Client-0 requests checkpoint from log', source: 'client-0', delay: 300 },
        { level: 'info', message: 'Client-1 requests checkpoint from log (different history)', source: 'client-1', delay: 300 },
        { level: 'info', message: 'Client-0 submits checkpoint to witnesses for cosignature', source: 'client-0', delay: 400 },
        { level: 'info', message: 'Client-1 submits checkpoint to witnesses for cosignature', source: 'client-1', delay: 400 },
        { level: 'success', message: 'Witness-0 verified consistency, cosignature issued', source: 'witness-0', delay: 500 },
        { level: 'success', message: 'Witness-1 verified consistency, cosignature issued', source: 'witness-1', delay: 500 },
        { level: 'success', message: 'Witness-2 verified consistency, cosignature issued', source: 'witness-2', delay: 500 },
        { level: 'warning', message: 'Witness-0 rejected inconsistent checkpoint (old size mismatch)', source: 'witness-0', delay: 500 },
        { level: 'warning', message: 'Witness-1 rejected inconsistent checkpoint (old size mismatch)', source: 'witness-1', delay: 500 },
        { level: 'warning', message: 'Witness-2 rejected inconsistent checkpoint (old size mismatch)', source: 'witness-2', delay: 500 },
        { level: 'success', message: 'Client-0: Quorum verification failed - insufficient valid cosignatures', source: 'client-0', delay: 400 },
        { level: 'success', message: 'Client-1: Quorum verification failed - insufficient valid cosignatures', source: 'client-1', delay: 400 },
      )
      break
    case 'rollback':
      steps.push(
        { level: 'info', message: 'Creating SQLite snapshot of witness-0 database', source: 'witness-0', delay: 500 },
        { level: 'info', message: 'Advancing witness-0 to checkpoint size 1,240', source: 'witness-0', delay: 800 },
        { level: 'info', message: 'Restoring witness-0 database from snapshot (size 1,230)', source: 'witness-0', delay: 600 },
        { level: 'info', message: 'Enabling malicious mode on transparency log', source: 'log', delay: 500 },
        { level: 'info', message: 'Malicious log presents checkpoint at size 1,235 (conflicting history)', source: 'log', delay: 800 },
        { level: 'info', message: 'Client-0 requests checkpoint from log', source: 'client-0', delay: 300 },
        { level: 'info', message: 'Client-0 submits checkpoint to witnesses', source: 'client-0', delay: 400 },
        { level: 'warning', message: 'Witness-0 (rolled back) accepts inconsistent checkpoint', source: 'witness-0', delay: 500 },
        { level: 'success', message: 'Witness-1 rejects inconsistent checkpoint', source: 'witness-1', delay: 500 },
        { level: 'success', message: 'Witness-2 rejects inconsistent checkpoint', source: 'witness-2', delay: 500 },
        { level: 'success', message: 'Monitor detects fork: same log, different roots at size 1,235', source: 'monitor', delay: 600 },
        { level: 'success', message: 'Evidence bundle generated: same-size fork', source: 'monitor', delay: 500 },
      )
      break
    case 'collusion':
      steps.push(
        { level: 'info', message: 'Configuring witness-1 as compromised', source: 'witness-1', delay: 500 },
        { level: 'info', message: 'Enabling malicious mode on transparency log', source: 'log', delay: 500 },
        { level: 'info', message: 'Log presents conflicting checkpoint to witness-1', source: 'log', delay: 800 },
        { level: 'warning', message: 'Witness-1 (compromised) signs conflicting checkpoint', source: 'witness-1', delay: 500 },
        { level: 'info', message: 'Client-0 collects cosignatures from witnesses', source: 'client-0', delay: 400 },
        { level: 'success', message: 'Witness-0 and Witness-2 reject inconsistent checkpoint', source: 'monitor', delay: 500 },
        { level: 'success', message: 'Client-0: Quorum not met (only 1/3 valid cosignatures)', source: 'client-0', delay: 400 },
        { level: 'success', message: 'Monitor detects witness equivocation: Witness-1 signed conflicting checkpoints', source: 'monitor', delay: 600 },
        { level: 'success', message: 'Evidence bundle generated: witness equivocation', source: 'monitor', delay: 500 },
      )
      break
    case 'network-partition':
      steps.push(
        { level: 'info', message: 'Applying network delay (100ms) between clients and witness-2', source: 'network', delay: 500 },
        { level: 'info', message: 'Client-0 requests checkpoint', source: 'client-0', delay: 300 },
        { level: 'info', message: 'Witness-2 response delayed by network partition', source: 'witness-2', delay: 800 },
        { level: 'warning', message: 'Client-0 timeout waiting for witness-2 cosignature', source: 'client-0', delay: 1000 },
        { level: 'success', message: 'Client-0 proceeds with quorum from witness-0 and witness-1', source: 'client-0', delay: 400 },
        { level: 'info', message: 'Network partition restored', source: 'network', delay: 500 },
        { level: 'success', message: 'Witness-2 catches up, state synchronized', source: 'witness-2', delay: 500 },
      )
      break
  }

  return steps
}

function simulateAttackResult(attackId: string): { status: Attack['status']; message: string; evidenceId?: string } {
  switch (attackId) {
    case 'split-view':
      return { status: 'prevented', message: 'Honest witnesses rejected inconsistent checkpoints. Clients failed quorum verification.', evidenceId: undefined }
    case 'rollback':
      return { status: 'detected', message: 'Rolled-back witness accepted conflicting checkpoint. Monitor detected same-size fork.', evidenceId: 'ev-2024-001' }
    case 'collusion':
      return { status: 'detected', message: 'Compromised witness signed conflicting checkpoint. Quorum not met. Witness equivocation detected.', evidenceId: 'ev-2024-002' }
    case 'network-partition':
      return { status: 'recovering', message: 'Temporary partition handled gracefully. Quorum maintained with available witnesses. System recovered.', evidenceId: undefined }
    default:
      return { status: 'failed', message: 'Unknown attack', evidenceId: undefined }
  }
}

function viewEvidence(evidenceId: string) {
  window.location.href = `/evidence?id=${evidenceId}`
}