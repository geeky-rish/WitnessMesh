import React, { useState, useEffect } from 'react'
import ReactFlow, {
  Node,
  Edge,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  Background,
  Controls,
  MiniMap,
  NodeTypes,
  EdgeTypes,
  Handle,
  Position,
} from 'reactflow'
import { Server, Monitor, Shield, AlertTriangle, WifiOff, CheckCircle, XCircle, Wifi } from 'lucide-react'
import { Card } from '../components/ui/Card'
import 'reactflow/dist/style.css'

interface CustomNodeData {
  label: string
  type: 'log' | 'client' | 'witness' | 'monitor'
  status: 'healthy' | 'warning' | 'critical' | 'offline'
  details?: Record<string, string>
}

type CustomNode = Node<CustomNodeData, 'custom'>

const nodeTypes: NodeTypes = {
  custom: CustomNodeComponent,
}

function CustomNodeComponent({ data }: { data: CustomNodeData }) {
  const getIcon = () => {
    switch (data.type) {
      case 'log': return <Server className="w-5 h-5" />
      case 'client': return <Monitor className="w-5 h-5" />
      case 'witness': return <Shield className="w-5 h-5" />
      case 'monitor': return <AlertTriangle className="w-5 h-5" />
    }
  }

  const getStatusColor = () => {
    switch (data.status) {
      case 'healthy': return '#27865B'
      case 'warning': return '#D69A32'
      case 'critical': return '#C74747'
      case 'offline': return '#75818A'
    }
  }

  return (
    <div
      className="custom-node"
      style={{
        background: 'white',
        border: `2px solid ${getStatusColor()}`,
        borderRadius: '12px',
        padding: '12px 16px',
        minWidth: '160px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      }}
    >
      <div className="flex items-center gap-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center text-white"
          style={{ backgroundColor: getStatusColor() }}
        >
          {getIcon()}
        </div>
        <div>
          <p className="font-medium text-[#233746]">{data.label}</p>
          <p className="text-xs text-[#75818A] capitalize">{data.type}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 mt-2 pt-2 border-t border-[#DCE1E5]">
        <span
          className="status-dot"
          style={{ backgroundColor: getStatusColor() }}
        />
        <span className="text-xs font-medium" style={{ color: getStatusColor() }}>
          {data.status.charAt(0).toUpperCase() + data.status.slice(1)}
        </span>
      </div>
      <Handle type="source" position={Position.Right} className="w-3 h-3 bg-[#328C89]" />
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-[#328C89]" />
    </div>
  )
}

const initialNodes: CustomNode[] = [
  {
    id: 'log-1',
    type: 'custom',
    position: { x: 100, y: 200 },
    data: {
      label: 'Transparency Log',
      type: 'log',
      status: 'healthy',
      details: { 'Tree Size': '1,234', 'Root Hash': 'abc123...', 'Origin': 'sigsum.org/v1/...' },
    },
  },
  {
    id: 'witness-0',
    type: 'custom',
    position: { x: 400, y: 80 },
    data: {
      label: 'Witness-0',
      type: 'witness',
      status: 'healthy',
      details: { 'Cosignatures': '47', 'Last Checkpoint': 'Size 1,234' },
    },
  },
  {
    id: 'witness-1',
    type: 'custom',
    position: { x: 400, y: 200 },
    data: {
      label: 'Witness-1',
      type: 'witness',
      status: 'healthy',
      details: { 'Cosignatures': '47', 'Last Checkpoint': 'Size 1,234' },
    },
  },
  {
    id: 'witness-2',
    type: 'custom',
    position: { x: 400, y: 320 },
    data: {
      label: 'Witness-2',
      type: 'witness',
      status: 'healthy',
      details: { 'Cosignatures': '46', 'Last Checkpoint': 'Size 1,230' },
    },
  },
  {
    id: 'client-0',
    type: 'custom',
    position: { x: 700, y: 120 },
    data: {
      label: 'Client-0',
      type: 'client',
      status: 'healthy',
      details: { 'Policy': '2-of-3', 'Verified': 'Yes' },
    },
  },
  {
    id: 'client-1',
    type: 'custom',
    position: { x: 700, y: 280 },
    data: {
      label: 'Client-1',
      type: 'client',
      status: 'healthy',
      details: { 'Policy': '2-of-3', 'Verified': 'Yes' },
    },
  },
  {
    id: 'monitor-1',
    type: 'custom',
    position: { x: 550, y: 400 },
    data: {
      label: 'Monitor',
      type: 'monitor',
      status: 'healthy',
      details: { 'Incidents': '1', 'Polling': '10s' },
    },
  },
]

const initialEdges: Edge[] = [
  { id: 'e1', source: 'log-1', target: 'witness-0', animated: true, style: { stroke: '#328C89', strokeWidth: 2 } },
  { id: 'e2', source: 'log-1', target: 'witness-1', animated: true, style: { stroke: '#328C89', strokeWidth: 2 } },
  { id: 'e3', source: 'log-1', target: 'witness-2', animated: true, style: { stroke: '#328C89', strokeWidth: 2 } },
  { id: 'e4', source: 'witness-0', target: 'client-0', animated: true, style: { stroke: '#27865B', strokeWidth: 2, strokeDasharray: '5,5' } },
  { id: 'e5', source: 'witness-1', target: 'client-0', animated: true, style: { stroke: '#27865B', strokeWidth: 2, strokeDasharray: '5,5' } },
  { id: 'e6', source: 'witness-1', target: 'client-1', animated: true, style: { stroke: '#27865B', strokeWidth: 2, strokeDasharray: '5,5' } },
  { id: 'e7', source: 'witness-2', target: 'client-1', animated: true, style: { stroke: '#27865B', strokeWidth: 2, strokeDasharray: '5,5' } },
  { id: 'e8', source: 'witness-0', target: 'monitor-1', style: { stroke: '#D69A32', strokeWidth: 1 } },
  { id: 'e9', source: 'witness-1', target: 'monitor-1', style: { stroke: '#D69A32', strokeWidth: 1 } },
  { id: 'e10', source: 'witness-2', target: 'monitor-1', style: { stroke: '#D69A32', strokeWidth: 1 } },
  { id: 'e11', source: 'log-1', target: 'monitor-1', style: { stroke: '#D69A32', strokeWidth: 1 } },
]

export function NetworkTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const [selectedNode, setSelectedNode] = useState<CustomNode | null>(null)

  const onConnect = (connection: Connection) => {
    setEdges((eds) => addEdge({ ...connection, animated: true, style: { stroke: '#328C89', strokeWidth: 2 } }, eds))
  }

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNode(node as CustomNode)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-[#233746]">Network Topology</h2>
          <p className="text-[#75818A] mt-1">Real-time visualization of the WitnessMesh network</p>
        </div>
        <div className="flex items-center gap-4 text-sm text-[#75818A]">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-[#328C89]" /> Checkpoint</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-[#27865B]" /> Cosignature</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-[#D69A32]" /> Monitoring</span>
        </div>
      </div>

      <div className="section-grid">
        <div className="topology-container lg:col-span-2">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            attributionPosition="bottom-left"
          >
            <Background color="#DCE1E5" gap={16} />
            <Controls />
            <MiniMap nodeColor={(node) => {
              const status = (node.data as CustomNodeData).status
              switch (status) {
                case 'healthy': return '#27865B'
                case 'warning': return '#D69A32'
                case 'critical': return '#C74747'
                default: return '#75818A'
              }
            }} />
          </ReactFlow>
        </div>

        {/* Node Details Panel */}
        <Card>
          <div className="card-header">
            <h3 className="font-medium text-[#233746]">Node Details</h3>
          </div>
          <div className="card-body">
            {selectedNode ? (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-lg flex items-center justify-center text-white bg-[#328C89]">
                    {selectedNode.data.type === 'log' && <Server className="w-6 h-6" />}
                    {selectedNode.data.type === 'client' && <Monitor className="w-6 h-6" />}
                    {selectedNode.data.type === 'witness' && <Shield className="w-6 h-6" />}
                    {selectedNode.data.type === 'monitor' && <AlertTriangle className="w-6 h-6" />}
                  </div>
                  <div>
                    <p className="font-medium text-[#233746] text-lg">{selectedNode.data.label}</p>
                    <span className={`badge badge-${selectedNode.data.status === 'healthy' ? 'success' : selectedNode.data.status === 'warning' ? 'warning' : 'danger'}`}>
                      {selectedNode.data.status}
                    </span>
                  </div>
                </div>
                <div className="space-y-2">
                  {selectedNode.data.details && Object.entries(selectedNode.data.details).map(([key, value]) => (
                    <div key={key} className="flex justify-between text-sm">
                      <span className="text-[#75818A]">{key}</span>
                      <span className="font-mono text-[#233746]">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p>Click a node to view details</p>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Legend */}
      <Card>
        <div className="card-body">
          <div className="flex flex-wrap gap-6">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-[#27865B]" />
              <span className="text-sm text-[#75818A]">Healthy</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-[#D69A32]" />
              <span className="text-sm text-[#75818A]">Warning</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-[#C74747]" />
              <span className="text-sm text-[#75818A]">Critical</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-[#75818A]" />
              <span className="text-sm text-[#75818A]">Offline</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-[#328C89]" />
              <span className="text-sm text-[#75818A]">Checkpoint Flow</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-[#27865B] border-t border-b border-dashed" style={{ borderColor: '#27865B' }} />
              <span className="text-sm text-[#75818A]">Cosignature Flow</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-[#D69A32]" />
              <span className="text-sm text-[#75818A]">Monitoring</span>
            </div>
            <div className="ml-auto flex items-center text-xs text-[#75818A]">
              <span>mesh engine: <a href="https://github.com/geeky-rish" target="_blank" rel="noopener noreferrer" className="text-[#328C89] hover:underline font-mono">@geeky-rish</a></span>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}