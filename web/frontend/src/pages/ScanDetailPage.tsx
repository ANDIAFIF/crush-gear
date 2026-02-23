/**
 * Scan Detail page - Real-time monitoring and results
 */

import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useScan, useHosts, useVulnerabilities, useToolOutputs } from '../hooks/useScans';
import { useWebSocket } from '../hooks/useWebSocket';
import { ScanStatusBadge } from '../components/ScanStatusBadge';
import { PhaseProgress } from '../components/PhaseProgress';
import { ToolStatusCard } from '../components/ToolStatusCard';
import { ToolOutput } from '../components/ToolOutput';
import type { WebSocketMessage, ToolOutputLine } from '../types';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const scanId = parseInt(id || '0');

  // Auto-refresh hooks use refetchInterval internally based on scan status
  const { data: scan, isLoading, error } = useScan(scanId);
  const { data: hostsData } = useHosts(scanId, scan?.status);
  const { data: vulnsData } = useVulnerabilities(scanId, scan?.status);

  const [activeTab, setActiveTab] = useState<'overview' | 'terminal' | 'hosts' | 'vulnerabilities'>('overview');
  const [terminalLines, setTerminalLines] = useState<ToolOutputLine[]>([]);
  const [selectedTool, setSelectedTool] = useState<string>('all');

  // Fetch historical tool outputs - auto-refetches for running scans
  const toolOutputFilter = selectedTool !== 'all' ? selectedTool : undefined;
  const { data: historicalOutputs } = useToolOutputs(scanId, toolOutputFilter, { limit: 5000 }, scan?.status);

  // Debug: Log when filter changes
  useEffect(() => {
    console.log('🔍 Filter changed:', { selectedTool, toolOutputFilter });
  }, [selectedTool, toolOutputFilter]);

  // WebSocket for real-time updates (TEMPORARILY DISABLED due to connection issues)
  // Using REST API polling with refetchInterval instead
  const { isConnected } = useWebSocket(
    0, // Disabled - pass 0 to prevent connection
    {
      onMessage: (message: WebSocketMessage) => {
        if (message.type === 'tool_output') {
          // Add to terminal output
          if (selectedTool === 'all' || selectedTool === message.tool) {
            setTerminalLines((prev) => [
              ...prev,
              {
                line_num: message.line_num,
                line_text: `[${message.tool}] ${message.line}`,
                tool_name: message.tool,
                timestamp: message.timestamp
              },
            ]);
          }
        }
      },
    }
  );
  
  // Load historical outputs when scan is completed or when filter changes
  useEffect(() => {
    if (historicalOutputs?.outputs) {
      // Always update terminal lines when historical outputs change
      // This handles: completed scans, running scans, and filter changes
      setTerminalLines(historicalOutputs.outputs);
    }
  }, [historicalOutputs]);

  // Compute phase statuses
  type PhaseStatus = 'pending' | 'running' | 'completed' | 'error';
  const phases: Array<{ number: number; name: string; status: PhaseStatus }> = [
    { number: 0, name: 'Port Scan', status: 'pending' },
    { number: 1, name: 'Reconnaissance', status: 'pending' },
    { number: 2, name: 'Scanning', status: 'pending' },
    { number: 3, name: 'Exploitation', status: 'pending' },
  ];

  // Update phase statuses based on tool executions
  if (scan?.tool_executions) {
    scan.tool_executions.forEach((tool) => {
      const phase = phases[tool.phase];
      if (phase) {
        if (tool.status === 'RUNNING') {
          phase.status = 'running';
        } else if (tool.status === 'DONE' && phase.status !== 'running') {
          phase.status = 'completed';
        } else if (tool.status === 'ERROR') {
          phase.status = 'error';
        }
      }
    });
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl">Loading scan...</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-red-600">Error loading scan</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <Link to="/" className="text-blue-600 hover:underline mb-4 inline-block">
          ← Back to Dashboard
        </Link>
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Scan #{scan.id}</h1>
            <p className="text-gray-600 mt-1">Target: {scan.target}</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <ScanStatusBadge status={scan.status} />
            {isConnected && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                Live
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Phase Progress */}
      <PhaseProgress phases={phases} />

      {/* Current Progress - Show for running scans */}
      {scan.status === 'RUNNING' && scan.tool_executions && (
        <div className="mb-6 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-lg p-6 shadow-sm">
          <h2 className="text-xl font-bold text-blue-900 mb-4 flex items-center gap-2">
            <span className="w-3 h-3 bg-blue-500 rounded-full animate-pulse"></span>
            Current Progress
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Current Phase */}
            {(() => {
              const currentPhase = phases.find(p => p.status === 'running');
              return currentPhase && (
                <div className="bg-white rounded-lg p-4 border border-blue-100">
                  <p className="text-sm text-gray-600 mb-1">Current Phase</p>
                  <p className="text-lg font-bold text-blue-900">
                    Phase {currentPhase.number}: {currentPhase.name}
                  </p>
                </div>
              );
            })()}

            {/* Current Tool */}
            {(() => {
              const runningTool = scan.tool_executions.find(t => t.status === 'RUNNING');
              return runningTool && (
                <div className="bg-white rounded-lg p-4 border border-blue-100">
                  <p className="text-sm text-gray-600 mb-1">Running Tool</p>
                  <p className="text-lg font-bold text-blue-900 uppercase">
                    {runningTool.tool_name}
                  </p>
                  {runningTool.started_at && (
                    <p className="text-xs text-gray-500 mt-1">
                      Started: {new Date(runningTool.started_at).toLocaleTimeString()}
                    </p>
                  )}
                </div>
              );
            })()}

            {/* Progress Stats */}
            <div className="bg-white rounded-lg p-4 border border-blue-100">
              <p className="text-sm text-gray-600 mb-1">Progress</p>
              <p className="text-lg font-bold text-blue-900">
                {scan.tool_executions.filter(t => t.status === 'DONE').length} / {scan.tool_executions.length} tools
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {scan.tool_executions.filter(t => t.status === 'ERROR').length} errors, {scan.tool_executions.filter(t => t.status === 'SKIPPED').length} skipped
              </p>
            </div>
          </div>

          {/* Live Output Preview */}
          {terminalLines.length > 0 && (
            <div className="mt-4 bg-gray-900 text-green-400 rounded-lg p-4 font-mono text-sm max-h-48 overflow-y-auto">
              <p className="text-gray-500 text-xs mb-2">Live Output (last 10 lines):</p>
              {terminalLines.slice(-10).map((line, idx) => (
                <div key={`preview-${idx}`} className="text-xs">
                  <span className="text-gray-500">[{line.tool_name}]</span> {line.line_text}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8">
          {(['overview', 'terminal', 'hosts', 'vulnerabilities'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`
                py-4 px-1 border-b-2 font-medium text-sm capitalize
                ${activeTab === tab
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }
              `}
            >
              {tab}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div>
          <h2 className="text-2xl font-bold mb-4">Tool Executions</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {scan.tool_executions.map((tool) => (
              <ToolStatusCard
                key={tool.id}
                toolName={tool.tool_name}
                phase={tool.phase}
                status={tool.status}
                duration={tool.duration}
                returncode={tool.returncode}
                onClick={() => {
                  console.log('🎯 Tool card clicked:', tool.tool_name);
                  setActiveTab('terminal');
                  setSelectedTool(tool.tool_name);
                }}
              />
            ))}
          </div>

          {scan.total_duration && (
            <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
              <p className="text-sm font-semibold text-blue-900">
                Total Duration: {scan.total_duration.toFixed(1)}s
              </p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'terminal' && (
        <div>
          <div className="mb-4 flex items-center gap-4">
            <label className="font-semibold">Filter by tool:</label>
            <select
              value={selectedTool}
              onChange={(e) => setSelectedTool(e.target.value)}
              className="border border-gray-300 rounded px-3 py-2"
            >
              <option value="all">All Tools</option>
              {Array.from(new Set(scan.tool_executions.map((t) => t.tool_name))).map((tool) => (
                <option key={tool} value={tool}>{tool}</option>
              ))}
            </select>
          </div>
          <ToolOutput lines={terminalLines} />
        </div>
      )}

      {activeTab === 'hosts' && (
        <div>
          <h2 className="text-2xl font-bold mb-4">Discovered Hosts</h2>
          {hostsData?.hosts.length === 0 ? (
            <p className="text-gray-500">No hosts discovered yet.</p>
          ) : (
            <div className="space-y-4">
              {hostsData?.hosts.map((host) => (
                <div key={host.id} className="bg-white border border-gray-200 rounded-lg p-4">
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h3 className="text-lg font-bold">{host.ip}</h3>
                      {host.hostname && <p className="text-sm text-gray-600">{host.hostname}</p>}
                    </div>
                    <div className="flex gap-2">
                      {host.is_windows && (
                        <span className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">Windows</span>
                      )}
                      {host.is_dc && (
                        <span className="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded">DC</span>
                      )}
                    </div>
                  </div>

                  {host.os_guess && (
                    <p className="text-sm text-gray-600 mb-3">OS: {host.os_guess}</p>
                  )}

                  <div className="border-t pt-3">
                    <h4 className="font-semibold text-sm mb-2">Open Ports:</h4>
                    <div className="flex flex-wrap gap-2">
                      {host.ports.map((port) => (
                        <div
                          key={port.id}
                          className="px-3 py-1 bg-gray-100 rounded text-sm"
                        >
                          <span className="font-mono font-bold">{port.port_num}</span>
                          {port.service && <span className="text-gray-600"> / {port.service}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'vulnerabilities' && (
        <div>
          <h2 className="text-2xl font-bold mb-4">Vulnerabilities</h2>
          {vulnsData?.vulnerabilities.length === 0 ? (
            <p className="text-gray-500">No vulnerabilities found yet.</p>
          ) : (
            <div className="space-y-3">
              {vulnsData?.vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className={`border-l-4 rounded-lg p-4 bg-white shadow ${
                    vuln.severity === 'critical' ? 'border-red-600' :
                    vuln.severity === 'high' ? 'border-orange-500' :
                    vuln.severity === 'medium' ? 'border-yellow-500' :
                    vuln.severity === 'low' ? 'border-blue-500' :
                    'border-gray-400'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div>
                      {vuln.cve_id && (
                        <h3 className="font-bold text-lg">{vuln.cve_id}</h3>
                      )}
                      <p className="text-sm text-gray-600">Host: {vuln.host}</p>
                      {vuln.template_id && (
                        <p className="text-xs text-gray-500">Template: {vuln.template_id}</p>
                      )}
                    </div>
                    {vuln.severity && (
                      <span className={`px-3 py-1 rounded-full text-sm font-semibold uppercase ${
                        vuln.severity === 'critical' ? 'bg-red-600 text-white' :
                        vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                        vuln.severity === 'medium' ? 'bg-yellow-500 text-white' :
                        vuln.severity === 'low' ? 'bg-blue-500 text-white' :
                        'bg-gray-400 text-white'
                      }`}>
                        {vuln.severity}
                      </span>
                    )}
                  </div>

                  {vuln.msf_module && (
                    <div className="mt-3 pt-3 border-t">
                      <p className="text-sm">
                        <span className="font-semibold">Metasploit Module:</span>{' '}
                        <code className="bg-gray-100 px-2 py-1 rounded text-xs">{vuln.msf_module}</code>
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
