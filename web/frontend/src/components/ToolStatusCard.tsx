/**
 * Tool status card component
 */

import { ScanStatusBadge } from './ScanStatusBadge';

interface ToolStatusCardProps {
  toolName: string;
  phase: number;
  status: 'PENDING' | 'RUNNING' | 'DONE' | 'ERROR' | 'SKIPPED';
  duration?: number | null;
  returncode?: number | null;
}

const TOOL_COLORS: Record<string, string> = {
  nmap: 'border-cyan-400',
  netexec: 'border-green-400',
  smbmap: 'border-cyan-600',
  amass: 'border-blue-400',
  httpx: 'border-yellow-400',
  nuclei: 'border-red-400',
  feroxbuster: 'border-purple-400',
  metasploit: 'border-white',
};

export function ToolStatusCard({ toolName, phase, status, duration, returncode }: ToolStatusCardProps) {
  const borderColor = TOOL_COLORS[toolName.toLowerCase()] || 'border-gray-400';

  return (
    <div className={`border-l-4 ${borderColor} bg-white shadow rounded-lg p-4`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-bold uppercase">{toolName}</h3>
        <ScanStatusBadge status={status as any} />
      </div>

      <div className="text-sm text-gray-600 space-y-1">
        <div>
          <span className="font-semibold">Phase:</span> {phase}
        </div>

        {duration !== null && duration !== undefined && (
          <div>
            <span className="font-semibold">Duration:</span> {duration.toFixed(2)}s
          </div>
        )}

        {returncode !== null && returncode !== undefined && (
          <div>
            <span className="font-semibold">Exit Code:</span>{' '}
            <span className={returncode === 0 ? 'text-green-600' : 'text-red-600'}>
              {returncode}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
