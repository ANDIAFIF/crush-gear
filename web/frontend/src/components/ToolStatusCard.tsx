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
  onClick?: () => void;
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

export function ToolStatusCard({ toolName, phase, status, duration, returncode, onClick }: ToolStatusCardProps) {
  const borderColor = TOOL_COLORS[toolName.toLowerCase()] || 'border-gray-400';
  const isClickable = onClick && (status === 'DONE' || status === 'ERROR' || status === 'RUNNING');
  const clickableClass = isClickable ? 'cursor-pointer hover:shadow-lg hover:scale-105 transition-all' : '';

  return (
    <div
      className={`border-l-4 ${borderColor} bg-white shadow rounded-lg p-4 ${clickableClass}`}
      onClick={isClickable ? onClick : undefined}
      title={isClickable ? `Click to view ${toolName} output` : ''}
    >
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

      {isClickable && (
        <div className="mt-3 pt-3 border-t border-gray-200">
          <p className="text-xs text-blue-600 font-semibold flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
            Click to view output
          </p>
        </div>
      )}
    </div>
  );
}
