/**
 * Status badge component for scans
 */

interface ScanStatusBadgeProps {
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'ERROR';
}

export function ScanStatusBadge({ status }: ScanStatusBadgeProps) {
  const getStatusColor = () => {
    switch (status) {
      case 'PENDING':
        return 'bg-gray-500 text-white';
      case 'RUNNING':
        return 'bg-blue-500 text-white animate-pulse';
      case 'COMPLETED':
        return 'bg-green-500 text-white';
      case 'ERROR':
        return 'bg-red-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  };

  return (
    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getStatusColor()}`}>
      {status}
    </span>
  );
}
