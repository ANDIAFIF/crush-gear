/**
 * Dashboard page - List of all scans
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useScans, useDeleteScan } from '../hooks/useScans';
import { ScanStatusBadge } from '../components/ScanStatusBadge';

export function DashboardPage() {
  const [statusFilter, setStatusFilter] = useState<string>('');
  const { data, isLoading, error } = useScans({ status: statusFilter || undefined });
  const deleteScan = useDeleteScan();

  const handleDelete = async (scanId: number) => {
    if (confirm('Are you sure you want to delete this scan?')) {
      await deleteScan.mutateAsync(scanId);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl">Loading scans...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-red-600">Error loading scans: {error.message}</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">CrushGear Dashboard</h1>
        <Link
          to="/new-scan"
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        >
          New Scan
        </Link>
      </div>

      <div className="mb-4">
        <label className="mr-2 font-semibold">Filter by status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="border border-gray-300 rounded px-3 py-2"
        >
          <option value="">All</option>
          <option value="PENDING">PENDING</option>
          <option value="RUNNING">RUNNING</option>
          <option value="COMPLETED">COMPLETED</option>
          <option value="ERROR">ERROR</option>
        </select>
      </div>

      <div className="bg-white shadow-md rounded-lg overflow-hidden">
        <table className="min-w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {data?.scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm">{scan.id}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <Link to={`/scans/${scan.id}`} className="text-blue-600 hover:underline">
                    {scan.target}
                  </Link>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <ScanStatusBadge status={scan.status} />
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {new Date(scan.started_at).toLocaleString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {scan.total_duration ? `${scan.total_duration.toFixed(1)}s` : '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <button
                    onClick={() => handleDelete(scan.id)}
                    className="text-red-600 hover:text-red-800"
                    disabled={deleteScan.isPending}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data?.scans.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          No scans found. <Link to="/new-scan" className="text-blue-600 hover:underline">Create one!</Link>
        </div>
      )}
    </div>
  );
}
