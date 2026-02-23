/**
 * New Scan page - Form to start a new scan
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useStartScan } from '../hooks/useScans';

const AVAILABLE_TOOLS = [
  { name: 'nmap', label: 'Nmap (Port Scanning)', phase: 0 },
  { name: 'amass', label: 'Amass (Subdomain Enumeration)', phase: 1 },
  { name: 'httpx', label: 'HTTPx (Web Probing)', phase: 1 },
  { name: 'netexec', label: 'NetExec (SMB/SSH Enumeration)', phase: 2 },
  { name: 'smbmap', label: 'SMBMap (Share Enumeration)', phase: 2 },
  { name: 'nuclei', label: 'Nuclei (Vulnerability Scanning)', phase: 2 },
  { name: 'feroxbuster', label: 'Feroxbuster (Directory Bruteforce)', phase: 2 },
  { name: 'metasploit', label: 'Metasploit (Exploitation)', phase: 3 },
];

export function NewScanPage() {
  const navigate = useNavigate();
  const startScan = useStartScan();

  const [formData, setFormData] = useState({
    target: '',
    lhost: '',
    lport: '',
    username: '',
    password: '',
  });

  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const scan = await startScan.mutateAsync({
        target: formData.target,
        tools: selectedTools.length > 0 ? selectedTools.join(',') : undefined,
        lhost: formData.lhost || undefined,
        lport: formData.lport ? parseInt(formData.lport) : undefined,
        username: formData.username || undefined,
        password: formData.password || undefined,
      });

      navigate(`/scans/${scan.id}`);
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan. Please try again.');
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleToolToggle = (toolName: string) => {
    setSelectedTools((prev) =>
      prev.includes(toolName)
        ? prev.filter((t) => t !== toolName)
        : [...prev, toolName]
    );
  };

  const handleSelectAll = () => {
    if (selectAll) {
      setSelectedTools([]);
    } else {
      setSelectedTools(AVAILABLE_TOOLS.map((t) => t.name));
    }
    setSelectAll(!selectAll);
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <h1 className="text-3xl font-bold mb-8">Start New Scan</h1>

      <form onSubmit={handleSubmit} className="bg-white shadow-md rounded-lg p-6 space-y-6">
        {/* Target */}
        <div>
          <label htmlFor="target" className="block text-sm font-medium text-gray-700 mb-2">
            Target <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            id="target"
            name="target"
            value={formData.target}
            onChange={handleChange}
            required
            placeholder="IP, domain, URL, or CIDR (e.g., 192.168.1.1, scanme.nmap.org)"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Tools Selection */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <label className="block text-sm font-medium text-gray-700">
              Tools (leave empty for all tools)
            </label>
            <button
              type="button"
              onClick={handleSelectAll}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              {selectAll ? 'Deselect All' : 'Select All'}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-gray-50 p-4 rounded-md">
            {AVAILABLE_TOOLS.map((tool) => (
              <label
                key={tool.name}
                className="flex items-center space-x-3 p-2 hover:bg-white rounded cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={selectedTools.includes(tool.name)}
                  onChange={() => handleToolToggle(tool.name)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <div>
                  <span className="text-sm font-medium text-gray-900">{tool.label}</span>
                  <span className="ml-2 text-xs text-gray-500">Phase {tool.phase}</span>
                </div>
              </label>
            ))}
          </div>

          {selectedTools.length > 0 && (
            <div className="mt-2 text-sm text-gray-600">
              Selected: <span className="font-mono text-blue-600">{selectedTools.join(', ')}</span>
            </div>
          )}
        </div>

        {/* LHOST and LPORT */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label htmlFor="lhost" className="block text-sm font-medium text-gray-700 mb-2">
              LHOST (optional)
            </label>
            <input
              type="text"
              id="lhost"
              name="lhost"
              value={formData.lhost}
              onChange={handleChange}
              placeholder="Auto-detected if empty"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label htmlFor="lport" className="block text-sm font-medium text-gray-700 mb-2">
              LPORT (optional)
            </label>
            <input
              type="number"
              id="lport"
              name="lport"
              value={formData.lport}
              onChange={handleChange}
              placeholder="4444"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Credentials */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
              Username (optional)
            </label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
              Password (optional)
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Submit Buttons */}
        <div className="flex gap-4 pt-4">
          <button
            type="submit"
            disabled={startScan.isPending}
            className="flex-1 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {startScan.isPending ? 'Starting...' : 'Start Scan'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/')}
            className="flex-1 bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
