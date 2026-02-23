/**
 * TypeScript type definitions for CrushGear API
 */

export interface Scan {
  id: number;
  target: string;
  target_type: string | null;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'ERROR';
  started_at: string;
  completed_at: string | null;
  total_duration: number | null;
  output_dir: string | null;
  feed_data: Record<string, any> | null;
  error_message: string | null;
}

export interface ScanDetail extends Scan {
  tool_executions: ToolExecution[];
}

export interface ToolExecution {
  id: number;
  scan_id: number;
  tool_name: string;
  phase: number;
  status: 'PENDING' | 'RUNNING' | 'DONE' | 'ERROR' | 'SKIPPED';
  started_at: string;
  completed_at: string | null;
  duration: number | null;
  returncode: number | null;
  output_file: string | null;
  command: string;
}

export interface Host {
  id: number;
  scan_id: number;
  ip: string;
  hostname: string | null;
  os_guess: string | null;
  is_windows: boolean;
  is_dc: boolean;
  services_json: Record<string, string>;
  products_json: Record<string, string>;
  ports: Port[];
}

export interface Port {
  id: number;
  host_id: number;
  port_num: number;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
}

export interface URL {
  id: number;
  scan_id: number;
  url: string;
  status_code: number | null;
  title: string | null;
  is_live: boolean;
  metadata_json: Record<string, any> | null;
}

export interface Vulnerability {
  id: number;
  scan_id: number;
  cve_id: string | null;
  host: string | null;
  template_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  msf_module: string | null;
  msf_payload: string | null;
  metadata_json: Record<string, any> | null;
}

export interface ScanCreateRequest {
  target: string;
  tools?: string;
  lhost?: string;
  lport?: number;
  username?: string;
  password?: string;
}

export interface ScanListResponse {
  scans: Scan[];
  total: number;
}

export interface HostListResponse {
  hosts: Host[];
}

export interface VulnerabilityListResponse {
  vulnerabilities: Vulnerability[];
}

// WebSocket message types
export type WebSocketMessage =
  | { type: 'connected'; scan_id: number; message: string }
  | { type: 'tool_start'; tool: string; phase: number; timestamp: string }
  | { type: 'tool_output'; tool: string; line: string; line_num: number; timestamp: string }
  | { type: 'tool_complete'; tool: string; status: string; duration: number; returncode: number | null }
  | { type: 'phase_complete'; phase: number; feed_summary: Record<string, number> }
  | { type: 'scan_complete'; scan_id: number; status: string; total_duration: number }
  | { type: 'scan_error'; scan_id: number; error: string }
  | { type: 'pong' };
