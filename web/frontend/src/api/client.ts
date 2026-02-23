/**
 * API client for CrushGear backend
 */

import axios from 'axios';
import type {
  Scan,
  ScanDetail,
  ScanListResponse,
  ScanCreateRequest,
  HostListResponse,
  VulnerabilityListResponse,
} from '../types';

// Base URL for API (adjust for production)
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Create axios instance with default config
const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Scan endpoints
export const scanApi = {
  /**
   * List all scans with pagination and filtering
   */
  list: async (params?: {
    skip?: number;
    limit?: number;
    status?: string;
    target?: string;
  }): Promise<ScanListResponse> => {
    const response = await api.get<ScanListResponse>('/api/scans', { params });
    return response.data;
  },

  /**
   * Get scan details by ID
   */
  get: async (scanId: number): Promise<ScanDetail> => {
    const response = await api.get<ScanDetail>(`/api/scans/${scanId}`);
    return response.data;
  },

  /**
   * Start a new scan
   */
  start: async (data: ScanCreateRequest): Promise<Scan> => {
    const response = await api.post<Scan>('/api/scans/start', data);
    return response.data;
  },

  /**
   * Delete a scan
   */
  delete: async (scanId: number): Promise<{ success: boolean; message: string }> => {
    const response = await api.delete(`/api/scans/${scanId}`);
    return response.data;
  },

  /**
   * Get tool outputs for a scan
   */
  getToolOutputs: async (
    scanId: number,
    params?: {
      tool_name?: string;
      skip?: number;
      limit?: number;
    }
  ): Promise<import('../types').ToolOutputsResponse> => {
    const response = await api.get(`/api/scans/${scanId}/tool-outputs`, { params });
    return response.data;
  },
};

// Host endpoints
export const hostApi = {
  /**
   * Get all hosts for a scan
   */
  list: async (scanId: number): Promise<HostListResponse> => {
    const response = await api.get<HostListResponse>(`/api/scans/${scanId}/hosts`);
    return response.data;
  },
};

// Vulnerability endpoints
export const vulnerabilityApi = {
  /**
   * Get all vulnerabilities for a scan
   */
  list: async (scanId: number): Promise<VulnerabilityListResponse> => {
    const response = await api.get<VulnerabilityListResponse>(`/api/scans/${scanId}/vulnerabilities`);
    return response.data;
  },
};

export default api;
