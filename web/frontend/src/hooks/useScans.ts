/**
 * React Query hooks for scans
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scanApi, hostApi, vulnerabilityApi } from '../api/client';
import type { ScanCreateRequest } from '../types';

// Query keys
export const scanKeys = {
  all: ['scans'] as const,
  lists: () => [...scanKeys.all, 'list'] as const,
  list: (filters: Record<string, any>) => [...scanKeys.lists(), filters] as const,
  details: () => [...scanKeys.all, 'detail'] as const,
  detail: (id: number) => [...scanKeys.details(), id] as const,
  hosts: (id: number) => [...scanKeys.detail(id), 'hosts'] as const,
  vulnerabilities: (id: number) => [...scanKeys.detail(id), 'vulnerabilities'] as const,
};

/**
 * Hook to list scans with optional filters
 */
export function useScans(filters?: {
  skip?: number;
  limit?: number;
  status?: string;
  target?: string;
}) {
  return useQuery({
    queryKey: scanKeys.list(filters || {}),
    queryFn: () => scanApi.list(filters),
  });
}

/**
 * Hook to get scan details
 */
export function useScan(scanId: number) {
  return useQuery({
    queryKey: scanKeys.detail(scanId),
    queryFn: () => scanApi.get(scanId),
    refetchInterval: (data) => {
      // Auto-refetch every 2 seconds if scan is running
      if (data?.status === 'RUNNING' || data?.status === 'PENDING') {
        return 2000;
      }
      return false;
    },
  });
}

/**
 * Hook to get hosts for a scan
 */
export function useHosts(scanId: number) {
  return useQuery({
    queryKey: scanKeys.hosts(scanId),
    queryFn: () => hostApi.list(scanId),
    enabled: scanId > 0,
  });
}

/**
 * Hook to get vulnerabilities for a scan
 */
export function useVulnerabilities(scanId: number) {
  return useQuery({
    queryKey: scanKeys.vulnerabilities(scanId),
    queryFn: () => vulnerabilityApi.list(scanId),
    enabled: scanId > 0,
  });
}

/**
 * Hook to start a new scan
 */
export function useStartScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: ScanCreateRequest) => scanApi.start(data),
    onSuccess: () => {
      // Invalidate scans list to refetch
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}

/**
 * Hook to delete a scan
 */
export function useDeleteScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (scanId: number) => scanApi.delete(scanId),
    onSuccess: () => {
      // Invalidate scans list to refetch
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}
