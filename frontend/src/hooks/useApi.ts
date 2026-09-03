import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import {
  ScanRequest,
  ScanResponse,
  FindingResponse,
  TriageRunResponse,
  TriageMode,
  TriageCompareResponse,
  FindingsStats,
  UUID,
  ReportFormat,
} from "@/types/api";

// Scan hooks
export function useScans(params?: { status?: string; limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => api.listScans(params),
    refetchInterval: 5000,
  });
}

export function useScan(scanId: UUID | undefined) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.status === "running" ? 2000 : false;
    },
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: ScanRequest) => api.startScan(data),
    onSuccess: (newScan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      return newScan;
    },
  });
}

// Findings hooks
export function useFindings(
  scanId: UUID | undefined,
  params?: { severity?: string; check?: string; limit?: number; offset?: number }
) {
  return useQuery({
    queryKey: ["findings", scanId, params],
    queryFn: () => api.getFindings(scanId!, params),
    enabled: !!scanId,
  });
}

export function useFindingsStats(scanId: UUID | undefined) {
  return useQuery({
    queryKey: ["findings-stats", scanId],
    queryFn: () => api.getFindingsStats(scanId!),
    enabled: !!scanId,
  });
}

// Triage hooks
export function useTriageRuns(scanId: UUID | undefined) {
  return useQuery({
    queryKey: ["triage-runs", scanId],
    queryFn: () => api.listTriageRuns(scanId!),
    enabled: !!scanId,
  });
}

export function useTriage(triageId: UUID | undefined) {
  return useQuery({
    queryKey: ["triage", triageId],
    queryFn: () => api.getTriage(triageId!),
    enabled: !!triageId,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.status === "running" ? 2000 : false;
    },
  });
}

export function useCompareTriage(scanId: UUID | undefined) {
  return useQuery({
    queryKey: ["triage-compare", scanId],
    queryFn: () => api.compareTriage(scanId!),
    enabled: !!scanId,
  });
}

export function useStartTriage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scanId, mode }: { scanId: UUID; mode: TriageMode }) =>
      api.startTriage(scanId, mode),
    onSuccess: (_, { scanId }) => {
      queryClient.invalidateQueries({ queryKey: ["triage-runs", scanId] });
    },
  });
}

// Report hooks
export function useReport(scanId: UUID | undefined, format: ReportFormat) {
  return useQuery({
    queryKey: ["report", scanId, format],
    queryFn: () => api.getReport(scanId!, format),
    enabled: !!scanId,
  });
}

// KB Context hook
export function useKbContext(findingId: string | undefined, scanId: UUID | undefined) {
  return useQuery({
    queryKey: ["kb-context", findingId, scanId],
    queryFn: () => api.getKbContext(findingId!, scanId!),
    enabled: !!findingId && !!scanId,
  });
}