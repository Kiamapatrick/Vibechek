import axios, { AxiosInstance } from "axios";
import {
  ScanRequest,
  ScanResponse,
  FindingResponse,
  TriageRunResponse,
  TriageMode,
  TriageCompareResponse,
  FindingsStats,
  ReportFormat,
  UUID,
} from "@/types/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE,
      headers: { "Content-Type": "application/json" },
      timeout: 30000,
    });
  }

  // Scans
  async startScan(data: ScanRequest): Promise<ScanResponse> {
    const res = await this.client.post("/api/scans", data);
    return res.data;
  }

  async listScans(params?: {
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<ScanResponse[]> {
    const res = await this.client.get("/api/scans", { params });
    return res.data;
  }

  async getScan(scanId: UUID): Promise<ScanResponse> {
    const res = await this.client.get(`/api/scans/${scanId}`);
    return res.data;
  }

  async getFindings(
    scanId: UUID,
    params?: { severity?: string; check?: string; limit?: number; offset?: number }
  ): Promise<FindingResponse[]> {
    const res = await this.client.get(`/api/scans/${scanId}/findings`, { params });
    return res.data;
  }

  async getFindingsStats(scanId: UUID): Promise<FindingsStats> {
    const res = await this.client.get(`/api/scans/${scanId}/findings/stats`);
    return res.data;
  }

  async startTriage(scanId: UUID, mode: TriageMode): Promise<TriageRunResponse> {
    const res = await this.client.post(`/api/scans/${scanId}/triage`, null, {
      params: { mode },
    });
    return res.data;
  }

  async listTriageRuns(scanId: UUID): Promise<TriageRunResponse[]> {
    const res = await this.client.get(`/api/scans/${scanId}/triage`);
    return res.data;
  }

  async getTriage(triageId: UUID): Promise<TriageRunResponse> {
    const res = await this.client.get(`/api/triage/${triageId}`);
    return res.data;
  }

  async compareTriage(scanId: UUID): Promise<TriageCompareResponse> {
    const res = await this.client.get(`/api/scans/${scanId}/triage/compare`);
    return res.data;
  }

  async getReport(scanId: UUID, format: ReportFormat): Promise<string | object> {
    const res = await this.client.get(`/api/scans/${scanId}/report`, {
      params: { format },
      responseType: format === "plain" ? "text" : "json",
    });
    return res.data;
  }

  async getKbContext(findingId: string, scanId: UUID) {
    const res = await this.client.get("/api/triage/kb-context", {
      params: { finding_id: findingId, scan_id: scanId },
    });
    return res.data;
  }
}

export const api = new ApiClient();