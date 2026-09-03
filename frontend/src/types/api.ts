export type UUID = string;

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Info";

export type TriageMode = "baseline" | "llm";

export type TriageSource = "baseline" | "llm";

export type ReportFormat = "plain" | "json" | "both";

export interface ScanProgress {
  pages_crawled: number;
  current_check?: string;
  current_url?: string;
  findings_found: number;
  errors: number;
}

export interface ScanRequest {
  url: string;
  max_pages?: number;
  max_depth?: number;
  timeout?: number;
  allow_write_tests?: boolean;
}

export interface ScanResponse {
  scan_id: UUID;
  status: ScanStatus;
  progress: ScanProgress;
  created_at: string;
  updated_at: string;
  target_url: string;
  error?: string;
}

export interface Evidence {
  url: string;
  snippet: string;
  matched_pattern?: string;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  response_status?: number;
}

export interface Finding {
  id: string;
  check: string;
  title: string;
  severity: SeverityLevel;
  score: number;
  impact: number;
  likelihood: number;
  wstg_id?: string;
  attck_ids: string[];
  evidence: Evidence;
  confidence: number;
  remediation: string;
  references: string[];
}

export interface FindingResponse extends Finding {
  scan_id: UUID;
  created_at: string;
}

export interface TriageResult {
  finding_id: string;
  finding_title: string;
  explanation: string;
  exploitability: number;
  fix: string;
  revised_priority: number;
  source: TriageSource;
  prompt_version: string;
  original_severity: SeverityLevel;
}

export interface TriageRunResponse {
  triage_id: UUID;
  scan_id: UUID;
  mode: TriageMode;
  status: "pending" | "running" | "completed" | "failed";
  results: TriageResult[];
  created_at: string;
  completed_at?: string;
  error?: string;
}

export interface TriageCompareResponse {
  scan_id: UUID;
  baseline: TriageResult[];
  llm: TriageResult[];
  baseline_only: string[];
  llm_only: string[];
  changed_priority: Array<{
    finding_id: string;
    baseline_priority: number;
    llm_priority: number;
  }>;
}

export interface FindingsStats {
  by_severity: Record<SeverityLevel, number>;
  by_check: Record<string, number>;
}

export interface ProgressLog {
  scan_id: UUID;
  timestamp: string;
  level: "info" | "warning" | "error";
  message: string;
  stage?: string;
}