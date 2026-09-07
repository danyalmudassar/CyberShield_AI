export type ExecutionMode = "live" | "rules_only" | "demo";
export type ScanStatus = "queued" | "running" | "cancelling" | "completed" | "partial" | "failed" | "cancelled" | "interrupted" | "timed_out";
export interface ScanRequest {
  domain: string;
  authorized: boolean;
  scope_type: string;
  contact_email: string;
  execution_mode: ExecutionMode;
  strict_live: boolean;
  ai_model: string;
  max_duration_seconds?: number;
  max_stage_seconds?: number;
}
export interface Finding {
  finding_id: string;
  check_id: string;
  title: string;
  severity: string;
  check_status: string;
  provenance: string;
  url: string;
  evidence: string;
  [key: string]: unknown;
}
export interface ScanState {
  scan_id?: string;
  execution_mode?: ExecutionMode;
  strict_live?: boolean;
  domain?: string;
  security_score?: number;
  all_findings?: Finding[];
  pisf?: Record<string, unknown>;
  visual?: Record<string, unknown>;
  executive_summary?: string;
  pdf_path?: string | null;
  report_status?: string;
  fallback_triggered?: boolean;
  scan_progress?: Record<string, string>;
}
export interface ScanJob {
  id: string;
  status: ScanStatus;
  config: ScanRequest;
  result: ScanState | null;
  error?: unknown;
  created_at?: string;
}
export type ScanEvent =
  | { type: "progress"; stage: string; message: string; status?: "running" | "completed" | "partial" | "failed" | "mock" | "skipped"; id?: number }
  | { type: "complete"; status: ScanStatus; state: ScanState | null; message?: string; error?: unknown; id?: number }
  | { type: "error"; message: string; code?: string; id?: number };
