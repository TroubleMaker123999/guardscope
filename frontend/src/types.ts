export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

export type Confidence = "high" | "medium" | "low";

export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  cvss: number;
  cwe: string[];
  owasp: string[];
  source: string;
  asset: string;
  evidence: string;
  remediation: string;
  created_at: string;
  updated_at: string;
  duplicate_count: number;
}

export interface Lab {
  id: string;
  name: string;
  host: string;
  port: number;
  description: string;
  created_at: string;
}

export interface ImportResult {
  parser: string;
  imported: number;
  unique: number;
  findings: Finding[];
}

export interface ReportResponse {
  format: "markdown" | "html" | "json" | "sarif";
  body: string;
}

export interface Health {
  status: "ok" | string;
  version: string;
  db: string;
}

export interface ScopeCheck {
  host: string;
  in_scope: boolean;
  registered?: boolean;
  reason?: string;
}

export type ReportFormat = "markdown" | "html" | "json" | "sarif";

export type SourceName =
  | "nmap"
  | "zap"
  | "sarif"
  | "bandit"
  | "semgrep"
  | "trivy"
  | "pipaudit";

export const ALL_SOURCES: SourceName[] = [
  "nmap",
  "zap",
  "sarif",
  "bandit",
  "semgrep",
  "trivy",
  "pipaudit",
];

export const ALL_SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
  info: "信息",
  unknown: "未知",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

export const CONFIDENCE_RANK: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function riskScore(f: Finding): number {
  const sev = SEVERITY_RANK[f.severity] ?? 0;
  const conf = CONFIDENCE_RANK[f.confidence] ?? 2;
  const cvss = Math.max(0, Math.min(10, Number(f.cvss) || 0));
  const dup = Number(f.duplicate_count) || 1;
  return Math.round((sev * 5 + conf * 2 + cvss + (dup - 1) * 1.5) * 1000) / 1000;
}

export function compareRisk(a: Finding, b: Finding): number {
  return riskScore(b) - riskScore(a);
}

export interface BackendState {
  online: boolean;
  demo: boolean;
  loading: boolean;
  version?: string;
  db?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Offensive module types (mirrors backend `offensive.api` schemas).
// ---------------------------------------------------------------------------

export interface Availability {
  nmap: boolean;
  hydra: boolean;
  sqlmap: boolean;
  nuclei: boolean;
}

export interface LabTarget {
  key: string;
  name: string;
  host: string;
  port: number;
  description: string;
  compose_file: string;
}

export interface NmapRequest {
  target: string;
  ports?: string;
  scan_type?: string;
  scripts?: string[];
}

export interface HydraRequest {
  target: string;
  service: string;
  username: string;
  wordlist_path: string;
  port?: number;
  throttle?: number;
}

export interface SqlmapRequest {
  target: string;
  url: string;
  level?: number;
  risk?: number;
}

export interface NucleiRequest {
  target: string;
  url: string;
  categories?: string[];
}

export interface OffensiveRun {
  ok: boolean;
  tool: string;
  target: string;
  summary: string;
  output_path?: string | null;
  injectable?: boolean | null;
  matched?: number | null;
}

export interface RunHistoryEntry {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  target: string;
  exit_code: number | null;
  summary: string;
}