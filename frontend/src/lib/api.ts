/**
 * Centralized API client for GuardScope.
 *
 * All HTTP calls go through here so:
 *   - the base URL is read once from VITE_API_BASE_URL,
 *   - loading/error/demo-fallback behavior is uniform,
 *   - types are guaranteed to match the backend contract.
 */

import type {
  Finding,
  Health,
  ImportResult,
  Lab,
  ReportFormat,
  ScopeCheck,
} from "../types";
import { DEMO_FINDINGS } from "./demoData";

const BASE = (import.meta.env.VITE_API_BASE_URL ?? "/api").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${BASE}${path}`;
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (err) {
    throw new ApiError(0, err instanceof Error ? err.message : "network unreachable");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body && typeof body === "object" && "detail" in body) {
        const d = (body as { detail?: unknown }).detail;
        if (typeof d === "string") detail = d;
        else detail = JSON.stringify(d);
      }
    } catch {
      /* fall back to statusText */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export async function getHealth(): Promise<Health> {
  return request<Health>("/health");
}

export async function listFindings(opts: {
  severity?: string;
  source?: string;
  sort?: "risk" | "created_at" | "severity";
  limit?: number;
} = {}): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (opts.severity) params.set("severity", opts.severity);
  if (opts.source) params.set("source", opts.source);
  if (opts.sort) params.set("sort", opts.sort);
  if (opts.limit) params.set("limit", String(opts.limit));
  const q = params.toString();
  return request<Finding[]>(`/findings${q ? `?${q}` : ""}`);
}

export async function getFinding(id: string): Promise<Finding> {
  return request<Finding>(`/findings/${encodeURIComponent(id)}`);
}

export async function listLabs(): Promise<Lab[]> {
  return request<Lab[]>("/labs");
}

export async function registerLab(payload: {
  name: string;
  host: string;
  port: number;
  description?: string;
}): Promise<Lab> {
  return request<Lab>("/labs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function checkScope(host: string, port?: number): Promise<ScopeCheck> {
  const params = new URLSearchParams({ host });
  if (port) params.set("port", String(port));
  return request<ScopeCheck>(`/scope/check?${params.toString()}`);
}

export async function importReport(
  file: File,
  source: string | null,
): Promise<ImportResult> {
  const fd = new FormData();
  fd.append("file", file);
  if (source) fd.append("source", source);
  return request<ImportResult>("/import", { method: "POST", body: fd });
}

export async function getReportRaw(
  format: ReportFormat,
  opts: { severity?: string; source?: string } = {},
): Promise<string> {
  const params = new URLSearchParams({ format });
  if (opts.severity) params.set("severity", opts.severity);
  if (opts.source) params.set("source", opts.source);
  const url = `${BASE}/report/raw?${params.toString()}`;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 20_000);
  const maxBytes = 25 * 1024 * 1024;
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new ApiError(res.status, res.statusText);
    const advertisedLength = Number(res.headers.get("content-length") || 0);
    if (advertisedLength > maxBytes) {
      throw new ApiError(413, "report exceeds the 25 MB browser download limit");
    }
    const body = await res.text();
    if (new TextEncoder().encode(body).byteLength > maxBytes) {
      throw new ApiError(413, "report exceeds the 25 MB browser download limit");
    }
    return body;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(408, "report request timed out after 20 seconds");
    }
    throw new ApiError(0, err instanceof Error ? err.message : "报告请求失败");
  } finally {
    window.clearTimeout(timeout);
  }
}

/**
 * Demo-mode data sources.
 *
 * When the backend is unreachable, callers fall back to these so the UI
 * stays demonstrable without ever silently claiming live data. Each
 * helper is annotated with a `demo: true` flag in the consumer.
 */
export function getDemoFindings(): Finding[] {
  return DEMO_FINDINGS.map((f) => ({ ...f }));
}

export function getDemoLabs(): Lab[] {
  const now = new Date().toISOString();
  return [
    {
      id: "demo-lab-1",
      name: "demo-nginx",
      host: "127.0.0.1",
      port: 8080,
      description: "Loopback nginx demo (docker compose up -d)",
      created_at: now,
    },
  ];
}

export { ApiError as default, BASE as API_BASE };