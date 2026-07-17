/**
 * Centralized API client for the offensive module.
 *
 * Mirrors the shape of `lib/api.ts` (used by the defensive console) so the
 * Offensive page can compose familiar request/error/demo-fallback patterns.
 */

import type {
  Availability,
  HydraRequest,
  LabTarget,
  NmapRequest,
  NucleiRequest,
  OffensiveRun,
  RunHistoryEntry,
  SqlmapRequest,
} from "../types";

const BASE = (import.meta.env.VITE_API_BASE_URL ?? "/api").replace(/\/$/, "");

export class OffensiveApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, init);
  } catch (err) {
    throw new OffensiveApiError(
      0,
      err instanceof Error ? err.message : "network unreachable"
    );
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body && typeof body === "object" && "detail" in body) {
        const d = (body as { detail?: unknown }).detail;
        detail = typeof d === "string" ? d : JSON.stringify(d);
      }
    } catch {
      /* fall back to statusText */
    }
    throw new OffensiveApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export function getAvailability(): Promise<Availability> {
  return request<Availability>("/offensive/availability");
}

export function getOffensiveLabs(): Promise<LabTarget[]> {
  return request<LabTarget[]>("/offensive/labs");
}

export function getOffensiveRuns(limit = 50): Promise<RunHistoryEntry[]> {
  return request<RunHistoryEntry[]>(
    `/offensive/runs?limit=${encodeURIComponent(String(limit))}`
  );
}

export async function runNmap(body: NmapRequest): Promise<OffensiveRun> {
  return request<OffensiveRun>("/offensive/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function runHydra(body: HydraRequest): Promise<OffensiveRun> {
  return request<OffensiveRun>("/offensive/brute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function runSqlmap(body: SqlmapRequest): Promise<OffensiveRun> {
  return request<OffensiveRun>("/offensive/sqli", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function runNuclei(body: NucleiRequest): Promise<OffensiveRun> {
  return request<OffensiveRun>("/offensive/nuclei", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
