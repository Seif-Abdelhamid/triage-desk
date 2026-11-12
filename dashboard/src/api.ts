import type { StatsResponse } from "./types";

export async function fetchStats(signal?: AbortSignal): Promise<StatsResponse> {
  const res = await fetch("/api/stats", { signal, headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`API returned ${res.status}`);
  const data: unknown = await res.json();
  if (!isStats(data)) throw new Error("Unexpected response shape");
  return data;
}

function isStats(d: unknown): d is StatsResponse {
  if (typeof d !== "object" || d === null) return false;
  const o = d as Record<string, unknown>;
  return Array.isArray(o.rules) && typeof o.totals === "object" && o.totals !== null;
}
