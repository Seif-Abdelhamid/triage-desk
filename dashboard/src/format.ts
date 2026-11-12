/** "—" for unknown; a rate with no triaged findings is unknown, not 0%. */
export function formatRate(rate: number | null): string {
  if (rate === null || Number.isNaN(rate)) return "—";
  return `${Number((rate * 100).toFixed(1))}%`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || Number.isNaN(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}
