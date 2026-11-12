import { formatDuration, formatRate } from "../format";
import type { Totals } from "../types";

export function SummaryTiles({ totals }: { totals: Totals }) {
  const tiles = [
    { label: "Findings", value: totals.findings.toLocaleString() },
    { label: "Triaged", value: totals.triaged.toLocaleString() },
    { label: "False-positive rate", value: formatRate(totals.fp_rate) },
    { label: "Median time to triage", value: formatDuration(totals.median_time_to_triage_s) },
  ];
  return (
    <dl className="tiles">
      {tiles.map((t) => (
        <div className="tile" key={t.label}>
          <dt>{t.label}</dt>
          <dd>{t.value}</dd>
        </div>
      ))}
    </dl>
  );
}
