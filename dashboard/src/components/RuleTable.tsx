import { useMemo, useState } from "react";
import { formatDuration, formatRate } from "../format";
import type { RuleStats } from "../types";

type SortKey = "rule_id" | "findings" | "fp_rate" | "median_time_to_triage_s";

const COLUMNS: { key: SortKey; label: string; numeric: boolean }[] = [
  { key: "rule_id", label: "Rule", numeric: false },
  { key: "findings", label: "Findings", numeric: true },
  { key: "fp_rate", label: "False-positive rate", numeric: true },
  { key: "median_time_to_triage_s", label: "Median time to triage", numeric: true },
];

function compare(a: RuleStats, b: RuleStats, key: SortKey): number {
  const x = a[key];
  const y = b[key];
  // Unknown values (null) always sort last, whatever the direction.
  if (x === null && y === null) return 0;
  if (x === null) return 1;
  if (y === null) return -1;
  if (typeof x === "string" && typeof y === "string") return x.localeCompare(y);
  return (x as number) - (y as number);
}

export function RuleTable({ rules }: { rules: RuleStats[] }) {
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({
    key: "findings",
    desc: true,
  });

  const rows = useMemo(() => {
    const sorted = [...rules].sort((a, b) => {
      const c = compare(a, b, sort.key);
      const bothKnown = a[sort.key] !== null && b[sort.key] !== null;
      return sort.desc && bothKnown ? -c : c;
    });
    return sorted;
  }, [rules, sort]);

  if (rules.length === 0) {
    return <p className="empty">No findings yet. Open a pull request on a connected repository.</p>;
  }

  return (
    <table className="rules">
      <caption>Findings per Semgrep rule</caption>
      <thead>
        <tr>
          {COLUMNS.map((c) => {
            const active = sort.key === c.key;
            return (
              <th
                key={c.key}
                scope="col"
                className={c.numeric ? "num" : undefined}
                aria-sort={active ? (sort.desc ? "descending" : "ascending") : "none"}
              >
                <button
                  type="button"
                  onClick={() =>
                    setSort((s) => ({ key: c.key, desc: s.key === c.key ? !s.desc : c.numeric }))
                  }
                >
                  {c.label}
                  <span aria-hidden="true">{active ? (sort.desc ? " ▼" : " ▲") : ""}</span>
                </button>
              </th>
            );
          })}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.rule_id}>
            <th scope="row" className="rule-id">
              <code>{r.rule_id}</code>
            </th>
            <td className="num">
              {r.findings}
              <span className="sub">
                {" "}
                ({r.open} open, {r.triaged} triaged)
              </span>
            </td>
            <td className="num">
              <span className="meter-cell">
                <span
                  className="meter"
                  role="img"
                  aria-label={`${formatRate(r.fp_rate)} false positives`}
                  title={`${r.false_positives} of ${r.triaged} triaged findings were false positives`}
                >
                  <span
                    className="meter-fill"
                    style={{ width: `${Math.round((r.fp_rate ?? 0) * 100)}%` }}
                  />
                </span>
                <span>{formatRate(r.fp_rate)}</span>
              </span>
            </td>
            <td className="num">{formatDuration(r.median_time_to_triage_s)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
