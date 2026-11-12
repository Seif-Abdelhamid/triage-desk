import { useEffect, useState } from "react";
import { fetchStats } from "./api";
import { RuleTable } from "./components/RuleTable";
import { SummaryTiles } from "./components/SummaryTiles";
import type { StatsResponse } from "./types";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: StatsResponse };

export function App({ load = fetchStats }: { load?: typeof fetchStats }) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    const ctrl = new AbortController();
    setState({ kind: "loading" });
    load(ctrl.signal)
      .then((data) => setState({ kind: "ready", data }))
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      });
    return () => ctrl.abort();
  }, [load, reloads]);

  return (
    <main className="viz-root">
      <header>
        <h1>triage-desk</h1>
        <p className="lede">Semgrep findings and triage decisions across connected repositories.</p>
        <button type="button" onClick={() => setReloads((n) => n + 1)}>
          Refresh
        </button>
      </header>
      {state.kind === "loading" && <p role="status">Loading…</p>}
      {state.kind === "error" && (
        <p role="alert" className="error">
          Could not load stats: {state.message}
        </p>
      )}
      {state.kind === "ready" && (
        <>
          <SummaryTiles totals={state.data.totals} />
          <RuleTable rules={state.data.rules} />
          <p className="note">
            False-positive rate = findings triaged as false positive ÷ triaged findings (open
            findings have no verdict yet). Time to triage = first triage decision − first detection.
          </p>
        </>
      )}
    </main>
  );
}
