import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RuleStats } from "../types";
import { RuleTable } from "./RuleTable";

const rule = (id: string, findings: number, fp: number | null, ttt: number | null): RuleStats => ({
  rule_id: id,
  findings,
  open: 1,
  triaged: findings - 1,
  false_positives: 0,
  accepted_risk: 0,
  fixed: 0,
  fp_rate: fp,
  median_time_to_triage_s: ttt,
});

const RULES = [
  rule("python.flask.xss", 3, 0.5, 600),
  rule("python.subprocess.shell-true", 8, 0.25, 120),
  rule("js.eval", 2, null, null),
];

function ruleOrder(): string[] {
  return screen
    .getAllByRole("rowheader")
    .map((h) => h.textContent ?? "");
}

describe("RuleTable", () => {
  it("renders one row per rule, most findings first", () => {
    render(<RuleTable rules={RULES} />);
    expect(ruleOrder()).toEqual(["python.subprocess.shell-true", "python.flask.xss", "js.eval"]);
  });

  it("shows FP rate and median time to triage, with unknowns as a dash", () => {
    render(<RuleTable rules={RULES} />);
    const xss = screen.getByText("python.flask.xss").closest("tr")!;
    expect(within(xss).getByText("50%")).toBeInTheDocument();
    expect(within(xss).getByText("10m")).toBeInTheDocument();
    const js = screen.getByText("js.eval").closest("tr")!;
    expect(within(js).getAllByText("—")).toHaveLength(2);
    expect(within(js).getByRole("img", { name: "— false positives" })).toBeInTheDocument();
  });

  it("sorts by false-positive rate and keeps unknown last", async () => {
    render(<RuleTable rules={RULES} />);
    const header = screen.getByRole("button", { name: /False-positive rate/ });
    await userEvent.click(header);
    expect(ruleOrder()).toEqual(["python.flask.xss", "python.subprocess.shell-true", "js.eval"]);
    expect(header.closest("th")).toHaveAttribute("aria-sort", "descending");
    await userEvent.click(header);
    expect(ruleOrder()).toEqual(["python.subprocess.shell-true", "python.flask.xss", "js.eval"]);
    expect(header.closest("th")).toHaveAttribute("aria-sort", "ascending");
  });

  it("sorts rule ids alphabetically", async () => {
    render(<RuleTable rules={RULES} />);
    await userEvent.click(screen.getByRole("button", { name: /^Rule/ }));
    expect(ruleOrder()).toEqual(["js.eval", "python.flask.xss", "python.subprocess.shell-true"]);
  });

  it("renders rule ids as text, never as HTML", () => {
    render(<RuleTable rules={[rule("<img src=x onerror=alert(1)>", 1, 0, 1)]} />);
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("has an empty state", () => {
    render(<RuleTable rules={[]} />);
    expect(screen.getByText(/No findings yet/)).toBeInTheDocument();
  });
});
