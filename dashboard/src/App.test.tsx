import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { fetchStats } from "./api";
import type { StatsResponse } from "./types";

const DATA: StatsResponse = {
  rules: [
    {
      rule_id: "python.subprocess.shell-true",
      findings: 4,
      open: 1,
      triaged: 3,
      false_positives: 1,
      accepted_risk: 1,
      fixed: 1,
      fp_rate: 1 / 3,
      median_time_to_triage_s: 7200,
    },
  ],
  totals: { findings: 4, triaged: 3, false_positives: 1, fp_rate: 1 / 3, median_time_to_triage_s: 7200 },
};

describe("App", () => {
  it("shows loading, then the summary tiles and table", async () => {
    render(<App load={() => Promise.resolve(DATA)} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading");
    expect(await screen.findByText("python.subprocess.shell-true")).toBeInTheDocument();
    const tiles = screen.getByText("False-positive rate", { selector: "dt" }).parentElement!;
    expect(tiles).toHaveTextContent("33.3%");
    expect(screen.getByText("Median time to triage", { selector: "dt" }).parentElement).toHaveTextContent(
      "2.0h",
    );
  });

  it("shows an error and recovers on refresh", async () => {
    const load = vi
      .fn<typeof fetchStats>()
      .mockRejectedValueOnce(new Error("API returned 500"))
      .mockResolvedValueOnce(DATA);
    render(<App load={load} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("API returned 500");
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("python.subprocess.shell-true")).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(2);
  });
});

describe("fetchStats", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects non-2xx responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("nope", { status: 503 })));
    await expect(fetchStats()).rejects.toThrow("API returned 503");
  });

  it("rejects unexpected shapes", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ hello: 1 })));
    await expect(fetchStats()).rejects.toThrow("Unexpected response shape");
  });

  it("returns parsed stats", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json(DATA)));
    await expect(fetchStats()).resolves.toEqual(DATA);
  });
});
