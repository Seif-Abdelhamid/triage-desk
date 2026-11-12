import { formatDuration, formatRate } from "./format";

describe("formatRate", () => {
  it("shows unknown when nothing was triaged", () => expect(formatRate(null)).toBe("—"));
  it("formats percentages", () => {
    expect(formatRate(0)).toBe("0%");
    expect(formatRate(1)).toBe("100%");
    expect(formatRate(0.6667)).toBe("66.7%");
  });
});

describe("formatDuration", () => {
  it.each([
    [null, "—"],
    [42, "42s"],
    [180, "3m"],
    [5400, "1.5h"],
    [3 * 86400, "3.0d"],
  ])("%s -> %s", (input, out) => expect(formatDuration(input)).toBe(out));
});
