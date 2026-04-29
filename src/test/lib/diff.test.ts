import { describe, it, expect } from "vitest";
import { computeDiff } from "@/lib/diff";
import type { Finding } from "@/lib/scanner-types";

function makeFinding(id: string): Finding {
  return {
    id,
    title: `Finding ${id}`,
    category: "headers",
    severity: "low",
    description: "test",
    remediation: "test",
    fixOwner: "site_owner",
  };
}

describe("computeDiff", () => {
  it("returns empty diff when no previous scan", () => {
    const result = computeDiff([makeFinding("a")], undefined);
    expect(result.added).toEqual([]);
    expect(result.fixed).toEqual([]);
    expect(result.unchanged).toBe(0);
  });

  it("detects newly added findings", () => {
    const current = [makeFinding("a"), makeFinding("b")];
    const previous = [makeFinding("a")];
    const result = computeDiff(current, previous);
    expect(result.added).toContain("b");
    expect(result.added).not.toContain("a");
  });

  it("detects fixed (removed) findings", () => {
    const current = [makeFinding("a")];
    const previous = [makeFinding("a"), makeFinding("b")];
    const result = computeDiff(current, previous);
    expect(result.fixed).toContain("b");
    expect(result.fixed).not.toContain("a");
  });

  it("counts unchanged findings correctly", () => {
    const current = [makeFinding("a"), makeFinding("b"), makeFinding("c")];
    const previous = [makeFinding("a"), makeFinding("b"), makeFinding("d")];
    const result = computeDiff(current, previous);
    expect(result.unchanged).toBe(2); // a and b are in both
    expect(result.added).toContain("c");
    expect(result.fixed).toContain("d");
  });

  it("handles identical scans with no changes", () => {
    const findings = [makeFinding("a"), makeFinding("b")];
    const result = computeDiff(findings, findings);
    expect(result.added).toHaveLength(0);
    expect(result.fixed).toHaveLength(0);
    expect(result.unchanged).toBe(2);
  });

  it("handles empty current scan (all fixed)", () => {
    const previous = [makeFinding("a"), makeFinding("b")];
    const result = computeDiff([], previous);
    expect(result.fixed).toHaveLength(2);
    expect(result.unchanged).toBe(0);
  });

  it("handles empty previous scan (all new)", () => {
    const current = [makeFinding("a"), makeFinding("b")];
    const result = computeDiff(current, []);
    expect(result.added).toHaveLength(2);
    expect(result.unchanged).toBe(0);
  });
});
