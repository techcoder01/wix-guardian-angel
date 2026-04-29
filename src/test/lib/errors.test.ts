import { describe, it, expect } from "vitest";
import { ScannerError, classifyScanError } from "@/lib/errors";

describe("classifyScanError", () => {
  it("preserves ScannerError code", () => {
    const e = new ScannerError("rate_limited", "slow down");
    expect(classifyScanError(e)).toEqual({
      code: "rate_limited",
      message: "slow down",
    });
  });

  it("classifies timeouts", () => {
    expect(classifyScanError(new Error("timed out after 15s")).code).toBe(
      "timeout",
    );
    expect(classifyScanError({ name: "AbortError" } as unknown).code).toBe(
      "timeout",
    );
  });

  it("classifies blocked targets", () => {
    expect(
      classifyScanError(new Error("private IP not permitted")).code,
    ).toBe("blocked_target");
  });

  it("classifies invalid URLs", () => {
    expect(
      classifyScanError(new Error("only http:// and https://")).code,
    ).toBe("invalid_url");
  });

  it("classifies network errors", () => {
    expect(classifyScanError(new Error("DNS lookup failed")).code).toBe(
      "network",
    );
  });

  it("classifies TLS errors", () => {
    expect(classifyScanError(new Error("TLS certificate invalid")).code).toBe(
      "tls",
    );
  });

  it("classifies rate limits", () => {
    expect(classifyScanError(new Error("Rate limit exceeded")).code).toBe(
      "rate_limited",
    );
  });

  it("classifies unknowns as internal", () => {
    expect(classifyScanError("something weird").code).toBe("internal");
  });
});
