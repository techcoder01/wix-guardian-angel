import { describe, it, expect } from "vitest";
import { checkCookies } from "@/utils/checks/cookies";

describe("checkCookies", () => {
  it("returns no findings for a fully-flagged cookie", () => {
    const findings = checkCookies(
      ["session=abc; Secure; HttpOnly; SameSite=Lax"],
      false,
    );
    expect(findings).toHaveLength(0);
  });

  it("flags missing Secure flag", () => {
    const findings = checkCookies(["pref=val; HttpOnly; SameSite=Lax"], false);
    expect(findings.some((f) => f.id.startsWith("cookie-no-secure-"))).toBe(true);
  });

  it("flags missing HttpOnly flag", () => {
    const findings = checkCookies(["pref=val; Secure; SameSite=Lax"], false);
    expect(findings.some((f) => f.id.startsWith("cookie-no-httponly-"))).toBe(true);
  });

  it("flags missing SameSite attribute", () => {
    const findings = checkCookies(["pref=val; Secure; HttpOnly"], false);
    expect(findings.some((f) => f.id.startsWith("cookie-no-samesite-"))).toBe(true);
  });

  it("uses high severity for session cookies missing Secure", () => {
    const findings = checkCookies(["sessionId=abc; HttpOnly; SameSite=Lax"], false);
    const f = findings.find((f) => f.id.startsWith("cookie-no-secure-"));
    expect(f?.severity).toBe("high");
  });

  it("uses medium severity for non-session cookies missing Secure", () => {
    const findings = checkCookies(["pref=dark; HttpOnly; SameSite=Lax"], false);
    const f = findings.find((f) => f.id.startsWith("cookie-no-secure-"));
    expect(f?.severity).toBe("medium");
  });

  it("uses high severity for session cookies missing HttpOnly", () => {
    const findings = checkCookies(["authToken=xyz; Secure; SameSite=Strict"], false);
    const f = findings.find((f) => f.id.startsWith("cookie-no-httponly-"));
    expect(f?.severity).toBe("high");
  });

  it("uses low severity for non-session cookies missing HttpOnly", () => {
    const findings = checkCookies(["theme=dark; Secure; SameSite=Lax"], false);
    const f = findings.find((f) => f.id.startsWith("cookie-no-httponly-"));
    expect(f?.severity).toBe("low");
  });

  it("handles multiple cookies independently", () => {
    const findings = checkCookies(
      [
        "a=1; Secure; HttpOnly; SameSite=Lax",
        "b=2; HttpOnly; SameSite=Lax",
      ],
      false,
    );
    // Only cookie 'b' should have the Secure finding
    expect(findings.some((f) => f.id === "cookie-no-secure-b")).toBe(true);
    expect(findings.some((f) => f.id === "cookie-no-secure-a")).toBe(false);
  });

  it("returns empty array for empty input", () => {
    expect(checkCookies([], false)).toEqual([]);
  });

  it("attributes to wix_platform for Wix sites", () => {
    const findings = checkCookies(["sid=x; HttpOnly; SameSite=Lax"], true);
    expect(findings.every((f) => f.fixOwner === "wix_platform")).toBe(true);
  });

  it("includes evidence truncated to EVIDENCE_TRUNCATE_LENGTH", () => {
    const longCookie = "x=".padEnd(200, "a") + "; Secure; HttpOnly; SameSite=Lax";
    const findings = checkCookies([longCookie], false);
    // Should have a finding (SameSite is missing... wait, no it's present)
    // Let's use a cookie missing Secure
    const cookie = "y=".padEnd(200, "b") + "; HttpOnly; SameSite=Lax";
    const f2 = checkCookies([cookie], false);
    const finding = f2.find((f) => f.id.startsWith("cookie-no-secure-"));
    expect(finding?.evidence?.length).toBeLessThanOrEqual(160);
  });
});
