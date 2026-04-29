import { describe, it, expect } from "vitest";
import { checkHeaders } from "@/utils/checks/headers";
import { HSTS_MIN_AGE_SECONDS } from "@/lib/constants";

describe("checkHeaders", () => {
  // --- HSTS ---
  it("flags missing HSTS", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-hsts")).toBe(true);
  });

  it("does not flag HSTS when present and strong", () => {
    const findings = checkHeaders(
      { "strict-transport-security": `max-age=${HSTS_MIN_AGE_SECONDS}; includeSubDomains` },
      false,
    );
    expect(findings.some((f) => f.id === "missing-hsts")).toBe(false);
    expect(findings.some((f) => f.id === "weak-hsts")).toBe(false);
  });

  it("flags weak HSTS (max-age below threshold)", () => {
    const findings = checkHeaders(
      { "strict-transport-security": "max-age=3600" },
      false,
    );
    expect(findings.some((f) => f.id === "weak-hsts")).toBe(true);
    expect(findings.find((f) => f.id === "weak-hsts")?.evidence).toContain("max-age=3600");
  });

  it("weak HSTS finding includes evidence", () => {
    const header = "max-age=86400";
    const findings = checkHeaders(
      { "strict-transport-security": header },
      false,
    );
    const f = findings.find((f) => f.id === "weak-hsts");
    expect(f?.evidence).toBe(header);
  });

  // --- CSP ---
  it("flags missing CSP", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-csp")).toBe(true);
  });

  it("does not flag CSP when header is present", () => {
    const findings = checkHeaders(
      { "content-security-policy": "default-src 'self'" },
      false,
    );
    expect(findings.some((f) => f.id === "missing-csp")).toBe(false);
  });

  // --- X-Content-Type-Options ---
  it("flags missing X-Content-Type-Options", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-xcto")).toBe(true);
  });

  it("does not flag XCTO when nosniff set", () => {
    const findings = checkHeaders({ "x-content-type-options": "nosniff" }, false);
    expect(findings.some((f) => f.id === "missing-xcto")).toBe(false);
  });

  // --- Frame protection ---
  it("flags missing clickjacking protection when both X-Frame-Options and frame-ancestors absent", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-frame-protection")).toBe(true);
  });

  it("does not flag frame protection when X-Frame-Options present", () => {
    const findings = checkHeaders({ "x-frame-options": "SAMEORIGIN" }, false);
    expect(findings.some((f) => f.id === "missing-frame-protection")).toBe(false);
  });

  it("does not flag frame protection when CSP contains frame-ancestors", () => {
    const findings = checkHeaders(
      { "content-security-policy": "frame-ancestors 'self'" },
      false,
    );
    expect(findings.some((f) => f.id === "missing-frame-protection")).toBe(false);
  });

  // --- Referrer-Policy ---
  it("flags missing Referrer-Policy", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-referrer-policy")).toBe(true);
  });

  it("does not flag Referrer-Policy when set", () => {
    const findings = checkHeaders(
      { "referrer-policy": "strict-origin-when-cross-origin" },
      false,
    );
    expect(findings.some((f) => f.id === "missing-referrer-policy")).toBe(false);
  });

  // --- Permissions-Policy ---
  it("flags missing Permissions-Policy", () => {
    const findings = checkHeaders({}, false);
    expect(findings.some((f) => f.id === "missing-permissions-policy")).toBe(true);
  });

  // --- Information disclosure ---
  it("flags X-Powered-By disclosure", () => {
    const findings = checkHeaders({ "x-powered-by": "Express" }, false);
    const f = findings.find((f) => f.id === "x-powered-by");
    expect(f).toBeDefined();
    expect(f?.evidence).toContain("Express");
  });

  it("flags server version disclosure when version number present", () => {
    const findings = checkHeaders({ server: "nginx/1.18.0" }, false);
    expect(findings.some((f) => f.id === "server-version")).toBe(true);
  });

  it("does not flag server version when no digits in value", () => {
    const findings = checkHeaders({ server: "cloudflare" }, false);
    expect(findings.some((f) => f.id === "server-version")).toBe(false);
  });

  // --- Fix owner attribution ---
  it("attributes headers findings to wix_platform for Wix sites", () => {
    const findings = checkHeaders({}, true);
    const hsts = findings.find((f) => f.id === "missing-hsts");
    expect(hsts?.fixOwner).toBe("wix_platform");
  });

  it("attributes headers findings to site_owner for non-Wix sites", () => {
    const findings = checkHeaders({}, false);
    const hsts = findings.find((f) => f.id === "missing-hsts");
    expect(hsts?.fixOwner).toBe("site_owner");
  });
});
