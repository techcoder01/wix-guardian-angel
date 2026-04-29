import { describe, it, expect } from "vitest";
import { checkTransport, fixOwnerFor } from "@/utils/checks/transport";

describe("checkTransport", () => {
  it("flags site that stays on HTTP without redirect", () => {
    const findings = checkTransport(
      "http://example.com",
      "http://example.com",
      false,
    );
    expect(findings.some((f) => f.id === "no-https")).toBe(true);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not flag when HTTP redirects to HTTPS", () => {
    const findings = checkTransport(
      "http://example.com",
      "https://example.com",
      false,
    );
    expect(findings.some((f) => f.id === "no-https")).toBe(false);
  });

  it("does not flag when site is already HTTPS", () => {
    const findings = checkTransport(
      "https://example.com",
      "https://example.com",
      false,
    );
    expect(findings).toHaveLength(0);
  });

  it("attributes no-https to wix_platform for Wix sites", () => {
    const findings = checkTransport(
      "http://example.com",
      "http://example.com",
      true,
    );
    expect(findings[0].fixOwner).toBe("wix_platform");
  });

  it("attributes no-https to site_owner for non-Wix sites", () => {
    const findings = checkTransport(
      "http://example.com",
      "http://example.com",
      false,
    );
    expect(findings[0].fixOwner).toBe("site_owner");
  });
});

describe("fixOwnerFor", () => {
  it("returns site_owner when isWix is false regardless of category", () => {
    expect(fixOwnerFor("headers", false)).toBe("site_owner");
    expect(fixOwnerFor("cookies", false)).toBe("site_owner");
    expect(fixOwnerFor("content", false)).toBe("site_owner");
  });

  it("returns wix_platform for platform-controlled categories on Wix", () => {
    expect(fixOwnerFor("headers", true)).toBe("wix_platform");
    expect(fixOwnerFor("cookies", true)).toBe("wix_platform");
    expect(fixOwnerFor("transport", true)).toBe("wix_platform");
  });

  it("returns site_owner for editable categories on Wix", () => {
    expect(fixOwnerFor("content", true)).toBe("site_owner");
    expect(fixOwnerFor("forms", true)).toBe("site_owner");
    expect(fixOwnerFor("information_disclosure", true)).toBe("site_owner");
  });

  it("returns third_party for third_party category", () => {
    expect(fixOwnerFor("third_party", true)).toBe("third_party");
  });

  it("returns shared for unknown categories", () => {
    expect(fixOwnerFor("unknown_category", true)).toBe("shared");
  });
});
