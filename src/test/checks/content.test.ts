import { describe, it, expect } from "vitest";
import { checkContent } from "@/utils/checks/content";

const HTTPS_URL = "https://example.com";
const HTTP_URL = "http://example.com";

describe("checkContent — mixed content", () => {
  it("flags HTTP resource on HTTPS page", () => {
    const html = `<img src="http://cdn.example.com/img.jpg">`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "mixed-content")).toBe(true);
  });

  it("does not flag HTTP resources on HTTP page", () => {
    const html = `<img src="http://cdn.example.com/img.jpg">`;
    const findings = checkContent(html, HTTP_URL, false);
    expect(findings.some((f) => f.id === "mixed-content")).toBe(false);
  });

  it("ignores w3.org HTTP references in mixed content check", () => {
    const html = `<html xmlns="http://www.w3.org/1999/xhtml">`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "mixed-content")).toBe(false);
  });

  it("counts multiple mixed content references", () => {
    const html = `<img src="http://a.com/a.jpg"><script src="http://b.com/b.js"></script>`;
    const findings = checkContent(html, HTTPS_URL, false);
    const f = findings.find((f) => f.id === "mixed-content");
    expect(f?.description).toContain("2");
  });
});

describe("checkContent — forms", () => {
  it("flags form with HTTP action", () => {
    const html = `<form action="http://example.com/submit">`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "form-insecure-action")).toBe(true);
  });

  it("does not flag form with HTTPS action", () => {
    const html = `<form action="https://example.com/submit">`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "form-insecure-action")).toBe(false);
  });

  it("does not flag form with no action attribute", () => {
    const html = `<form method="post">`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "form-insecure-action")).toBe(false);
  });
});

describe("checkContent — email exposure", () => {
  it("flags exposed email addresses", () => {
    const html = `<p>Contact us at hello@example.com</p>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "exposed-emails")).toBe(true);
  });

  it("deduplicates emails in evidence", () => {
    const html = `hello@example.com hello@example.com other@example.com`;
    const findings = checkContent(html, HTTPS_URL, false);
    const f = findings.find((f) => f.id === "exposed-emails");
    expect(f?.description).toContain("2"); // 2 unique addresses
  });

  it("does not flag image paths that look like emails", () => {
    const html = `<img src="icon.svg@2x.png">`;
    // This matches the email regex but ends in .png so should be filtered
    const findings = checkContent(html, HTTPS_URL, false);
    const f = findings.find((f) => f.id === "exposed-emails");
    // The filter removes entries ending in .png
    if (f) expect(f.evidence).not.toContain("icon.svg@2x.png");
  });
});

describe("checkContent — source maps", () => {
  it("flags sourceMappingURL references", () => {
    const html = `//# sourceMappingURL=app.js.map`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "sourcemap-reference")).toBe(true);
  });

  it("does not flag when no sourcemap reference exists", () => {
    const html = `<html><body>Hello</body></html>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "sourcemap-reference")).toBe(false);
  });
});

describe("checkContent — suspicious comments", () => {
  it("flags TODO in HTML comments", () => {
    const html = `<!-- TODO: remove this before launch -->`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "suspicious-comments")).toBe(true);
  });

  it("flags password mention in HTML comments", () => {
    const html = `<!-- password: admin123 -->`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "suspicious-comments")).toBe(true);
  });

  it("does not flag harmless comments", () => {
    const html = `<!-- Navigation component -->`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "suspicious-comments")).toBe(false);
  });
});

describe("checkContent — third-party scripts", () => {
  it("flags external scripts without SRI", () => {
    const html = `<script src="https://cdn.example.com/lib.js"></script>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "third-party-scripts")).toBe(true);
    const f = findings.find((f) => f.id === "third-party-scripts");
    expect(f?.severity).toBe("medium"); // no SRI = medium
  });

  it("uses info severity when all external scripts have SRI", () => {
    const html = `<script src="https://cdn.example.com/lib.js" integrity="sha256-abc" crossorigin="anonymous"></script>`;
    const findings = checkContent(html, HTTPS_URL, false);
    const f = findings.find((f) => f.id === "third-party-scripts");
    if (f) expect(f.severity).toBe("info");
  });

  it("does not flag same-origin scripts", () => {
    const html = `<script src="https://example.com/app.js"></script>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "third-party-scripts")).toBe(false);
  });

  it("handles URLs with regex special chars without throwing", () => {
    const html = `<script src="https://cdn.example.com/lib.v1.2+min.js"></script>`;
    expect(() => checkContent(html, HTTPS_URL, false)).not.toThrow();
  });
});

describe("checkContent — directory listing", () => {
  it("flags directory listing signal in title", () => {
    const html = `<title>Index of /var/www</title>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "directory-listing")).toBe(true);
  });

  it("does not flag normal page title", () => {
    const html = `<title>My Website</title>`;
    const findings = checkContent(html, HTTPS_URL, false);
    expect(findings.some((f) => f.id === "directory-listing")).toBe(false);
  });
});

describe("checkContent — fix owner", () => {
  it("attributes content findings to site_owner for Wix sites", () => {
    const html = `hello@example.com`;
    const findings = checkContent(html, HTTPS_URL, true);
    const f = findings.find((f) => f.id === "exposed-emails");
    expect(f?.fixOwner).toBe("site_owner");
  });

  it("attributes third-party findings to third_party always", () => {
    const html = `<script src="https://cdn.other.com/lib.js"></script>`;
    const findings = checkContent(html, HTTPS_URL, true);
    const f = findings.find((f) => f.id === "third-party-scripts");
    expect(f?.fixOwner).toBe("third_party");
  });
});
