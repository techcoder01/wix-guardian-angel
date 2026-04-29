import { describe, it, expect } from "vitest";
import { getRemediation, listRegistryIds } from "@/lib/remediation/registry";
import { attachRemediationDetails } from "@/lib/remediation/attach";
import type { Finding } from "@/lib/scanner-types";
import { checkHeaders } from "@/utils/checks/headers";
import { checkCookies } from "@/utils/checks/cookies";
import { checkContent } from "@/utils/checks/content";
import { checkTransport } from "@/utils/checks/transport";
import { checkWix } from "@/utils/checks/wix";

describe("remediation registry", () => {
  it("returns full remediation for known IDs", () => {
    const r = getRemediation("missing-hsts", "fallback");
    expect(r.steps.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
    expect(r.summary).not.toBe("fallback");
  });

  it("normalises cookie-name-suffixed IDs", () => {
    const r = getRemediation("cookie-no-secure-session", "fallback");
    expect(r.summary).toMatch(/Secure/i);
  });

  it("falls back gracefully for unknown IDs", () => {
    const r = getRemediation("totally-made-up", "do this thing");
    expect(r.summary).toBe("do this thing");
    expect(r.steps[0].action).toBe("do this thing");
  });

  it("registry contains entries for every emitted finding ID", () => {
    // Run every check with payloads that produce as many findings as possible
    // and assert each ID resolves to a non-fallback remediation.
    const sampleHtml = `
      <html>
        <a href="mailto:hi@example.com">contact</a>
        <form action="http://x.com"><input name="email"></form>
        <script src="https://cdn.example.com/lib.js"></script>
        <iframe src="https://embed.example.com"></iframe>
        <!-- TODO: remove this -->
        <script>const k = "AKIAIOSFODNN7EXAMPLE";</script>
        <script>{"collectionId":"Members/X"}</script>
        //# sourceMappingURL=app.js.map
      </html>
    `;
    const findings: Finding[] = [
      ...checkHeaders({}, true),
      ...checkCookies(["s=1"], true),
      ...checkContent(sampleHtml, "https://example.com", true),
      ...checkTransport("http://x.com", "http://x.com", true),
      ...checkWix(
        sampleHtml,
        [
          { url: "https://example.com/_functions/admin", status: 200, ok: true },
          {
            url: "https://example.com/.well-known/security.txt",
            status: 404,
            ok: false,
          },
        ],
        "User-agent: *\nDisallow: /admin",
        "<urlset><url><loc>https://example.com/staging/x</loc></url></urlset>",
        true,
      ),
    ];

    const ids = new Set(listRegistryIds());
    const orphan: string[] = [];
    for (const f of findings) {
      const norm = f.id
        .replace(/^cookie-no-secure-.+$/, "cookie-no-secure")
        .replace(/^cookie-no-httponly-.+$/, "cookie-no-httponly")
        .replace(/^cookie-no-samesite-.+$/, "cookie-no-samesite");
      if (!ids.has(norm)) orphan.push(f.id);
    }
    expect(orphan).toEqual([]);
  });
});

describe("attachRemediationDetails", () => {
  it("hydrates findings without mutating originals", () => {
    const original: Finding[] = [
      {
        id: "missing-hsts",
        title: "x",
        category: "headers",
        severity: "high",
        description: "x",
        remediation: "x",
        fixOwner: "site_owner",
      },
    ];
    const out = attachRemediationDetails(original);
    expect(out[0].remediationDetail).toBeDefined();
    expect(original[0].remediationDetail).toBeUndefined();
  });
});
