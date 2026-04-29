import { describe, it, expect } from "vitest";
import { checkWix, parseWixRuntime } from "@/utils/checks/wix";
import type { CrawledResource } from "@/lib/scanner-types";

const ok = (url: string, status = 200): CrawledResource => ({
  url,
  status,
  ok: true,
});
const notOk = (url: string, status = 404): CrawledResource => ({
  url,
  status,
  ok: false,
});

describe("parseWixRuntime", () => {
  it("extracts metaSiteId from inline JSON", () => {
    const html = `<script>window.viewerModel = {"metaSiteId":"abcd1234-ef56-7890-abcd-ef1234567890"}</script>`;
    const r = parseWixRuntime(html);
    expect(r.metaSiteId).toBe("abcd1234-ef56-7890-abcd-ef1234567890");
  });
  it("returns empty when no Wix runtime present", () => {
    const r = parseWixRuntime("<html></html>");
    expect(r.metaSiteId).toBeUndefined();
    expect(r.raw).toEqual([]);
  });
});

describe("checkWix — Velo functions", () => {
  it("flags reachable _functions paths", () => {
    const crawl = [ok("https://example.com/_functions/admin")];
    const findings = checkWix("", crawl, undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-velo-functions-exposed")).toBe(true);
  });
  it("does not flag when no _functions reachable", () => {
    const crawl = [notOk("https://example.com/_functions/admin")];
    const findings = checkWix("", crawl, undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-velo-functions-exposed")).toBe(false);
  });
});

describe("checkWix — CMS collections", () => {
  it("flags exposed wix-data collection IDs", () => {
    const html = `<script>{"collectionId":"Members/PrivateData","x":1}</script>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    const f = findings.find((f) => f.id === "wix-data-collection-exposed");
    expect(f).toBeDefined();
    expect(f?.evidence).toContain("Members/PrivateData");
  });
});

describe("checkWix — members area", () => {
  it("flags Members API surface mention", () => {
    const html = `<script>{"membersAreaInstalled":true}</script>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-members-area-exposed")).toBe(true);
  });
});

describe("checkWix — runtime metadata leak", () => {
  it("flags metaSiteId leak only on Wix sites", () => {
    const html = `<script>{"metaSiteId":"a1b2c3d4-e5f6-7890-aaaa-bbbbccccdddd"}</script>`;
    const wix = checkWix(html, [], undefined, undefined, true);
    const nonWix = checkWix(html, [], undefined, undefined, false);
    expect(wix.some((f) => f.id === "wix-bi-session-leak")).toBe(true);
    expect(nonWix.some((f) => f.id === "wix-bi-session-leak")).toBe(false);
  });
});

describe("checkWix — forms PII without captcha", () => {
  it("flags Wix form with email field and no captcha", () => {
    const html = `<form action="/_api/wix-forms/submit"><input name="email"></form>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-form-pii-no-captcha")).toBe(true);
  });
  it("does not flag when captcha is present", () => {
    const html = `<form action="/_api/wix-forms/submit"><input name="email"><div class="g-recaptcha"></div></form>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-form-pii-no-captcha")).toBe(false);
  });
});

describe("checkWix — dashboard URL leaks", () => {
  it("flags manage.wix.com URLs in HTML", () => {
    const html = `<a href="https://manage.wix.com/dashboard/abc/site">edit</a>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-dashboard-url-leak")).toBe(true);
  });
  it("ignores legal/about wix.com pages", () => {
    const html = `<a href="https://www.wix.com/about/us">About</a>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-dashboard-url-leak")).toBe(false);
  });
});

describe("checkWix — iframe sandbox", () => {
  it("flags iframes without sandbox", () => {
    const html = `<iframe src="https://embed.example.com/widget"></iframe>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-iframe-no-sandbox")).toBe(true);
  });
  it("does not flag Wix-internal iframes", () => {
    const html = `<iframe src="https://www.wixstatic.com/widget"></iframe>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-iframe-no-sandbox")).toBe(false);
  });
  it("does not flag iframes with sandbox attribute", () => {
    const html = `<iframe src="https://embed.example.com" sandbox="allow-scripts"></iframe>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-iframe-no-sandbox")).toBe(false);
  });
});

describe("checkWix — inline secrets", () => {
  it("flags AWS access keys", () => {
    const html = `<script>const k = "AKIAIOSFODNN7EXAMPLE";</script>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    const f = findings.find((f) => f.id === "wix-inline-secret");
    expect(f?.severity).toBe("critical");
  });
  it("flags Stripe live keys", () => {
    const html = `<script>const k = "sk_live_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";</script>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-inline-secret")).toBe(true);
  });
  it("does not flag normal HTML", () => {
    const html = `<p>hello world</p>`;
    const findings = checkWix(html, [], undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-inline-secret")).toBe(false);
  });
});

describe("checkWix — security.txt missing", () => {
  it("flags missing security.txt when crawler returned 404", () => {
    const crawl = [notOk("https://example.com/.well-known/security.txt", 404)];
    const findings = checkWix("", crawl, undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-security-txt-missing")).toBe(true);
  });
  it("does not flag when present (200)", () => {
    const crawl = [ok("https://example.com/.well-known/security.txt")];
    const findings = checkWix("", crawl, undefined, undefined, true);
    expect(findings.some((f) => f.id === "wix-security-txt-missing")).toBe(false);
  });
});

describe("checkWix — robots.txt sensitive paths", () => {
  it("flags sensitive Disallow paths", () => {
    const robots = `User-agent: *\nDisallow: /admin\nDisallow: /backup`;
    const findings = checkWix("", [], robots, undefined, true);
    expect(findings.some((f) => f.id === "robots-disallow-secret-paths")).toBe(true);
  });
  it("does not flag harmless robots.txt", () => {
    const robots = `User-agent: *\nDisallow: /search?q=`;
    const findings = checkWix("", [], robots, undefined, true);
    expect(findings.some((f) => f.id === "robots-disallow-secret-paths")).toBe(false);
  });
});

describe("checkWix — sitemap private pages", () => {
  it("flags staging/dev URLs in sitemap", () => {
    const sitemap = `<urlset><url><loc>https://example.com/staging/secret</loc></url></urlset>`;
    const findings = checkWix("", [], undefined, sitemap, true);
    expect(findings.some((f) => f.id === "sitemap-exposes-private-pages")).toBe(true);
  });
});
