import { createServerFn } from "@tanstack/react-start";
import type { Finding, ScanResult, Severity, FixOwner } from "@/lib/scanner-types";

function normalizeUrl(input: string): string {
  let u = input.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

function emptySummary(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function detectWix(headers: Record<string, string>, html: string): { isWix: boolean; signals: string[] } {
  const signals: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase().startsWith("x-wix")) signals.push(`Header ${k}: ${v.slice(0, 80)}`);
    if (k.toLowerCase() === "server" && /wix/i.test(v)) signals.push(`Server: ${v}`);
  }
  if (/static\.wixstatic\.com/i.test(html)) signals.push("Asset host static.wixstatic.com referenced");
  if (/static\.parastorage\.com/i.test(html)) signals.push("Asset host static.parastorage.com (Wix CDN)");
  if (/<meta[^>]+generator[^>]+wix/i.test(html)) signals.push("<meta generator> indicates Wix");
  if (/wixBiSession|wix-?warmup-?data/i.test(html)) signals.push("Inline Wix runtime detected");
  return { isWix: signals.length > 0, signals };
}

function fixOwnerFor(category: string, isWix: boolean): FixOwner {
  if (!isWix) return "site_owner";
  switch (category) {
    case "headers":
    case "cookies":
    case "transport":
      return "wix_platform"; // Wix controls response headers/cookies for hosted sites
    case "third_party":
      return "third_party";
    case "content":
    case "forms":
    case "information_disclosure":
      return "site_owner"; // editable in Wix dashboard
    default:
      return "shared";
  }
}

function checkHeaders(h: Record<string, string>, isWix: boolean): Finding[] {
  const f: Finding[] = [];
  const get = (n: string) => h[n.toLowerCase()];

  if (!get("strict-transport-security")) {
    f.push({
      id: "missing-hsts",
      title: "Missing Strict-Transport-Security (HSTS) header",
      category: "headers",
      severity: "high",
      description:
        "HSTS instructs browsers to use HTTPS only. Without it, users are vulnerable to SSL-stripping and downgrade attacks on first visit or hostile networks.",
      remediation:
        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. On Wix, this is controlled by the platform for managed domains.",
      fixOwner: fixOwnerFor("headers", isWix),
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    });
  } else {
    const v = get("strict-transport-security")!;
    const m = v.match(/max-age=(\d+)/i);
    const age = m ? parseInt(m[1], 10) : 0;
    if (age < 15552000) {
      f.push({
        id: "weak-hsts",
        title: "HSTS max-age below recommended threshold",
        category: "headers",
        severity: "medium",
        description: `HSTS is set but max-age=${age}s is shorter than the recommended 6 months (15552000s).`,
        evidence: v,
        remediation: "Increase max-age to at least 15552000 and include 'includeSubDomains'.",
        fixOwner: fixOwnerFor("headers", isWix),
      });
    }
  }

  if (!get("content-security-policy")) {
    f.push({
      id: "missing-csp",
      title: "Missing Content-Security-Policy header",
      category: "headers",
      severity: "high",
      description:
        "A CSP mitigates cross-site scripting (XSS) and data injection by restricting resource origins. No CSP was returned.",
      remediation:
        "Define a strict CSP. Wix-hosted sites do not currently let owners configure a custom CSP — this is a platform limitation.",
      fixOwner: fixOwnerFor("headers", isWix),
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    });
  }

  if (!get("x-content-type-options")) {
    f.push({
      id: "missing-xcto",
      title: "Missing X-Content-Type-Options header",
      category: "headers",
      severity: "low",
      description: "Without 'nosniff', browsers may MIME-sniff responses, enabling some XSS variants.",
      remediation: "Set 'X-Content-Type-Options: nosniff'.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  const xfo = get("x-frame-options");
  const csp = get("content-security-policy") || "";
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    f.push({
      id: "missing-frame-protection",
      title: "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
      category: "headers",
      severity: "medium",
      description: "The site can be embedded in a frame, enabling clickjacking attacks.",
      remediation: "Set 'X-Frame-Options: SAMEORIGIN' or a CSP 'frame-ancestors' directive.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  if (!get("referrer-policy")) {
    f.push({
      id: "missing-referrer-policy",
      title: "Missing Referrer-Policy header",
      category: "headers",
      severity: "low",
      description: "Without a referrer policy, full URLs (with query parameters) may leak to third parties.",
      remediation: "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  if (!get("permissions-policy")) {
    f.push({
      id: "missing-permissions-policy",
      title: "Missing Permissions-Policy header",
      category: "headers",
      severity: "info",
      description: "Permissions-Policy lets you disable powerful browser features (camera, geolocation, etc.).",
      remediation: "Define a Permissions-Policy denying unused features.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  const server = get("server");
  const xpb = get("x-powered-by");
  if (xpb) {
    f.push({
      id: "x-powered-by",
      title: "Server discloses technology via X-Powered-By",
      category: "information_disclosure",
      severity: "low",
      description: "Disclosing the underlying stack helps attackers target known CVEs.",
      evidence: `X-Powered-By: ${xpb}`,
      remediation: "Remove or mask the X-Powered-By header.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }
  if (server && /\d/.test(server)) {
    f.push({
      id: "server-version",
      title: "Server header discloses software version",
      category: "information_disclosure",
      severity: "low",
      description: "Version disclosure aids targeted exploitation.",
      evidence: `Server: ${server}`,
      remediation: "Strip version detail from the Server header.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  return f;
}

function checkCookies(setCookieValues: string[], isWix: boolean): Finding[] {
  const f: Finding[] = [];
  for (const c of setCookieValues) {
    const name = c.split("=")[0]?.trim() ?? "(unknown)";
    const lower = c.toLowerCase();
    const isSession = /sess|auth|token|sid|login/i.test(name);
    if (!/;\s*secure/i.test(lower)) {
      f.push({
        id: `cookie-no-secure-${name}`,
        title: `Cookie '${name}' missing Secure flag`,
        category: "cookies",
        severity: isSession ? "high" : "medium",
        description: "Cookies without Secure can be transmitted over plaintext HTTP.",
        evidence: c.slice(0, 160),
        remediation: "Add the 'Secure' attribute to every cookie set on HTTPS responses.",
        fixOwner: fixOwnerFor("cookies", isWix),
      });
    }
    if (!/;\s*httponly/i.test(lower)) {
      f.push({
        id: `cookie-no-httponly-${name}`,
        title: `Cookie '${name}' missing HttpOnly flag`,
        category: "cookies",
        severity: isSession ? "high" : "low",
        description: "Cookies accessible to JavaScript can be exfiltrated by XSS.",
        evidence: c.slice(0, 160),
        remediation: "Add the 'HttpOnly' attribute, especially for session cookies.",
        fixOwner: fixOwnerFor("cookies", isWix),
      });
    }
    if (!/;\s*samesite=/i.test(lower)) {
      f.push({
        id: `cookie-no-samesite-${name}`,
        title: `Cookie '${name}' missing SameSite attribute`,
        category: "cookies",
        severity: "low",
        description: "Without SameSite, the cookie is more exposed to CSRF.",
        evidence: c.slice(0, 160),
        remediation: "Set 'SameSite=Lax' or 'SameSite=Strict' as appropriate.",
        fixOwner: fixOwnerFor("cookies", isWix),
      });
    }
  }
  return f;
}

function checkTransport(url: string, finalUrl: string, isWix: boolean): Finding[] {
  const f: Finding[] = [];
  if (url.startsWith("http://") && !finalUrl.startsWith("https://")) {
    f.push({
      id: "no-https",
      title: "Site does not enforce HTTPS",
      category: "transport",
      severity: "critical",
      description: "The site is reachable over plaintext HTTP and does not redirect to HTTPS.",
      remediation: "Force HTTPS via a 301 redirect and enable HSTS.",
      fixOwner: fixOwnerFor("transport", isWix),
    });
  }
  return f;
}

function checkContent(html: string, finalUrl: string, isWix: boolean): Finding[] {
  const f: Finding[] = [];
  const isHttps = finalUrl.startsWith("https://");

  // Mixed content
  if (isHttps) {
    const mixed = html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi) || [];
    const filtered = mixed.filter((m) => !/http:\/\/(www\.)?w3\.org/i.test(m));
    if (filtered.length > 0) {
      f.push({
        id: "mixed-content",
        title: "Mixed content: HTTP resources loaded on HTTPS page",
        category: "content",
        severity: "medium",
        description: `${filtered.length} resource reference(s) use http:// on an https:// page. Browsers may block these or expose users to MITM.`,
        evidence: filtered.slice(0, 3).join("\n"),
        remediation: "Update references to use https:// or protocol-relative URLs.",
        fixOwner: fixOwnerFor("content", isWix),
      });
    }
  }

  // Forms over HTTP / no CSRF token visible
  const formMatches = html.match(/<form\b[^>]*>/gi) || [];
  for (const form of formMatches) {
    const action = form.match(/action\s*=\s*["']([^"']+)["']/i)?.[1] ?? "";
    if (action.startsWith("http://")) {
      f.push({
        id: "form-insecure-action",
        title: "Form submits to an insecure (HTTP) endpoint",
        category: "forms",
        severity: "high",
        description: "Form data including credentials or PII would be transmitted in plaintext.",
        evidence: form.slice(0, 200),
        remediation: "Change the form action to use HTTPS.",
        fixOwner: fixOwnerFor("forms", isWix),
      });
    }
  }

  // Email / phone exposure (passive PII surface, info-level)
  const emails = Array.from(new Set((html.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || []).filter((e) => !/\.(png|jpg|svg|webp)$/i.test(e))));
  if (emails.length > 0) {
    f.push({
      id: "exposed-emails",
      title: "Email addresses exposed in page source",
      category: "information_disclosure",
      severity: "info",
      description: `${emails.length} email address(es) found in the HTML, which can be harvested by spam bots.`,
      evidence: emails.slice(0, 5).join(", "),
      remediation: "Use a contact form or obfuscate addresses (mailto handlers via JS, image fallbacks).",
      fixOwner: fixOwnerFor("content", isWix),
    });
  }

  // Source-map / debug exposure
  if (/sourceMappingURL=/.test(html)) {
    f.push({
      id: "sourcemap-reference",
      title: "Source map reference present in HTML",
      category: "information_disclosure",
      severity: "low",
      description: "Source maps can leak original source code if served publicly.",
      remediation: "Disable source maps in production or restrict access.",
      fixOwner: fixOwnerFor("content", isWix),
    });
  }

  // HTML comments containing TODO/secret-like terms
  const comments = html.match(/<!--[\s\S]*?-->/g) || [];
  const suspect = comments.filter((c) => /todo|fixme|password|secret|api[_-]?key|debug/i.test(c));
  if (suspect.length > 0) {
    f.push({
      id: "suspicious-comments",
      title: "Suspicious HTML comments in page source",
      category: "information_disclosure",
      severity: "low",
      description: "HTML comments may contain developer notes, credentials, or debug info.",
      evidence: suspect.slice(0, 3).map((s) => s.slice(0, 120)).join("\n"),
      remediation: "Strip comments from production HTML.",
      fixOwner: fixOwnerFor("content", isWix),
    });
  }

  // Third-party scripts inventory
  const scripts = Array.from(html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)).map((m) => m[1]);
  const hosts = new Set<string>();
  for (const s of scripts) {
    try {
      const h = new URL(s, finalUrl).hostname;
      if (!finalUrl.includes(h)) hosts.add(h);
    } catch { /* ignore */ }
  }
  if (hosts.size > 0) {
    const noSri = scripts.filter((s) => /^https?:\/\//.test(s)).filter((s) => {
      const tag = html.match(new RegExp(`<script[^>]+src\\s*=\\s*["']${s.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}["'][^>]*>`, "i"));
      return tag && !/integrity\s*=/.test(tag[0]);
    });
    f.push({
      id: "third-party-scripts",
      title: `Third-party scripts loaded from ${hosts.size} external host(s)`,
      category: "third_party",
      severity: noSri.length > 0 ? "medium" : "info",
      description:
        "External scripts execute with full page privileges. Without Subresource Integrity (SRI), a compromise of the third party (or its CDN) can inject code into the site.",
      evidence: Array.from(hosts).slice(0, 8).join(", "),
      remediation:
        "Audit third-party scripts, remove unused ones, and add 'integrity' (SRI) hashes plus 'crossorigin' to <script> tags where possible.",
      fixOwner: "third_party",
      reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    });
  }

  // Directory-listing-like signals (passive)
  if (/<title>\s*Index of \//i.test(html)) {
    f.push({
      id: "directory-listing",
      title: "Directory listing appears enabled",
      category: "configuration",
      severity: "medium",
      description: "Auto-generated directory index detected; may expose internal files.",
      remediation: "Disable directory listing on the web server.",
      fixOwner: fixOwnerFor("configuration", isWix),
    });
  }

  return f;
}

function summarize(findings: Finding[]): Record<Severity, number> {
  const s = emptySummary();
  for (const f of findings) s[f.severity]++;
  return s;
}

async function performScan(rawUrl: string): Promise<ScanResult> {
  const start = Date.now();
  const url = normalizeUrl(rawUrl);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "WixSecAudit/0.1 (+passive-scanner; dissertation prototype)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
  } finally {
    clearTimeout(timeout);
  }

  const finalUrl = response.url || url;
  const headers: Record<string, string> = {};
  const setCookies: string[] = [];
  response.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
    if (k.toLowerCase() === "set-cookie") setCookies.push(v);
  });
  // Some runtimes coalesce Set-Cookie; split conservatively.
  const allSetCookies =
    setCookies.length > 0
      ? setCookies.flatMap((s) => s.split(/,(?=\s*\w+=)/g))
      : [];

  const html = (await response.text()).slice(0, 800_000);
  const wix = detectWix(headers, html);

  const findings: Finding[] = [
    ...checkTransport(url, finalUrl, wix.isWix),
    ...checkHeaders(headers, wix.isWix),
    ...checkCookies(allSetCookies, wix.isWix),
    ...checkContent(html, finalUrl, wix.isWix),
  ];

  if (wix.isWix) {
    findings.push({
      id: "wix-platform-context",
      title: "Target identified as a Wix-hosted site",
      category: "configuration",
      severity: "info",
      description:
        "Many response-header and cookie-level controls (HSTS, CSP, X-Frame-Options, cookie flags) are managed by the Wix platform and cannot be modified by the site owner. Findings in those categories are labelled 'wix_platform'.",
      evidence: wix.signals.slice(0, 5).join(" | "),
      remediation:
        "Site owners should focus on dashboard-level controls: removing exposed PII, vetting third-party embeds, enabling 2FA on the Wix account, and using https-only forms.",
      fixOwner: "shared",
    });
  }

  return {
    url,
    finalUrl,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - start,
    isWix: wix.isWix,
    platformSignals: wix.signals,
    statusCode: response.status,
    findings,
    summary: summarize(findings),
    responseHeaders: headers,
  };
}

export const scanUrl = createServerFn({ method: "POST" })
  .inputValidator((data: { url: string }) => {
    if (!data || typeof data.url !== "string" || data.url.length < 3 || data.url.length > 2048) {
      throw new Error("Invalid URL");
    }
    return data;
  })
  .handler(async ({ data }) => {
    try {
      return await performScan(data.url);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Scan failed";
      throw new Error(`Scan failed for ${data.url}: ${msg}`);
    }
  });