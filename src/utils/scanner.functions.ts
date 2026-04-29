import { createServerFn } from "@tanstack/react-start";
import { getRequestIP } from "@tanstack/react-start/server";
import type { Finding, ScanResult, Severity } from "@/lib/scanner-types";
import {
  SCAN_TIMEOUT_MS,
  HTML_BODY_CAP_BYTES,
  MAX_URL_LENGTH,
  MIN_URL_LENGTH,
} from "@/lib/constants";
import { ScannerError, classifyScanError } from "@/lib/errors";
import { attachRemediationDetails } from "@/lib/remediation/attach";
import { checkHeaders } from "./checks/headers";
import { checkCookies } from "./checks/cookies";
import { checkTransport } from "./checks/transport";
import { checkContent } from "./checks/content";
import { checkWix } from "./checks/wix";
import { checkCves } from "./checks/cve";
import { crawlSurface } from "./crawler";
import { checkRateLimit, getStore } from "./rate-limit";

// ---------------------------------------------------------------------------
// SSRF prevention
// ---------------------------------------------------------------------------

/** IP patterns that must never be scanned (private / loopback / link-local). */
const BLOCKED_IP_PATTERNS: RegExp[] = [
  /^127\./,                        // 127.0.0.0/8 loopback
  /^10\./,                         // 10.0.0.0/8 RFC-1918
  /^192\.168\./,                   // 192.168.0.0/16 RFC-1918
  /^172\.(1[6-9]|2\d|3[01])\./,   // 172.16.0.0/12 RFC-1918
  /^169\.254\./,                   // 169.254.0.0/16 link-local / cloud metadata
  /^0\./,                          // 0.0.0.0/8 "this" network
  /^::1$/,                         // IPv6 loopback
  /^fc[0-9a-f]{2}:/i,             // IPv6 ULA fc00::/7
  /^fd[0-9a-f]{2}:/i,             // IPv6 ULA fd00::/8
];

/** Exact hostnames that are never valid scan targets. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "169.254.169.254",       // AWS / GCP / Azure IMDS
  "100.100.100.200",       // Alibaba Cloud IMDS
  "metadata.google.internal",
  "metadata.internal",
]);

/**
 * Validates and normalises a user-supplied URL.
 * Throws ScannerError("blocked_target" | "invalid_url") on rejection.
 */
function validateScanTarget(rawUrl: string): string {
  const trimmed = rawUrl.trim();

  if (!/^https?:\/\//i.test(trimmed)) {
    throw new ScannerError(
      "invalid_url",
      "Only http:// and https:// URLs are supported.",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ScannerError(
      "invalid_url",
      "Invalid URL: could not be parsed. Check for typos.",
    );
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ScannerError(
      "invalid_url",
      "Only http:// and https:// URLs are supported.",
    );
  }

  const host = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(host)) {
    throw new ScannerError(
      "blocked_target",
      "Scanning internal, loopback or cloud-metadata hostnames is not permitted.",
    );
  }

  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(host)) {
      throw new ScannerError(
        "blocked_target",
        "Scanning private, loopback or link-local IP addresses is not permitted.",
      );
    }
  }

  return trimmed;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeUrl(input: string): string {
  let u = input.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

function emptySummary(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function detectWix(
  headers: Record<string, string>,
  html: string,
): { isWix: boolean; signals: string[] } {
  const signals: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase().startsWith("x-wix"))
      signals.push(`Header ${k}: ${v.slice(0, 80)}`);
    if (k.toLowerCase() === "server" && /wix/i.test(v))
      signals.push(`Server: ${v}`);
  }
  if (/static\.wixstatic\.com/i.test(html))
    signals.push("Asset host static.wixstatic.com referenced");
  if (/static\.parastorage\.com/i.test(html))
    signals.push("Asset host static.parastorage.com (Wix CDN)");
  if (/<meta[^>]+generator[^>]+wix/i.test(html))
    signals.push("<meta generator> indicates Wix");
  if (/wixBiSession|wix-?warmup-?data/i.test(html))
    signals.push("Inline Wix runtime detected");
  return { isWix: signals.length > 0, signals };
}

function summarize(findings: Finding[]): Record<Severity, number> {
  const s = emptySummary();
  for (const f of findings) s[f.severity]++;
  return s;
}

// ---------------------------------------------------------------------------
// Core scan
// ---------------------------------------------------------------------------

async function performScan(rawUrl: string): Promise<ScanResult> {
  const validatedUrl = validateScanTarget(rawUrl);
  const url = normalizeUrl(validatedUrl);
  const start = Date.now();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "WixSecAudit/0.2 (+passive-scanner; dissertation prototype)",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new ScannerError(
        "timeout",
        `Scan timed out after ${SCAN_TIMEOUT_MS / 1000}s. The target may be slow or unreachable.`,
      );
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }

  const finalUrl = response.url || url;
  const headers: Record<string, string> = {};
  const rawSetCookies: string[] = [];

  response.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
    if (k.toLowerCase() === "set-cookie") rawSetCookies.push(v);
  });

  // Prefer getSetCookie() which returns each Set-Cookie value separately,
  // correctly handling date commas in Expires=.
  const allSetCookies: string[] =
    typeof (response.headers as unknown as Record<string, unknown>)
      .getSetCookie === "function"
      ? (
          response.headers as unknown as { getSetCookie(): string[] }
        ).getSetCookie()
      : rawSetCookies;

  const html = (await response.text()).slice(0, HTML_BODY_CAP_BYTES);
  const wix = detectWix(headers, html);

  // Multi-surface crawl + CVE lookup in parallel — both are network-bound.
  const [crawl, cveFindings] = await Promise.all([
    crawlSurface(finalUrl).catch(
      () => ({ resources: [], bodies: {} } as Awaited<ReturnType<typeof crawlSurface>>),
    ),
    checkCves(html).catch(() => [] as Finding[]),
  ]);

  const robotsTxt = crawl.bodies["/robots.txt"];
  const sitemap = crawl.bodies["/sitemap.xml"];

  const findings: Finding[] = [
    ...checkTransport(url, finalUrl, wix.isWix),
    ...checkHeaders(headers, wix.isWix),
    ...checkCookies(allSetCookies, wix.isWix),
    ...checkContent(html, finalUrl, wix.isWix),
    ...checkWix(html, crawl.resources, robotsTxt, sitemap, wix.isWix),
    ...cveFindings,
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

  const hydrated = attachRemediationDetails(findings);

  return {
    url,
    finalUrl,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - start,
    isWix: wix.isWix,
    platformSignals: wix.signals,
    statusCode: response.status,
    findings: hydrated,
    summary: summarize(hydrated),
    responseHeaders: headers,
    crawled: crawl.resources,
  };
}

// ---------------------------------------------------------------------------
// Public server function
// ---------------------------------------------------------------------------

function clientIp(): string {
  try {
    return getRequestIP({ xForwardedFor: true }) ?? "unknown";
  } catch {
    return "unknown";
  }
}

export const scanUrl = createServerFn({ method: "POST" })
  .inputValidator((data: { url: string; clientKey?: string }) => {
    if (
      !data ||
      typeof data.url !== "string" ||
      data.url.length < MIN_URL_LENGTH ||
      data.url.length > MAX_URL_LENGTH
    ) {
      throw new ScannerError(
        "invalid_url",
        "Invalid URL: must be between 3 and 2048 characters.",
      );
    }
    return data;
  })
  .handler(async ({ data }) => {
    let host = "global";
    try {
      host = new URL(
        data.url.trim().replace(/^(?!https?:\/\/)/i, "https://"),
      ).hostname;
    } catch {
      /* fall back to global key */
    }

    const ip = clientIp();
    const store = getStore(
      // KV binding wired through Cloudflare env when deployed; undefined locally.
      (globalThis as { RATE_LIMIT_KV?: unknown }).RATE_LIMIT_KV,
    );
    const verdict = await checkRateLimit(store, ip, host);
    if (!verdict.allowed) {
      throw new ScannerError(
        "rate_limited",
        verdict.reason ?? "Rate limit exceeded. Please wait and try again.",
        verdict.retryAfterMs,
      );
    }

    try {
      return await performScan(data.url);
    } catch (e) {
      const { code, message } = classifyScanError(e);
      throw new ScannerError(code, message);
    }
  });
