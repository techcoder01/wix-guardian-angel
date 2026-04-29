import type { CrawledResource, Finding } from "@/lib/scanner-types";
import { EVIDENCE_TRUNCATE_LENGTH } from "@/lib/constants";

/**
 * Wix-specific deep checks. All inputs are passive: HTML body of `/`, HTTP
 * results from probed paths, and parsed Wix runtime metadata. No active
 * exploitation — just signal extraction from public artefacts.
 */

// Common Velo http-functions paths to probe. Hits are evaluated, misses ignored.
export const VELO_PROBE_PATHS = [
  "/_functions/",
  "/_functions/health",
  "/_functions/contact",
  "/_functions/api",
  "/_functions/admin",
  "/_functions/test",
];

const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "Stripe live key", re: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: "Stripe publishable key", re: /\bpk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: "Generic API key assignment", re: /["']?(?:api[_-]?key|secret|token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{24,}["']/gi },
];

const SUSPICIOUS_ROBOTS_PATHS = /\b(admin|secret|private|internal|backup|api|test|dev|staging)\b/i;

/**
 * Parse Wix runtime metadata embedded in the page. Wix injects two common
 * inline JSON blobs: `wixBiSession` (session telemetry) and `wix-warmup-data`.
 * Both can leak metaSiteId, viewerSiteId, userId.
 */
export function parseWixRuntime(html: string): {
  metaSiteId?: string;
  viewerSiteId?: string;
  userId?: string;
  raw: string[];
} {
  const out = { raw: [] as string[] } as ReturnType<typeof parseWixRuntime>;

  const idMatch = (re: RegExp) => html.match(re)?.[1];

  out.metaSiteId = idMatch(/metaSiteId["']?\s*[:=]\s*["']([0-9a-f-]{8,})["']/i);
  out.viewerSiteId = idMatch(/viewerSiteId["']?\s*[:=]\s*["']([0-9a-f-]{8,})["']/i);
  out.userId = idMatch(/(?:visitorId|userId)["']?\s*[:=]\s*["']([0-9a-f-]{8,})["']/i);

  if (out.metaSiteId) out.raw.push(`metaSiteId=${out.metaSiteId}`);
  if (out.viewerSiteId) out.raw.push(`viewerSiteId=${out.viewerSiteId}`);
  if (out.userId) out.raw.push(`userId=${out.userId}`);

  return out;
}

/**
 * Build findings from probed Velo / well-known paths plus deep HTML inspection.
 *
 * @param html      HTML body of the root document
 * @param crawled   Results of probing additional URLs (robots.txt, sitemap.xml,
 *                  /.well-known/security.txt, Velo paths, etc.)
 * @param robotsTxt Body of robots.txt if fetched
 * @param sitemap   Body of sitemap.xml if fetched
 * @param isWix     Whether the target was identified as Wix-hosted
 */
export function checkWix(
  html: string,
  crawled: CrawledResource[],
  robotsTxt: string | undefined,
  sitemap: string | undefined,
  isWix: boolean,
): Finding[] {
  const f: Finding[] = [];

  // ------------------------------------------------------------------
  // Velo http-functions exposure
  // ------------------------------------------------------------------
  const reachableVelo = crawled.filter(
    (c) =>
      c.url.includes("/_functions/") &&
      c.ok &&
      c.status >= 200 &&
      c.status < 400,
  );
  if (reachableVelo.length > 0) {
    f.push({
      id: "wix-velo-functions-exposed",
      title: `${reachableVelo.length} Velo http-function(s) reachable without authentication`,
      category: "velo",
      severity: "high",
      description:
        "Wix Velo http-functions are public unless the function body checks the caller. Each reachable endpoint is a potential attack surface — review every function for auth and input validation.",
      evidence: reachableVelo
        .slice(0, 3)
        .map((r) => `${r.status} ${r.url}`)
        .join("\n"),
      remediation:
        "Wrap each http-function in an authentication check; rate-limit; validate inputs.",
      fixOwner: "site_owner",
      reference: "https://www.wix.com/velo/reference/wix-http-functions",
    });
  }

  // ------------------------------------------------------------------
  // wix-data CMS collection mention in page source
  // ------------------------------------------------------------------
  const wixDataMatches = html.match(
    /(?:wixData|@wix\/data|"collectionId"\s*:\s*"[^"]+")/gi,
  );
  if (wixDataMatches && wixDataMatches.length > 0) {
    const collections = Array.from(
      new Set(
        (html.match(/"collectionId"\s*:\s*"([^"]+)"/g) ?? [])
          .map((m) => m.match(/"collectionId"\s*:\s*"([^"]+)"/)?.[1])
          .filter(Boolean) as string[],
      ),
    );
    if (collections.length > 0) {
      f.push({
        id: "wix-data-collection-exposed",
        title: `Wix CMS collection IDs visible in page source (${collections.length})`,
        category: "cms",
        severity: "medium",
        description:
          "Public collection IDs combined with default permissive read permissions can let an attacker enumerate or download CMS contents. Confirm permissions in the Wix CMS for each collection.",
        evidence: collections.slice(0, 5).join(", "),
        remediation:
          "Check each collection's read permissions in the Wix CMS and tighten to Member/Admin where appropriate.",
        fixOwner: "site_owner",
        reference:
          "https://support.wix.com/en/article/wix-cms-formerly-content-manager-setting-collection-permissions-and-privacy",
      });
    }
  }

  // ------------------------------------------------------------------
  // Wix Members API surface
  // ------------------------------------------------------------------
  if (
    /\/_api\/(?:wix-sso|members(?:-area)?|public-profile|contacts)/i.test(html) ||
    /["']?membersAreaInstalled["']?\s*[:=]\s*true/i.test(html)
  ) {
    f.push({
      id: "wix-members-area-exposed",
      title: "Wix Members area / public-profile API references found",
      category: "members",
      severity: "low",
      description:
        "The site appears to have a Members area enabled. By default, member profiles can be partially enumerable via Wix's public-profile endpoints.",
      remediation:
        "In Wix Dashboard → Members → Privacy, review default privacy and disable directory pages if not required.",
      fixOwner: "site_owner",
      reference:
        "https://support.wix.com/en/article/wix-members-area-managing-the-privacy-of-your-members-area",
    });
  }

  // ------------------------------------------------------------------
  // Wix runtime metadata leak
  // ------------------------------------------------------------------
  const runtime = parseWixRuntime(html);
  if (runtime.raw.length > 0 && isWix) {
    f.push({
      id: "wix-bi-session-leak",
      title: "Wix runtime metadata embedded in HTML",
      category: "wix_platform",
      severity: "info",
      description:
        "Wix injects identifiers (metaSiteId / viewerSiteId / userId) into the page. This is platform behaviour and not a vulnerability per se — but treat the HTML as world-readable and never reflect secrets into it.",
      evidence: runtime.raw.join(" | "),
      remediation:
        "No site-owner action required; awareness only. Never store secrets in inline scripts or page state.",
      fixOwner: "wix_platform",
    });
  }

  // ------------------------------------------------------------------
  // Wix Forms collecting PII without obvious CAPTCHA
  // ------------------------------------------------------------------
  const wixFormBlocks = Array.from(
    html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi),
  ).map((m) => m[0]);
  for (const formHtml of wixFormBlocks) {
    if (!/_api\/wix-forms|wixform|wix-forms/i.test(formHtml)) continue;
    const collectsPii =
      /name\s*=\s*["'][^"']*(email|phone|tel|ssn|dob|birth|address|passport)/i.test(
        formHtml,
      );
    const hasCaptcha = /captcha|recaptcha|hcaptcha|turnstile/i.test(formHtml);
    if (collectsPii && !hasCaptcha) {
      f.push({
        id: "wix-form-pii-no-captcha",
        title: "Wix Form collects PII without visible bot/spam protection",
        category: "forms",
        severity: "medium",
        description:
          "A form posting to Wix Forms collects sensitive personal information yet shows no CAPTCHA / Turnstile / hCaptcha integration in the page source. Confirm anti-spam is enabled in the Form settings.",
        evidence: formHtml.slice(0, EVIDENCE_TRUNCATE_LENGTH),
        remediation:
          "Enable CAPTCHA in Form Settings; review which PII fields are strictly necessary.",
        fixOwner: "site_owner",
      });
      break; // one finding per page is enough
    }
  }

  // ------------------------------------------------------------------
  // Dashboard / editor URLs leaked into public HTML
  // ------------------------------------------------------------------
  const dashboardLeak = html.match(
    /https?:\/\/(?:manage|editor|users|www)\.wix\.com\/[^"'\s<>]+/g,
  );
  if (dashboardLeak && dashboardLeak.length > 0) {
    const filtered = dashboardLeak.filter(
      (u) => !/wix\.com\/(?:about|privacy|legal|terms|tos)/i.test(u),
    );
    if (filtered.length > 0) {
      f.push({
        id: "wix-dashboard-url-leak",
        title: "Wix dashboard / editor URLs present in public HTML",
        category: "information_disclosure",
        severity: "low",
        description:
          "Internal Wix dashboard or editor URLs (manage.wix.com, editor.wix.com) appear in the public page source. These often arrive via copy-pasted preview links and may leak account/site identifiers.",
        evidence: filtered.slice(0, 3).join("\n"),
        remediation: "Remove dashboard / editor URLs from public components.",
        fixOwner: "site_owner",
      });
    }
  }

  // ------------------------------------------------------------------
  // iframe sandbox check
  // ------------------------------------------------------------------
  const iframes = Array.from(html.matchAll(/<iframe\b[^>]*>/gi)).map((m) => m[0]);
  const unsandboxed = iframes.filter(
    (i) => !/sandbox\s*=/.test(i) && !/wix\.com|wixstatic\.com|parastorage\.com/.test(i),
  );
  if (unsandboxed.length > 0) {
    f.push({
      id: "wix-iframe-no-sandbox",
      title: `${unsandboxed.length} iframe(s) without sandbox attribute`,
      category: "configuration",
      severity: "low",
      description:
        "Untrusted iframes should use the sandbox attribute to restrict what the embedded content can do.",
      evidence: unsandboxed.slice(0, 2).join("\n").slice(0, EVIDENCE_TRUNCATE_LENGTH),
      remediation:
        'Add sandbox="allow-scripts allow-same-origin" (or stricter) to untrusted iframes.',
      fixOwner: "site_owner",
    });
  }

  // ------------------------------------------------------------------
  // Inline secret heuristic
  // ------------------------------------------------------------------
  const secretsFound: string[] = [];
  for (const { name, re } of SECRET_PATTERNS) {
    const hits = html.match(re);
    if (hits && hits.length > 0) {
      secretsFound.push(`${name}: ${hits[0].slice(0, 40)}`);
    }
  }
  if (secretsFound.length > 0) {
    f.push({
      id: "wix-inline-secret",
      title: "Possible secret / API key embedded in page source",
      category: "information_disclosure",
      severity: "critical",
      description:
        "A pattern matching a known credential format was found in the public HTML. Even if false-positive, treat as exposed: rotate the secret and move it to wix-secrets-backend or a server-side store.",
      evidence: secretsFound.slice(0, 3).join("\n"),
      remediation:
        "Rotate the credential immediately and move secrets server-side.",
      fixOwner: "site_owner",
      reference: "https://www.wix.com/velo/reference/wix-secrets-backend",
    });
  }

  // ------------------------------------------------------------------
  // .well-known/security.txt missing
  // ------------------------------------------------------------------
  const securityTxt = crawled.find((c) =>
    c.url.endsWith("/.well-known/security.txt"),
  );
  if (securityTxt && !securityTxt.ok) {
    f.push({
      id: "wix-security-txt-missing",
      title: "No /.well-known/security.txt published",
      category: "configuration",
      severity: "info",
      description:
        "Without a security.txt file, security researchers have no advertised path to disclose vulnerabilities responsibly.",
      remediation:
        "Publish a security.txt at /.well-known/security.txt advertising a contact and disclosure policy.",
      fixOwner: "site_owner",
      reference: "https://www.rfc-editor.org/rfc/rfc9116",
    });
  }

  // ------------------------------------------------------------------
  // robots.txt advertising sensitive paths
  // ------------------------------------------------------------------
  if (robotsTxt) {
    const disallowed = robotsTxt
      .split(/\r?\n/)
      .filter((l) => /^disallow\s*:/i.test(l))
      .map((l) => l.split(":")[1]?.trim() ?? "")
      .filter((p) => p && SUSPICIOUS_ROBOTS_PATHS.test(p));
    if (disallowed.length > 0) {
      f.push({
        id: "robots-disallow-secret-paths",
        title: "robots.txt advertises sensitive-looking paths",
        category: "information_disclosure",
        severity: "low",
        description:
          "robots.txt is publicly readable. Listing 'admin', 'private', 'backup' etc. in Disallow directives reveals their existence to anyone reading the file.",
        evidence: disallowed.slice(0, 5).join(", "),
        remediation:
          "Don't use robots.txt as a security boundary — protect sensitive paths with authentication and noindex meta tags.",
        fixOwner: "site_owner",
        reference:
          "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
      });
    }
  }

  // ------------------------------------------------------------------
  // sitemap.xml exposing private-looking pages
  // ------------------------------------------------------------------
  if (sitemap) {
    const urls = Array.from(sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)).map(
      (m) => m[1],
    );
    const privateLooking = urls.filter((u) =>
      /staging|test|dev|preview|admin|internal|hidden/i.test(u),
    );
    if (privateLooking.length > 0) {
      f.push({
        id: "sitemap-exposes-private-pages",
        title: "sitemap.xml lists private-looking pages",
        category: "information_disclosure",
        severity: "low",
        description:
          "The sitemap advertises pages whose URL hints at non-public content (staging, dev, admin, etc.).",
        evidence: privateLooking.slice(0, 3).join("\n"),
        remediation:
          "Either remove these URLs from the sitemap or restrict them properly with authentication.",
        fixOwner: "site_owner",
      });
    }
  }

  return f;
}
