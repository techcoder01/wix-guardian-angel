import type { CveMatch, Finding } from "@/lib/scanner-types";

/**
 * Best-effort third-party library version + CVE detection.
 *
 * Strategy:
 *   1. Match well-known CDN URL patterns (jsDelivr, unpkg, cdnjs) and extract
 *      `name` + `version`.
 *   2. Query OSV.dev for matching vulns (npm ecosystem). OSV is free, no API
 *      key, generous rate limits.
 *   3. Cache results in-memory per Worker invocation. Caller can supply an
 *      external cache (KV / DO) for cross-invocation persistence.
 *
 * Bounded: at most 8 lookups per scan, 3s wall-clock per lookup. CVE failures
 * never break the scan — the function returns an empty array on any error.
 */

const MAX_LOOKUPS = 8;
const LOOKUP_TIMEOUT_MS = 3_000;

const CDN_PATTERNS: Array<{
  re: RegExp;
  // Match groups: name (1), version (2)
  ecosystem: "npm";
}> = [
  { re: /\/\/cdn\.jsdelivr\.net\/npm\/([@a-z0-9._\-/]+?)@([\d.]+)/gi, ecosystem: "npm" },
  { re: /\/\/unpkg\.com\/([@a-z0-9._\-/]+?)@([\d.]+)/gi, ecosystem: "npm" },
  { re: /\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/([a-z0-9._\-]+)\/([\d.]+)\//gi, ecosystem: "npm" },
];

export interface ExtractedLibrary {
  name: string;
  version: string;
  ecosystem: "npm";
  source: string;
}

export function extractLibraries(html: string): ExtractedLibrary[] {
  const out = new Map<string, ExtractedLibrary>();
  for (const { re, ecosystem } of CDN_PATTERNS) {
    for (const match of html.matchAll(re)) {
      const name = match[1];
      const version = match[2];
      if (!name || !version) continue;
      const key = `${ecosystem}:${name}@${version}`;
      if (!out.has(key)) {
        out.set(key, { name, version, ecosystem, source: match[0] });
      }
    }
  }
  return Array.from(out.values()).slice(0, MAX_LOOKUPS);
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
}

interface OsvResponse {
  vulns?: OsvVuln[];
}

interface CacheEntry {
  vulns: CveMatch[];
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

async function queryOsv(
  lib: ExtractedLibrary,
): Promise<CveMatch[]> {
  const cacheKey = `${lib.ecosystem}:${lib.name}@${lib.version}`;
  const hit = cache.get(cacheKey);
  if (hit && hit.expiresAt > Date.now()) return hit.vulns;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: lib.version,
        package: { name: lib.name, ecosystem: "npm" },
      }),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as OsvResponse;
    const vulns = (data.vulns ?? []).slice(0, 5).map<CveMatch>((v) => ({
      id: v.id,
      summary: (v.summary ?? v.details ?? "").slice(0, 200) || v.id,
      url: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,
    }));
    cache.set(cacheKey, {
      vulns,
      expiresAt: Date.now() + 1000 * 60 * 60 * 6,
    });
    return vulns;
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Run CVE lookups for every library detected in the HTML, parallelised.
 * Returns a single Finding aggregating any vulnerable libraries; empty array
 * if no CVEs found or no recognisable libraries.
 */
export async function checkCves(html: string): Promise<Finding[]> {
  const libs = extractLibraries(html);
  if (libs.length === 0) return [];

  const results = await Promise.all(
    libs.map(async (l) => ({ lib: l, vulns: await queryOsv(l) })),
  );
  const vulnerable = results.filter((r) => r.vulns.length > 0);
  if (vulnerable.length === 0) return [];

  return vulnerable.map((v) => ({
    id: `third-party-cve-${v.lib.name.replace(/[^a-z0-9]/gi, "_")}-${v.lib.version}`,
    title: `${v.lib.name}@${v.lib.version} has ${v.vulns.length} known CVE(s)`,
    category: "third_party",
    severity: "high",
    description: `The page loads ${v.lib.name}@${v.lib.version} from a public CDN. OSV.dev reports ${v.vulns.length} known vulnerability record(s) affecting this version.`,
    evidence: `${v.lib.source}\n${v.vulns.map((x) => x.id).slice(0, 3).join(", ")}`,
    remediation:
      "Upgrade to the patched version listed in the CVE record, or self-host a vetted build.",
    fixOwner: "site_owner",
    cves: v.vulns,
    reference: "https://osv.dev/",
  }));
}
