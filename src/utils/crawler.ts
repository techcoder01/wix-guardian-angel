import type { CrawledResource } from "@/lib/scanner-types";
import {
  CRAWL_PER_REQUEST_TIMEOUT_MS,
  CRAWL_TOTAL_BUDGET_MS,
  HTML_BODY_CAP_BYTES,
} from "@/lib/constants";
import { VELO_PROBE_PATHS } from "./checks/wix";

/**
 * Multi-surface passive crawler. Probes a fixed allow-list of low-risk paths
 * (robots.txt, sitemap.xml, /.well-known/security.txt, Velo function paths) so
 * that downstream checks have richer signal to work with.
 *
 * Constraints:
 * - HEAD where the path doesn't need a body; GET only when we need the body.
 * - Per-request timeout via AbortController.
 * - Total wall-clock budget enforced by Promise.race.
 * - Identifying User-Agent — easily blockable.
 * - Errors never throw out: each result is recorded, including transport
 *   errors, so callers see the full picture.
 */

const USER_AGENT =
  "WixSecAudit/0.2 (+passive-scanner; dissertation prototype)";

interface ProbeOptions {
  method: "GET" | "HEAD";
  /** When true, response body is captured (capped) into the fetched map. */
  captureBody?: boolean;
}

const PROBE_PATHS: Array<{ path: string; opts: ProbeOptions }> = [
  { path: "/robots.txt", opts: { method: "GET", captureBody: true } },
  { path: "/sitemap.xml", opts: { method: "GET", captureBody: true } },
  {
    path: "/.well-known/security.txt",
    opts: { method: "GET", captureBody: true },
  },
  ...VELO_PROBE_PATHS.map((p) => ({
    path: p,
    opts: { method: "HEAD" as const },
  })),
];

interface ProbeOutcome {
  resource: CrawledResource;
  body?: string;
}

async function probe(
  baseUrl: string,
  path: string,
  opts: ProbeOptions,
): Promise<ProbeOutcome> {
  const url = new URL(path, baseUrl).toString();
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    CRAWL_PER_REQUEST_TIMEOUT_MS,
  );

  try {
    const res = await fetch(url, {
      method: opts.method,
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "*/*" },
    });

    let body: string | undefined;
    let bytes: number | undefined;
    if (opts.captureBody && res.ok) {
      const text = await res.text();
      body = text.slice(0, HTML_BODY_CAP_BYTES);
      bytes = text.length;
    } else if (opts.method === "HEAD") {
      const cl = res.headers.get("content-length");
      bytes = cl ? parseInt(cl, 10) : undefined;
    }

    return {
      resource: {
        url,
        status: res.status,
        contentType: res.headers.get("content-type") ?? undefined,
        bytes,
        ok: res.ok,
      },
      body,
    };
  } catch (e) {
    return {
      resource: {
        url,
        status: 0,
        ok: false,
        error: e instanceof Error ? e.message : "fetch failed",
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}

export interface CrawlOutcome {
  resources: CrawledResource[];
  /** Map keyed by path suffix → captured body (only for GET+captureBody). */
  bodies: Record<string, string>;
}

/**
 * Probe all configured paths in parallel under a global wall-clock budget.
 * Late results past the budget are discarded.
 */
export async function crawlSurface(baseUrl: string): Promise<CrawlOutcome> {
  const all = Promise.all(
    PROBE_PATHS.map(({ path, opts }) => probe(baseUrl, path, opts)),
  );
  const budget = new Promise<ProbeOutcome[]>((resolve) =>
    setTimeout(() => resolve([]), CRAWL_TOTAL_BUDGET_MS),
  );

  // Race the global budget against the full crawl. If the budget wins, we get
  // an empty array — but settled results from `all` may still arrive; we
  // discard them.
  const outcomes = await Promise.race([all, budget]);

  const resources: CrawledResource[] = [];
  const bodies: Record<string, string> = {};
  for (const o of outcomes) {
    resources.push(o.resource);
    if (o.body !== undefined) {
      const u = new URL(o.resource.url);
      bodies[u.pathname] = o.body;
    }
  }
  return { resources, bodies };
}
