/** Scanner tuning constants — change these instead of hunting for magic numbers. */
export const SCAN_TIMEOUT_MS = 15_000;
export const HSTS_MIN_AGE_SECONDS = 15_552_000; // 6 months
export const HTML_BODY_CAP_BYTES = 800_000;
export const MAX_URL_LENGTH = 2_048;
export const MIN_URL_LENGTH = 3;
export const EVIDENCE_TRUNCATE_LENGTH = 160;

/** Rate-limiting: max scans per IP per window. */
export const RATE_LIMIT_MAX_REQUESTS = 10;
export const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
export const RATE_LIMIT_PER_HOST_MAX = 6;

/** Crawler tuning. */
export const CRAWL_PER_REQUEST_TIMEOUT_MS = 5_000;
export const CRAWL_TOTAL_BUDGET_MS = 12_000;

/** CVE intelligence cache TTL. */
export const CVE_CACHE_TTL_SECONDS = 24 * 60 * 60;
