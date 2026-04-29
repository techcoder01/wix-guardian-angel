export type ScanErrorCode =
  | "invalid_url"
  | "blocked_target"
  | "rate_limited"
  | "timeout"
  | "network"
  | "tls"
  | "internal";

export class ScannerError extends Error {
  readonly code: ScanErrorCode;
  readonly retryAfterMs?: number;
  constructor(code: ScanErrorCode, message: string, retryAfterMs?: number) {
    super(message);
    this.name = "ScannerError";
    this.code = code;
    this.retryAfterMs = retryAfterMs;
  }
}

/**
 * Map an unknown error into a user-friendly message + code. Used by both the
 * server function (to render a stable error shape) and the UI (to pick the
 * right hint).
 */
export function classifyScanError(e: unknown): {
  code: ScanErrorCode;
  message: string;
} {
  if (e instanceof ScannerError) {
    return { code: e.code, message: e.message };
  }
  // Recognise raw AbortError objects (DOM AbortController surfaces these).
  if (
    typeof e === "object" &&
    e !== null &&
    "name" in e &&
    (e as { name?: unknown }).name === "AbortError"
  ) {
    return {
      code: "timeout",
      message: "Scan timed out — the target may be slow or unreachable.",
    };
  }
  const raw = e instanceof Error ? e.message : String(e ?? "Scan failed");
  const lower = raw.toLowerCase();
  if (/timed out|timeout|aborterror/.test(lower))
    return {
      code: "timeout",
      message: "Scan timed out — the target may be slow or unreachable.",
    };
  if (/rate limit/.test(lower)) return { code: "rate_limited", message: raw };
  if (
    /private|loopback|reserved|internal|metadata|not permitted/i.test(lower)
  )
    return { code: "blocked_target", message: raw };
  if (/only http|could not be parsed|invalid url/.test(lower))
    return { code: "invalid_url", message: raw };
  if (/certificate|ssl|tls/.test(lower))
    return {
      code: "tls",
      message: "TLS / certificate error connecting to the target.",
    };
  if (/fetch|network|dns|connect|socket/.test(lower))
    return {
      code: "network",
      message: "Network error — check the URL and try again.",
    };
  return { code: "internal", message: raw || "Scan failed." };
}
