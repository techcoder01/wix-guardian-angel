import type { Finding } from "@/lib/scanner-types";
import { HSTS_MIN_AGE_SECONDS } from "@/lib/constants";
import { fixOwnerFor } from "./transport";

export function checkHeaders(h: Record<string, string>, isWix: boolean): Finding[] {
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
      reference:
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    });
  } else {
    const v = get("strict-transport-security")!;
    const m = v.match(/max-age=(\d+)/i);
    const age = m ? parseInt(m[1], 10) : 0;
    if (age < HSTS_MIN_AGE_SECONDS) {
      f.push({
        id: "weak-hsts",
        title: "HSTS max-age below recommended threshold",
        category: "headers",
        severity: "medium",
        description: `HSTS is set but max-age=${age}s is shorter than the recommended 6 months (${HSTS_MIN_AGE_SECONDS}s).`,
        evidence: v,
        remediation:
          "Increase max-age to at least 15552000 and include 'includeSubDomains'.",
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
      description:
        "Without 'nosniff', browsers may MIME-sniff responses, enabling some XSS variants.",
      remediation: "Set 'X-Content-Type-Options: nosniff'.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  const xfo = get("x-frame-options");
  const csp = get("content-security-policy") ?? "";
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    f.push({
      id: "missing-frame-protection",
      title: "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
      category: "headers",
      severity: "medium",
      description: "The site can be embedded in a frame, enabling clickjacking attacks.",
      remediation:
        "Set 'X-Frame-Options: SAMEORIGIN' or a CSP 'frame-ancestors' directive.",
      fixOwner: fixOwnerFor("headers", isWix),
    });
  }

  if (!get("referrer-policy")) {
    f.push({
      id: "missing-referrer-policy",
      title: "Missing Referrer-Policy header",
      category: "headers",
      severity: "low",
      description:
        "Without a referrer policy, full URLs (with query parameters) may leak to third parties.",
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
      description:
        "Permissions-Policy lets you disable powerful browser features (camera, geolocation, etc.).",
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
