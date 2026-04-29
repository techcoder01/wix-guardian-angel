import type { Finding } from "@/lib/scanner-types";
import { EVIDENCE_TRUNCATE_LENGTH } from "@/lib/constants";
import { fixOwnerFor } from "./transport";

export function checkCookies(setCookieValues: string[], isWix: boolean): Finding[] {
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
        description:
          "Cookies without Secure can be transmitted over plaintext HTTP.",
        evidence: c.slice(0, EVIDENCE_TRUNCATE_LENGTH),
        remediation:
          "Add the 'Secure' attribute to every cookie set on HTTPS responses.",
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
        evidence: c.slice(0, EVIDENCE_TRUNCATE_LENGTH),
        remediation:
          "Add the 'HttpOnly' attribute, especially for session cookies.",
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
        evidence: c.slice(0, EVIDENCE_TRUNCATE_LENGTH),
        remediation:
          "Set 'SameSite=Lax' or 'SameSite=Strict' as appropriate.",
        fixOwner: fixOwnerFor("cookies", isWix),
      });
    }
  }
  return f;
}
