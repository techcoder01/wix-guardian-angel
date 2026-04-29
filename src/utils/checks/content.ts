import type { Finding } from "@/lib/scanner-types";
import { fixOwnerFor } from "./transport";

/** Escapes a string for safe use as a literal pattern inside `new RegExp(...)`. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function checkContent(html: string, finalUrl: string, isWix: boolean): Finding[] {
  const f: Finding[] = [];
  const isHttps = finalUrl.startsWith("https://");

  // Mixed content
  if (isHttps) {
    const mixed = html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi) ?? [];
    const filtered = mixed.filter((m) => !/http:\/\/(www\.)?w3\.org/i.test(m));
    if (filtered.length > 0) {
      f.push({
        id: "mixed-content",
        title: "Mixed content: HTTP resources loaded on HTTPS page",
        category: "content",
        severity: "medium",
        description: `${filtered.length} resource reference(s) use http:// on an https:// page. Browsers may block these or expose users to MITM.`,
        evidence: filtered.slice(0, 3).join("\n"),
        remediation:
          "Update references to use https:// or protocol-relative URLs.",
        fixOwner: fixOwnerFor("content", isWix),
      });
    }
  }

  // Forms over HTTP
  const formMatches = html.match(/<form\b[^>]*>/gi) ?? [];
  for (const form of formMatches) {
    const action = form.match(/action\s*=\s*["']([^"']+)["']/i)?.[1] ?? "";
    if (action.startsWith("http://")) {
      f.push({
        id: "form-insecure-action",
        title: "Form submits to an insecure (HTTP) endpoint",
        category: "forms",
        severity: "high",
        description:
          "Form data including credentials or PII would be transmitted in plaintext.",
        evidence: form.slice(0, 200),
        remediation: "Change the form action to use HTTPS.",
        fixOwner: fixOwnerFor("forms", isWix),
      });
    }
  }

  // Exposed email addresses (passive PII surface)
  const emails = Array.from(
    new Set(
      (html.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) ?? []).filter(
        (e) => !/\.(png|jpg|svg|webp)$/i.test(e),
      ),
    ),
  );
  if (emails.length > 0) {
    f.push({
      id: "exposed-emails",
      title: "Email addresses exposed in page source",
      category: "information_disclosure",
      severity: "info",
      description: `${emails.length} email address(es) found in the HTML, which can be harvested by spam bots.`,
      evidence: emails.slice(0, 5).join(", "),
      remediation:
        "Use a contact form or obfuscate addresses (mailto handlers via JS, image fallbacks).",
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

  // Suspicious HTML comments
  const comments = html.match(/<!--[\s\S]*?-->/g) ?? [];
  const suspect = comments.filter((c) =>
    /todo|fixme|password|secret|api[_-]?key|debug/i.test(c),
  );
  if (suspect.length > 0) {
    f.push({
      id: "suspicious-comments",
      title: "Suspicious HTML comments in page source",
      category: "information_disclosure",
      severity: "low",
      description:
        "HTML comments may contain developer notes, credentials, or debug info.",
      evidence: suspect
        .slice(0, 3)
        .map((s) => s.slice(0, 120))
        .join("\n"),
      remediation: "Strip comments from production HTML.",
      fixOwner: fixOwnerFor("content", isWix),
    });
  }

  // Third-party scripts without SRI
  const scripts = Array.from(
    html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi),
  ).map((m) => m[1]);
  const hosts = new Set<string>();
  for (const s of scripts) {
    try {
      const h = new URL(s, finalUrl).hostname;
      if (!finalUrl.includes(h)) hosts.add(h);
    } catch {
      /* ignore unparseable src values */
    }
  }
  if (hosts.size > 0) {
    const noSri = scripts
      .filter((s) => /^https?:\/\//.test(s))
      .filter((s) => {
        const escaped = escapeRegExp(s);
        const tag = html.match(
          new RegExp(
            `<script[^>]+src\\s*=\\s*["']${escaped}["'][^>]*>`,
            "i",
          ),
        );
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
      reference:
        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    });
  }

  // Directory listing
  if (/<title>\s*Index of \//i.test(html)) {
    f.push({
      id: "directory-listing",
      title: "Directory listing appears enabled",
      category: "configuration",
      severity: "medium",
      description:
        "Auto-generated directory index detected; may expose internal files.",
      remediation: "Disable directory listing on the web server.",
      fixOwner: fixOwnerFor("configuration", isWix),
    });
  }

  return f;
}
