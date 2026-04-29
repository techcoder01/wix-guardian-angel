import type { Remediation } from "@/lib/scanner-types";

/**
 * Remediation registry. Keyed by `Finding.id`. Centralised so that copy can be
 * audited, translated, and tested independently of detection logic.
 *
 * Each entry is a self-contained playbook: summary, ordered owner-tagged steps,
 * optional code snippets and Wix dashboard click-paths, references and effort.
 *
 * When adding a new check that emits a Finding, add a matching entry here.
 * The vitest suite asserts every emitted Finding ID has a registry entry.
 */

const REGISTRY: Record<string, Remediation> = {
  // -------------------------------------------------------------------------
  // Headers
  // -------------------------------------------------------------------------
  "missing-hsts": {
    summary:
      "Tell browsers to use HTTPS only by enabling Strict-Transport-Security.",
    estimatedEffort: "platform_dependent",
    wixDashboardPath:
      "Wix Dashboard → Settings → Advanced → Custom Code (or Domains → SSL)",
    steps: [
      {
        owner: "wix_platform",
        action: "Wix-managed: HSTS is set automatically once SSL is active.",
        details:
          "If you connected a custom domain, confirm SSL status is 'Enabled' in Domains. New custom domains can take 24h before HSTS appears.",
      },
      {
        owner: "site_owner",
        action: "Verify HSTS is present on a live request to your domain.",
        details:
          "Run `curl -sI https://your-domain.com | grep -i strict-transport-security`. The header should include max-age=31536000 and includeSubDomains.",
      },
      {
        owner: "site_owner",
        action: "If self-hosted: configure your reverse proxy / CDN.",
      },
    ],
    codeSnippets: [
      {
        label: "Nginx",
        language: "nginx",
        code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      },
      {
        label: "Cloudflare Worker",
        language: "ts",
        code: `response.headers.set(
  "Strict-Transport-Security",
  "max-age=31536000; includeSubDomains; preload",
);`,
      },
    ],
    references: [
      {
        title: "MDN: Strict-Transport-Security",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
      },
      {
        title: "HSTS Preload list",
        url: "https://hstspreload.org/",
      },
    ],
  },

  "weak-hsts": {
    summary:
      "HSTS is set but max-age is too short. Browsers may downgrade if the cache expires.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Increase max-age to at least 15552000 (6 months).",
        details:
          "Production sites should use 31536000 (1 year) and includeSubDomains. Add 'preload' and submit to hstspreload.org once confident.",
      },
    ],
    codeSnippets: [
      {
        label: "Recommended header",
        language: "http",
        code: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      },
    ],
    references: [
      {
        title: "MDN: Strict-Transport-Security",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
      },
    ],
  },

  "missing-csp": {
    summary:
      "Define a Content-Security-Policy to mitigate XSS and data injection.",
    estimatedEffort: "platform_dependent",
    wixDashboardPath:
      "Wix Dashboard → Settings → Custom Code → Add Custom Code (Head)",
    steps: [
      {
        owner: "wix_platform",
        action:
          "Wix does not currently expose a custom CSP header. This is a known platform limitation.",
        details:
          "Track the Wix Velo roadmap. Until then, the platform CSP is what ships.",
      },
      {
        owner: "site_owner",
        action:
          "Optional: add a meta-tag CSP via Custom Code as a partial mitigation.",
        details:
          "Meta-tag CSP cannot use `frame-ancestors` or `report-uri` but can still restrict scripts. Test thoroughly — Wix runtime needs broad allowances.",
      },
      {
        owner: "site_owner",
        action: "If self-hosted: configure CSP at the server / edge.",
      },
    ],
    codeSnippets: [
      {
        label: "Strict starting CSP (server-set)",
        language: "http",
        code: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'`,
      },
      {
        label: "Meta tag (Wix Custom Code, head)",
        language: "html",
        code: `<meta http-equiv="Content-Security-Policy"
      content="default-src 'self' https:; script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:;">`,
      },
    ],
    references: [
      { title: "MDN: CSP", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" },
      { title: "OWASP CSP Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html" },
    ],
  },

  "missing-xcto": {
    summary: "Set X-Content-Type-Options: nosniff to disable MIME sniffing.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Add the header at your edge / reverse proxy / framework.",
      },
    ],
    codeSnippets: [
      {
        label: "Header",
        language: "http",
        code: "X-Content-Type-Options: nosniff",
      },
    ],
    references: [
      {
        title: "MDN: X-Content-Type-Options",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
      },
    ],
  },

  "missing-frame-protection": {
    summary:
      "Block clickjacking by setting X-Frame-Options or CSP frame-ancestors.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Set X-Frame-Options: SAMEORIGIN (legacy) and frame-ancestors in CSP (modern).",
        details:
          "Modern browsers prefer CSP frame-ancestors. Set both for compatibility unless you know your audience.",
      },
    ],
    codeSnippets: [
      {
        label: "Headers",
        language: "http",
        code: `X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'`,
      },
    ],
    references: [
      {
        title: "OWASP Clickjacking Defence",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
      },
    ],
  },

  "missing-referrer-policy": {
    summary:
      "Set a Referrer-Policy to avoid leaking full URLs (with query parameters) to third parties.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Use 'strict-origin-when-cross-origin' as a sensible default.",
      },
    ],
    codeSnippets: [
      {
        label: "Header",
        language: "http",
        code: "Referrer-Policy: strict-origin-when-cross-origin",
      },
    ],
    references: [
      {
        title: "MDN: Referrer-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
      },
    ],
  },

  "missing-permissions-policy": {
    summary:
      "Use Permissions-Policy to disable powerful browser features the site does not need.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Deny features by default; enable only what's required.",
      },
    ],
    codeSnippets: [
      {
        label: "Restrictive default",
        language: "http",
        code: "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
      },
    ],
    references: [
      {
        title: "MDN: Permissions-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
      },
    ],
  },

  "x-powered-by": {
    summary: "Strip the X-Powered-By header to avoid leaking the stack.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Disable the header at the framework or proxy layer.",
        details:
          "Express: app.disable('x-powered-by'). Nginx: proxy_hide_header X-Powered-By. PHP: expose_php=Off in php.ini.",
      },
    ],
    codeSnippets: [
      {
        label: "Express",
        language: "ts",
        code: "app.disable('x-powered-by');",
      },
      {
        label: "Nginx",
        language: "nginx",
        code: "proxy_hide_header X-Powered-By;",
      },
    ],
    references: [
      {
        title: "OWASP: information disclosure",
        url: "https://owasp.org/www-project-secure-headers/",
      },
    ],
  },

  "server-version": {
    summary: "Strip version detail from the Server header.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Configure your server to omit version numbers.",
        details:
          "Nginx: server_tokens off. Apache: ServerTokens Prod / ServerSignature Off.",
      },
    ],
    codeSnippets: [
      {
        label: "Nginx",
        language: "nginx",
        code: "server_tokens off;",
      },
      {
        label: "Apache",
        language: "apache",
        code: "ServerTokens Prod\nServerSignature Off",
      },
    ],
    references: [
      {
        title: "OWASP Secure Headers",
        url: "https://owasp.org/www-project-secure-headers/",
      },
    ],
  },

  // -------------------------------------------------------------------------
  // Cookies (parameterised — see getRemediation())
  // -------------------------------------------------------------------------
  "cookie-no-secure": {
    summary:
      "Cookies set on HTTPS responses must have the Secure attribute.",
    estimatedEffort: "platform_dependent",
    steps: [
      {
        owner: "wix_platform",
        action: "Wix-managed cookies: the platform sets these flags. No site-owner action.",
      },
      {
        owner: "site_owner",
        action: "If you set cookies via Velo / custom backend, add Secure.",
      },
    ],
    codeSnippets: [
      {
        label: "Set-Cookie",
        language: "http",
        code: "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax; Path=/",
      },
    ],
    references: [
      {
        title: "MDN: Set-Cookie Secure attribute",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure",
      },
    ],
  },

  "cookie-no-httponly": {
    summary:
      "Mark session cookies HttpOnly so XSS cannot read them via document.cookie.",
    estimatedEffort: "platform_dependent",
    steps: [
      {
        owner: "wix_platform",
        action: "Wix session cookies: managed by the platform.",
      },
      {
        owner: "site_owner",
        action: "Custom cookies you set in Velo / backends must use HttpOnly.",
      },
    ],
    codeSnippets: [
      {
        label: "Set-Cookie",
        language: "http",
        code: "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax",
      },
    ],
    references: [
      {
        title: "OWASP: HttpOnly",
        url: "https://owasp.org/www-community/HttpOnly",
      },
    ],
  },

  "cookie-no-samesite": {
    summary: "Set SameSite=Lax (or Strict) to reduce CSRF exposure.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Default to SameSite=Lax. Use Strict for highly sensitive flows.",
      },
    ],
    codeSnippets: [
      {
        label: "Set-Cookie",
        language: "http",
        code: "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax",
      },
    ],
    references: [
      {
        title: "MDN: SameSite",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",
      },
    ],
  },

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------
  "no-https": {
    summary: "Force HTTPS via redirect and enable HSTS.",
    estimatedEffort: "hours",
    steps: [
      {
        owner: "site_owner",
        action: "Issue a 301 redirect from http:// to https:// at your edge.",
      },
      {
        owner: "site_owner",
        action: "Enable HSTS (see missing-hsts) once HTTPS is the only path.",
      },
    ],
    codeSnippets: [
      {
        label: "Nginx redirect",
        language: "nginx",
        code: `server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}`,
      },
    ],
    references: [
      {
        title: "Let's Encrypt — getting started",
        url: "https://letsencrypt.org/getting-started/",
      },
    ],
  },

  // -------------------------------------------------------------------------
  // Content
  // -------------------------------------------------------------------------
  "mixed-content": {
    summary:
      "Replace http:// asset references with https:// (or protocol-relative).",
    estimatedEffort: "hours",
    steps: [
      {
        owner: "site_owner",
        action: "Find every offending tag in the page source.",
        details:
          "Search the rendered HTML for `http://` in `src=` and `href=`. Most modern CDNs serve over HTTPS — usually a search-and-replace.",
      },
      {
        owner: "site_owner",
        action: "If a third party only serves over HTTP, drop or self-host the asset.",
      },
    ],
    references: [
      {
        title: "MDN: Mixed content",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
      },
    ],
  },

  "form-insecure-action": {
    summary: "Change the form action to use HTTPS.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Update the action attribute on the affected <form>.",
      },
      {
        owner: "site_owner",
        action: "Confirm the receiving endpoint serves HTTPS with a valid certificate.",
      },
    ],
    references: [
      {
        title: "OWASP Forms",
        url: "https://owasp.org/www-community/vulnerabilities/Insecure_Transport",
      },
    ],
  },

  "exposed-emails": {
    summary:
      "Hide raw email addresses to reduce spam-bot harvesting.",
    estimatedEffort: "hours",
    wixDashboardPath:
      "Wix Editor → Add → Contact & Forms → Wix Forms (replace mailto with a form)",
    steps: [
      {
        owner: "site_owner",
        action: "Replace plaintext mailto links with a Wix Form or contact widget.",
      },
      {
        owner: "site_owner",
        action: "If a mailto must remain, render it via JavaScript or use an image.",
      },
    ],
    codeSnippets: [
      {
        label: "JS-rendered mailto (HTML / vanilla JS)",
        language: "html",
        code: `<span data-user="hello" data-domain="example.com" class="email-link"></span>
<script>
document.querySelectorAll('.email-link').forEach(el => {
  const a = document.createElement('a');
  a.href = 'mailto:' + el.dataset.user + '@' + el.dataset.domain;
  a.textContent = el.dataset.user + '@' + el.dataset.domain;
  el.replaceWith(a);
});
</script>`,
      },
    ],
    references: [
      {
        title: "OWASP — input validation",
        url: "https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet.html",
      },
    ],
  },

  "sourcemap-reference": {
    summary: "Disable source maps in production or restrict their access.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Build with source maps disabled, or upload them to your error tracker only.",
      },
      {
        owner: "site_owner",
        action: "If maps must be served, restrict to authenticated origins.",
      },
    ],
    codeSnippets: [
      {
        label: "Vite",
        language: "ts",
        code: `// vite.config.ts
export default defineConfig({
  build: { sourcemap: false }, // or 'hidden' to keep them but not reference
});`,
      },
    ],
    references: [
      {
        title: "Vite build options",
        url: "https://vitejs.dev/config/build-options.html#build-sourcemap",
      },
    ],
  },

  "suspicious-comments": {
    summary: "Strip developer comments from production HTML.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Configure your build / templating engine to remove HTML comments in production.",
      },
    ],
    codeSnippets: [
      {
        label: "html-minifier-terser",
        language: "ts",
        code: `import { minify } from 'html-minifier-terser';
await minify(html, { removeComments: true });`,
      },
    ],
    references: [
      {
        title: "OWASP — information leakage",
        url: "https://owasp.org/www-community/vulnerabilities/Information_disclosure_in_HTML_comments",
      },
    ],
  },

  "third-party-scripts": {
    summary:
      "Audit external scripts and add Subresource Integrity (SRI) where possible.",
    estimatedEffort: "hours",
    steps: [
      {
        owner: "site_owner",
        action: "Inventory every external script and remove anything unused.",
      },
      {
        owner: "third_party",
        action: "For pinned versions, generate an SRI hash and add integrity + crossorigin.",
        details:
          "Wix-injected platform scripts cannot have SRI added by the site owner — flag and accept the platform risk.",
      },
    ],
    codeSnippets: [
      {
        label: "Generate SRI hash (bash)",
        language: "bash",
        code: `curl -s https://cdn.example.com/lib.js \\
  | openssl dgst -sha384 -binary \\
  | openssl base64 -A`,
      },
      {
        label: "Script tag with SRI",
        language: "html",
        code: `<script src="https://cdn.example.com/lib.js"
  integrity="sha384-..."
  crossorigin="anonymous"></script>`,
      },
    ],
    references: [
      {
        title: "MDN: Subresource Integrity",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
      },
    ],
  },

  "directory-listing": {
    summary: "Disable directory listing on the web server.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Turn off auto-index at the server or edge.",
      },
    ],
    codeSnippets: [
      {
        label: "Nginx",
        language: "nginx",
        code: "autoindex off;",
      },
      {
        label: "Apache",
        language: "apache",
        code: "Options -Indexes",
      },
    ],
    references: [
      {
        title: "OWASP — directory indexing",
        url: "https://owasp.org/www-community/Improper_Access_Control",
      },
    ],
  },

  // -------------------------------------------------------------------------
  // Wix-specific (Phase 3)
  // -------------------------------------------------------------------------
  "wix-platform-context": {
    summary:
      "Identify what is and is not within your control as a Wix site owner.",
    estimatedEffort: "minutes",
    wixDashboardPath: "Wix Dashboard → Settings",
    steps: [
      {
        owner: "shared",
        action: "Headers, cookies, HSTS and CSP are set by the Wix platform.",
        details:
          "You cannot customise these. Findings in those categories are labelled 'wix_platform' — they are platform risks you accept.",
      },
      {
        owner: "site_owner",
        action: "Focus on what you can change: dashboard hardening, content hygiene, third-party embeds.",
      },
      {
        owner: "site_owner",
        action: "Enable 2FA on the Wix account (Wix Dashboard → Account Security).",
      },
    ],
    references: [
      {
        title: "Wix Trust Center",
        url: "https://www.wix.com/trust-center",
      },
    ],
  },

  "wix-velo-functions-exposed": {
    summary:
      "A Velo backend function (_functions/...) is reachable without authentication.",
    estimatedEffort: "hours",
    wixDashboardPath:
      "Wix Editor → Code Files → backend / http-functions.js",
    steps: [
      {
        owner: "site_owner",
        action: "Open the http-functions file containing the named handler.",
      },
      {
        owner: "site_owner",
        action: "Wrap the function body in an authentication check.",
        details:
          "Use wix-users-backend.currentUser to require a member, or check a shared secret header for service-to-service calls.",
      },
      {
        owner: "site_owner",
        action: "Validate every incoming parameter and return only what's needed.",
      },
    ],
    codeSnippets: [
      {
        label: "Authenticated http-function (Velo)",
        language: "ts",
        code: `// backend/http-functions.js
import { ok, forbidden, badRequest } from 'wix-http-functions';
import { currentUser } from 'wix-users-backend';

export async function get_secret(request) {
  const user = currentUser;
  if (!user.loggedIn) return forbidden({ body: 'auth required' });
  // ... actual logic
  return ok({ body: { ok: true } });
}`,
      },
    ],
    references: [
      {
        title: "Velo: HTTP Functions",
        url: "https://www.wix.com/velo/reference/wix-http-functions",
      },
      {
        title: "Velo: wix-users-backend",
        url: "https://www.wix.com/velo/reference/wix-users-backend",
      },
    ],
  },

  "wix-data-collection-exposed": {
    summary:
      "A Wix Data (CMS) collection appears readable from the public internet.",
    estimatedEffort: "minutes",
    wixDashboardPath:
      "Wix CMS → Collection → Permissions",
    steps: [
      {
        owner: "site_owner",
        action: "Open the affected collection in the Wix CMS.",
      },
      {
        owner: "site_owner",
        action: "Set 'Who can read content?' to 'Site member' or 'Admin' as appropriate.",
        details:
          "Public read is correct only for genuinely public content (blog posts, products). Default to least-privilege.",
      },
      {
        owner: "site_owner",
        action: "Restrict write/update/delete to Admin unless a Velo backend mediates writes.",
      },
    ],
    references: [
      {
        title: "Wix CMS: Collection permissions",
        url: "https://support.wix.com/en/article/wix-cms-formerly-content-manager-setting-collection-permissions-and-privacy",
      },
    ],
  },

  "wix-members-area-exposed": {
    summary:
      "Public Wix Members API surface detected. Profile data may be enumerable.",
    estimatedEffort: "hours",
    wixDashboardPath:
      "Wix Dashboard → Members → Privacy Settings",
    steps: [
      {
        owner: "site_owner",
        action: "In Members → Privacy, set member profiles to private by default.",
      },
      {
        owner: "site_owner",
        action: "Disable any member listing or directory pages that are not strictly required.",
      },
    ],
    references: [
      {
        title: "Wix Members Privacy",
        url: "https://support.wix.com/en/article/wix-members-area-managing-the-privacy-of-your-members-area",
      },
    ],
  },

  "wix-bi-session-leak": {
    summary:
      "Wix runtime metadata (metaSiteId / userId / viewerSessionId) is embedded in the HTML.",
    estimatedEffort: "platform_dependent",
    steps: [
      {
        owner: "wix_platform",
        action: "Inline runtime data is a Wix platform behaviour and cannot be removed by site owners.",
      },
      {
        owner: "site_owner",
        action: "Awareness only: do not store secrets in inline JSON, page source or page-level state.",
        details:
          "Treat the inline JSON as world-readable. Anything in it is effectively public. Move secrets to backend/Velo and never reflect them into pages.",
      },
    ],
    references: [
      {
        title: "Wix Trust Center — data handling",
        url: "https://www.wix.com/trust-center",
      },
    ],
  },

  "wix-form-pii-no-captcha": {
    summary:
      "A Wix Form collects sensitive PII without visible bot/spam protection.",
    estimatedEffort: "minutes",
    wixDashboardPath:
      "Wix Editor → Form → Settings → Form Submissions / CAPTCHA",
    steps: [
      {
        owner: "site_owner",
        action: "Enable CAPTCHA on the form (Form settings → CAPTCHA).",
      },
      {
        owner: "site_owner",
        action: "Restrict submission rate via Wix Forms anti-spam toggles.",
      },
      {
        owner: "site_owner",
        action: "Review whether PII fields are necessary; remove what isn't.",
      },
    ],
    references: [
      {
        title: "Wix Forms CAPTCHA",
        url: "https://support.wix.com/en/article/wix-forms-adding-a-captcha-to-your-form",
      },
    ],
  },

  "wix-dashboard-url-leak": {
    summary:
      "Internal Wix dashboard or editor URLs appear in the public HTML.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Find and remove the offending references from the page or component.",
        details:
          "Common cause: copy-pasted preview links from the editor. Often appears in hand-coded HTML embeds.",
      },
    ],
    references: [
      {
        title: "Information disclosure (OWASP)",
        url: "https://owasp.org/www-community/vulnerabilities/Information_disclosure",
      },
    ],
  },

  "wix-iframe-no-sandbox": {
    summary:
      "An <iframe> embed lacks a sandbox attribute, expanding the attack surface.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Add a restrictive sandbox to every untrusted iframe.",
      },
    ],
    codeSnippets: [
      {
        label: "Sandboxed iframe",
        language: "html",
        code: `<iframe src="https://embed.example.com"
  sandbox="allow-scripts allow-same-origin"
  loading="lazy"
  referrerpolicy="no-referrer"></iframe>`,
      },
    ],
    references: [
      {
        title: "MDN: iframe sandbox",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox",
      },
    ],
  },

  "wix-inline-secret": {
    summary:
      "An inline script appears to expose an API key, token or secret.",
    estimatedEffort: "hours",
    steps: [
      {
        owner: "site_owner",
        action: "Rotate the exposed credential immediately.",
      },
      {
        owner: "site_owner",
        action: "Move the secret to a Velo backend / wix-secrets-backend and never reflect it into HTML.",
      },
    ],
    codeSnippets: [
      {
        label: "Velo secrets",
        language: "ts",
        code: `// backend/secrets.js
import { getSecret } from 'wix-secrets-backend';
export async function getApiKey() {
  return await getSecret('thirdPartyApiKey');
}`,
      },
    ],
    references: [
      {
        title: "Velo Secrets",
        url: "https://www.wix.com/velo/reference/wix-secrets-backend",
      },
    ],
  },

  "wix-security-txt-missing": {
    summary:
      "No /.well-known/security.txt published. Security researchers have no disclosure path.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Publish a security.txt file at /.well-known/security.txt.",
        details:
          "On Wix, this often requires a custom file route (Velo HTTP Functions or a proxy) since static files at well-known paths aren't directly exposed.",
      },
    ],
    codeSnippets: [
      {
        label: "security.txt",
        language: "text",
        code: `Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt`,
      },
      {
        label: "Velo HTTP function (serve security.txt)",
        language: "ts",
        code: `// backend/http-functions.js
import { ok } from 'wix-http-functions';
export function get_securityTxt() {
  return ok({
    headers: { 'Content-Type': 'text/plain' },
    body: \`Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Canonical: https://example.com/_functions/securityTxt\`,
  });
}`,
      },
    ],
    references: [
      {
        title: "RFC 9116 (security.txt)",
        url: "https://www.rfc-editor.org/rfc/rfc9116",
      },
    ],
  },

  "robots-disallow-secret-paths": {
    summary:
      "robots.txt references paths that hint at admin or hidden content.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Do not use robots.txt to hide secret paths — it advertises them.",
        details:
          "Move sensitive endpoints behind authentication. Use noindex meta tags or proper auth instead.",
      },
    ],
    references: [
      {
        title: "Google: robots.txt is not a security control",
        url: "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
      },
    ],
  },

  "sitemap-exposes-private-pages": {
    summary:
      "sitemap.xml lists pages that look private or staging.",
    estimatedEffort: "minutes",
    steps: [
      {
        owner: "site_owner",
        action: "Either remove the pages from the sitemap or properly restrict them.",
      },
    ],
    references: [
      {
        title: "sitemaps.org",
        url: "https://www.sitemaps.org/protocol.html",
      },
    ],
  },

  "third-party-cve": {
    summary:
      "A third-party script identifies a library version with known CVEs.",
    estimatedEffort: "hours",
    steps: [
      {
        owner: "site_owner",
        action: "Upgrade the library to the patched version listed in the CVE record.",
      },
      {
        owner: "third_party",
        action: "If the CDN serves the version unpatched, switch CDN or self-host.",
      },
    ],
    references: [
      {
        title: "OSV.dev",
        url: "https://osv.dev/",
      },
    ],
  },
};

/**
 * Fetch a remediation playbook by ID. Returns a generic fallback when the ID
 * has no entry — keeps the UI functional even if a check is added without a
 * matching registry update (a vitest test catches this in CI).
 */
export function getRemediation(
  id: string,
  fallbackSummary: string,
): Remediation {
  // Cookie findings encode the cookie name in the id, so strip the suffix.
  const normalised = id
    .replace(/^cookie-no-secure-.+$/, "cookie-no-secure")
    .replace(/^cookie-no-httponly-.+$/, "cookie-no-httponly")
    .replace(/^cookie-no-samesite-.+$/, "cookie-no-samesite");

  const hit = REGISTRY[normalised];
  if (hit) return hit;

  return {
    summary: fallbackSummary,
    estimatedEffort: "platform_dependent",
    steps: [{ owner: "site_owner", action: fallbackSummary }],
    references: [],
  };
}

export function listRegistryIds(): string[] {
  return Object.keys(REGISTRY);
}
