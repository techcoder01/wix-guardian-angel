# WixSecAudit — Passive Security Auditor for Low-Code Sites

A black-box passive security scanner purpose-built for Wix-hosted and other low-code websites. Built as a dissertation prototype.

> **Full dissertation report:** [`docs/REPORT.md`](docs/REPORT.md) — abstract, methodology, detection catalogue, fix-owner taxonomy, evaluation, case studies, OWASP/CWE mapping.

---

## What it does

- **Single passive HTTP audit** of a public URL (no active probing, no credentials).
- **Bounded passive crawl**: `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, six common Velo paths (HEAD only).
- **19 detection rules** across six modules (transport, headers, cookies, content, Wix-specific, third-party CVE).
- **Structured remediation playbooks** per finding: ordered owner-tagged steps, copyable code snippets, Wix dashboard click-paths, references, effort estimate.
- **Fix-owner taxonomy**: every finding labelled `site_owner`, `wix_platform`, `third_party`, or `shared` — so the owner sees what *they* can fix instead of triaging platform behaviours they cannot control.
- **Validation/retest** with diff (resolved / new / unchanged) against prior scans.
- **JSON export** — machine-readable evidence suitable for dissertation case studies.
- **Wix-aware deep checks**: Velo function exposure, CMS collection leaks, Members API surface, runtime metadata leak, Wix Forms PII without CAPTCHA, dashboard URL leak, inline secrets, security.txt absence, robots.txt anti-patterns, sitemap.xml leakage.
- **Third-party CVE intelligence** via OSV.dev for CDN-hosted libraries (jsDelivr, unpkg, cdnjs).

---

## What it scans

| Category | Checks |
|---|---|
| **Transport** | HTTP → HTTPS enforcement |
| **Headers** | HSTS (presence + min age), CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, Permissions-Policy, server/technology disclosure |
| **Cookies** | Secure, HttpOnly, SameSite — per cookie, with session-cookie heuristic |
| **Content** | Mixed content, HTTP form actions, exposed emails, source-map references, suspicious comments, directory listing, third-party SRI |
| **Wix-specific** | Velo `_functions/*` exposure, CMS collection IDs, Members API, runtime metadata, Wix Forms CAPTCHA, dashboard URL leaks, iframe sandbox, inline secrets, security.txt, robots.txt anti-patterns, sitemap leakage |
| **Third-party** | CVE lookup against detected CDN-hosted library versions (OSV.dev) |

---

## Fix-owner taxonomy

Every finding carries one of:

| Label | Meaning |
|---|---|
| `site_owner` | Fixable in the Wix dashboard or site code |
| `wix_platform` | Controlled by Wix infrastructure; owner cannot change it |
| `third_party` | Requires action with an external service / CDN |
| `shared` | Responsibility is split |

This is the dissertation's primary original contribution — see [`docs/REPORT.md` §8](docs/REPORT.md#8-fix-owner-taxonomy-original-contribution).

---

## Quick start

```bash
npm install
npm run dev               # http://localhost:3000
npm test                  # 109 tests
npm run test:coverage     # 80% line/function/statement, 75% branch
npm run build
npx wrangler deploy       # Cloudflare Workers
```

Optional KV-backed rate limit: uncomment the `kv_namespaces` block in [`wrangler.jsonc`](wrangler.jsonc) and create the namespace with `npx wrangler kv:namespace create RATE_LIMIT_KV`.

---

## Project structure

```
src/
├── lib/
│   ├── scanner-types.ts       Finding, ScanResult, Remediation, FixOwner
│   ├── constants.ts           Timeouts, thresholds, rate-limit caps
│   ├── diff.ts                Scan-to-scan delta
│   ├── errors.ts              ScannerError + classifyScanError
│   └── remediation/
│       ├── registry.ts        Per-finding remediation playbooks
│       └── attach.ts          Hydrates findings with remediation detail
├── utils/
│   ├── scanner.functions.ts   Server fn: SSRF guard, rate limit, orchestration
│   ├── crawler.ts             Bounded passive crawl
│   ├── rate-limit.ts          Two-tier IP+host limiter, KV-aware
│   └── checks/
│       ├── transport.ts       HTTPS enforcement + fixOwnerFor helper
│       ├── headers.ts
│       ├── cookies.ts
│       ├── content.ts
│       ├── wix.ts             11 Wix-specific deep checks
│       └── cve.ts             OSV.dev CVE intelligence
├── components/
│   ├── FindingCard.tsx        Expandable card with full remediation playbook
│   ├── ScanSummary.tsx        Severity bars, fix-owner counts, top-3
│   ├── ResultPanel.tsx        Filter, retest, export, diff
│   ├── SeverityBadge.tsx
│   ├── ThemeToggle.tsx        Dark/light/system
│   └── LoadingSkeleton.tsx
├── routes/
│   ├── __root.tsx             HTML shell + theme bootstrap
│   └── index.tsx              Main scan page
└── test/                      109 tests across 9 files
```

---

## Methodology

1. URL validated server-side: scheme allow-list, SSRF guard (private IPs, link-local, cloud-metadata IPs and hostnames blocked).
2. Two-tier rate limit (per-IP, per-target-host) checked.
3. Single `GET` to root with identifying `User-Agent`.
4. In parallel: bounded passive crawl + OSV CVE lookup on detected CDN libraries.
5. Six check modules run against headers, cookies, body, crawl results.
6. Remediation playbook attached per finding from registry.
7. JSON result returned. Nothing persisted server-side.

Per-request timeout 5s; total crawl budget 12s; main GET timeout 15s.

---

## Validation / retest

Click **Retest** on any prior result to re-run. The diff strip shows:

> *Validation vs previous scan: 4 resolved · 1 new · 12 unchanged*

History persists 20 most recent scans in `localStorage`. JSON export captures full result for dissertation appendices.

---

## Comparison with existing tools

| | ZAP baseline | Mozilla Observatory | WixSecAudit |
|---|:-:|:-:|:-:|
| Header / cookie / TLS checks | ✓ | ✓ | ✓ |
| Mixed content + form HTTPS | ✓ | – | ✓ |
| SRI on third-party scripts | – | – | ✓ |
| Velo function exposure | – | – | ✓ |
| Wix CMS / Members surface | – | – | ✓ |
| Inline secret detection | – | – | ✓ |
| Fix-owner labelling | – | – | ✓ |
| Retest / diff | (manual) | – | ✓ |
| Structured remediation playbook | – | – | ✓ |
| OSV.dev CVE intel | – | – | ✓ |

Full evaluation in [`docs/REPORT.md` §11](docs/REPORT.md#11-evaluation).

---

## Known limitations

- **Passive only** by design. Single-page scan; subpage issues missed unless surfaced via sitemap.
- **No DOM rendering.** SPA-rendered content invisible. Static HTML only.
- **Heuristic Wix detection.** Multi-signal voting; theoretical false positives if a non-Wix site mirrors Wix asset hosts.
- **Wix Forms CAPTCHA detection is HTML-only.** Server-side anti-spam not visible.
- **Rate limit fallback is per-Worker-instance.** KV binding documented; one-line wrangler config to enable cross-instance.
- **OSV detection is CDN-URL-pattern-based.** Self-hosted libraries with version in inline comments are not fingerprinted.

---

## Security & responsible use

- Scheme allow-list (`http`, `https` only).
- SSRF guard against RFC-1918, loopback, link-local, IPv6 ULA, cloud metadata IPs and hostnames.
- 15-second timeout on main GET; 12s total crawl budget; 5s per-probe timeout.
- Two-tier rate limit (10 IP/min, 6 host/min).
- Identifying `User-Agent`; HEAD-only Velo probes.
- No payload injection, no auth bypass, no fuzzing.

**Use only against sites you own or have explicit permission to test.**

---

## Licence

Dissertation prototype — not intended for production use without further security review.
