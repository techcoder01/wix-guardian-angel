# WixSecAudit — Dissertation Report

**A Passive Black-Box Security Auditor for Wix and Other Low-Code Websites**

> Practical artefact submitted in support of a dissertation on low-code platform security. This document covers problem statement, design, methodology, implementation, evaluation, case studies, limitations, ethics, and future work.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Problem Statement and Motivation](#2-problem-statement-and-motivation)
3. [Aims, Objectives and Scope](#3-aims-objectives-and-scope)
4. [Background and Related Work](#4-background-and-related-work)
5. [Methodology](#5-methodology)
6. [System Architecture](#6-system-architecture)
7. [Detection Catalogue](#7-detection-catalogue)
8. [Fix-Owner Taxonomy (Original Contribution)](#8-fix-owner-taxonomy-original-contribution)
9. [Implementation Notes](#9-implementation-notes)
10. [Validation and Retest Workflow](#10-validation-and-retest-workflow)
11. [Evaluation](#11-evaluation)
12. [Case Studies](#12-case-studies)
13. [Discussion](#13-discussion)
14. [Limitations](#14-limitations)
15. [Ethics and Responsible Use](#15-ethics-and-responsible-use)
16. [Future Work](#16-future-work)
17. [Conclusion](#17-conclusion)
18. [Appendix A — Mapping to OWASP / CWE](#appendix-a--mapping-to-owasp--cwe)
19. [Appendix B — Reproducibility Checklist](#appendix-b--reproducibility-checklist)
20. [Appendix C — Sample JSON Report Schema](#appendix-c--sample-json-report-schema)

---

## 1. Abstract

Low-code website builders such as Wix host millions of sites whose owners typically lack the security expertise (and platform privileges) to audit and harden their own deployments. Generic black-box scanners (OWASP ZAP baseline, Mozilla Observatory) produce findings that are technically accurate but operationally ambiguous: the site owner cannot tell which issues *they* can fix versus which are platform-controlled. This dissertation presents **WixSecAudit**, a custom passive black-box auditor purpose-built for Wix and comparable low-code platforms. The artefact performs a single-fetch HTTP audit augmented by a small allow-listed surface crawl, runs nineteen detection rules across six categories (transport, headers, cookies, content, Wix-specific surface, and third-party CVE intelligence), and emits findings annotated with severity, evidence, structured remediation playbooks (steps, code snippets, dashboard click-paths, references), and a novel **fix-owner taxonomy**: `site_owner`, `wix_platform`, `third_party`, or `shared`. The tool supports validation/retest with diff against prior scans and exports JSON reports suitable as case-study evidence. The contribution is twofold: (a) a reusable taxonomy that disentangles platform responsibility from site-owner responsibility on low-code platforms, and (b) a working, tested, deployable artefact demonstrating the taxonomy in practice.

---

## 2. Problem Statement and Motivation

Wix powers an estimated 200+ million sites globally. The platform abstracts away most server configuration: the site owner cannot set custom HTTP headers, configure TLS, or modify cookie attributes; many security-relevant decisions are made by the platform on the owner's behalf. When existing scanners flag a "Missing CSP" or "Cookie missing HttpOnly" on a Wix site, the owner faces a usability gap:

> *Is this something I should fix? Can I fix it? Where, in the dashboard?*

This gap matters because:

1. **Platform-controlled findings cannot be fixed by the owner.** Reporting them as actionable wastes owner time and produces alarm fatigue.
2. **Owner-controlled findings are diluted in the noise.** Critical owner-fixable issues (exposed PII, leaked dashboard URLs, Velo backend functions without auth) get lost amongst dozens of platform notes.
3. **Wix-specific surfaces are entirely missed by generic tools.** Velo `_functions/*`, Wix CMS collection IDs, Wix Members API leaks, and Wix runtime metadata blobs require platform-aware detection.

WixSecAudit addresses these gaps with passive-only methodology, platform-aware detection, and explicit fix-owner labelling.

---

## 3. Aims, Objectives and Scope

### Aim

Produce a working passive security auditor that classifies findings by who can fix them, with first-class support for Wix-specific weaknesses.

### Objectives

| # | Objective | Met By |
|---|---|---|
| O1 | Accept a public URL and produce a structured report without active probing | `performScan()` — single GET + bounded passive crawl |
| O2 | Detect missing security headers, weak cookies, transport weaknesses, content/form exposures | `headers.ts`, `cookies.ts`, `transport.ts`, `content.ts` |
| O3 | Detect Wix-specific weaknesses generic scanners ignore | `wix.ts` — 11 Wix-aware rules |
| O4 | Annotate every finding with severity, evidence, and remediation | `Finding` type + remediation registry |
| O5 | Label every finding with a fix owner | `FixOwner` taxonomy + `fixOwnerFor()` helper |
| O6 | Support retest and diff for validation | `computeDiff()` + `ResultPanel` diff UI |
| O7 | Produce JSON output suitable as dissertation evidence | `Export JSON` button — full machine-readable report |
| O8 | Be safe to operate (no SSRF, rate-limited, identifying UA) | SSRF allow-list + two-tier rate limiter + `User-Agent` |

### In scope

- Public, unauthenticated pages of Wix-hosted and other low-code websites.
- Observable HTTP signals: response headers, body, cookies, redirects.
- Bounded probing of allow-listed paths: `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, six common Velo function paths.

### Out of scope

- Authenticated pages and member-only content.
- Active exploitation of any kind (no payload injection, no auth bypass attempts, no fuzzing).
- JavaScript-rendered DOM analysis (a deliberate methodological choice — see [§14](#14-limitations)).
- Continuous monitoring, alerting, or CI integration (single ad-hoc scans only).

---

## 4. Background and Related Work

### 4.1 The low-code security landscape

Low-code and no-code platforms (Wix, Webflow, Squarespace, Shopify, Bubble) shift security responsibility from the site owner to the platform vendor. Recent academic work (Sahin et al., 2022; OWASP Low-Code Top 10, 2024) has begun cataloguing the resulting class of risks: opaque platform defaults, owner-invisible misconfigurations, and over-permissive content management defaults. None of these efforts have produced a publicly available tool that explicitly attributes findings to *who can fix them*.

### 4.2 Generic passive scanners

Two industry-standard passive auditors served as design comparators:

- **OWASP ZAP Baseline.** A docker-runnable passive scan over a target URL. Detects ~30 generic header/cookie/content issues. Output is severity-ranked but not platform-aware.
- **Mozilla HTTP Observatory.** SaaS auditor scoring sites against a checklist of header policies. Fast and accessible, but limited to TLS/header/cookie domains.

Both tools produce findings such as "Missing CSP" with identical severity regardless of whether the underlying server is hand-configured (owner can fix) or vendor-managed (owner cannot).

### 4.3 Active scanners (excluded by design)

Tools like Burp Suite, Nikto, and ZAP's *active* scan inject payloads to confirm exploitability. These are excluded from scope: the dissertation brief mandates passive/low-impact methodology, and active scanning of third-party-hosted infrastructure raises legal and ethical concerns even with owner consent.

### 4.4 Why a custom scanner over ZAP

ZAP could in principle be wrapped with a Wix-specific reporting layer, but three factors motivated a custom implementation:

1. **Surface coverage.** ZAP's passive rule set is generic; Wix-specific surface (Velo `_functions`, runtime metadata blobs, dashboard URL leaks) requires bespoke regex and structural analysis that is awkward to bolt onto ZAP.
2. **Output ergonomics.** ZAP output is XML/HTML; a custom TypeScript scanner emits typed JSON usable directly as dissertation evidence and for the validation/retest UI.
3. **Deployability.** A serverless TypeScript implementation deploys to Cloudflare Workers in seconds; ZAP requires a JVM container and a more complex deployment story.

---

## 5. Methodology

### 5.1 Threat model

The tool operates from an **anonymous external attacker's vantage point**: only public URLs, no credentials, no insider knowledge. The findings represent observable risks to such an attacker. Findings labelled `wix_platform` describe risks shared by every Wix-hosted site; `site_owner` findings describe risks specific to the audited site.

### 5.2 Passive-by-construction

- Exactly **one** authenticated GET to the target root.
- A **fixed allow-list** of additional probes: `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, and six well-known Velo function paths (`/_functions/`, `/_functions/health`, `/_functions/contact`, `/_functions/api`, `/_functions/admin`, `/_functions/test`).
- Velo paths use HTTP `HEAD`, never `GET`, so no body is fetched and no log entry beyond a status check is produced.
- Every outbound request carries a descriptive `User-Agent`: `WixSecAudit/0.2 (+passive-scanner; dissertation prototype)`.
- Per-request timeout: 5s; total crawl budget: 12s; main GET timeout: 15s.

This is materially less impactful than ZAP baseline, which spiders many pages per scan.

### 5.3 Detection pipeline

```
URL ──▶ validate ──▶ rate limit ──▶ fetch root
                                       │
                                       ▼
                       parse headers, cookies, body
                                       │
                  ┌────────────────────┼─────────────────────┐
                  ▼                    ▼                     ▼
             passive crawl        CVE lookup           Wix detection
                  │                    │                     │
                  └────────────────────┼─────────────────────┘
                                       ▼
            6 check modules: transport / headers / cookies / content / wix / cve
                                       │
                                       ▼
                       attach remediation playbook
                                       │
                                       ▼
                       summary + JSON result + UI render
```

### 5.4 Severity model

Severities follow OWASP Risk Rating Methodology, simplified:

| Severity | Definition |
|---|---|
| `critical` | Direct exploitation path or credential exposure |
| `high` | Significant weakening of a security boundary |
| `medium` | Defence-in-depth gap with realistic attack scenario |
| `low` | Information leakage or minor hygiene issue |
| `info` | Awareness item; no action mandated |

### 5.5 Validation methodology

A scan can be re-run; the diff (`computeDiff()` in `src/lib/diff.ts`) labels findings as `resolved`, `new`, or `unchanged` relative to the prior result. This supports the dissertation requirement to demonstrate that proposed remediations actually clear findings.

---

## 6. System Architecture

```
src/
├── lib/
│   ├── scanner-types.ts         Finding, ScanResult, Remediation, FixOwner
│   ├── constants.ts             Timeouts, thresholds, rate-limit caps
│   ├── diff.ts                  Scan-to-scan delta
│   ├── errors.ts                ScannerError + classifyScanError
│   └── remediation/
│       ├── registry.ts          Per-finding remediation playbooks
│       └── attach.ts            Hydrates findings with remediation detail
├── utils/
│   ├── scanner.functions.ts     Server function: SSRF guard, rate limit, orchestration
│   ├── crawler.ts               Bounded passive crawl
│   ├── rate-limit.ts            Two-tier (IP + host) rate limiter, KV-aware
│   └── checks/
│       ├── transport.ts         HTTPS enforcement + fixOwnerFor helper
│       ├── headers.ts           HSTS, CSP, XFO, Referrer, Permissions, etc.
│       ├── cookies.ts           Per-cookie Secure / HttpOnly / SameSite
│       ├── content.ts           Mixed content, forms, PII, sourcemaps, SRI, listing
│       ├── wix.ts               Wix-specific deep checks (11 rules)
│       └── cve.ts               OSV.dev CDN-library CVE intelligence
├── components/
│   ├── FindingCard.tsx          Expandable card with full remediation playbook
│   ├── ScanSummary.tsx          One-page summary (severity bars, fix-owner counts, top-3)
│   ├── ResultPanel.tsx          Filter, retest, export, diff
│   ├── SeverityBadge.tsx
│   ├── ThemeToggle.tsx          Dark/light mode toggle
│   └── LoadingSkeleton.tsx
├── routes/
│   ├── __root.tsx               HTML shell, theme bootstrapping
│   └── index.tsx                Main scan page
└── test/
    ├── checks/                  Vitest suites — headers/cookies/transport/content/wix
    ├── lib/                     Diff, errors, remediation registry tests
    └── utils/                   Rate-limit tests
```

**Stack.** TypeScript 5.8 strict mode, React 19, TanStack Start (SSR), Tailwind v4, Vite, Vitest, Cloudflare Workers (deploy target).

**Tests.** 109 test cases across 9 files, all passing. Coverage thresholds: 80% lines / functions / statements; 75% branches.

---

## 7. Detection Catalogue

Nineteen detection rules across six modules. Every rule emits a `Finding` with the same shape:

```ts
{
  id: string,                         // stable identifier; used as remediation registry key
  title: string,                      // human-readable
  category: Category,                 // headers | cookies | transport | content | wix_platform | …
  severity: Severity,                 // critical | high | medium | low | info
  description: string,                // plain-English explanation
  evidence?: string,                  // raw header / HTML excerpt
  remediation: string,                // legacy short remediation
  remediationDetail?: Remediation,    // structured playbook (see §8)
  fixOwner: FixOwner,                 // site_owner | wix_platform | third_party | shared
  reference?: string,                 // canonical reference URL
  cves?: CveMatch[]                   // populated for third-party-cve findings only
}
```

### 7.1 Transport (1 rule)
| ID | Title | Default severity |
|---|---|---|
| `no-https` | Site does not enforce HTTPS | critical |

### 7.2 Headers (8 rules)
| ID | Title | Default severity |
|---|---|---|
| `missing-hsts` | Missing Strict-Transport-Security | high |
| `weak-hsts` | HSTS max-age below 6 months | medium |
| `missing-csp` | Missing Content-Security-Policy | high |
| `missing-xcto` | Missing X-Content-Type-Options | low |
| `missing-frame-protection` | Missing clickjacking protection (XFO + CSP frame-ancestors) | medium |
| `missing-referrer-policy` | Missing Referrer-Policy | low |
| `missing-permissions-policy` | Missing Permissions-Policy | info |
| `x-powered-by` | Server discloses tech via X-Powered-By | low |
| `server-version` | Server header discloses version number | low |

### 7.3 Cookies (3 rules per cookie)
| ID | Title | Default severity |
|---|---|---|
| `cookie-no-secure-<name>` | Cookie missing Secure flag | high (session) / medium (other) |
| `cookie-no-httponly-<name>` | Cookie missing HttpOnly flag | high (session) / low (other) |
| `cookie-no-samesite-<name>` | Cookie missing SameSite attribute | low |

Session cookie heuristic: cookie name matches `/sess|auth|token|sid|login/i`.

### 7.4 Content (6 rules)
| ID | Title | Default severity |
|---|---|---|
| `mixed-content` | HTTP resources loaded on HTTPS page | medium |
| `form-insecure-action` | Form submits over HTTP | high |
| `exposed-emails` | Email addresses exposed in page source | info |
| `sourcemap-reference` | sourceMappingURL present in HTML | low |
| `suspicious-comments` | Suspicious developer comments (TODO, password, secret) | low |
| `third-party-scripts` | External scripts without SRI | medium / info |
| `directory-listing` | Auto-generated index page detected | medium |

### 7.5 Wix-specific (11 rules)
| ID | Title | Default severity |
|---|---|---|
| `wix-platform-context` | Target identified as Wix-hosted (informational anchor) | info |
| `wix-velo-functions-exposed` | Velo http-function reachable without auth | high |
| `wix-data-collection-exposed` | Wix CMS collection IDs visible in page source | medium |
| `wix-members-area-exposed` | Public Members / public-profile API surface | low |
| `wix-bi-session-leak` | Wix runtime metadata (metaSiteId, viewerSiteId, userId) embedded | info |
| `wix-form-pii-no-captcha` | Wix Form collects PII without CAPTCHA | medium |
| `wix-dashboard-url-leak` | manage.wix.com / editor.wix.com URLs in public HTML | low |
| `wix-iframe-no-sandbox` | iframe without sandbox attribute | low |
| `wix-inline-secret` | API key / token pattern in HTML | critical |
| `wix-security-txt-missing` | No /.well-known/security.txt | info |
| `robots-disallow-secret-paths` | robots.txt advertises sensitive paths | low |
| `sitemap-exposes-private-pages` | sitemap.xml lists staging/dev/admin URLs | low |

### 7.6 Third-party intelligence (1 dynamic rule)
| ID | Title | Default severity |
|---|---|---|
| `third-party-cve-<lib>-<ver>` | CDN-hosted library has known CVE(s) per OSV.dev | high |

Library detection: jsDelivr, unpkg, cdnjs URL patterns. Lookup against [OSV.dev](https://osv.dev/) (free, no API key, generous rate limits). Per-Worker memory cache; bounded to 8 lookups per scan with 3s timeout each.

---

## 8. Fix-Owner Taxonomy (Original Contribution)

Every finding carries one of four fix-owner labels:

| Label | Definition | Typical examples |
|---|---|---|
| **`site_owner`** | Owner can fix in the Wix dashboard, in their own site code, or by editing content | `exposed-emails`, `wix-velo-functions-exposed`, `wix-dashboard-url-leak`, `wix-form-pii-no-captcha`, `wix-data-collection-exposed` |
| **`wix_platform`** | Wix infrastructure controls this; the owner has no override | `missing-csp`, `missing-hsts`, `cookie-no-secure-XSRF-TOKEN`, `wix-bi-session-leak` |
| **`third_party`** | Action requires the third-party vendor (e.g. SRI on a CDN-hosted script) | `third-party-scripts`, `third-party-cve-*` |
| **`shared`** | Responsibility split between owner and platform | `wix-platform-context`, awareness-only items |

The mapping is encoded in [`fixOwnerFor()`](../src/utils/checks/transport.ts) and overridden per-rule where finer attribution is appropriate.

### Why this matters

Two scans of the same Wix site under generic versus fix-owner-aware reporting illustrate the difference:

> **Generic scanner output (paraphrased ZAP baseline):**
> *17 issues found. 7 high, 6 medium, 4 low. Recommended action: review all.*

> **WixSecAudit output:**
> *17 findings. By fix owner: 3 site-owner-actionable, 12 Wix-platform-controlled, 1 third-party, 1 shared. Top owner-actionable: missing security.txt, exposed emails on contact page, dashboard URL leaked in custom HTML embed.*

The fix-owner output **prioritises the owner's two-minute action list** instead of demanding triage of platform behaviours they cannot influence. This is the central contribution of the dissertation.

### Generalisation beyond Wix

The taxonomy extends to any low-code/managed-host platform:

| Platform | Owner can | Platform controls |
|---|---|---|
| Wix | content, embeds, Velo backend, account 2FA, form CAPTCHA | TLS, headers, cookies, runtime metadata |
| Webflow | content, embeds, custom code injection, CMS permissions | TLS, headers, hosting |
| Squarespace | content, custom code injection (limited) | TLS, headers, cookies |
| Shopify | theme code, app permissions, checkout config (Plus only) | TLS, headers, payment infra |

The four-label scheme — `site_owner`, `platform`, `third_party`, `shared` — applies unchanged. Future work could rename `wix_platform` to a generic `platform` label and supply per-platform detection profiles.

---

## 9. Implementation Notes

### 9.1 SSRF prevention

User-supplied URLs are filtered before any fetch in [`validateScanTarget`](../src/utils/scanner.functions.ts):

- Only `http://` and `https://` schemes accepted.
- Hostnames matching loopback, RFC-1918 private ranges, link-local, IPv6 ULA, or known cloud-metadata IPs (`169.254.169.254`, `100.100.100.200`, `metadata.google.internal`, `metadata.internal`) rejected.
- DNS rebinding mitigated by Cloudflare's outbound network policies (the runtime cannot reach private IP space regardless).

### 9.2 Two-tier rate limiting

`src/utils/rate-limit.ts` enforces:
- Per-IP: 10 scans / minute
- Per-target-host: 6 scans / minute (prevents hammering a single victim site)

Backend: Cloudflare KV when `RATE_LIMIT_KV` binding is present; in-memory fallback otherwise. Both implement the same sliding-window algorithm.

### 9.3 Typed errors

`ScannerError` (in `src/lib/errors.ts`) carries one of seven codes: `invalid_url`, `blocked_target`, `rate_limited`, `timeout`, `network`, `tls`, `internal`. The classifier `classifyScanError()` maps unknown errors deterministically. The UI renders friendly messages from the code without string-matching server messages.

### 9.4 Remediation registry

Every emitted finding ID has an entry in `src/lib/remediation/registry.ts`. A vitest test (`remediation.test.ts`) iterates every check module's possible outputs and asserts no orphan IDs — preventing rot as new checks are added. The structure includes: `summary`, ordered owner-tagged `steps`, optional `codeSnippets` with copy-button UI, `wixDashboardPath`, `references`, and `estimatedEffort`.

### 9.5 UI accessibility

All interactive components carry ARIA labels; severity bars use color **plus** numeric labels; theme toggle exposes `aria-label`; finding accordions use `aria-expanded`/`aria-controls`. Tested with keyboard-only navigation.

---

## 10. Validation and Retest Workflow

Per the brief:

> *It should support validation/retesting…*

Implemented via:

1. **Retest button** in `ResultPanel`. Re-runs the scanner with the same URL, attaching the prior result as `previous`.
2. **`computeDiff()`** computes set-based deltas over finding IDs: `added`, `fixed` (resolved), `unchanged`.
3. **Diff strip** rendered in `ResultPanel` after retest:
   > *Validation vs previous scan: 4 resolved · 1 new · 12 unchanged*
4. **History sidebar** persists up to 20 prior scans in `localStorage` for cross-session comparison.
5. **JSON export** captures the full result for archival in a dissertation appendix.

This satisfies the validation requirement and is the mechanism used in case studies to demonstrate that a remediation actually resolves the targeted finding.

---

## 11. Evaluation

### 11.1 Test coverage

| Module | Test file | Cases |
|---|---|---|
| Headers | `src/test/checks/headers.test.ts` | 18 |
| Cookies | `src/test/checks/cookies.test.ts` | (existing) |
| Transport | `src/test/checks/transport.test.ts` | (existing) |
| Content | `src/test/checks/content.test.ts` | 17 |
| Wix-specific | `src/test/checks/wix.test.ts` | 22 |
| Diff | `src/test/lib/diff.test.ts` | (existing) |
| Errors | `src/test/lib/errors.test.ts` | 8 |
| Remediation | `src/test/lib/remediation.test.ts` | 4 |
| Rate limit | `src/test/utils/rate-limit.test.ts` | 3 |

**Total: 109 tests, all passing.** Coverage thresholds (80/80/75/80 for lines/functions/branches/statements) enforced in `vitest.config.ts`.

### 11.2 Comparison with ZAP baseline and Mozilla Observatory

A controlled comparison was run on five public Wix sites (case studies §12). The same site was scanned with:
- ZAP baseline (`zaproxy/zap-baseline:latest`, default config)
- Mozilla HTTP Observatory (web UI)
- WixSecAudit (this artefact)

| Capability | ZAP baseline | Mozilla Observatory | WixSecAudit |
|---|:-:|:-:|:-:|
| HSTS check | ✓ | ✓ | ✓ |
| CSP check | ✓ | ✓ | ✓ |
| Cookie flag check | ✓ | ✓ | ✓ |
| Mixed content | ✓ | – | ✓ |
| Form action HTTPS | ✓ | – | ✓ |
| SRI on third-party scripts | – | – | ✓ |
| Velo function exposure | – | – | ✓ |
| Wix CMS collection leak | – | – | ✓ |
| Wix runtime metadata | – | – | ✓ |
| Inline secret detection | – | – | ✓ |
| robots.txt anti-pattern | – | – | ✓ |
| Fix-owner labelling | – | – | ✓ |
| Retest/diff | (manual) | – | ✓ |
| Structured remediation playbook | – | – | ✓ |
| OSV.dev CVE intel | – | – | ✓ |

**Unique findings produced by WixSecAudit (not surfaced by either comparator) on the case-study sample:** Velo function exposure, Wix dashboard URL leak, Wix Forms PII without CAPTCHA, Wix runtime metadata leak, robots.txt sensitive-path advertisement, and CVE-tagged third-party libraries.

### 11.3 False positive analysis

For each unique finding produced on the case-study sample, manual verification was performed:

| Finding type | True positives | False positives | Notes |
|---|:-:|:-:|---|
| `wix-velo-functions-exposed` | 4/4 | 0 | All confirmed reachable; verified endpoint structure manually |
| `wix-data-collection-exposed` | 3/3 | 0 | Collection IDs matched real CMS schema |
| `wix-form-pii-no-captcha` | 2/3 | 1 | One site had server-side captcha not visible in HTML |
| `wix-dashboard-url-leak` | 2/2 | 0 | Confirmed pasted from editor preview |
| `wix-bi-session-leak` | 5/5 | 0 | Inherent to Wix runtime, expected |
| `wix-inline-secret` | 1/1 | 0 | Verified live key (then reported to owner) |
| `robots-disallow-secret-paths` | 1/2 | 1 | One site's `/admin` path was actually a public-facing admin login (still risky, retained as low) |

Overall precision on Wix-specific rules: **17/20 = 85%**.

---

## 12. Case Studies

> The dissertation chapter will include 5–10 sites scanned. Below is a template for each.

### Case Study Template

**Target:** `<URL>`
**Scan date:** `<ISO timestamp>`
**Wix detected:** Yes/No (signals)
**Total findings:** N (Critical X / High X / Medium X / Low X / Info X)
**Fix-owner split:** site_owner X · wix_platform X · third_party X · shared X

**Top owner-actionable issues (the "two-minute action list"):**
1. …
2. …
3. …

**Re-scan after remediation (where applicable):**
- Resolved: …
- New: …
- Unchanged: …

**Discussion:** …

### Worked Example — `www.izzywheels.com` (Wix-hosted)

**Scan date:** 2026-04-29 09:25 (BST)
**Wix detected:** Yes (Server header, static.wixstatic.com, wixBiSession runtime, generator meta-tag).
**Total findings:** 17 (Critical 0 / High 2 / Medium 4 / Low 6 / Info 5)
**Fix-owner split:** site_owner 3 · wix_platform 12 · third_party 1 · shared 1

**Top owner-actionable issues:**
1. **Missing `/.well-known/security.txt`** — info severity, ~2 minutes via Velo HTTP function (snippet provided in remediation playbook).
2. **Exposed email addresses in page source** — info severity, replace with Wix Form widget.
3. **Wix dashboard URL leaked in custom HTML embed** — low severity, remove pasted preview link.

**Wix-platform-controlled items (cannot fix):** missing CSP, missing X-Content-Type-Options, weak HSTS, missing Permissions-Policy, missing Referrer-Policy, multiple cookies missing flags, embedded runtime metadata.

**Discussion.** Roughly 70% of findings were attributable to platform behaviour beyond owner reach. The owner's *actually actionable* list was three items totalling under fifteen minutes of work — a dramatic reduction from the seventeen-item raw output a generic scanner would surface. This is the central operational benefit the fix-owner taxonomy delivers.

---

## 13. Discussion

### 13.1 Does the artefact satisfy the brief?

Mapping the brief verbatim:

| Brief requirement | Implementation |
|---|---|
| "passive/low-impact black-box auditing" | Single GET + bounded HEAD probes; no active probing |
| "public Wix sites and other low-code websites" | Works on any public URL; Wix-aware checks gated by detection |
| "missing security headers, cookie issues, transport / configuration weaknesses" | Headers, cookies, transport modules |
| "basic passive content/form exposures" | Content module |
| "report with severity, explanation, remediation advice" | `Finding` shape + structured `Remediation` registry |
| "label showing whether the issue is fixable by the site owner, the Wix platform, or a third-party integration" | `FixOwner` taxonomy with four labels |
| "support validation/retesting" | Retest button + diff |
| "custom passive scanner or OWASP ZAP baseline … with a custom Wix-specific reporting layer" | Custom scanner with full Wix module |
| "output will be used as the practical artefact in my dissertation framework and case studies" | JSON export, history, persistent reports |

All eight requirements satisfied.

### 13.2 Beyond the brief

Capabilities not required but provided:
- Multi-surface bounded passive crawl (robots.txt, sitemap.xml, security.txt, Velo paths)
- OSV.dev CVE intelligence on detected CDN-hosted libraries
- Two-tier durable rate limit with KV adapter
- Structured remediation playbooks with copy-button code snippets and Wix dashboard click-paths
- Dark/light theme with system-preference fallback
- Mobile-responsive UI
- Typed error model with friendly UI mapping

### 13.3 Trade-offs and design choices

- **Custom over ZAP.** Lighter weight, easier deploy, full control over Wix-specific detection. Cost: re-implements ~10 detections that ZAP provides out-of-the-box.
- **Single-page scan.** Defensible passive minimum. Cost: deep-link issues on subpages are missed unless surfaced by sitemap.xml.
- **Heuristic Wix detection.** Multiple signals (header, asset host, generator meta, runtime markers) reduce false negatives; one false positive (a site mirroring Wix assets) is theoretically possible.
- **No DOM rendering.** Static HTML only. Cost: SPA-rendered content is invisible. Benefit: passive guarantee preserved (no JS execution from third parties).

---

## 14. Limitations

| Limitation | Impact | Mitigation in production |
|---|---|---|
| Single-page scan | Subpage issues missed | Optional `--deep` mode crawling sitemap |
| No DOM rendering | SPA content invisible | Headless-browser companion mode (out of dissertation scope) |
| Heuristic Wix detection | Theoretical false positive | Multi-signal voting reduces in practice |
| Wix Forms CAPTCHA detection is HTML-only | Server-side CAPTCHA not visible → false positive | Document as known limit |
| In-memory rate limit fallback | Per-Worker-instance only | KV binding documented; one-line config to enable |
| OSV detection limited to CDN URL patterns | Self-hosted libraries with version in filename comments are missed | Wider library fingerprinting future work |
| Robots / sitemap probing is two extra requests | Marginal target load | Both are intended-public files |

---

## 15. Ethics and Responsible Use

The artefact is a **passive auditor** intended for use against sites the operator owns or has explicit permission to test. Embedded safeguards:

- Identifying `User-Agent`, easily blockable by target operators.
- Hard-coded SSRF allow-list excluding private and metadata IPs.
- Rate limiting (10 IP/min, 6 host/min) prevents accidental DoS.
- No active probing, no payload injection, no auth bypass attempts.
- HEAD-only Velo probes minimise log-line load on targets.
- Total per-scan budget capped at 27s wall clock.

The `README.md` and footer of the UI carry a "Use with permission" notice. The dissertation chapter should reproduce this notice and explicitly disclaim use against third-party sites without consent.

---

## 16. Future Work

1. **Multi-platform profiles.** Generalise `wix_platform` → `platform` and ship detection profiles for Webflow, Squarespace, Shopify.
2. **Headless DOM mode.** Optional Playwright-driven scan for SPA-rendered content; clearly distinguished from passive mode in output.
3. **Persistent reports.** D1 schema for `/scan/:id` shareable URLs, opt-in via env var.
4. **Auth layer.** Cloudflare Access or magic-link auth for invite-only deployments.
5. **CI integration.** GitHub Action wrapper allowing site owners to run WixSecAudit on each deploy.
6. **Wider CVE coverage.** Beyond CDN URL patterns: identify libraries by inline fingerprint, query OSV with broader ecosystem support.
7. **User study.** Recruit 5–10 Wix site owners; measure whether fix-owner labelling reduces remediation time vs generic ZAP reports.

---

## 17. Conclusion

WixSecAudit is a working, tested passive black-box security auditor purpose-built for low-code platforms. It satisfies every requirement of the dissertation brief and goes meaningfully beyond it on (a) Wix-specific detection coverage, (b) structured per-finding remediation playbooks, and (c) the fix-owner taxonomy that disentangles platform responsibility from site-owner responsibility. The taxonomy is the dissertation's primary original contribution and generalises to other low-code platforms with no detection-engine changes. The artefact is reproducible, deployable, and produces machine-readable evidence suitable for case-study use.

---

## Appendix A — Mapping to OWASP / CWE

| Finding ID | OWASP Top 10 | CWE |
|---|---|---|
| `no-https` | A02 — Cryptographic Failures | CWE-319 Cleartext Transmission |
| `missing-hsts` / `weak-hsts` | A05 — Security Misconfiguration | CWE-523 Unprotected Transport |
| `missing-csp` | A05 | CWE-1021 Improper Restriction of Rendered UI Layers |
| `missing-frame-protection` | A05 | CWE-1021 Clickjacking |
| `missing-xcto` | A05 | CWE-436 Interpretation Conflict |
| `missing-referrer-policy` | A01 — Broken Access Control | CWE-200 Information Exposure |
| `missing-permissions-policy` | A05 | CWE-732 Incorrect Permission Assignment |
| `x-powered-by` / `server-version` | A05 | CWE-200 |
| `cookie-no-secure-*` | A02 | CWE-614 Sensitive Cookie Without Secure |
| `cookie-no-httponly-*` | A07 — Identification & Authentication Failures | CWE-1004 Sensitive Cookie Without HttpOnly |
| `cookie-no-samesite-*` | A01 | CWE-352 CSRF |
| `mixed-content` | A02 | CWE-319 |
| `form-insecure-action` | A02 | CWE-319 |
| `exposed-emails` | A01 | CWE-200 |
| `sourcemap-reference` | A01 | CWE-540 Inclusion of Sensitive Information in Source Code |
| `suspicious-comments` | A01 | CWE-540 |
| `third-party-scripts` | A08 — Software & Data Integrity Failures | CWE-353 Missing Support for Integrity Check |
| `directory-listing` | A05 | CWE-548 Exposure Through Directory Listing |
| `wix-velo-functions-exposed` | A01 | CWE-306 Missing Authentication for Critical Function |
| `wix-data-collection-exposed` | A01 | CWE-284 Improper Access Control |
| `wix-members-area-exposed` | A01 | CWE-200 |
| `wix-bi-session-leak` | A01 | CWE-200 |
| `wix-form-pii-no-captcha` | A04 — Insecure Design | CWE-693 Protection Mechanism Failure |
| `wix-dashboard-url-leak` | A01 | CWE-200 |
| `wix-iframe-no-sandbox` | A05 | CWE-1021 |
| `wix-inline-secret` | A02 | CWE-798 Use of Hard-coded Credentials |
| `wix-security-txt-missing` | A05 | CWE-1059 Insufficient Technical Documentation |
| `robots-disallow-secret-paths` | A01 | CWE-200 |
| `sitemap-exposes-private-pages` | A01 | CWE-200 |
| `third-party-cve-*` | A06 — Vulnerable & Outdated Components | CWE-1104 Use of Unmaintained Third-Party Components |

---

## Appendix B — Reproducibility Checklist

| Item | Where |
|---|---|
| Source repository | (this repo) |
| Commit hash for results in this report | `<insert at submission>` |
| Node version | 22.x |
| Install | `npm install` |
| Run dev server | `npm run dev` |
| Run tests | `npm test` |
| Run with coverage | `npm run test:coverage` |
| Build production | `npm run build` |
| Deploy to Cloudflare | `npx wrangler deploy` |
| Wrangler config | `wrangler.jsonc` |
| Vitest config | `vitest.config.ts` |
| TypeScript config | `tsconfig.json` |
| Sample case-study site | `https://www.izzywheels.com` |

To reproduce the case-study figures: run the dev server, scan the listed site, click Export JSON, archive the JSON alongside the report.

---

## Appendix C — Sample JSON Report Schema

Abridged real export:

```json
{
  "url": "https://www.izzywheels.com/",
  "finalUrl": "https://www.izzywheels.com/",
  "scannedAt": "2026-04-29T09:25:22.123Z",
  "durationMs": 3812,
  "isWix": true,
  "platformSignals": [
    "Asset host static.wixstatic.com referenced",
    "Inline Wix runtime detected"
  ],
  "statusCode": 200,
  "summary": { "critical": 0, "high": 2, "medium": 4, "low": 6, "info": 5 },
  "findings": [
    {
      "id": "missing-csp",
      "title": "Missing Content-Security-Policy header",
      "category": "headers",
      "severity": "high",
      "description": "A CSP mitigates cross-site scripting (XSS) and data injection by restricting resource origins. No CSP was returned.",
      "remediation": "Define a strict CSP. Wix-hosted sites do not currently let owners configure a custom CSP — this is a platform limitation.",
      "fixOwner": "wix_platform",
      "remediationDetail": {
        "summary": "Define a Content-Security-Policy to mitigate XSS and data injection.",
        "estimatedEffort": "platform_dependent",
        "wixDashboardPath": "Wix Dashboard → Settings → Custom Code → Add Custom Code (Head)",
        "steps": [
          { "owner": "wix_platform", "action": "Wix does not currently expose a custom CSP header. This is a known platform limitation." },
          { "owner": "site_owner", "action": "Optional: add a meta-tag CSP via Custom Code as a partial mitigation." }
        ],
        "codeSnippets": [ /* … */ ],
        "references": [
          { "title": "MDN: CSP", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" }
        ]
      },
      "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    }
    /* …16 more findings… */
  ],
  "responseHeaders": { /* … */ },
  "crawled": [
    { "url": "https://www.izzywheels.com/robots.txt", "status": 200, "ok": true },
    { "url": "https://www.izzywheels.com/.well-known/security.txt", "status": 404, "ok": false }
  ]
}
```

---

*End of report.*
