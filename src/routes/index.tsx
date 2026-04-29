import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useServerFn } from "@tanstack/react-start";
import { scanUrl } from "@/utils/scanner.functions";
import type { ScanResult, Severity } from "@/lib/scanner-types";
import { ResultPanel } from "@/components/ResultPanel";
import type { HistoryItem } from "@/components/ResultPanel";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { ThemeToggle } from "@/components/ThemeToggle";
import { classifyScanError } from "@/lib/errors";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "WixSecAudit — Passive Security Auditor for Low-Code Sites" },
      {
        name: "description",
        content:
          "Black-box passive security auditor for Wix and other low-code websites. Scans headers, cookies, transport, content and forms with severity, remediation and fix-owner labelling.",
      },
    ],
  }),
  component: Index,
});

const STORAGE_KEY = "wixsecaudit_history";

function loadHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as HistoryItem[];
  } catch {
    return [];
  }
}

function saveHistory(items: HistoryItem[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, 20)));
  } catch {
    /* ignore storage quota errors */
  }
}

function classifyError(message: string): string {
  return classifyScanError(new Error(message)).message;
}

function Index() {
  const scan = useServerFn(scanUrl);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [historyOpen, setHistoryOpen] = useState(false);

  useEffect(() => {
    const stored = loadHistory();
    if (stored.length > 0) {
      setHistory(stored);
      setActiveId(stored[0].id);
    }
  }, []);

  const active = history.find((h) => h.id === activeId) ?? null;

  async function runScan(target: string, previous?: ScanResult) {
    setLoading(true);
    setError(null);
    try {
      const result = await scan({ data: { url: target } });
      const id = `${result.url}-${Date.now()}`;
      const newItem: HistoryItem = { id, result, previous };
      setHistory((h) => {
        const updated = [newItem, ...h];
        saveHistory(updated);
        return updated;
      });
      setActiveId(id);
    } catch (e) {
      const raw = e instanceof Error ? e.message : "Scan failed";
      setError(classifyError(raw));
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim() || loading) return;
    runScan(url.trim());
  }

  function retest(item: HistoryItem) {
    if (loading) return;
    runScan(item.result.url, item.result);
  }

  function exportJson(item: HistoryItem) {
    const blob = new Blob([JSON.stringify(item.result, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `wixsecaudit-${new Date(item.result.scannedAt).getTime()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border sticky top-0 z-30 bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <div
              className="h-8 w-8 sm:h-9 sm:w-9 rounded-md flex items-center justify-center font-bold text-primary-foreground shrink-0"
              style={{
                background: "var(--gradient-hero)",
                boxShadow: "var(--shadow-glow)",
              }}
              aria-hidden="true"
            >
              W
            </div>
            <div className="min-w-0">
              <h1 className="text-sm sm:text-base font-semibold leading-tight truncate">
                WixSecAudit
              </h1>
              <p className="text-[10px] sm:text-xs text-muted-foreground leading-tight truncate">
                Passive black-box auditor for low-code sites
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <span className="text-xs text-muted-foreground hidden lg:inline">
              Dissertation prototype · v0.2
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-6 sm:py-10 space-y-8 sm:space-y-10">
        <section className="space-y-4">
          <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold tracking-tight">
            Audit any public Wix or low-code website
          </h2>
          <p className="text-sm sm:text-base text-muted-foreground max-w-2xl">
            Enter a URL. The scanner performs a passive HTTP request and
            evaluates headers, cookies, transport, third-party scripts and
            content exposure. Findings include severity, remediation and a
            label showing whether the site owner, the Wix platform, or a third
            party owns the fix.
          </p>

          <form
            onSubmit={handleSubmit}
            className="flex flex-col sm:flex-row gap-2"
          >
            <label htmlFor="scan-url" className="sr-only">
              Website URL to audit
            </label>
            <input
              id="scan-url"
              type="url"
              inputMode="url"
              autoComplete="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.wixsite.com/mysite"
              className="flex-1 min-w-0 rounded-md bg-input border border-border px-4 py-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              disabled={loading}
              aria-describedby={error ? "scan-error" : undefined}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="rounded-md px-6 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50 transition-opacity whitespace-nowrap"
              style={{
                background: "var(--gradient-hero)",
                boxShadow: "var(--shadow-glow)",
              }}
            >
              {loading ? "Scanning…" : "Run passive scan"}
            </button>
          </form>

          {error && (
            <p
              id="scan-error"
              role="alert"
              className="text-sm text-[oklch(var(--severity-high))] bg-[oklch(var(--severity-high)/0.1)] border border-[oklch(var(--severity-high)/0.3)] rounded-md px-3 py-2"
            >
              {error}
            </p>
          )}
        </section>

        {(history.length > 0 || loading) && (
          <div className="grid lg:grid-cols-[260px_1fr] gap-4 sm:gap-6">
            {history.length > 0 && (
              <aside aria-label="Scan history" className="lg:block">
                <div className="flex items-center justify-between mb-2 lg:mb-2">
                  <h3 className="text-xs uppercase tracking-wider text-muted-foreground">
                    Scan history ({history.length})
                  </h3>
                  <button
                    type="button"
                    onClick={() => setHistoryOpen((v) => !v)}
                    className="lg:hidden text-xs text-primary hover:underline"
                    aria-expanded={historyOpen}
                    aria-controls="history-list"
                  >
                    {historyOpen ? "Hide" : "Show"}
                  </button>
                </div>
                <ul
                  id="history-list"
                  className={`space-y-2 ${historyOpen ? "block" : "hidden"} lg:block lg:max-h-[60vh] lg:overflow-y-auto pr-1`}
                >
                  {history.map((h) => (
                    <li key={h.id}>
                      <button
                        onClick={() => {
                          setActiveId(h.id);
                          setHistoryOpen(false);
                        }}
                        aria-current={activeId === h.id ? "true" : undefined}
                        className={`w-full text-left rounded-md border px-3 py-2 transition-colors ${
                          activeId === h.id
                            ? "bg-accent border-primary/40"
                            : "border-border hover:bg-accent/40"
                        }`}
                      >
                        <p className="text-xs truncate font-medium">
                          {h.result.url}
                        </p>
                        <p className="text-[10px] text-muted-foreground">
                          {new Date(h.result.scannedAt).toLocaleTimeString()} ·{" "}
                          {h.result.findings.length} findings
                        </p>
                      </button>
                    </li>
                  ))}
                </ul>
              </aside>
            )}

            <div className="min-w-0">
              {loading ? (
                <LoadingSkeleton />
              ) : (
                active && (
                  <ResultPanel
                    item={active}
                    filter={filter}
                    setFilter={setFilter}
                    onRetest={() => retest(active)}
                    onExport={() => exportJson(active)}
                    loading={loading}
                  />
                )
              )}
            </div>
          </div>
        )}

        {history.length === 0 && !loading && (
          <section
            aria-label="Scanner capabilities"
            className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4"
          >
            {[
              {
                t: "Headers & transport",
                d: "HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, HTTPS enforcement.",
              },
              {
                t: "Cookies",
                d: "Secure, HttpOnly and SameSite flags per cookie, with session-cookie heuristics.",
              },
              {
                t: "Content & forms",
                d: "Mixed content, insecure form actions, third-party scripts without SRI, exposed PII, debug leaks.",
              },
              {
                t: "Wix-specific",
                d: "Velo function exposure, CMS collection leaks, Members API, dashboard URL leaks, inline secrets.",
              },
              {
                t: "Multi-surface crawl",
                d: "robots.txt, sitemap.xml, /.well-known/security.txt, common Wix admin paths probed passively.",
              },
              {
                t: "CVE intelligence",
                d: "Detects pinned third-party libraries from CDN URLs and queries OSV.dev for known CVEs.",
              },
            ].map((c) => (
              <div
                key={c.t}
                className="rounded-lg border border-border bg-card p-4 sm:p-5"
              >
                <h3 className="font-semibold mb-1.5 sm:mb-2 text-sm sm:text-base">
                  {c.t}
                </h3>
                <p className="text-xs sm:text-sm text-muted-foreground leading-relaxed">
                  {c.d}
                </p>
              </div>
            ))}
          </section>
        )}
      </main>

      <footer className="border-t border-border mt-12 sm:mt-16">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-5 sm:py-6 text-xs text-muted-foreground">
          Passive scanner only. Use with permission. Output intended as a
          dissertation artefact.
        </div>
      </footer>
    </div>
  );
}
