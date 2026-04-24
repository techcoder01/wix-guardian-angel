import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { scanUrl } from "@/utils/scanner.functions";
import type { ScanResult, Severity, Finding } from "@/lib/scanner-types";
import { FindingCard } from "@/components/FindingCard";
import { SeverityBadge } from "@/components/SeverityBadge";

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

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

type HistoryItem = { id: string; result: ScanResult; previous?: ScanResult };

function Index() {
  const scan = useServerFn(scanUrl);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");

  const active = history.find((h) => h.id === activeId) ?? null;

  async function runScan(target: string, previous?: ScanResult) {
    setLoading(true);
    setError(null);
    try {
      const result = await scan({ data: { url: target } });
      const id = `${result.url}-${Date.now()}`;
      setHistory((h) => [{ id, result, previous }, ...h]);
      setActiveId(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
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
    const blob = new Blob([JSON.stringify(item.result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `wixsecaudit-${new Date(item.result.scannedAt).getTime()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="h-9 w-9 rounded-md flex items-center justify-center font-bold text-primary-foreground"
              style={{ background: "var(--gradient-hero)", boxShadow: "var(--shadow-glow)" }}
            >
              W
            </div>
            <div>
              <h1 className="text-base font-semibold leading-tight">WixSecAudit</h1>
              <p className="text-xs text-muted-foreground leading-tight">
                Passive black-box auditor for low-code sites
              </p>
            </div>
          </div>
          <span className="text-xs text-muted-foreground hidden md:inline">
            Dissertation prototype · v0.1
          </span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-10 space-y-10">
        <section className="space-y-4">
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight">
            Audit any public Wix or low-code website
          </h2>
          <p className="text-muted-foreground max-w-2xl">
            Enter a URL. The scanner performs a single passive HTTP request, then evaluates security
            headers, cookies, transport, third-party scripts and content exposure. Findings include
            severity, remediation and a label showing whether the site owner, the Wix platform, or a
            third party owns the fix.
          </p>

          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.wixsite.com/mysite"
              className="flex-1 rounded-md bg-input border border-border px-4 py-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="rounded-md px-6 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50 transition-opacity"
              style={{ background: "var(--gradient-hero)", boxShadow: "var(--shadow-glow)" }}
            >
              {loading ? "Scanning…" : "Run passive scan"}
            </button>
          </form>
          {error && (
            <p className="text-sm text-[oklch(var(--severity-high))] bg-[oklch(var(--severity-high)/0.1)] border border-[oklch(var(--severity-high)/0.3)] rounded-md px-3 py-2">
              {error}
            </p>
          )}
        </section>

        {history.length > 0 && (
          <div className="grid lg:grid-cols-[260px_1fr] gap-6">
            <aside className="space-y-2">
              <h3 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">
                Scan history
              </h3>
              {history.map((h) => (
                <button
                  key={h.id}
                  onClick={() => setActiveId(h.id)}
                  className={`w-full text-left rounded-md border px-3 py-2 transition-colors ${
                    activeId === h.id ? "bg-accent border-primary/40" : "border-border hover:bg-accent/40"
                  }`}
                >
                  <p className="text-xs truncate font-medium">{h.result.url}</p>
                  <p className="text-[10px] text-muted-foreground">
                    {new Date(h.result.scannedAt).toLocaleTimeString()} · {h.result.findings.length} findings
                  </p>
                </button>
              ))}
            </aside>

            {active && (
              <ResultPanel
                item={active}
                filter={filter}
                setFilter={setFilter}
                onRetest={() => retest(active)}
                onExport={() => exportJson(active)}
                loading={loading}
              />
            )}
          </div>
        )}

        {history.length === 0 && (
          <section className="grid md:grid-cols-3 gap-4">
            {[
              { t: "Headers & transport", d: "HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, HTTPS enforcement." },
              { t: "Cookies", d: "Secure, HttpOnly and SameSite flags evaluated per cookie, with session-cookie heuristics." },
              { t: "Content & forms", d: "Mixed content, insecure form actions, third-party scripts without SRI, exposed PII, debug leaks." },
            ].map((c) => (
              <div key={c.t} className="rounded-lg border border-border bg-card p-5">
                <h3 className="font-semibold mb-2">{c.t}</h3>
                <p className="text-sm text-muted-foreground">{c.d}</p>
              </div>
            ))}
          </section>
        )}
      </main>

      <footer className="border-t border-border mt-16">
        <div className="max-w-6xl mx-auto px-6 py-6 text-xs text-muted-foreground">
          Passive scanner only. Use with permission. Output intended as a dissertation artefact.
        </div>
      </footer>
    </div>
  );
}

function ResultPanel({
  item,
  filter,
  setFilter,
  onRetest,
  onExport,
  loading,
}: {
  item: HistoryItem;
  filter: Severity | "all";
  setFilter: (s: Severity | "all") => void;
  onRetest: () => void;
  onExport: () => void;
  loading: boolean;
}) {
  const r = item.result;
  const filtered = filter === "all" ? r.findings : r.findings.filter((f) => f.severity === filter);
  const grouped = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: filtered.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  // Diff vs previous scan
  const diff = computeDiff(r.findings, item.previous?.findings);

  return (
    <section className="space-y-5">
      <div className="rounded-lg border border-border bg-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground">Target</p>
            <p className="font-mono text-sm break-all">{r.finalUrl}</p>
            <p className="text-xs text-muted-foreground mt-1">
              HTTP {r.statusCode} · scanned in {r.durationMs} ms ·{" "}
              {r.isWix ? (
                <span className="text-primary font-medium">Wix platform detected</span>
              ) : (
                "Wix not detected"
              )}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onRetest}
              disabled={loading}
              className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
            >
              {loading ? "Retesting…" : "Retest"}
            </button>
            <button
              onClick={onExport}
              className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="grid grid-cols-5 gap-2 mt-5">
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(filter === sev ? "all" : sev)}
              className={`rounded-md border px-2 py-2 text-center transition-colors ${
                filter === sev ? "border-primary bg-accent" : "border-border hover:bg-accent/50"
              }`}
            >
              <div className="text-2xl font-bold tabular-nums">{r.summary[sev]}</div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{sev}</div>
            </button>
          ))}
        </div>

        {item.previous && (
          <div className="mt-4 text-xs text-muted-foreground border-t border-border pt-3">
            <span className="font-medium text-foreground">Validation vs previous scan:</span>{" "}
            <span className="text-[oklch(var(--severity-low))]">{diff.fixed.length} resolved</span> ·{" "}
            <span className="text-[oklch(var(--severity-high))]">{diff.added.length} new</span> ·{" "}
            <span>{diff.unchanged} unchanged</span>
          </div>
        )}
      </div>

      {filter !== "all" && (
        <button
          onClick={() => setFilter("all")}
          className="text-xs text-primary hover:underline"
        >
          Clear filter ({filter}) ↺
        </button>
      )}

      {grouped.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-muted-foreground">
          No findings matched.
        </div>
      ) : (
        grouped.map((g) => (
          <div key={g.sev} className="space-y-2">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={g.sev} />
              <span className="text-xs text-muted-foreground">{g.items.length} finding(s)</span>
            </div>
            {g.items.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        ))
      )}
    </section>
  );
}

function computeDiff(current: Finding[], previous?: Finding[]) {
  if (!previous) return { added: [], fixed: [], unchanged: 0 };
  const cur = new Set(current.map((f) => f.id));
  const prev = new Set(previous.map((f) => f.id));
  const added = [...cur].filter((id) => !prev.has(id));
  const fixed = [...prev].filter((id) => !cur.has(id));
  const unchanged = [...cur].filter((id) => prev.has(id)).length;
  return { added, fixed, unchanged };
}
