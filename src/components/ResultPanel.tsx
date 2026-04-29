import type { ScanResult, Severity, Finding } from "@/lib/scanner-types";
import { FindingCard } from "./FindingCard";
import { SeverityBadge } from "./SeverityBadge";
import { ScanSummary } from "./ScanSummary";
import { computeDiff } from "@/lib/diff";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export type HistoryItem = { id: string; result: ScanResult; previous?: ScanResult };

interface ResultPanelProps {
  item: HistoryItem;
  filter: Severity | "all";
  setFilter: (s: Severity | "all") => void;
  onRetest: () => void;
  onExport: () => void;
  loading: boolean;
}

export function ResultPanel({
  item,
  filter,
  setFilter,
  onRetest,
  onExport,
  loading,
}: ResultPanelProps) {
  const r = item.result;
  const filtered: Finding[] =
    filter === "all" ? r.findings : r.findings.filter((f) => f.severity === filter);
  const grouped = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: filtered.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  const diff = computeDiff(r.findings, item.previous?.findings);

  return (
    <section className="space-y-4 sm:space-y-5">
      <ScanSummary result={r} />

      <div className="rounded-lg border border-border bg-card p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 w-full sm:w-auto sm:flex-1">
            <p className="text-xs uppercase tracking-wider text-muted-foreground">
              Target
            </p>
            <p className="font-mono text-xs sm:text-sm break-all">
              {r.finalUrl}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              HTTP {r.statusCode} · scanned in {r.durationMs} ms ·{" "}
              {r.isWix ? (
                <span className="text-primary font-medium">
                  Wix platform detected
                </span>
              ) : (
                "Wix not detected"
              )}
            </p>
          </div>
          <div className="flex gap-2 w-full sm:w-auto">
            <button
              onClick={onRetest}
              disabled={loading}
              aria-label="Re-run scan for this URL"
              className="flex-1 sm:flex-none rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
            >
              {loading ? "Retesting…" : "Retest"}
            </button>
            <button
              onClick={onExport}
              aria-label="Download scan results as JSON"
              className="flex-1 sm:flex-none rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-accent"
            >
              Export JSON
            </button>
          </div>
        </div>

        {/* Severity filter bar — wraps to 2-column on smallest screens */}
        <div
          className="grid grid-cols-3 sm:grid-cols-5 gap-2 mt-4 sm:mt-5"
          role="group"
          aria-label="Filter by severity"
        >
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(filter === sev ? "all" : sev)}
              aria-pressed={filter === sev}
              aria-label={`${r.summary[sev]} ${sev} finding${r.summary[sev] !== 1 ? "s" : ""}`}
              className={`rounded-md border px-2 py-2 text-center transition-colors ${
                filter === sev
                  ? "border-primary bg-accent"
                  : "border-border hover:bg-accent/50"
              }`}
            >
              <div className="text-xl sm:text-2xl font-bold tabular-nums">
                {r.summary[sev]}
              </div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {sev}
              </div>
            </button>
          ))}
        </div>

        {item.previous && (
          <div className="mt-4 text-xs text-muted-foreground border-t border-border pt-3 flex flex-wrap gap-x-2 gap-y-1">
            <span className="font-medium text-foreground">
              Validation vs previous scan:
            </span>
            <span className="text-[oklch(var(--severity-low))]">
              {diff.fixed.length} resolved
            </span>
            <span>·</span>
            <span className="text-[oklch(var(--severity-high))]">
              {diff.added.length} new
            </span>
            <span>·</span>
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
        <div className="rounded-lg border border-border bg-card p-6 sm:p-8 text-center text-muted-foreground text-sm">
          No findings matched.
        </div>
      ) : (
        grouped.map((g) => (
          <div key={g.sev} className="space-y-2">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={g.sev} />
              <span className="text-xs text-muted-foreground">
                {g.items.length} finding{g.items.length !== 1 ? "s" : ""}
              </span>
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
