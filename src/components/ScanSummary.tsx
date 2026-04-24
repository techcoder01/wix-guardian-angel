import type { ScanResult, Severity, FixOwner, Finding } from "@/lib/scanner-types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
const FIX_OWNERS: FixOwner[] = ["site_owner", "wix_platform", "third_party", "shared"];
const OWNER_LABEL: Record<FixOwner, string> = {
  site_owner: "Site owner",
  wix_platform: "Wix platform",
  third_party: "Third party",
  shared: "Shared",
};
const SEV_VAR: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--severity-info)",
};

function topImpact(findings: Finding[]): Finding[] {
  return [...findings]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, 3);
}

export function ScanSummary({ result }: { result: ScanResult }) {
  const total = result.findings.length;
  const ownerCounts = FIX_OWNERS.map((o) => ({
    owner: o,
    count: result.findings.filter((f) => f.fixOwner === o).length,
  }));
  const top = topImpact(result.findings);

  return (
    <div className="rounded-lg border border-border bg-card p-5 space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-wider text-muted-foreground">One-page summary</p>
          <h3 className="text-lg font-semibold">
            {total} finding{total === 1 ? "" : "s"} across {result.finalUrl.replace(/^https?:\/\//, "").slice(0, 48)}
          </h3>
        </div>
        <span className="text-xs text-muted-foreground hidden sm:inline">
          {new Date(result.scannedAt).toLocaleString()}
        </span>
      </div>

      <div className="grid sm:grid-cols-2 gap-5">
        <div>
          <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">By severity</p>
          <div className="space-y-1.5">
            {SEVERITY_ORDER.map((sev) => {
              const n = result.summary[sev];
              const pct = total > 0 ? (n / total) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-2 text-xs">
                  <span className="w-16 uppercase tracking-wider text-muted-foreground">{sev}</span>
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${pct}%`, backgroundColor: `oklch(${SEV_VAR[sev]})` }}
                    />
                  </div>
                  <span className="w-6 text-right tabular-nums font-semibold">{n}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">By fix owner</p>
          <div className="grid grid-cols-2 gap-2">
            {ownerCounts.map(({ owner, count }) => (
              <div
                key={owner}
                className="rounded-md border border-border bg-background/40 px-3 py-2"
              >
                <div className="text-xl font-bold tabular-nums">{count}</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  {OWNER_LABEL[owner]}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div>
        <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">
          Top 3 highest-impact issues
        </p>
        {top.length === 0 ? (
          <p className="text-sm text-muted-foreground">No findings — nothing to prioritise.</p>
        ) : (
          <ol className="space-y-2">
            {top.map((f, i) => (
              <li
                key={f.id}
                className="flex items-start gap-3 rounded-md border border-border bg-background/40 px-3 py-2"
              >
                <span className="text-xs font-bold text-muted-foreground tabular-nums mt-0.5">
                  {i + 1}.
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-0.5">
                    <span
                      className="text-[10px] uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded"
                      style={{
                        backgroundColor: `oklch(${SEV_VAR[f.severity]} / 0.18)`,
                        color: `oklch(${SEV_VAR[f.severity]})`,
                      }}
                    >
                      {f.severity}
                    </span>
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      {OWNER_LABEL[f.fixOwner]}
                    </span>
                  </div>
                  <p className="text-sm font-medium truncate">{f.title}</p>
                  <p className="text-xs text-muted-foreground line-clamp-2">{f.remediation}</p>
                </div>
                {f.reference && (
                  <a
                    href={f.reference}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-primary hover:underline whitespace-nowrap mt-0.5"
                  >
                    Fix ↗
                  </a>
                )}
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}