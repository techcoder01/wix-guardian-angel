import { useState } from "react";
import type { Finding, FixOwner } from "@/lib/scanner-types";
import { SeverityBadge } from "./SeverityBadge";

const ownerLabel: Record<FixOwner, { label: string; tone: string }> = {
  site_owner: { label: "Site owner", tone: "bg-primary/15 text-primary border-primary/30" },
  wix_platform: { label: "Wix platform", tone: "bg-accent text-accent-foreground border-border" },
  third_party: { label: "Third party", tone: "bg-[oklch(var(--severity-medium)/0.15)] text-[oklch(var(--severity-medium))] border-[oklch(var(--severity-medium)/0.35)]" },
  shared: { label: "Shared", tone: "bg-muted text-muted-foreground border-border" },
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const owner = ownerLabel[finding.fixOwner];
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-accent/40 transition-colors"
      >
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${owner.tone}`}>
              Fix: {owner.label}
            </span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider">
              {finding.category.replace("_", " ")}
            </span>
          </div>
          <h3 className="font-semibold text-foreground">{finding.title}</h3>
        </div>
        <span className="text-muted-foreground text-sm mt-1">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-border bg-background/40">
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1 mt-3">Description</p>
            <p className="text-sm text-foreground/90 leading-relaxed">{finding.description}</p>
          </div>
          {finding.evidence && (
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">Evidence</p>
              <pre className="text-xs bg-muted/60 border border-border rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-foreground/80">
                {finding.evidence}
              </pre>
            </div>
          )}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">Remediation</p>
            <p className="text-sm text-foreground/90 leading-relaxed">{finding.remediation}</p>
          </div>
          {finding.reference && (
            <a
              href={finding.reference}
              target="_blank"
              rel="noreferrer"
              className="inline-block text-xs text-primary hover:underline"
            >
              Reference ↗
            </a>
          )}
        </div>
      )}
    </div>
  );
}