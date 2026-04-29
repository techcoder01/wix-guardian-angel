import { useState } from "react";
import type {
  Finding,
  FixOwner,
  Remediation,
  RemediationStep,
} from "@/lib/scanner-types";
import { SeverityBadge } from "./SeverityBadge";

const ownerLabel: Record<FixOwner, { label: string; tone: string }> = {
  site_owner: {
    label: "Site owner",
    tone: "bg-primary/15 text-primary border-primary/30",
  },
  wix_platform: {
    label: "Wix platform",
    tone: "bg-accent text-accent-foreground border-border",
  },
  third_party: {
    label: "Third party",
    tone: "bg-[oklch(var(--severity-medium)/0.15)] text-[oklch(var(--severity-medium))] border-[oklch(var(--severity-medium)/0.35)]",
  },
  shared: {
    label: "Shared",
    tone: "bg-muted text-muted-foreground border-border",
  },
};

const effortLabel: Record<Remediation["estimatedEffort"], string> = {
  minutes: "~ minutes",
  hours: "~ hours",
  days: "~ days",
  platform_dependent: "Platform-dependent",
};

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard not available — graceful no-op */
    }
  }
  return (
    <div className="rounded border border-border bg-muted/60 overflow-hidden">
      <div className="flex items-center justify-between px-2 py-1 border-b border-border bg-background/60">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          {language}
        </span>
        <button
          onClick={copy}
          className="text-[10px] text-primary hover:underline"
          aria-label="Copy code snippet"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="text-xs p-2 overflow-x-auto whitespace-pre text-foreground/90">
        {code}
      </pre>
    </div>
  );
}

function StepList({ steps }: { steps: RemediationStep[] }) {
  return (
    <ol className="space-y-2">
      {steps.map((s, i) => (
        <li
          key={i}
          className="flex gap-2 items-start rounded-md border border-border bg-background/40 px-3 py-2"
        >
          <span className="text-xs font-bold text-muted-foreground tabular-nums mt-0.5">
            {i + 1}.
          </span>
          <div className="flex-1 min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${ownerLabel[s.owner].tone}`}
              >
                {ownerLabel[s.owner].label}
              </span>
            </div>
            <p className="text-sm text-foreground/90 leading-relaxed">
              {s.action}
            </p>
            {s.details && (
              <p className="text-xs text-muted-foreground leading-relaxed">
                {s.details}
              </p>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const owner = ownerLabel[finding.fixOwner];
  const detail = finding.remediationDetail;

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={`finding-body-${finding.id}`}
        className="w-full text-left px-3 sm:px-4 py-3 flex items-start gap-3 hover:bg-accent/40 transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span
              className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${owner.tone}`}
            >
              Fix: {owner.label}
            </span>
            <span className="text-[10px] sm:text-xs text-muted-foreground uppercase tracking-wider">
              {finding.category.replace(/_/g, " ")}
            </span>
            {detail && (
              <span className="text-[10px] text-muted-foreground border border-border rounded px-1.5 py-0.5">
                {effortLabel[detail.estimatedEffort]}
              </span>
            )}
          </div>
          <h3 className="font-semibold text-foreground text-sm sm:text-base break-words">
            {finding.title}
          </h3>
        </div>
        <span className="text-muted-foreground text-sm mt-1 shrink-0">
          {open ? "−" : "+"}
        </span>
      </button>
      {open && (
        <div
          id={`finding-body-${finding.id}`}
          className="px-3 sm:px-4 pb-4 space-y-4 border-t border-border bg-background/40"
        >
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1 mt-3">
              Description
            </p>
            <p className="text-sm text-foreground/90 leading-relaxed">
              {finding.description}
            </p>
          </div>

          {finding.evidence && (
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Evidence
              </p>
              <pre className="text-xs bg-muted/60 border border-border rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-foreground/80">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.cves && finding.cves.length > 0 && (
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Known CVEs
              </p>
              <ul className="space-y-1">
                {finding.cves.map((c) => (
                  <li key={c.id} className="text-xs">
                    <a
                      href={c.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-primary hover:underline font-mono"
                    >
                      {c.id}
                    </a>
                    <span className="text-muted-foreground"> — {c.summary}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {detail ? (
            <>
              <div>
                <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                  How to fix
                </p>
                <p className="text-sm text-foreground/90 leading-relaxed mb-2">
                  {detail.summary}
                </p>
                {detail.wixDashboardPath && (
                  <p className="text-xs text-muted-foreground italic mb-2">
                    Wix path: <span className="font-mono">{detail.wixDashboardPath}</span>
                  </p>
                )}
                <StepList steps={detail.steps} />
              </div>

              {detail.codeSnippets && detail.codeSnippets.length > 0 && (
                <div>
                  <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">
                    Code snippets
                  </p>
                  <div className="space-y-2">
                    {detail.codeSnippets.map((s, i) => (
                      <div key={i} className="space-y-1">
                        <p className="text-xs font-medium text-foreground/80">
                          {s.label}
                        </p>
                        <CodeBlock code={s.code} language={s.language} />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {detail.references.length > 0 && (
                <div>
                  <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                    References
                  </p>
                  <ul className="space-y-1">
                    {detail.references.map((r) => (
                      <li key={r.url}>
                        <a
                          href={r.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-primary hover:underline"
                        >
                          {r.title} ↗
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Remediation
              </p>
              <p className="text-sm text-foreground/90 leading-relaxed">
                {finding.remediation}
              </p>
              {finding.reference && (
                <a
                  href={finding.reference}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-block text-xs text-primary hover:underline mt-2"
                >
                  Reference ↗
                </a>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
