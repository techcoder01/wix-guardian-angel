import type { Severity } from "@/lib/scanner-types";

const styles: Record<Severity, string> = {
  critical: "bg-[oklch(var(--severity-critical)/0.18)] text-[oklch(var(--severity-critical))] border-[oklch(var(--severity-critical)/0.4)]",
  high: "bg-[oklch(var(--severity-high)/0.18)] text-[oklch(var(--severity-high))] border-[oklch(var(--severity-high)/0.4)]",
  medium: "bg-[oklch(var(--severity-medium)/0.18)] text-[oklch(var(--severity-medium))] border-[oklch(var(--severity-medium)/0.4)]",
  low: "bg-[oklch(var(--severity-low)/0.18)] text-[oklch(var(--severity-low))] border-[oklch(var(--severity-low)/0.4)]",
  info: "bg-[oklch(var(--severity-info)/0.18)] text-[oklch(var(--severity-info))] border-[oklch(var(--severity-info)/0.4)]",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wider ${styles[severity]}`}
    >
      {severity}
    </span>
  );
}