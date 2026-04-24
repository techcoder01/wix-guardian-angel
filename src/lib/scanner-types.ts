export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FixOwner = "site_owner" | "wix_platform" | "third_party" | "shared";
export type Category =
  | "headers"
  | "cookies"
  | "transport"
  | "content"
  | "forms"
  | "information_disclosure"
  | "third_party"
  | "configuration";

export interface Finding {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  evidence?: string;
  remediation: string;
  fixOwner: FixOwner;
  reference?: string;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  scannedAt: string;
  durationMs: number;
  isWix: boolean;
  platformSignals: string[];
  statusCode: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  responseHeaders: Record<string, string>;
}

export interface ScanError {
  error: string;
}