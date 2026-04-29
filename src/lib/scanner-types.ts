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
  | "configuration"
  | "wix_platform"
  | "velo"
  | "cms"
  | "members";

export type EffortEstimate =
  | "minutes"
  | "hours"
  | "days"
  | "platform_dependent";

export interface RemediationStep {
  owner: FixOwner;
  action: string;
  details?: string;
}

export interface RemediationCodeSnippet {
  label: string;
  language: string;
  code: string;
}

export interface RemediationReference {
  title: string;
  url: string;
}

export interface Remediation {
  summary: string;
  steps: RemediationStep[];
  codeSnippets?: RemediationCodeSnippet[];
  wixDashboardPath?: string;
  references: RemediationReference[];
  estimatedEffort: EffortEstimate;
}

export interface CveMatch {
  id: string;
  summary: string;
  severity?: Severity;
  url: string;
}

export interface Finding {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  evidence?: string;
  /**
   * Short remediation string. Kept for backwards-compatibility with existing
   * tests and JSON exports. New UI consumers should prefer `remediationDetail`.
   */
  remediation: string;
  remediationDetail?: Remediation;
  fixOwner: FixOwner;
  reference?: string;
  cves?: CveMatch[];
}

export interface CrawledResource {
  url: string;
  status: number;
  contentType?: string;
  bytes?: number;
  ok: boolean;
  error?: string;
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
  crawled?: CrawledResource[];
}

export interface ScanError {
  error: string;
}
