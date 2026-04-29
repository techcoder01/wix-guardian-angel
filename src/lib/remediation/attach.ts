import type { Finding } from "@/lib/scanner-types";
import { getRemediation } from "./registry";

/**
 * Hydrates each finding with its `remediationDetail` from the registry. Pure
 * function: returns a new array with new objects, no mutation.
 */
export function attachRemediationDetails(findings: Finding[]): Finding[] {
  return findings.map((f) => ({
    ...f,
    remediationDetail: getRemediation(f.id, f.remediation),
  }));
}
