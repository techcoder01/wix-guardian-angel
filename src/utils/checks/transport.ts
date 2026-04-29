import type { Finding, FixOwner } from "@/lib/scanner-types";

export function fixOwnerFor(category: string, isWix: boolean): FixOwner {
  if (!isWix) return "site_owner";
  switch (category) {
    case "headers":
    case "cookies":
    case "transport":
      return "wix_platform";
    case "third_party":
      return "third_party";
    case "content":
    case "forms":
    case "information_disclosure":
      return "site_owner";
    default:
      return "shared";
  }
}

export function checkTransport(url: string, finalUrl: string, isWix: boolean): Finding[] {
  const f: Finding[] = [];
  if (url.startsWith("http://") && !finalUrl.startsWith("https://")) {
    f.push({
      id: "no-https",
      title: "Site does not enforce HTTPS",
      category: "transport",
      severity: "critical",
      description:
        "The site is reachable over plaintext HTTP and does not redirect to HTTPS.",
      remediation: "Force HTTPS via a 301 redirect and enable HSTS.",
      fixOwner: fixOwnerFor("transport", isWix),
    });
  }
  return f;
}
