import type { Finding } from "@/lib/scanner-types";

export interface DiffResult {
  added: string[];
  fixed: string[];
  unchanged: number;
}

export function computeDiff(current: Finding[], previous?: Finding[]): DiffResult {
  if (!previous) return { added: [], fixed: [], unchanged: 0 };
  const cur = new Set(current.map((f) => f.id));
  const prev = new Set(previous.map((f) => f.id));
  const added = [...cur].filter((id) => !prev.has(id));
  const fixed = [...prev].filter((id) => !cur.has(id));
  const unchanged = [...cur].filter((id) => prev.has(id)).length;
  return { added, fixed, unchanged };
}
