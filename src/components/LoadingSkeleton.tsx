export function LoadingSkeleton() {
  return (
    <div className="space-y-5 animate-pulse" role="status" aria-label="Loading scan results…">
      {/* Summary card */}
      <div className="rounded-lg border border-border bg-card p-5 space-y-4">
        <div className="h-4 w-48 rounded bg-muted" />
        <div className="h-6 w-72 rounded bg-muted" />
        <div className="grid sm:grid-cols-2 gap-5">
          <div className="space-y-2">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="flex items-center gap-2">
                <div className="h-3 w-16 rounded bg-muted" />
                <div className="flex-1 h-2 rounded-full bg-muted" />
                <div className="h-3 w-4 rounded bg-muted" />
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="rounded-md border border-border bg-background/40 p-3 space-y-1">
                <div className="h-6 w-8 rounded bg-muted" />
                <div className="h-2 w-16 rounded bg-muted" />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Result card */}
      <div className="rounded-lg border border-border bg-card p-5 space-y-4">
        <div className="flex justify-between">
          <div className="space-y-1">
            <div className="h-3 w-12 rounded bg-muted" />
            <div className="h-4 w-64 rounded bg-muted" />
            <div className="h-3 w-40 rounded bg-muted" />
          </div>
          <div className="flex gap-2">
            <div className="h-8 w-16 rounded-md bg-muted" />
            <div className="h-8 w-24 rounded-md bg-muted" />
          </div>
        </div>
        <div className="grid grid-cols-5 gap-2">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="rounded-md border border-border p-3 space-y-1">
              <div className="h-7 w-6 rounded bg-muted mx-auto" />
              <div className="h-2 w-12 rounded bg-muted mx-auto" />
            </div>
          ))}
        </div>
      </div>

      {/* Finding skeletons */}
      {[...Array(3)].map((_, i) => (
        <div key={i} className="rounded-lg border border-border bg-card p-4 space-y-2">
          <div className="flex gap-2">
            <div className="h-5 w-16 rounded-md bg-muted" />
            <div className="h-5 w-20 rounded-md bg-muted" />
            <div className="h-5 w-14 rounded-md bg-muted" />
          </div>
          <div className="h-4 w-3/4 rounded bg-muted" />
        </div>
      ))}

      <span className="sr-only">Scanning — please wait…</span>
    </div>
  );
}
