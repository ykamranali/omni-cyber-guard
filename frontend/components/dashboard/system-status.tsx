"use client";

interface ComponentStatus { name: string; status: string; detail: string }

const STATUS_COLOR: Record<string, string> = {
  operational: "bg-low",
  degraded: "bg-medium",
  down: "bg-critical",
};

export function SystemStatusWidget({ overallStatus, components }: { overallStatus: string; components: ComponentStatus[] }) {
  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${STATUS_COLOR[overallStatus] || "bg-muted"}`} />
        <span className="text-sm text-ink/85 capitalize">
          {overallStatus === "operational" ? "All systems operational" : `System status: ${overallStatus}`}
        </span>
      </div>
      <div className="space-y-1.5">
        {components.map((c) => (
          <div key={c.name} className="flex items-center justify-between text-xs">
            <span className="text-muted">{c.name}</span>
            <span className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${STATUS_COLOR[c.status] || "bg-muted"}`} />
              <span className="capitalize text-ink/70">{c.status}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
