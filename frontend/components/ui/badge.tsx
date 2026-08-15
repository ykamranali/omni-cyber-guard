import { cn } from "@/lib/utils";

const severityColors: Record<string, string> = {
  critical: "bg-critical/15 text-critical border-critical/30",
  high: "bg-high/15 text-high border-high/30",
  medium: "bg-medium/15 text-medium border-medium/30",
  low: "bg-low/15 text-low border-low/30",
  info: "bg-info/15 text-info border-info/30",
  active: "bg-low/15 text-low border-low/30",
  inactive: "bg-muted/15 text-muted border-muted/30",
  decommissioned: "bg-critical/15 text-critical border-critical/30",
  quarantined: "bg-high/15 text-high border-high/30",
  open: "bg-high/15 text-high border-high/30",
  in_progress: "bg-medium/15 text-medium border-medium/30",
  remediated: "bg-low/15 text-low border-low/30",
  false_positive: "bg-muted/15 text-muted border-muted/30",
  accepted_risk: "bg-info/15 text-info border-info/30",
};

export function Badge({ label }: { label: string }) {
  const key = label.toLowerCase();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize",
        severityColors[key] || "bg-surface-hover text-ink/75 border-border"
      )}
    >
      {label.replace(/_/g, " ")}
    </span>
  );
}
