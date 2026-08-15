"use client";

import { PieChart, Pie, Cell } from "recharts";

const COLORS: Record<string, string> = {
  Critical: "#EF4444", High: "#F97316", Medium: "#EAB308", Low: "#22C55E", Info: "#38BDF8",
};

export function SeverityDonut({ data }: { data: { name: string; count: number }[] }) {
  const total = data.reduce((sum, d) => sum + d.count, 0);
  const nonZero = data.filter((d) => d.count > 0);

  return (
    <div className="flex items-center gap-6">
      <div className="relative h-40 w-40 shrink-0">
        <PieChart width={160} height={160}>
          <Pie
            data={nonZero.length ? nonZero : [{ name: "None", count: 1 }]}
            dataKey="count"
            nameKey="name"
            innerRadius={52}
            outerRadius={72}
            paddingAngle={nonZero.length > 1 ? 2 : 0}
            stroke="none"
          >
            {(nonZero.length ? nonZero : [{ name: "None", count: 1 }]).map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || "rgba(148,163,184,0.25)"} />
            ))}
          </Pie>
        </PieChart>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold text-ink">{total}</span>
          <span className="text-[10px] text-muted">Total</span>
        </div>
      </div>
      <div className="space-y-1.5">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-2 text-xs">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: COLORS[d.name] }} />
            <span className="w-14 text-ink/75">{d.name}</span>
            <span className="text-muted">
              {d.count} {total > 0 ? `(${((d.count / total) * 100).toFixed(1)}%)` : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
