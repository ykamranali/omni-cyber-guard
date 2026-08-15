"use client";

import { PieChart, Pie, Cell } from "recharts";

const RING_COLORS = ["#0EA5E9", "#7C3AED", "#22C55E", "#F97316", "#EAB308", "#38BDF8", "#EF4444"];

export function ComplianceRings({ status }: { status: Record<string, number> }) {
  const entries = Object.entries(status);

  if (entries.length === 0) {
    return (
      <p className="text-xs text-muted">
        No compliance frameworks initialized for this organization yet.
      </p>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-4 sm:grid-cols-4 lg:grid-cols-7">
      {entries.map(([name, pct], i) => (
        <div key={name} className="flex flex-col items-center">
          <div className="relative h-16 w-16">
            <PieChart width={64} height={64}>
              <Pie
                data={[{ value: pct }, { value: 100 - pct }]}
                dataKey="value"
                innerRadius={22}
                outerRadius={30}
                startAngle={90}
                endAngle={-270}
                stroke="none"
              >
                <Cell fill={RING_COLORS[i % RING_COLORS.length]} />
                <Cell fill="rgba(148,163,184,0.2)" />
              </Pie>
            </PieChart>
            <div className="absolute inset-0 flex items-center justify-center text-[11px] font-semibold text-ink">
              {Math.round(pct)}%
            </div>
          </div>
          <p className="mt-1 text-center text-[10px] leading-tight text-muted">{name}</p>
        </div>
      ))}
    </div>
  );
}
