"use client";

import { PieChart, Pie, Cell } from "recharts";

export function ScoreRing({ score, label, colorClass }: { score: number; label: string; colorClass: string }) {
  const data = [
    { value: score },
    { value: 100 - score },
  ];
  const colorVar = colorClass;

  return (
    <div className="flex flex-col items-center">
      <div className="relative h-32 w-32">
        <PieChart width={128} height={128}>
          <Pie
            data={data}
            dataKey="value"
            innerRadius={48}
            outerRadius={60}
            startAngle={90}
            endAngle={-270}
            stroke="none"
          >
            <Cell fill={colorVar} />
            <Cell fill="rgba(148,163,184,0.2)" />
          </Pie>
        </PieChart>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-ink">{Math.round(score)}</span>
          <span className="text-[10px] text-muted">/ 100</span>
        </div>
      </div>
      <p className="mt-2 text-sm font-medium text-ink/75">{label}</p>
    </div>
  );
}
