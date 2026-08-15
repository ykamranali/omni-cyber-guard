"use client";

import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

interface TrendPoint { date: string; security_score: number; risk_score: number; open_findings: number }

export function RiskTrendChart({ data }: { data: TrendPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="flex h-56 items-center justify-center text-center text-xs text-muted px-6">
        No trend history yet — a snapshot is recorded automatically each day you use the dashboard.
        Check back tomorrow to see this fill in.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={224}>
      <LineChart data={data} margin={{ left: -20, right: 10, top: 10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" vertical={false} />
        <XAxis dataKey="date" tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid #1F2937", borderRadius: 8, fontSize: 12 }} />
        <Line type="monotone" dataKey="risk_score" stroke="#EF4444" strokeWidth={2} dot={{ r: 3 }} name="Risk Score" />
        <Line type="monotone" dataKey="security_score" stroke="#0EA5E9" strokeWidth={2} dot={{ r: 3 }} name="Security Score" />
      </LineChart>
    </ResponsiveContainer>
  );
}
