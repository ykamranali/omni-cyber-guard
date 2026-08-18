"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import {
  AlertTriangle, ShieldCheck, Server, TrendingUp, ChevronRight,
} from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/dashboard/score-ring";
import { SeverityDonut } from "@/components/dashboard/severity-donut";
import { HeroOrb } from "@/components/dashboard/hero-orb";
import { GeoAssetMap } from "@/components/dashboard/geo-asset-map";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { RiskTrendChart } from "@/components/dashboard/risk-trend-chart";
import { ComplianceRings } from "@/components/dashboard/compliance-rings";
import { SystemStatusWidget } from "@/components/dashboard/system-status";
import { api } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

interface DashboardSummary {
  security_score: number;
  risk_score: number;
  findings_by_severity: { critical: number; high: number; medium: number; low: number; info: number };
  total_assets: number;
  active_assets: number;
  asset_health_percent: number;
  compliance_status: Record<string, number>;
  remediation_progress_percent: number;
  open_findings: number;
  remediated_findings_last_30_days: number;
}
interface TrendPoint { date: string; security_score: number; risk_score: number; open_findings: number }
interface AssetOut { id: string; hostname: string; risk_score: number; asset_type: string; site: string | null; latitude: number | null; longitude: number | null }
interface ScanJobOut { id: string; target_cidr: string; status: string; hosts_discovered: number; findings_generated: number; created_at: string }
interface ComponentStatus { name: string; status: string; detail: string }
interface SystemStatusOut { overall_status: string; components: ComponentStatus[] }

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user);

  const { data: summary, isLoading, isError } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary"),
  });
  const { data: trend } = useQuery({
    queryKey: ["dashboard-trend"],
    queryFn: () => api.get<TrendPoint[]>("/dashboard/trend?days=7"),
    enabled: !!summary,
  });
  const { data: topRisky } = useQuery({
    queryKey: ["top-risky-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/top-risky-assets?limit=5"),
    enabled: !!summary,
  });
  const { data: geoAssets } = useQuery({
    queryKey: ["geo-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/geo-assets"),
    enabled: !!summary,
  });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanJobOut[]>("/scans"),
    enabled: !!summary,
  });
  const { data: systemStatus } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatusOut>("/system/status"),
    enabled: !!summary,
    refetchInterval: 30_000,
  });

  const severityData = summary
    ? [
        { name: "Critical", count: summary.findings_by_severity.critical },
        { name: "High", count: summary.findings_by_severity.high },
        { name: "Medium", count: summary.findings_by_severity.medium },
        { name: "Low", count: summary.findings_by_severity.low },
        { name: "Info", count: summary.findings_by_severity.info },
      ]
    : [];

  return (
    <>
      <Topbar title="Security Dashboard" criticalCount={summary?.findings_by_severity.critical ?? 0} />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        {isLoading && <p className="text-sm text-muted">Loading dashboard…</p>}
        {isError && (
          <p className="text-sm text-critical">
            Unable to load dashboard data. Confirm the backend API is running and reachable.
          </p>
        )}

        {summary && (
          <>
            <div>
              <h2 className="text-xl font-semibold text-ink">
                Welcome back{user?.full_name ? `, ${user.full_name.split(" ")[0]}` : ""}
              </h2>
              <p className="text-sm text-muted">Here&apos;s what&apos;s happening in your organization today.</p>
            </div>

            {/* Stat cards + hero */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <StatCard icon={Server} label="Total Assets" value={summary.total_assets} accent="text-primary" />
              <StatCard icon={AlertTriangle} label="Open Findings" value={summary.open_findings} accent="text-high" />
              <StatCard icon={ShieldCheck} label="Critical Risks" value={summary.findings_by_severity.critical} accent="text-critical" />
              <StatCard icon={TrendingUp} label="Asset Health" value={`${summary.asset_health_percent}%`} accent="text-low" />
              <StatCard icon={ShieldCheck} label="Remediated (30d)" value={summary.remediated_findings_last_30_days} accent="text-low" />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="jarvis-panel flex items-center justify-around gap-4 lg:col-span-1">
                <ScoreRing score={summary.security_score} label="Security Score" colorClass="#0EA5E9" />
                <ScoreRing score={summary.risk_score} label="Risk Score" colorClass="#EF4444" />
              </Card>

              <Card className="jarvis-panel flex flex-col lg:col-span-1">
                <CardHeader><CardTitle>Network Overview</CardTitle></CardHeader>
                <div className="flex-1">
                  <HeroOrb />
                </div>
              </Card>

              <Card className="jarvis-panel lg:col-span-1">
                <CardHeader>
                  <CardTitle>Top Risky Assets</CardTitle>
                  <Link href="/assets" className="flex items-center gap-1 text-xs text-primary hover:underline">
                    View all <ChevronRight size={12} />
                  </Link>
                </CardHeader>
                {topRisky && topRisky.length > 0 ? (
                  <div className="space-y-2">
                    {topRisky.map((a) => (
                      <div key={a.id} className="flex items-center justify-between text-sm">
                        <div className="min-w-0">
                          <p className="truncate text-ink/85">{a.hostname}</p>
                          <p className="text-xs text-muted">{a.site || a.asset_type}</p>
                        </div>
                        <Badge label={a.risk_score >= 66 ? "critical" : a.risk_score >= 33 ? "high" : "low"} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">
                    No risk-scored assets yet — risk scores are computed from real findings, so this fills in as you add findings or run a scan.
                  </p>
                )}
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="jarvis-panel lg:col-span-2">
                <CardHeader><CardTitle>Findings by Severity</CardTitle></CardHeader>
                <SeverityDonut data={severityData} />
              </Card>
              <Card className="jarvis-panel">
                <CardHeader><CardTitle>Recent Scans</CardTitle></CardHeader>
                <RecentScans scans={scans || []} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="jarvis-panel lg:col-span-2">
                <CardHeader>
                  <CardTitle>Geographic Asset Distribution</CardTitle>
                </CardHeader>
                <GeoAssetMap assets={geoAssets || []} />
              </Card>
              <Card className="jarvis-panel">
                <CardHeader><CardTitle>Risk Trend (Last 7 Days)</CardTitle></CardHeader>
                <RiskTrendChart data={trend || []} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="jarvis-panel">
                <CardHeader><CardTitle>Remediation Progress</CardTitle></CardHeader>
                <div className="mb-2 h-3 w-full overflow-hidden rounded-full bg-surface-hover border border-primary/20">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-primary to-secondary shadow-neon"
                    style={{ width: `${summary.remediation_progress_percent}%` }}
                  />
                </div>
                <p className="text-sm font-semibold neon-text text-primary">{summary.remediation_progress_percent}% <span className="text-muted font-normal">of all findings remediated</span></p>
              </Card>

              <Card className="jarvis-panel lg:col-span-2">
                <CardHeader><CardTitle>Compliance Overview</CardTitle></CardHeader>
                <ComplianceRings status={summary.compliance_status} />
              </Card>
            </div>

            {systemStatus && (
              <Card className="jarvis-panel border-primary/50 shadow-neon">
                <CardHeader><CardTitle className="neon-text text-primary flex items-center gap-2"><div className="h-2 w-2 bg-primary rounded-full animate-pulse-glow"/> System Status</CardTitle></CardHeader>
                <SystemStatusWidget overallStatus={systemStatus.overall_status} components={systemStatus.components} />
              </Card>
            )}
          </>
        )}
      </main>
    </>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: typeof AlertTriangle;
  label: string;
  value: string | number;
  accent: string;
}) {
  return (
    <Card className="jarvis-panel relative group hover:border-primary/80 transition-colors">
      <div className="flex items-center gap-4">
        <div className={`glossy-icon p-3 rounded-xl border border-current shadow-neon transition-transform group-hover:scale-110 ${accent}`}>
          <Icon size={22} className="animate-pulse-glow" />
        </div>
        <div>
          <p className={`text-3xl font-bold tracking-tight neon-text ${accent}`}>{value}</p>
          <p className="text-[10px] tracking-widest uppercase text-muted font-bold mt-1">{label}</p>
        </div>
      </div>
    </Card>
  );
}
