"use client";

import { useEffect, useState } from "react";
import { FileCheck2, Loader2, ShieldCheck, AlertTriangle } from "lucide-react";
import { useAuthStore } from "@/store/auth";

interface Framework {
  id: string;
  name: string;
  coverage_percent: number;
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    async function fetchFrameworks() {
      try {
        const res = await fetch("http://localhost:8000/api/v1/compliance/frameworks", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setFrameworks(data);
        }
      } catch (error) {
        console.error("Failed to fetch compliance frameworks", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchFrameworks();
  }, [token]);

  return (
    <div className="flex h-full flex-col gap-6 p-6">
      <div className="flex items-center gap-3 border-b border-border pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-secondary">
          <FileCheck2 className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink">Compliance Engine</h1>
          <p className="text-sm text-muted">Track alignment with ISO 27001, NIST CSF, and other industry standards</p>
        </div>
      </div>

      {isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      ) : frameworks.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-surface p-12 text-center shadow-sm">
          <ShieldCheck className="mb-4 h-12 w-12 text-muted" />
          <h3 className="mb-2 text-lg font-medium text-ink">No Frameworks Configured</h3>
          <p className="text-sm text-muted">Your organization has not yet set up any compliance frameworks.</p>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2">
          {frameworks.map((fw) => (
            <div key={fw.id} className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm hover:border-primary/50 transition-colors">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-ink text-lg">{fw.name}</h3>
                <span className={`text-sm font-semibold ${fw.coverage_percent > 80 ? 'text-green-500' : fw.coverage_percent > 50 ? 'text-yellow-500' : 'text-red-500'}`}>
                  {fw.coverage_percent.toFixed(1)}% Compliant
                </span>
              </div>
              
              <div className="h-3 w-full overflow-hidden rounded-full bg-surface-hover">
                <div
                  className={`h-full ${fw.coverage_percent > 80 ? 'bg-green-500' : fw.coverage_percent > 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{ width: `${fw.coverage_percent}%` }}
                />
              </div>

              <div className="mt-4 flex flex-col gap-2 border-t border-border pt-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">Top Deficiencies</h4>
                {fw.coverage_percent < 100 ? (
                  <div className="flex items-start gap-2 text-sm text-ink bg-red-500/10 p-3 rounded-lg border border-red-500/20">
                    <AlertTriangle className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
                    <p>Some critical controls lack technical evidence. Review open vulnerabilities mapped to this framework.</p>
                  </div>
                ) : (
                  <p className="text-sm text-green-500">All mapped controls have satisfactory evidence.</p>
                )}
                <button className="mt-2 rounded-lg bg-surface-hover px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-border w-fit">
                  View Detailed Controls
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
