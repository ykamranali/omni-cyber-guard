"use client";

import { useState } from "react";
import { 
  FileBarChart2, Download, FileText, 
  ShieldCheck, Activity, Calendar
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function ReportsPage() {
  const [downloading, setDownloading] = useState<string | null>(null);

  const downloadReport = async (type: string, url: string) => {
    try {
      setDownloading(type);
      // In a real app we'd fetch with auth headers, but assuming cookie-based or just triggering a download
      const response = await fetch(`/api/v1/reports/${url}`);
      
      if (!response.ok) throw new Error("Download failed");
      
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `${type}_Report_${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(downloadUrl);
      document.body.removeChild(a);
    } catch (error) {
      console.error("Failed to download report:", error);
    } finally {
      setDownloading(null);
    }
  };

  const reports = [
    {
      id: "executive",
      title: "Executive Security Summary",
      description: "High-level overview of organizational risk, compliance posture, and remediation progress designed for C-suite and board members.",
      icon: ShieldCheck,
      color: "text-emerald-500",
      bg: "bg-emerald-500/10 border-emerald-500/30 shadow-emerald-500/10",
      url: "executive/pdf"
    },
    {
      id: "technical",
      title: "Technical Vulnerability Report",
      description: "Detailed breakdown of discovered vulnerabilities, affected assets, CVSS/EPSS scores, and step-by-step remediation guidance for engineers.",
      icon: Activity,
      color: "text-blue-500",
      bg: "bg-blue-500/10 border-blue-500/30 shadow-blue-500/10",
      url: "technical/pdf"
    }
  ];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Reports</h1>
          <p className="mt-2 text-muted">Generate and download comprehensive security reports</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {reports.map((report) => (
          <div key={report.id} className={cn("premium-card p-6 flex flex-col group", report.bg)}>
            <div className="absolute -right-12 -top-12 rounded-full p-20 blur-[60px] opacity-50 bg-current text-inherit transition-all duration-500 group-hover:scale-125" style={{ color: "var(--tw-text-opacity)" }} />
            <div className="premium-card-inner"></div>
            
            <div className="relative z-10 flex flex-col h-full">
              <div className="flex items-start justify-between">
                <div className={cn("premium-glass-icon p-3 w-14 h-14", report.color)}>
                  <report.icon className="h-8 w-8 drop-shadow-[0_0_8px_currentColor]" />
                </div>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/5 backdrop-blur-md px-3 py-1 text-xs font-semibold text-ink shadow-sm">
                  <FileText className="h-3.5 w-3.5" /> PDF
                </span>
              </div>
              
              <div className="mt-6 flex-1">
                <h3 className="text-xl font-bold text-ink drop-shadow-md">{report.title}</h3>
                <p className="mt-2 text-sm text-muted/90 leading-relaxed">{report.description}</p>
              </div>
              
              <div className="mt-8 pt-4 border-t border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-muted font-medium">
                  <Calendar className="h-4 w-4" />
                  <span>Latest Snapshot</span>
                </div>
                
                <button
                  onClick={() => downloadReport(report.id, report.url)}
                  disabled={downloading === report.id}
                  className={cn(
                    "relative flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-primary-foreground transition-all duration-300 overflow-hidden",
                    downloading === report.id 
                      ? "bg-primary/50 cursor-wait shadow-[0_0_15px_rgba(var(--color-primary)/0.2)]"
                      : "bg-primary shadow-[0_0_15px_rgba(var(--color-primary)/0.5)] hover:bg-primary/90 hover:shadow-[0_0_25px_rgba(var(--color-primary)/0.7)] hover:scale-105"
                  )}
                >
                  {downloading === report.id && (
                    <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(255,255,255,0.2)_50%,transparent_75%,transparent_100%)] bg-[length:250%_250%,100%_100%] animate-[gradient_2s_linear_infinite]" />
                  )}
                  <Download className={cn("h-4 w-4 relative z-10", downloading === report.id && "animate-bounce")} />
                  <span className="relative z-10">{downloading === report.id ? "Generating..." : "Download"}</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
