"use client";

import { useState } from "react";
import { FileBarChart2, Download, FileText, FileSpreadsheet, Loader2 } from "lucide-react";
import { useAuthStore } from "@/store/auth";

export default function ReportsPage() {
  const [isGenerating, setIsGenerating] = useState(false);
  const token = useAuthStore((s) => s.accessToken);

  const downloadExecutiveReport = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/reports/executive/pdf", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!res.ok) throw new Error("Failed to generate report");
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "Executive_Security_Report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Download failed", error);
      alert("Failed to download the report. Please ensure the backend is running and you have sufficient permissions.");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3 border-b border-border pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-secondary">
          <FileBarChart2 className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink">Reports</h1>
          <p className="text-sm text-muted">Generate and download professional security reports</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10 text-red-500">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-ink">Executive Security Report</h3>
              <p className="text-xs text-muted">PDF Format</p>
            </div>
          </div>
          <p className="text-sm text-muted flex-1">
            A high-level overview of your organization&apos;s security posture, including total assets, risk scores, and critical vulnerability summaries.
          </p>
          <button
            onClick={downloadExecutiveReport}
            disabled={isGenerating}
            className="flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {isGenerating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {isGenerating ? "Generating..." : "Download PDF"}
          </button>
        </div>

        <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm opacity-50">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10 text-blue-500">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-ink">Technical Vulnerability Report</h3>
              <p className="text-xs text-muted">PDF Format</p>
            </div>
          </div>
          <p className="text-sm text-muted flex-1">
            Detailed technical breakdown of all open findings, including CVEs, CVSS scores, affected assets, and remediation steps.
          </p>
          <button disabled className="flex items-center justify-center gap-2 rounded-lg bg-surface-hover px-4 py-2 text-sm font-medium text-muted transition-colors">
            Coming Soon
          </button>
        </div>
        
        <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm opacity-50">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-500/10 text-green-500">
              <FileSpreadsheet className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-ink">Asset Inventory Export</h3>
              <p className="text-xs text-muted">CSV Format</p>
            </div>
          </div>
          <p className="text-sm text-muted flex-1">
            Raw export of all discovered and manually entered assets across your organization.
          </p>
          <button disabled className="flex items-center justify-center gap-2 rounded-lg bg-surface-hover px-4 py-2 text-sm font-medium text-muted transition-colors">
            Coming Soon
          </button>
        </div>
      </div>
    </div>
  );
}
