"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileBarChart2, Download, FileText, FileSpreadsheet, Loader2 } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";

export default function ReportsPage() {
  const [isGeneratingExe, setIsGeneratingExe] = useState(false);
  const [isGeneratingTech, setIsGeneratingTech] = useState(false);
  const [scanIdTech, setScanIdTech] = useState("all");
  const [scanIdAsset, setScanIdAsset] = useState("all");
  const token = useAuthStore((s) => s.accessToken);

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<any[]>("/scans"),
  });

  const downloadReport = async (url: string, filename: string, setGenerating: (v: boolean) => void) => {
    setGenerating(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1${url}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to generate report");
      
      const blob = await res.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objectUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error("Download failed", error);
      alert("Failed to download the report. Please ensure the backend is running and you have sufficient permissions.");
    } finally {
      setGenerating(false);
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
            onClick={() => downloadReport("/reports/executive/pdf", "Executive_Security_Report.pdf", setIsGeneratingExe)}
            disabled={isGeneratingExe}
            className="flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {isGeneratingExe ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {isGeneratingExe ? "Generating..." : "Download PDF"}
          </button>
        </div>

        <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm">
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
          <div className="flex flex-col gap-2">
            <select
              value={scanIdTech}
              onChange={(e) => setScanIdTech(e.target.value)}
              className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="all">All Scans</option>
              {scans?.filter(s => s.status === "completed").map((s) => (
                <option key={s.id} value={s.id}>
                  Scan: {s.target_cidr}
                </option>
              ))}
            </select>
            <button 
              onClick={() => {
                const url = scanIdTech !== "all" ? `/reports/technical/pdf?scan_id=${scanIdTech}` : "/reports/technical/pdf";
                downloadReport(url, "Technical_Vulnerability_Report.pdf", setIsGeneratingTech);
              }}
              disabled={isGeneratingTech}
              className="flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
            >
              {isGeneratingTech ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              {isGeneratingTech ? "Generating..." : "Download PDF"}
            </button>
          </div>
        </div>
        
        <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-6 shadow-sm">
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
          <div className="flex flex-col gap-2">
            <select
              value={scanIdAsset}
              onChange={(e) => setScanIdAsset(e.target.value)}
              className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="all">All Scans</option>
              {scans?.filter(s => s.status === "completed").map((s) => (
                <option key={s.id} value={s.id}>
                  Scan: {s.target_cidr}
                </option>
              ))}
            </select>
            <button 
              onClick={() => {
                const url = scanIdAsset !== "all" ? `/assets/export/csv?scan_id=${scanIdAsset}` : "/assets/export/csv";
                // Using standard HTML download for CSV
                window.location.href = `http://localhost:8000/api/v1${url}`;
              }}
              className="flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90"
            >
              <Download className="h-4 w-4" /> Download CSV
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
