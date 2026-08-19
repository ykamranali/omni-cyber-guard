"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileBarChart2, Download, FileText, FileSpreadsheet, Loader2, Sparkles } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";
import { motion } from "framer-motion";

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

  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const item = {
    hidden: { opacity: 0, scale: 0.95, y: 20 },
    show: { opacity: 1, scale: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <div className="flex flex-col gap-8 p-8 max-w-7xl mx-auto w-full">
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-4 border-b border-border/50 pb-6"
      >
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 shadow-neon">
          <FileBarChart2 className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink neon-text">Report Generation</h1>
          <p className="text-muted mt-1">Compile and export professional security reports for executive and technical audiences.</p>
        </div>
      </motion.div>

      <motion.div 
        variants={container}
        initial="hidden"
        animate="show"
        className="grid gap-8 md:grid-cols-2 lg:grid-cols-3"
      >
        {/* Executive Report */}
        <motion.div variants={item} className="group flex flex-col gap-6 rounded-2xl glass-panel p-8 transition-all duration-300 hover:shadow-neon hover:border-primary/50 relative overflow-hidden">
          <div className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-red-500/5 blur-3xl group-hover:bg-red-500/10 transition-colors" />
          
          <div className="flex items-start gap-4 relative z-10">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-red-500/10 text-red-500 border border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
              <FileText className="h-6 w-6" />
            </div>
            <div>
              <h3 className="font-bold text-ink text-lg tracking-wide">Executive Summary</h3>
              <p className="text-xs font-mono tracking-widest text-red-500 uppercase mt-1">PDF Format</p>
            </div>
          </div>
          <p className="text-sm text-muted leading-relaxed flex-1 relative z-10">
            A high-level overview of your organization's security posture, including total assets, risk scores, and critical vulnerability summaries suitable for C-suite presentation.
          </p>
          <div className="mt-auto relative z-10 pt-4 border-t border-border/50">
            <button
              onClick={() => downloadReport("/reports/executive/pdf", "Executive_Security_Report.pdf", setIsGeneratingExe)}
              disabled={isGeneratingExe}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-surface-hover border border-border/50 px-4 py-3 text-sm font-semibold text-ink transition-all hover:bg-red-500 hover:text-white hover:border-red-500 hover:shadow-[0_0_15px_rgba(239,68,68,0.5)] disabled:opacity-50 group-hover:bg-primary/5"
            >
              {isGeneratingExe ? <Loader2 className="h-5 w-5 animate-spin" /> : <Download className="h-5 w-5" />}
              {isGeneratingExe ? "Generating Report..." : "Compile & Download"}
            </button>
          </div>
        </motion.div>

        {/* Technical Report */}
        <motion.div variants={item} className="group flex flex-col gap-6 rounded-2xl jarvis-panel p-8 transition-all duration-300 hover:shadow-neon hover:border-primary/50 relative overflow-hidden">
          <div className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-primary/5 blur-3xl group-hover:bg-primary/10 transition-colors" />
          
          <div className="flex items-start gap-4 relative z-10">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_rgba(14,165,233,0.2)]">
              <Sparkles className="h-6 w-6" />
            </div>
            <div>
              <h3 className="font-bold text-ink text-lg tracking-wide">Technical Details</h3>
              <p className="text-xs font-mono tracking-widest text-primary uppercase mt-1">PDF Format</p>
            </div>
          </div>
          <p className="text-sm text-muted leading-relaxed flex-1 relative z-10">
            Detailed technical breakdown of all open findings, including CVEs, CVSS scores, affected assets, and remediation steps intended for engineering teams.
          </p>
          
          <div className="flex flex-col gap-3 mt-auto relative z-10 pt-4 border-t border-primary/20">
            <label className="text-xs font-semibold text-muted uppercase tracking-wider">Scope Selection</label>
            <select
              value={scanIdTech}
              onChange={(e) => setScanIdTech(e.target.value)}
              className="h-10 w-full rounded-xl border border-primary/30 bg-surface-hover/50 px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary transition-all"
            >
              <option value="all">Global Workspace (All Scans)</option>
              {scans?.filter(s => s.status === "completed").map((s) => (
                <option key={s.id} value={s.id}>
                  Scan Target: {s.target_cidr}
                </option>
              ))}
            </select>
            <button 
              onClick={() => {
                const url = scanIdTech !== "all" ? `/reports/technical/pdf?scan_id=${scanIdTech}` : "/reports/technical/pdf";
                downloadReport(url, "Technical_Vulnerability_Report.pdf", setIsGeneratingTech);
              }}
              disabled={isGeneratingTech}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 hover:shadow-neon disabled:opacity-50 mt-1"
            >
              {isGeneratingTech ? <Loader2 className="h-5 w-5 animate-spin" /> : <Download className="h-5 w-5" />}
              {isGeneratingTech ? "Generating Report..." : "Compile & Download"}
            </button>
          </div>
        </motion.div>
        
        {/* Asset Export */}
        <motion.div variants={item} className="group flex flex-col gap-6 rounded-2xl glass-panel p-8 transition-all duration-300 hover:shadow-[0_0_15px_rgba(34,197,94,0.4)] hover:border-green-500/50 relative overflow-hidden">
          <div className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-green-500/5 blur-3xl group-hover:bg-green-500/10 transition-colors" />
          
          <div className="flex items-start gap-4 relative z-10">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-green-500/10 text-green-500 border border-green-500/20 shadow-[0_0_15px_rgba(34,197,94,0.2)]">
              <FileSpreadsheet className="h-6 w-6" />
            </div>
            <div>
              <h3 className="font-bold text-ink text-lg tracking-wide">Asset Inventory</h3>
              <p className="text-xs font-mono tracking-widest text-green-500 uppercase mt-1">CSV Raw Export</p>
            </div>
          </div>
          <p className="text-sm text-muted leading-relaxed flex-1 relative z-10">
            Raw, unfiltered data export of all discovered and manually entered assets across your organization for external BI tools.
          </p>
          
          <div className="flex flex-col gap-3 mt-auto relative z-10 pt-4 border-t border-border/50">
            <label className="text-xs font-semibold text-muted uppercase tracking-wider">Scope Selection</label>
            <select
              value={scanIdAsset}
              onChange={(e) => setScanIdAsset(e.target.value)}
              className="h-10 w-full rounded-xl border border-border/50 bg-surface-hover/50 px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-green-500/50 transition-all"
            >
              <option value="all">Global Workspace (All Scans)</option>
              {scans?.filter(s => s.status === "completed").map((s) => (
                <option key={s.id} value={s.id}>
                  Scan Target: {s.target_cidr}
                </option>
              ))}
            </select>
            <button 
              onClick={() => {
                const url = scanIdAsset !== "all" ? `/assets/export/csv?scan_id=${scanIdAsset}` : "/assets/export/csv";
                window.location.href = `http://localhost:8000/api/v1${url}`;
              }}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-surface-hover border border-border/50 px-4 py-3 text-sm font-semibold text-ink transition-all hover:bg-green-500 hover:text-white hover:border-green-500 hover:shadow-[0_0_15px_rgba(34,197,94,0.5)] mt-1"
            >
              <Download className="h-5 w-5" /> Export Data
            </button>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
}

