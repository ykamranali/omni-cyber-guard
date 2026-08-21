"use client";

import { useEffect, useState } from "react";
import { FileCheck2, Loader2, ShieldCheck, AlertTriangle, ArrowRight } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";
import { motion } from "framer-motion";

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
        setFrameworks(await api.get<Framework[]>("/compliance/frameworks"));
      } catch (error) {
        console.error("Failed to fetch compliance frameworks", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchFrameworks();
  }, [token]);

  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <div className="flex h-full flex-col gap-8 p-8 max-w-7xl mx-auto w-full">
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-4 border-b border-border/50 pb-6"
      >
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 shadow-[0_0_15px_rgba(var(--color-primary)/0.2)]">
          <FileCheck2 className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink neon-text">Compliance Engine</h1>
          <p className="text-muted mt-1">Track and enforce alignment with industry standards and regulatory frameworks</p>
        </div>
      </motion.div>

      {isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-10 w-10 animate-spin text-primary" />
        </div>
      ) : frameworks.length === 0 ? (
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-center justify-center rounded-2xl jarvis-panel p-16 text-center"
        >
          <div className="rounded-full bg-primary/10 p-6 mb-6">
            <ShieldCheck className="h-16 w-16 text-primary neon-pulse-border rounded-full" />
          </div>
          <h3 className="mb-3 text-2xl font-semibold text-ink">No Frameworks Configured</h3>
          <p className="text-muted max-w-md">Your organization has not yet mapped any assets or findings to a compliance framework. Initialize a standard like SOC2 or ISO 27001 to begin tracking.</p>
          <button className="mt-8 rounded-lg bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 shadow-[0_0_15px_rgba(var(--color-primary)/0.4)]">
            Configure Frameworks
          </button>
        </motion.div>
      ) : (
        <motion.div 
          variants={container}
          initial="hidden"
          animate="show"
          className="grid gap-8 lg:grid-cols-2"
        >
          {frameworks.map((fw) => {
            const isGood = fw.coverage_percent > 80;
            const isWarn = fw.coverage_percent > 50 && fw.coverage_percent <= 80;
            
            return (
              <motion.div 
                key={fw.id} 
                variants={item}
                className="group flex flex-col gap-6 rounded-2xl glass-panel p-8 transition-all duration-300 hover:shadow-neon hover:border-primary/50 relative overflow-hidden"
              >
                {/* Background decorative gradient */}
                <div className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-primary/5 blur-3xl group-hover:bg-primary/10 transition-colors" />

                <div className="flex items-start justify-between relative z-10">
                  <div>
                    <h3 className="font-bold text-ink text-xl mb-1">{fw.name}</h3>
                    <p className="text-sm text-muted">Continuous Compliance Monitoring</p>
                  </div>
                  <div className={`flex flex-col items-end`}>
                    <span className={`text-3xl font-bold tracking-tighter ${isGood ? 'text-green-500' : isWarn ? 'text-yellow-500' : 'text-red-500'}`}>
                      {fw.coverage_percent.toFixed(0)}%
                    </span>
                    <span className="text-xs font-medium uppercase tracking-wider text-muted">Coverage</span>
                  </div>
                </div>
                
                <div className="relative z-10 h-2 w-full overflow-hidden rounded-full bg-surface-hover/80 border border-border/50">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${fw.coverage_percent}%` }}
                    transition={{ duration: 1, delay: 0.2, ease: "easeOut" }}
                    className={`h-full ${isGood ? 'bg-green-500' : isWarn ? 'bg-yellow-500' : 'bg-red-500'} shadow-[0_0_10px_currentColor]`}
                  />
                </div>

                <div className="mt-2 flex flex-col gap-4 relative z-10">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium text-ink">Action Required</span>
                    <button className="flex items-center gap-1 text-primary hover:text-primary/80 transition-colors font-medium">
                      View Controls <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>
                  
                  {fw.coverage_percent < 100 ? (
                    <div className="flex items-start gap-3 text-sm text-ink bg-surface/50 p-4 rounded-xl border border-red-500/20 backdrop-blur-sm">
                      <div className="mt-0.5 rounded-full bg-red-500/10 p-1 shrink-0">
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                      </div>
                      <p className="text-muted leading-relaxed">
                        <span className="text-ink font-medium">Deficiencies detected.</span> Some required controls lack sufficient technical evidence. Review unmapped assets and open high-severity findings.
                      </p>
                    </div>
                  ) : (
                    <div className="flex items-start gap-3 text-sm text-ink bg-surface/50 p-4 rounded-xl border border-green-500/20 backdrop-blur-sm">
                      <div className="mt-0.5 rounded-full bg-green-500/10 p-1 shrink-0">
                        <ShieldCheck className="h-4 w-4 text-green-500" />
                      </div>
                      <p className="text-muted leading-relaxed">
                        <span className="text-ink font-medium">Fully Compliant.</span> All tracked controls within this framework currently satisfy evidence requirements.
                      </p>
                    </div>
                  )}
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      )}
    </div>
  );
}

