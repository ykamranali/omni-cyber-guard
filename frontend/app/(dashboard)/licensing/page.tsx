"use client";

import { 
  BadgeDollarSign, CheckCircle2, ShieldCheck, 
  Zap, Users, Activity, BrainCircuit, ShieldAlert
} from "lucide-react";

export default function LicensingPage() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Licensing & Subscriptions</h1>
          <p className="mt-2 text-muted">Manage your Omni Cyber Guard enterprise subscription</p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <div className="glossy-card relative overflow-hidden rounded-xl border border-primary/30 p-8 shadow-[0_0_30px_rgba(var(--color-primary)/0.15)]">
            <div className="absolute -right-20 -top-20 rounded-full bg-primary/10 p-32 blur-[80px]" />
            
            <div className="relative z-10 flex flex-col md:flex-row gap-8 items-start justify-between">
              <div>
                <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-sm font-bold uppercase tracking-widest text-primary">
                  <ShieldCheck className="h-4 w-4" /> Enterprise Edition
                </div>
                <h2 className="mt-6 text-4xl font-bold text-ink">Omni One</h2>
                <p className="mt-2 text-lg text-muted">Full exposure management platform.</p>
                
                <div className="mt-8 space-y-4">
                  <div className="flex items-center gap-4 border-l-2 border-primary/50 pl-4">
                    <div>
                      <p className="text-sm font-medium text-muted uppercase tracking-wider">Status</p>
                      <p className="text-lg font-bold text-emerald-500">Active</p>
                    </div>
                    <div className="h-10 w-px bg-border"></div>
                    <div>
                      <p className="text-sm font-medium text-muted uppercase tracking-wider">Renewal Date</p>
                      <p className="text-lg font-bold text-ink">Dec 31, 2028</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="w-full md:w-auto rounded-xl border border-border bg-surface p-6 shadow-lg min-w-[250px]">
                <p className="text-sm font-semibold uppercase tracking-wider text-muted">Asset Allocation</p>
                <div className="mt-4 flex items-end gap-2">
                  <span className="text-4xl font-bold text-ink">8,492</span>
                  <span className="text-sm font-medium text-muted mb-1">/ 10,000</span>
                </div>
                <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-surface-hover">
                  <div className="h-full bg-primary rounded-full" style={{ width: "85%" }} />
                </div>
                <p className="mt-2 text-xs text-muted text-right">85% Utilized</p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-surface shadow-lg backdrop-blur-xl p-6">
            <h3 className="text-lg font-bold text-ink mb-6">Included Capabilities</h3>
            
            <div className="grid sm:grid-cols-2 gap-6">
              {[
                { icon: ShieldAlert, title: "Vulnerability Management", desc: "Continuous scanning and assessment" },
                { icon: Activity, title: "Attack Surface Management", desc: "External domain and IP discovery" },
                { icon: BrainCircuit, title: "AI Security Engineer", desc: "Context-aware threat analysis" },
                { icon: Zap, title: "Threat Intelligence", desc: "CISA KEV and EPSS integration" },
              ].map((feature, i) => (
                <div key={i} className="flex gap-4">
                  <div className="rounded-lg bg-surface-hover p-2 h-fit border border-border/50">
                    <feature.icon className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-ink">{feature.title}</h4>
                    <p className="text-sm text-muted mt-1">{feature.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-xl border border-border bg-surface shadow-lg backdrop-blur-xl p-6">
            <div className="flex items-center gap-3 mb-6">
              <Users className="h-5 w-5 text-primary" />
              <h3 className="text-lg font-bold text-ink">Organization Details</h3>
            </div>
            
            <div className="space-y-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted">Organization Name</p>
                <p className="font-medium text-ink mt-1">Acme Corp Global</p>
              </div>
              <div className="pt-4 border-t border-border/50">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted">Tenant ID</p>
                <p className="font-mono text-sm text-ink mt-1">org_7f8a9b2c1d3e4f5</p>
              </div>
              <div className="pt-4 border-t border-border/50">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted">Support Tier</p>
                <p className="font-medium text-ink mt-1 flex items-center gap-2">
                  Premium 24/7 <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-surface-hover shadow-lg p-6 text-center">
            <BadgeDollarSign className="mx-auto h-8 w-8 text-muted/50 mb-3" />
            <h3 className="font-semibold text-ink">Need more capacity?</h3>
            <p className="text-sm text-muted mt-2 mb-4">Contact your technical account manager to increase your asset limit.</p>
            <button className="w-full rounded-lg bg-primary/10 border border-primary/20 px-4 py-2 text-sm font-semibold text-primary transition-colors hover:bg-primary/20">
              Contact Sales
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
