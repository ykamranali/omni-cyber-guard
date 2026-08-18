import { useQuery } from "@tanstack/react-query";
import { X, Server, Activity, AlertTriangle, ShieldCheck, Cpu } from "lucide-react";
import { api } from "@/lib/api";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

interface AssetOut {
  id: string;
  hostname: string;
  ip_address: string | null;
  mac_address: string | null;
  asset_type: string;
  status: string;
  operating_system: string | null;
  vendor: string | null;
  site: string | null;
  department: string | null;
  risk_score: number;
}

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  created_at: string;
}

export function AssetDrawer({ asset, onClose }: { asset: AssetOut | null; onClose: () => void }) {
  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", asset?.id],
    queryFn: () => api.get<Finding[]>(`/findings?asset_id=${asset?.id}`),
    enabled: !!asset,
  });

  if (!asset) return null;

  return (
    <>
      <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 transition-all" onClick={onClose} />
      <div className="fixed right-0 top-0 h-full w-full max-w-md bg-surface/90 backdrop-blur-xl border-l border-primary/20 shadow-[0_0_40px_rgba(var(--color-primary)/0.15)] z-50 flex flex-col transform transition-transform duration-300 ease-out animate-in slide-in-from-right">
        <div className="p-6 border-b border-border/50 flex justify-between items-center bg-surface-hover/50">
          <div className="flex items-center gap-3">
            <div className="p-2 border border-primary/50 bg-primary/10 rounded shadow-neon text-primary">
              <Server size={20} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-ink tracking-widest uppercase neon-text">{asset.hostname}</h2>
              <p className="text-xs text-muted font-mono">{asset.ip_address || "NO IP DISCOVERED"}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-muted hover:text-ink p-1 rounded-md hover:bg-surface-hover transition-colors"><X size={20} /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-border bg-surface-hover/30 text-center">
              <p className="text-xs text-muted uppercase tracking-wider mb-1">Risk Score</p>
              <p className={cn("text-3xl font-mono font-bold drop-shadow-md", (asset.risk_score || 0) > 66 ? "text-critical" : (asset.risk_score || 0) > 33 ? "text-orange-500" : "text-green-500")}>
                {(asset.risk_score || 0).toFixed(0)}
              </p>
            </div>
            <div className="p-4 rounded-xl border border-border bg-surface-hover/30 text-center">
              <p className="text-xs text-muted uppercase tracking-wider mb-1">Status</p>
              <p className="text-xl font-bold tracking-widest text-primary uppercase mt-2">{asset.status}</p>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-xs font-bold text-muted uppercase tracking-widest flex items-center gap-2"><Cpu size={14}/> System Details</h3>
            <div className="p-4 rounded-xl border border-border bg-surface-hover/30 space-y-2 text-sm">
              <div className="flex justify-between border-b border-border/50 pb-2"><span className="text-muted">Type:</span> <span className="capitalize">{asset.asset_type?.replace(/_/g, " ") || "Unknown"}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-2 pt-1"><span className="text-muted">OS:</span> <span>{asset.operating_system || "Unknown"}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-2 pt-1"><span className="text-muted">MAC:</span> <span className="font-mono">{asset.mac_address || "Unknown"}</span></div>
              <div className="flex justify-between border-b border-border/50 pb-2 pt-1"><span className="text-muted">Vendor:</span> <span>{asset.vendor || "Unknown"}</span></div>
              <div className="flex justify-between pt-1"><span className="text-muted">Site:</span> <span>{asset.site || "Unknown"}</span></div>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-xs font-bold text-muted uppercase tracking-widest flex items-center gap-2"><Activity size={14}/> Detected Vulnerabilities</h3>
            <div className="space-y-3">
              {isLoading ? (
                <p className="text-xs text-muted text-center py-4">Scanning records...</p>
              ) : findings && findings.length > 0 ? (
                findings.map(finding => (
                  <div key={finding.id} className="p-3 rounded-lg border border-border/50 bg-surface flex items-start gap-3 hover:border-primary/50 transition-colors">
                    <AlertTriangle size={16} className={cn("mt-0.5", 
                      finding.severity === "critical" ? "text-critical" : 
                      finding.severity === "high" ? "text-orange-500" : "text-blue-500")} 
                    />
                    <div>
                      <p className="text-sm font-semibold text-ink line-clamp-1">{finding.title}</p>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-muted font-mono">
                        <span className="uppercase">{finding.severity}</span>
                        <span>•</span>
                        <span>{finding.status}</span>
                        <span>•</span>
                        <span>{finding.created_at ? `${formatDistanceToNow(new Date(finding.created_at))} ago` : "Unknown time"}</span>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-6 rounded-xl border border-dashed border-border text-center text-muted">
                  <ShieldCheck size={24} className="mx-auto mb-2 opacity-50" />
                  <p className="text-xs">No active findings detected for this asset.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
