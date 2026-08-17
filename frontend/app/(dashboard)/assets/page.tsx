"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, Plus, Download, Upload, Trash2, Radar, ArrowRight } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AssetFormModal, AssetFormValues } from "@/components/assets/asset-form-modal";
import { api } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

interface AssetOut {
  id: string;
  hostname: string;
  ip_address: string | null;
  asset_type: string;
  status: string;
  operating_system: string | null;
  vendor: string | null;
  site: string | null;
  department: string | null;
  risk_score: number;
}

export default function AssetsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [scanIdFilter, setScanIdFilter] = useState<string>("all");

  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get("search");
    if (fromUrl) setSearch(fromUrl);
  }, []);

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<any[]>("/scans"),
  });

  const { data: assets, isLoading, isError } = useQuery({
    queryKey: ["assets", search, scanIdFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (scanIdFilter !== "all") params.append("scan_id", scanIdFilter);
      const queryStr = params.toString();
      return api.get<AssetOut[]>(`/assets${queryStr ? `?${queryStr}` : ""}`);
    },
  });

  const createAsset = useMutation({
    mutationFn: (values: AssetFormValues) =>
      api.post<AssetOut>("/assets", {
        hostname: values.hostname,
        ip_address: values.ip_address || null,
        asset_type: values.asset_type,
        operating_system: values.operating_system || null,
        vendor: values.vendor || null,
        site: values.site || null,
        department: values.department || null,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setModalOpen(false);
    },
  });

  const deleteAsset = useMutation({
    mutationFn: (id: string) => api.delete(`/assets/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assets"] }),
  });

  async function handleExport() {
    const token = useAuthStore.getState().accessToken;
    const res = await fetch(`${api.base}/assets/export/csv`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "omni_cyber_guard_assets.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleImportFile(file: File) {
    const form = new FormData();
    form.append("file", file);
    await api.postForm("/assets/import/csv", form);
    queryClient.invalidateQueries({ queryKey: ["assets"] });
  }

  return (
    <>
      <Topbar title="Asset Inventory" />
      <main className="flex-1 space-y-4 overflow-y-auto p-6">
        <Link href="/scans">
          <Card className="flex items-center justify-between transition-colors hover:bg-surface-hover/60">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/15 text-primary">
                <Radar size={17} />
              </div>
              <div>
                <p className="text-sm font-medium text-ink">Discover assets with a real network scan</p>
                <p className="text-xs text-muted">Run an authorized nmap-backed scan to find real devices on your network — go to Scan Center</p>
              </div>
            </div>
            <ArrowRight size={16} className="text-muted" />
          </Card>
        </Link>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-1 items-center gap-3">
            <div className="relative w-full max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                placeholder="Search by hostname, IP, or vendor…"
                className="pl-9"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <select
              value={scanIdFilter}
              onChange={(e) => setScanIdFilter(e.target.value)}
              className="h-10 rounded-md border border-border bg-surface px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="all">All Scans (Entire Inventory)</option>
              {scans?.filter(s => s.status === "completed").map((s) => (
                <option key={s.id} value={s.id}>
                  Scan: {s.target_cidr} ({new Date(s.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleImportFile(file);
                e.target.value = "";
              }}
            />
            <Button variant="outline" onClick={() => fileInputRef.current?.click()}>
              <Upload size={15} /> Import CSV
            </Button>
            <Button variant="outline" onClick={handleExport}>
              <Download size={15} /> Export CSV
            </Button>
            <Button onClick={() => setModalOpen(true)}>
              <Plus size={15} /> Add Asset
            </Button>
          </div>
        </div>

        <Card className="overflow-hidden p-0">
          {isLoading && <p className="p-6 text-sm text-muted">Loading assets…</p>}
          {isError && <p className="p-6 text-sm text-critical">Unable to load assets from the API.</p>}
          {assets && assets.length === 0 && <p className="p-6 text-sm text-muted">No assets found. Add your first asset, import a CSV, or run a network scan to get started.</p>}

          {assets && assets.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-surface-hover/50 text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th className="px-4 py-3 font-medium">Hostname</th>
                    <th className="px-4 py-3 font-medium">IP Address</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">OS</th>
                    <th className="px-4 py-3 font-medium">Site</th>
                    <th className="px-4 py-3 font-medium">Risk Score</th>
                    <th className="px-4 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr key={asset.id} className="border-b border-border/60 hover:bg-surface-hover/40">
                      <td className="px-4 py-3 font-medium text-ink">{asset.hostname}</td>
                      <td className="px-4 py-3 text-ink/75">{asset.ip_address || "—"}</td>
                      <td className="px-4 py-3 capitalize text-ink/75">{asset.asset_type.replace(/_/g, " ")}</td>
                      <td className="px-4 py-3"><Badge label={asset.status} /></td>
                      <td className="px-4 py-3 text-ink/75">{asset.operating_system || "—"}</td>
                      <td className="px-4 py-3 text-ink/75">{asset.site || "—"}</td>
                      <td className="px-4 py-3">
                        <span className={asset.risk_score > 66 ? "text-critical" : asset.risk_score > 33 ? "text-medium" : "text-low"}>
                          {asset.risk_score.toFixed(0)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => deleteAsset.mutate(asset.id)}
                          className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </main>

      <AssetFormModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        submitting={createAsset.isPending}
        onSubmit={(values) => createAsset.mutate(values)}
      />
    </>
  );
}
