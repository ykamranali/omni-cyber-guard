"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, Plus, Download, Upload, Trash2, Pencil, Radar, ArrowRight, Folder, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AssetFormModal, AssetFormValues } from "@/components/assets/asset-form-modal";
import { AssetDrawer } from "@/components/assets/asset-drawer";
import { api, ApiError } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

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
  scan_job_id: string | null;
}

export default function AssetsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<AssetOut | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [scanIdFilter, setScanIdFilter] = useState<string>("all");
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set(["manual"]));
  const [profiledAsset, setProfiledAsset] = useState<AssetOut | null>(null);

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

  // Group assets by scan_job_id
  const groupedAssets = useMemo(() => {
    if (!assets) return {};
    const groups: Record<string, AssetOut[]> = { manual: [] };
    
    if (scans) {
      scans.filter(s => s.status === "completed").forEach(s => {
        groups[s.id] = [];
      });
    }

    assets.forEach(asset => {
      const key = asset.scan_job_id || "manual";
      if (!groups[key]) groups[key] = [];
      groups[key].push(asset);
    });
    return groups;
  }, [assets, scans]);

  const toggleFolder = (folderId: string) => {
    const newSet = new Set(expandedFolders);
    if (newSet.has(folderId)) newSet.delete(folderId);
    else newSet.add(folderId);
    setExpandedFolders(newSet);
  };

  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<string>>(new Set());

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
      setFormError(null);
    },
    onError: (err) =>
      setFormError(err instanceof ApiError ? err.message : "The asset could not be created."),
  });

  const updateAsset = useMutation({
    mutationFn: ({ id, values }: { id: string; values: AssetFormValues }) =>
      api.patch(`/assets/${id}`, {
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
      setEditingAsset(null);
      setFormError(null);
    },
    onError: (err) =>
      setFormError(err instanceof ApiError ? err.message : "The asset could not be saved."),
  });

  // Every delete previously had no onError at all, so a refusal — a role
  // without manage_assets, a constraint, anything — produced complete silence
  // and looked like the button did nothing.
  const deleteAsset = useMutation({
    mutationFn: (id: string) => api.delete(`/assets/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setActionError(null);
    },
    onError: (err) =>
      setActionError(
        err instanceof ApiError ? err.message : "The asset could not be deleted.",
      ),
  });

  const deleteBulkAssets = useMutation({
    mutationFn: (ids: string[]) => api.delete("/assets/bulk", ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setSelectedAssetIds(new Set());
      setActionError(null);
    },
    onError: (err) =>
      setActionError(
        err instanceof ApiError ? err.message : "The assets could not be deleted.",
      ),
  });

  const toggleAssetSelection = (id: string) => {
    const newSet = new Set(selectedAssetIds);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setSelectedAssetIds(newSet);
  };

  const toggleGroupAssets = (groupAssets: AssetOut[]) => {
    if (!groupAssets || groupAssets.length === 0) return;
    const groupAssetIds = groupAssets.map(a => a.id);
    const allSelected = groupAssetIds.every(id => selectedAssetIds.has(id));
    
    const newSet = new Set(selectedAssetIds);
    if (allSelected) {
      groupAssetIds.forEach(id => newSet.delete(id));
    } else {
      groupAssetIds.forEach(id => newSet.add(id));
    }
    setSelectedAssetIds(newSet);
  };

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
        {actionError && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1">{actionError}</span>
            <button
              type="button"
              onClick={() => setActionError(null)}
              className="text-xs underline"
            >
              dismiss
            </button>
          </div>
        )}
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
            {selectedAssetIds.size > 0 && (
              <Button
                variant="danger"
                onClick={() => {
                  if (confirm(`Are you sure you want to delete ${selectedAssetIds.size} asset(s)?`)) {
                    deleteBulkAssets.mutate(Array.from(selectedAssetIds));
                  }
                }}
                disabled={deleteBulkAssets.isPending}
              >
                <Trash2 size={15} /> Delete Selected
              </Button>
            )}
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

        <div className="space-y-4">
          {isLoading && <Card className="p-6"><p className="text-sm text-muted">Loading assets…</p></Card>}
          {isError && <Card className="p-6"><p className="text-sm text-critical">Unable to load assets from the API.</p></Card>}
          {assets && assets.length === 0 && (
            <Card className="p-6">
              <p className="text-sm text-muted">No assets found. Add your first asset, import a CSV, or run a network scan to get started.</p>
            </Card>
          )}

          {assets && assets.length > 0 && (
            <>
              {Object.entries(groupedAssets).map(([groupId, groupAssets]) => {
                const isManual = groupId === "manual";
                const scan = scans?.find(s => s.id === groupId);
                
                if (!isManual && !scan) return null;
                if (isManual && groupAssets.length === 0 && (scans?.filter(s => s.status === "completed").length || 0) > 0) return null;

                const isExpanded = expandedFolders.has(groupId);
                const title = isManual ? "Manual / Uncategorized Assets" : `Scan Folder: ${scan.target_cidr} (${new Date(scan.created_at).toLocaleDateString()})`;
                const allSelected = groupAssets.length > 0 && groupAssets.every(a => selectedAssetIds.has(a.id));

                return (
                  <Card key={groupId} className="overflow-hidden p-0 transition-all">
                    <div 
                      className="flex cursor-pointer items-center justify-between border-b border-border px-5 py-3 bg-surface-hover/50 transition-colors hover:bg-surface-hover/80"
                      onClick={() => toggleFolder(groupId)}
                    >
                      <div className="flex items-center gap-3">
                        <Folder size={18} className="text-primary" />
                        <span className="text-sm font-medium text-ink">{title}</span>
                        <Badge label={`${groupAssets.length} asset(s)`} />
                      </div>
                      <div className="flex items-center gap-3">
                        {isExpanded ? <ChevronDown size={18} className="text-muted" /> : <ChevronRight size={18} className="text-muted" />}
                      </div>
                    </div>

                    {isExpanded && groupAssets.length === 0 && (
                      <p className="p-6 text-sm text-muted">No assets in this folder.</p>
                    )}

                    {isExpanded && groupAssets.length > 0 && (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                          <thead className="border-b border-border bg-surface-hover/30 text-xs uppercase tracking-wide text-muted">
                            <tr>
                              <th className="px-4 py-3 font-medium w-10">
                                <input
                                  type="checkbox"
                                  className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                                  checked={allSelected}
                                  onChange={() => toggleGroupAssets(groupAssets)}
                                />
                              </th>
                              <th className="px-4 py-3 font-medium">Hostname</th>
                              <th className="px-4 py-3 font-medium">IP Address</th>
                              <th className="px-4 py-3 font-medium">MAC Address</th>
                              <th className="px-4 py-3 font-medium">Type</th>
                              <th className="px-4 py-3 font-medium">OS</th>
                              <th className="px-4 py-3 font-medium">Status</th>
                              <th className="px-4 py-3 font-medium">Risk Score</th>
                              <th className="px-4 py-3 font-medium"></th>
                            </tr>
                          </thead>
                          <tbody>
                            {groupAssets.map((asset) => (
                              <tr 
                                key={asset.id} 
                                className="border-b border-border/60 hover:bg-surface-hover/40 cursor-pointer"
                                onClick={() => setProfiledAsset(asset)}
                              >
                                <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                                  <input
                                    type="checkbox"
                                    className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                                    checked={selectedAssetIds.has(asset.id)}
                                    onChange={() => toggleAssetSelection(asset.id)}
                                  />
                                </td>
                                <td className="px-4 py-3 font-medium text-ink">{asset.hostname}</td>
                                <td className="px-4 py-3 text-ink/75">{asset.ip_address || "—"}</td>
                                <td className="px-4 py-3 text-ink/75">{asset.mac_address || "—"}</td>
                                <td className="px-4 py-3 capitalize text-ink/75">{asset.asset_type.replace(/_/g, " ")}</td>
                                <td className="px-4 py-3 text-ink/75">{asset.operating_system || "—"}</td>
                                <td className="px-4 py-3"><Badge label={asset.status} /></td>
                                <td className="px-4 py-3">
                                  <span className={asset.risk_score > 66 ? "text-critical" : asset.risk_score > 33 ? "text-medium" : "text-low"}>
                                    {asset.risk_score.toFixed(0)}
                                  </span>
                                </td>
                                <td className="px-4 py-3 text-right">
                                  <div className="flex items-center justify-end gap-1">
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setEditingAsset(asset);
                                        setFormError(null);
                                        setModalOpen(true);
                                      }}
                                      className="rounded-md p-1.5 text-muted hover:bg-primary/10 hover:text-primary"
                                      title={`Edit ${asset.hostname}`}
                                    >
                                      <Pencil size={15} />
                                    </button>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        if (
                                          confirm(
                                            `Delete ${asset.hostname}? Its findings, services and scan history go with it. This cannot be undone.`,
                                          )
                                        ) {
                                          deleteAsset.mutate(asset.id);
                                        }
                                      }}
                                      disabled={deleteAsset.isPending}
                                      className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical disabled:opacity-40"
                                      title={`Delete ${asset.hostname}`}
                                    >
                                      <Trash2 size={15} />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </Card>
                );
              })}
            </>
          )}
        </div>
      </main>

      <AssetFormModal
        open={modalOpen}
        onClose={() => {
          setModalOpen(false);
          setEditingAsset(null);
          setFormError(null);
        }}
        submitting={createAsset.isPending || updateAsset.isPending}
        error={formError}
        initialValues={
          editingAsset
            ? {
                hostname: editingAsset.hostname,
                ip_address: editingAsset.ip_address ?? "",
                asset_type: editingAsset.asset_type,
                operating_system: editingAsset.operating_system ?? "",
                vendor: (editingAsset as { vendor?: string | null }).vendor ?? "",
                site: editingAsset.site ?? "",
                department: (editingAsset as { department?: string | null }).department ?? "",
              }
            : null
        }
        onSubmit={(values) =>
          editingAsset
            ? updateAsset.mutate({ id: editingAsset.id, values })
            : createAsset.mutate(values)
        }
      />

      <AssetDrawer 
        asset={profiledAsset} 
        onClose={() => setProfiledAsset(null)} 
      />
    </>
  );
}
