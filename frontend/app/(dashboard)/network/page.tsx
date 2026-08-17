"use client";

import { useEffect, useState } from "react";
import { Radar, Loader2 } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import dynamic from "next/dynamic";

const NetworkMap = dynamic(
  () => import("@/components/assets/network-map").then((mod) => mod.NetworkMap),
  { ssr: false, loading: () => <Loader2 className="h-8 w-8 animate-spin text-primary m-auto" /> }
);


export default function NetworkMapPage() {
  const [assets, setAssets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    async function fetchAssets() {
      try {
        const res = await fetch("http://localhost:8000/api/v1/assets", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.ok) {
          const data = await res.json();
          setAssets(data);
        }
      } catch (error) {
        console.error("Failed to fetch assets", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchAssets();
  }, [token]);

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col gap-4 p-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-secondary">
            <Radar className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-ink">3D Network Visualization</h1>
            <p className="text-sm text-muted">Interactive map of all discovered assets and topology</p>
          </div>
        </div>
      </div>

      <div className="flex-1 relative rounded-xl border border-border overflow-hidden bg-surface shadow-sm">
        {isLoading ? (
          <div className="absolute inset-0 flex items-center justify-center bg-surface/50 backdrop-blur-sm z-10">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : assets.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="text-muted">No assets discovered yet. Run a network scan to populate the map.</p>
          </div>
        ) : (
          <NetworkMap assets={assets} />
        )}
      </div>
    </div>
  );
}
