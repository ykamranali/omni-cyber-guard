"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { getAuthToken } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import dynamic from "next/dynamic";
import { useToast } from "@/hooks/use-toast";

// Dynamically import ForceGraph2D since it requires the window object
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

export default function ExposureGraphPage() {
  const { toast } = useToast();
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const fgRef = useRef();

  const fetchGraphData = useCallback(async () => {
    try {
      const token = getAuthToken();
      if (!token) return;

      const res = await fetch("/api/v1/graph/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to fetch graph data");
      const data = await res.json();
      
      // react-force-graph expects 'source' and 'target' in links
      const formattedData = {
        nodes: data.nodes,
        links: data.edges,
      };
      
      setGraphData(formattedData);
    } catch (error) {
      toast({
        title: "Error",
        description: "Could not load exposure graph",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    fetchGraphData();
  }, [fetchGraphData]);

  const getNodeColor = (node: any) => {
    if (node.group === "Finding") {
      if (node.properties?.severity === "CRITICAL") return "#ef4444";
      if (node.properties?.severity === "HIGH") return "#f97316";
      if (node.properties?.severity === "MEDIUM") return "#eab308";
      return "#3b82f6";
    }
    if (node.group === "Asset") return "#10b981";
    if (node.group === "Service") return "#8b5cf6";
    if (node.group === "Network") return "#64748b";
    return "#cbd5e1";
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Exposure Graph</h1>
        <p className="text-muted-foreground mt-2">
          Interactive map of assets, services, and vulnerabilities.
        </p>
      </div>

      <Card className="flex flex-col flex-1 min-h-[600px] overflow-hidden">
        <CardHeader>
          <CardTitle>Topology</CardTitle>
          <CardDescription>
            Nodes represent network entities, and edges represent relationships (e.g., HAS_VULNERABILITY, EXPOSES_PORT).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex-1 p-0 relative min-h-[500px]">
          {loading ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : graphData.nodes.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center text-muted-foreground">
              No graph data available. Awaiting scans.
            </div>
          ) : (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              nodeLabel="name"
              nodeColor={getNodeColor}
              linkColor={() => "rgba(255,255,255,0.2)"}
              width={800} // Will be responsive in production, using fixed for simplicity initially
              height={500}
              onNodeClick={(node: any) => {
                // Center camera on node when clicked
                if (fgRef.current) {
                  (fgRef.current as any).centerAt(node.x, node.y, 1000);
                  (fgRef.current as any).zoom(8, 2000);
                }
              }}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
