"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { api, ApiError } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import dynamic from "next/dynamic";

// Dynamically import ForceGraph2D since it requires the window object
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

export default function ExposureGraphPage() {
  const [graphData, setGraphData] = useState<{ nodes: any[]; links: any[] }>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fgRef = useRef();
  const containerRef = useRef<HTMLDivElement>(null);
  // The canvas was a fixed 800x500 with the comment "will be responsive in
  // production". It measures its container instead.
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });

  const [note, setNote] = useState<string>("");

  const fetchGraphData = useCallback(async () => {
    try {
      // Through lib/api: the previous relative path "/api/v1/graph/" resolved
      // against the frontend origin, not the API's, so it 404'd everywhere and
      // the page permanently showed "Could not load exposure graph".
      const data = await api.get<{
        nodes: any[];
        edges: any[];
        note?: string;
      }>("/graph/");

      // react-force-graph expects 'source' and 'target' on links.
      setGraphData({ nodes: data.nodes ?? [], links: data.edges ?? [] });
      setNote(data.note ?? "");
      setError(null);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Could not load the exposure graph",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGraphData();
  }, [fetchGraphData]);

  useEffect(() => {
    const element = containerRef.current;
    if (!element || typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver((entries) => {
      const box = entries[0]?.contentRect;
      if (box) {
        setDimensions({
          width: Math.max(320, Math.floor(box.width)),
          height: Math.max(360, Math.floor(box.height)),
        });
      }
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const getNodeColor = (node: any) => {
    // A node whose backing record has been deleted is greyed out rather than
    // coloured as though it were a real one. The endpoint used to substitute
    // severity "INFO" for a missing finding, which put a benign colour on the
    // graph for a record nobody could look up.
    if (node.resolved === false) return "#475569";

    if (node.group === "Finding") {
      // The API returns lowercase severity values, matching every other page.
      // This previously compared against uppercase and so coloured every
      // finding blue regardless of how severe it was.
      switch (String(node.properties?.severity ?? "").toLowerCase()) {
        case "critical":
          return "#ef4444";
        case "high":
          return "#f97316";
        case "medium":
          return "#eab308";
        case "low":
          return "#22c55e";
        default:
          return "#3b82f6";
      }
    }
    if (node.group === "Asset") return node.properties?.internet_facing ? "#f59e0b" : "#10b981";
    if (node.group === "Service") return "#8b5cf6";
    if (node.group === "Network") return "#64748b";
    return "#cbd5e1";
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Exposure Graph</h1>
        <p className="mt-2 text-muted">
          Assets, services and open findings, drawn from the relationships the
          platform has actually recorded. Amber assets are declared
          internet-facing; grey nodes are records that no longer exist.
        </p>
      </div>

      <Card className="flex flex-col flex-1 min-h-[600px] overflow-hidden">
        <CardHeader>
          <CardTitle>Topology</CardTitle>
          <CardDescription>
            Nodes represent network entities, and edges represent relationships (e.g., HAS_VULNERABILITY, EXPOSES_PORT).
          </CardDescription>
        </CardHeader>
        <CardContent className="relative min-h-[500px] flex-1 p-0">
          <div ref={containerRef} className="absolute inset-0">
          {loading ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : graphData.nodes.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center px-8 text-center text-sm text-muted">
              {note ||
                "No relationships have been recorded yet. The graph is rebuilt after each completed scan; an empty graph means nothing has been computed, not that the estate has no relationships."}
            </div>
          ) : (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              nodeLabel={(node: any) =>
                node.resolved === false
                  ? `${node.group}: record no longer in the database`
                  : `${node.group}: ${node.name}`
              }
              nodeColor={getNodeColor}
              linkColor={() => "rgba(148,163,184,0.25)"}
              width={dimensions.width}
              height={dimensions.height}
              onNodeClick={(node: any) => {
                // Center camera on node when clicked
                if (fgRef.current) {
                  (fgRef.current as any).centerAt(node.x, node.y, 1000);
                  (fgRef.current as any).zoom(8, 2000);
                }
              }}
            />
          )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
