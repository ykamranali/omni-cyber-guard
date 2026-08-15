"use client";

/**
 * Geographic Asset Distribution — plots REAL assets that have a recorded
 * latitude/longitude (set manually, or via CSV import) on an abstract
 * world grid. This replaces the reference design's "Live Attack Map":
 * we have no real threat-intelligence feed to back a live attack
 * visualization this round, and showing fabricated attack markers would
 * misrepresent invented data as real telemetry. Real asset locations are
 * something we DO have, so that's what's rendered here.
 */
interface GeoAsset {
  id: string;
  hostname: string;
  latitude: number | null;
  longitude: number | null;
  risk_score: number;
  site: string | null;
}

const DOT_COLS = 44;
const DOT_ROWS = 22;

function riskColor(score: number) {
  if (score >= 66) return "#EF4444";
  if (score >= 33) return "#EAB308";
  if (score > 0) return "#22C55E";
  return "#38BDF8";
}

export function GeoAssetMap({ assets }: { assets: GeoAsset[] }) {
  const plotted = assets.filter((a) => a.latitude != null && a.longitude != null);

  return (
    <div className="relative h-64 w-full overflow-hidden rounded-xl bg-background/40">
      <div
        className="absolute inset-0 grid"
        style={{
          gridTemplateColumns: `repeat(${DOT_COLS}, 1fr)`,
          gridTemplateRows: `repeat(${DOT_ROWS}, 1fr)`,
        }}
      >
        {Array.from({ length: DOT_COLS * DOT_ROWS }).map((_, i) => (
          <span key={i} className="m-auto h-[2px] w-[2px] rounded-full bg-muted/30" />
        ))}
      </div>

      {plotted.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-muted">
          No assets with recorded coordinates yet. Set latitude/longitude on an asset, or run a network scan.
        </div>
      )}

      {plotted.map((a) => {
        const left = ((a.longitude! + 180) / 360) * 100;
        const top = ((90 - a.latitude!) / 180) * 100;
        return (
          <div
            key={a.id}
            title={`${a.hostname}${a.site ? " — " + a.site : ""} (risk ${a.risk_score})`}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${left}%`, top: `${top}%` }}
          >
            <span
              className="block h-2.5 w-2.5 rounded-full"
              style={{
                backgroundColor: riskColor(a.risk_score),
                boxShadow: `0 0 12px 2px ${riskColor(a.risk_score)}55`,
              }}
            />
          </div>
        );
      })}
    </div>
  );
}
