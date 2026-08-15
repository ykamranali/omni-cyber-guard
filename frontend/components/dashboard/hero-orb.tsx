"use client";

/**
 * Purely decorative — no data is rendered here. An animated glowing orb,
 * matching the aesthetic of the reference design, without fabricating any
 * "live" security telemetry (unlike the reference's attack map, which we
 * deliberately did not replicate — see GeoAssetMap for the real-data
 * replacement).
 */
export function HeroOrb() {
  return (
    <div className="relative flex h-full min-h-[260px] items-center justify-center overflow-hidden rounded-2xl">
      <div className="absolute h-64 w-64 animate-pulse rounded-full bg-primary/10 blur-3xl" />
      <div className="absolute h-48 w-48 rounded-full border border-primary/30" style={{ animation: "spin 18s linear infinite" }} />
      <div className="absolute h-64 w-64 rounded-full border border-secondary/20" style={{ animation: "spin 26s linear infinite reverse" }} />
      <div className="relative flex h-32 w-32 items-center justify-center rounded-full bg-gradient-to-br from-primary/80 to-secondary/80 shadow-[0_0_60px_rgba(14,165,233,0.35)]">
        <div className="h-20 w-20 rounded-full bg-background/80 backdrop-blur-sm flex items-center justify-center">
          <span className="text-xs font-semibold uppercase tracking-widest text-ink/70">Secure</span>
        </div>
      </div>
      {[...Array(6)].map((_, i) => (
        <span
          key={i}
          className="absolute h-1.5 w-1.5 rounded-full bg-primary/70"
          style={{
            top: `${20 + i * 10}%`,
            left: `${15 + ((i * 37) % 70)}%`,
            animation: `pulse ${2 + i * 0.4}s ease-in-out infinite`,
          }}
        />
      ))}
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
