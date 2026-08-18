import React from 'react';

export function HolographicShield() {
  return (
    <div className="relative flex items-center justify-center w-full h-full min-h-[200px]">
      <div className="absolute inset-0 bg-primary/10 rounded-full blur-[50px] animate-pulse-glow" />
      <svg viewBox="0 0 100 100" className="w-48 h-48 text-primary drop-shadow-[0_0_15px_rgba(14,165,233,0.8)] z-10 animate-float-particle">
        <defs>
          <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.8" />
            <stop offset="50%" stopColor="currentColor" stopOpacity="0.4" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.8" />
          </linearGradient>
          <pattern id="binary" width="10" height="10" patternUnits="userSpaceOnUse">
            <text x="0" y="8" fontSize="6" fill="currentColor" opacity="0.3" fontFamily="monospace">01</text>
          </pattern>
        </defs>
        
        {/* Outer Tech Ring */}
        <circle cx="50" cy="50" r="48" fill="none" stroke="currentColor" strokeWidth="0.5" strokeDasharray="2 4" className="animate-spin-slow opacity-50" />
        <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="10 5" className="animate-spin-slow opacity-70" style={{ animationDirection: 'reverse' }} />
        
        {/* Main Shield Body */}
        <path d="M50 10 C50 10, 80 15, 85 25 C85 50, 75 75, 50 90 C25 75, 15 50, 15 25 C20 15, 50 10, 50 10 Z" 
              fill="url(#binary)" stroke="url(#shieldGrad)" strokeWidth="2" />
        
        {/* Inner Keyhole */}
        <circle cx="50" cy="40" r="6" fill="currentColor" />
        <path d="M47 45 L53 45 L55 60 L45 60 Z" fill="currentColor" />
      </svg>
      
      {/* Scanning Laser */}
      <div className="absolute top-0 w-full h-1 bg-white shadow-[0_0_10px_#fff] animate-satellite-beam mix-blend-overlay z-20" />
    </div>
  );
}
