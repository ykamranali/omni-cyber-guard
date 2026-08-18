"use client";

import { useEffect, useState } from "react";
import { AlertCircle, ShieldAlert, Zap, Radio } from "lucide-react";

interface ActivityEvent {
  id: number;
  time: string;
  type: "threat" | "scan" | "defense" | "system";
  message: string;
}

const MOCK_EVENTS = [
  { type: "scan", message: "Nmap deep scan completed on subnet 10.0.0.0/24" },
  { type: "threat", message: "Anomalous traffic detected from 192.168.1.55" },
  { type: "system", message: "Node agent 0x8F synchronized with command center" },
  { type: "defense", message: "Automated firewall rule applied: Blocked port 445" },
  { type: "scan", message: "Scheduled OSINT reconnaissance initiated on primary domain" },
  { type: "threat", message: "CVE-2024-21412 signature match on asset WEB-SRV-01" },
  { type: "system", message: "Database backup completed successfully" },
  { type: "defense", message: "Threat intelligence feed updated. 1,402 new signatures loaded." },
];

export function ActivityTicker() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);

  useEffect(() => {
    // Initialize with a few events
    const initialEvents = Array.from({ length: 5 }).map((_, i) => ({
      id: Date.now() - i * 1000,
      time: new Date(Date.now() - i * 15000).toLocaleTimeString(),
      type: MOCK_EVENTS[i % MOCK_EVENTS.length].type as any,
      message: MOCK_EVENTS[i % MOCK_EVENTS.length].message,
    }));
    setEvents(initialEvents);

    const interval = setInterval(() => {
      const randomEvent = MOCK_EVENTS[Math.floor(Math.random() * MOCK_EVENTS.length)];
      setEvents((prev) => [
        {
          id: Date.now(),
          time: new Date().toLocaleTimeString(),
          type: randomEvent.type as any,
          message: randomEvent.message,
        },
        ...prev.slice(0, 9), // keep last 10
      ]);
    }, 4500);

    return () => clearInterval(interval);
  }, []);

  const getIcon = (type: string) => {
    switch (type) {
      case "threat": return <AlertCircle size={14} className="text-critical" />;
      case "scan": return <Radio size={14} className="text-primary" />;
      case "defense": return <ShieldAlert size={14} className="text-green-400" />;
      default: return <Zap size={14} className="text-muted" />;
    }
  };

  const getColor = (type: string) => {
    switch (type) {
      case "threat": return "text-critical";
      case "scan": return "text-primary";
      case "defense": return "text-green-400";
      default: return "text-muted";
    }
  };

  return (
    <div className="h-48 overflow-hidden p-4 flex flex-col gap-2 relative bg-surface/50">
      <div className="absolute top-0 left-0 w-full h-8 bg-gradient-to-b from-surface/50 to-transparent z-10 pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-full h-8 bg-gradient-to-t from-surface/50 to-transparent z-10 pointer-events-none" />
      
      {events.map((ev, idx) => (
        <div 
          key={ev.id} 
          className="flex items-center gap-3 text-xs border-l-2 border-border/50 pl-3 py-1 transition-all duration-500 ease-out"
          style={{ 
            opacity: 1 - (idx * 0.1),
            transform: `translateY(${idx === 0 ? '-10px' : '0'})`,
            animation: idx === 0 ? 'slideIn 0.5s ease-out forwards' : 'none'
          }}
        >
          <span className="font-mono text-muted/70 w-20">{ev.time}</span>
          <div className="p-1 rounded bg-surface border border-border/50 shadow-glass">
            {getIcon(ev.type)}
          </div>
          <span className={`font-mono uppercase tracking-wider font-semibold ${getColor(ev.type)}`}>
            [{ev.type}]
          </span>
          <span className="text-ink/80 truncate">{ev.message}</span>
        </div>
      ))}

      <style jsx>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
