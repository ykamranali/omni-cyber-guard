"use client";

import { useEffect, useRef } from "react";
import { useAuthStore } from "@/store/auth";
import { wsUrl } from "@/lib/api";
import toast, { Toaster } from "react-hot-toast";

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.accessToken);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!token) return;

    // Derived from NEXT_PUBLIC_API_BASE_URL so this works outside localhost.
    ws.current = new WebSocket(wsUrl("/ws", token));

    ws.current.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Use hot-toast for notifications
        if (data.type === "success") {
          toast.success(data.message, {
            style: {
              background: '#111827',
              color: '#F0F9FF',
              border: '1px solid rgba(34, 197, 94, 0.2)',
            },
            iconTheme: {
              primary: '#22C55E',
              secondary: '#111827',
            },
          });
        } else if (data.type === "error" || data.type === "critical") {
          toast.error(data.message, {
            style: {
              background: '#111827',
              color: '#F0F9FF',
              border: '1px solid rgba(239, 68, 68, 0.2)',
            },
          });
        } else {
          toast(data.message, {
            style: {
              background: '#111827',
              color: '#F0F9FF',
              border: '1px solid rgba(14, 165, 233, 0.2)',
            },
            icon: '🔔'
          });
        }
      } catch (e) {
        console.error("Error parsing WebSocket message:", e);
      }
    };

    ws.current.onclose = () => {
      console.log("WebSocket disconnected");
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [token]);

  return (
    <>
      <Toaster position="top-right" />
      {children}
    </>
  );
}
