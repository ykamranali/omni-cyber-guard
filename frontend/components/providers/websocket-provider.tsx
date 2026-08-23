"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import toast, { Toaster } from "react-hot-toast";
import { useAuthStore } from "@/store/auth";
import { wsUrl } from "@/lib/api";

/**
 * The live event channel.
 *
 * Two things were missing and both made "real time" cosmetic.
 *
 * A pushed event only ever raised a toast. It never touched the React Query
 * cache, so a scan finishing, a finding appearing or an alert firing left every
 * list, count and badge on screen showing the state from whenever the page last
 * fetched. The toast said something had happened; the page disagreed.
 *
 * And a dropped connection was permanent. `onclose` logged to the console and
 * nothing reconnected, so a laptop waking from sleep, a backend restart or any
 * transient network blip left the socket dead until a full remount — silently,
 * because a socket that is not receiving looks exactly like a quiet network.
 *
 * Now each event invalidates the queries it affects, and the socket reconnects
 * with exponential backoff. The connection state is exported so the UI can show
 * that live updates have stopped rather than implying everything is current.
 */

// Event type -> query key prefixes to invalidate. Kept declarative so adding a
// backend event means adding a line here, not editing the handler.
const INVALIDATIONS: Record<string, string[][]> = {
  scan_started: [["scans"], ["dashboard"], ["system"]],
  scan_progress: [["scans"]],
  scan_completed: [
    ["scans"], ["assets"], ["findings"], ["dashboard"], ["exposure"],
    ["attack-paths"], ["graph"],
  ],
  scan_failed: [["scans"], ["dashboard"]],
  finding_created: [["findings"], ["dashboard"], ["exposure"]],
  finding_resolved: [["findings"], ["dashboard"], ["exposure"], ["remediation"]],
  threat_event: [["threat-intel"], ["dashboard"], ["infrastructure"]],
  remediation_updated: [["remediation"], ["findings"], ["dashboard"]],
  compliance_assessed: [["compliance"], ["dashboard"]],
  discovery_completed: [["cloud"], ["identity"], ["attack-surface"]],
  intel_synced: [["cve-intelligence"], ["findings"], ["dashboard"]],
};

// Anything unrecognised still refreshes the dashboard: an event we do not have
// a mapping for is more likely to matter than not.
const FALLBACK_INVALIDATION: string[][] = [["dashboard"]];

const BASE_RECONNECT_DELAY = 1000;
const MAX_RECONNECT_DELAY = 30_000;

const TOAST_STYLE = {
  background: "rgb(var(--color-surface))",
  color: "rgb(var(--color-ink))",
  border: "1px solid rgb(var(--color-border))",
};

export type SocketState = "connecting" | "open" | "closed";

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((state) => state.accessToken);
  const queryClient = useQueryClient();
  const socket = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attempts = useRef(0);
  const deliberatelyClosed = useRef(false);
  const [, setState] = useState<SocketState>("connecting");

  const applyEvent = useCallback(
    (payload: { type?: string; message?: string }) => {
      const keys = INVALIDATIONS[payload.type ?? ""] ?? FALLBACK_INVALIDATION;
      for (const key of keys) {
        void queryClient.invalidateQueries({ queryKey: key });
      }

      if (!payload.message) return;

      if (payload.type === "error" || payload.type === "critical" || payload.type === "scan_failed") {
        toast.error(payload.message, { style: TOAST_STYLE });
      } else if (payload.type === "success" || payload.type === "scan_completed") {
        toast.success(payload.message, { style: TOAST_STYLE });
      } else {
        toast(payload.message, { style: TOAST_STYLE, icon: "🔔" });
      }
    },
    [queryClient],
  );

  const connect = useCallback(() => {
    if (!token) return;

    setState("connecting");
    const client = new WebSocket(wsUrl("/ws", token));
    socket.current = client;

    client.onopen = () => {
      attempts.current = 0;
      setState("open");
      // Anything that happened while the socket was down was missed entirely.
      // Refetching everything on reconnect is the only way the UI can be
      // trusted afterwards.
      void queryClient.invalidateQueries();
    };

    client.onmessage = (event) => {
      try {
        applyEvent(JSON.parse(event.data));
      } catch {
        // A malformed frame is the server's problem, not a reason to tear down
        // a working connection.
      }
    };

    client.onclose = () => {
      setState("closed");
      if (deliberatelyClosed.current) return;

      const delay = Math.min(
        MAX_RECONNECT_DELAY,
        BASE_RECONNECT_DELAY * 2 ** attempts.current,
      );
      attempts.current += 1;
      reconnectTimer.current = setTimeout(connect, delay);
    };

    client.onerror = () => {
      // `onclose` always follows, and that is where reconnection is handled.
      client.close();
    };
  }, [token, applyEvent, queryClient]);

  useEffect(() => {
    deliberatelyClosed.current = false;
    connect();

    return () => {
      deliberatelyClosed.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      socket.current?.close();
    };
  }, [connect]);

  return (
    <>
      <Toaster position="top-right" toastOptions={{ style: TOAST_STYLE }} />
      {children}
    </>
  );
}
