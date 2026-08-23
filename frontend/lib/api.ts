"use client";

import { useAuthStore } from "@/store/auth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/**
 * The request never reached the API, or the API dropped the connection before
 * answering.
 *
 * This is a different kind of failure from an ApiError and has to be reported
 * as one. `fetch` rejects with a bare TypeError when the connection is refused,
 * reset mid-request, or blocked by CORS — there is no status and no body to
 * read. Callers that write `err instanceof ApiError ? err.message : "Failed to
 * do the thing"` collapse all of that into a generic sentence, which sends you
 * looking for a bug in the feature when the actual problem is that the backend
 * is not answering.
 *
 * Status is 0 because no HTTP status was ever received. Do not treat it as one.
 */
export class NetworkError extends Error {
  status = 0;
  cause?: unknown;
  constructor(path: string, cause?: unknown) {
    super(
      `Could not reach the API at ${API_BASE_URL}${path}. The request was sent ` +
      `but no response came back — the service may be down, restarting, or ` +
      `crashing while handling this request. Check the backend logs.`,
    );
    this.name = "NetworkError";
    this.cause = cause;
  }
}


/**
 * Pull a human-readable message out of an error body.
 *
 * FastAPI answers a validation failure with `detail` as an array of objects
 * ({loc, msg, type}), not a string. Assigning that straight to a message
 * renders "[object Object]" in the UI — technically an error was shown, and it
 * tells the operator nothing about which field was wrong.
 */
function readDetail(data: unknown): string | null {
  if (!data || typeof data !== "object") return null;
  const detail = (data as { detail?: unknown }).detail;

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const entry = item as { loc?: unknown[]; msg?: string };
          const field = Array.isArray(entry.loc)
            ? entry.loc.filter((p) => p !== "body").join(".")
            : "";
          return field && entry.msg ? `${field}: ${entry.msg}` : entry.msg ?? null;
        }
        return null;
      })
      .filter(Boolean);
    return parts.length ? parts.join("; ") : null;
  }

  return null;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = useAuthStore.getState().accessToken;
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
  } catch (cause) {
    // Connection refused, reset, DNS failure, CORS rejection. No status exists.
    throw new NetworkError(path, cause);
  }

  if (res.status === 401) {
    if (!path.includes("/auth/login")) {
      useAuthStore.getState().logout();
      throw new ApiError("Session expired. Please sign in again.", 401);
    }
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = readDetail(data) || detail;
    } catch {
      /* no-op */
    }
    throw new ApiError(detail, res.status);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/**
 * Fetches an authenticated binary response and hands it to the browser as a
 * download. Needed because a plain `window.location.href = ...` navigation
 * carries no Authorization header, so every such "export" button previously
 * hit the API unauthenticated and failed.
 */
async function download(path: string, filename: string): Promise<void> {
  const token = useAuthStore.getState().accessToken;
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch (cause) {
    throw new NetworkError(path, cause);
  }

  if (res.status === 401) {
    useAuthStore.getState().logout();
    throw new ApiError("Session expired. Please sign in again.", 401);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = readDetail(await res.json()) || detail;
    } catch {
      /* no-op */
    }
    throw new ApiError(detail, res.status);
  }

  const blob = await res.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(objectUrl);
}

/** Base URL for the WebSocket endpoint, derived from the configured API base
 *  so a non-localhost deployment works without a code change. */
export function wsUrl(path: string, token: string | null): string {
  const httpBase = API_BASE_URL.replace(/\/$/, "");
  const wsBase = httpBase.replace(/^http/, "ws");
  const separator = path.includes("?") ? "&" : "?";
  return token ? `${wsBase}${path}${separator}token=${encodeURIComponent(token)}` : `${wsBase}${path}`;
}

/**
 * The message to show a person when a call failed.
 *
 * Every screen had written this itself as
 *   err instanceof ApiError ? err.message : "Failed to <do the thing>"
 * which quietly discards anything that is not an ApiError. A backend that is
 * down, restarting, or crashing mid-request rejects at the fetch layer, so the
 * operator was shown "Failed to start scan" — a sentence that points at the
 * feature when the problem is that nothing answered. The fallback is now the
 * last resort it was meant to be, not the usual outcome.
 */
export function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof NetworkError) return err.message;
  if (err instanceof Error && err.message) return `${fallback}: ${err.message}`;
  return fallback;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string, body?: unknown) => 
    request<T>(path, { method: "DELETE", body: body ? JSON.stringify(body) : undefined }),
  postForm: <T>(path: string, form: FormData) => request<T>(path, { method: "POST", body: form }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  download,
  base: API_BASE_URL,
};
