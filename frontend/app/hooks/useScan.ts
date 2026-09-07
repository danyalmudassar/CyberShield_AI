"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ScanEvent, ScanJob, ScanRequest, ScanState, ScanStatus } from "../../lib/api-types";

const LAST_SCAN = "cybershield.lastScan";
type AuthUser = { email: string; role: string };
class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}
const terminal = (status: ScanStatus) => !["queued", "running", "cancelling"].includes(status);

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.method && init.method !== "GET") headers.set("X-CyberShield-Request", "1");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin", cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(typeof body?.detail === "string" ? body.detail : `Request failed (${response.status})`, response.status);
  }
  return response.json() as Promise<T>;
}

export function useScan() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [scanState, setScanState] = useState<ScanState | null>(null);
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [scanProgress, setScanProgress] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [historyVersion, setHistoryVersion] = useState(0);
  const [connectionVersion, setConnectionVersion] = useState(0);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [authVersion, setAuthVersion] = useState(0);
  const generation = useRef(0);
  const owner = useRef<string | null>(null);
  const cursor = useRef(0);
  const selected = useRef<string | null>(null);
  const pending = useRef<{ config: ScanRequest; key: string } | null>(null);
  const mutation = useRef<AbortController | null>(null);

  const resetScan = useCallback(() => {
    generation.current += 1;
    mutation.current?.abort();
    mutation.current = null;
    pending.current = null;
    selected.current = null;
    cursor.current = 0;
    setScanId(null); setStatus(null); setScanState(null); setHistory([]);
    setProgressLog([]); setScanProgress({}); setCreating(false); setError(null);
    setConnectionVersion((v) => v + 1);
  }, []);

  const expireSession = useCallback(() => {
    resetScan(); owner.current = null; setAuthUser(null); setAuthReady(true);
    setError("Session expired. Sign in again.");
  }, [resetScan]);

  const loginUser = useCallback((email: string, role: string) => {
    resetScan(); owner.current = email; setAuthUser({ email, role });
    setAuthReady(true); setAuthVersion((v) => v + 1);
  }, [resetScan]);

  useEffect(() => {
    // Remove legacy script-readable tokens; identity is verified by the server.
    try {
      localStorage.removeItem("cybershield.authToken");
      localStorage.removeItem("cybershield.authUser");
      localStorage.removeItem(LAST_SCAN);
    } catch { /* Storage may be disabled. */ }
    const controller = new AbortController();
    const initialGeneration = generation.current;
    request<AuthUser>("/api/v1/auth/me", { signal: controller.signal })
      .then((user) => { if (!controller.signal.aborted && generation.current === initialGeneration) loginUser(user.email, user.role); })
      .catch((failure: Error) => {
        if (!controller.signal.aborted && !(failure instanceof ApiError && failure.status === 401)) setError(failure.message);
      }).finally(() => { if (!controller.signal.aborted) setAuthReady(true); });
    return () => { controller.abort(); mutation.current?.abort(); };
  }, [loginUser]);

  const logoutUser = async () => {
    if (isLoggingOut) return;
    setIsLoggingOut(true);
    setError(null);
    try {
      try { await request("/api/v1/auth/logout", { method: "POST" }); }
      catch (failure) {
        if (!(failure instanceof ApiError && failure.status === 401)) {
          setError("Logout could not be confirmed. Please try again."); return;
        }
      }
      try { if (owner.current) localStorage.removeItem(`${LAST_SCAN}.${owner.current}`); } catch { /* Optional storage. */ }
      resetScan(); owner.current = null; setAuthUser(null);
    } finally {
      setIsLoggingOut(false);
    }
  };

  const openScan = useCallback((id: string) => {
    selected.current = id;
    cursor.current = 0;
    setProgressLog([]);
    setScanProgress({});
    setScanState(null);
    setStatus(null);
    setError(null);
    setScanId(id);
    setConnectionVersion((value) => value + 1);
    try { if (owner.current) localStorage.setItem(`${LAST_SCAN}.${owner.current}`, id); } catch { /* Storage may be disabled. */ }
  }, []);

  useEffect(() => {
    if (!authUser) return;
    try {
      const id = localStorage.getItem(`${LAST_SCAN}.${authUser.email}`);
      if (id) openScan(id);
    } catch { /* History remains available without local storage. */ }
    return () => mutation.current?.abort();
  }, [openScan, authUser, authVersion]);

  useEffect(() => {
    if (!authUser) return;
    const controller = new AbortController();
    request<ScanJob[]>("/api/scans", { signal: controller.signal })
      .then((jobs) => { if (!controller.signal.aborted) setHistory(jobs); })
      .catch((failure: Error) => {
        if (!controller.signal.aborted) {
          if (failure instanceof ApiError && failure.status === 401) expireSession();
          else setError(failure.message);
        }
      });
    return () => controller.abort();
  }, [historyVersion, authUser, authVersion, expireSession]);

  useEffect(() => {
    if (!scanId || !authUser) return;
    const controller = new AbortController();
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let retries = 0;
    const active = () => !controller.signal.aborted && selected.current === scanId;
    const finish = (jobStatus: ScanStatus, state: ScanState | null, detail?: unknown) => {
      setStatus(jobStatus);
      setScanState(state);
      if (state?.scan_progress) setScanProgress(state.scan_progress);
      setError(jobStatus === "completed" ? null
        : typeof detail === "string" && detail ? detail
        : detail ? JSON.stringify(detail) : `Scan ${jobStatus.replaceAll("_", " ")}.`);
      source?.close();
      setHistoryVersion((value) => value + 1);
    };
    const connect = () => {
      if (!active()) return;
      source = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/events?after=${cursor.current}`);
      source.onopen = () => { if (active()) setError(null); };
      source.onmessage = (event) => {
        if (!active()) return;
        try {
          const data = JSON.parse(event.data) as ScanEvent;
          const sequence = data.id;
          if (sequence !== undefined && Number.isFinite(sequence)) {
            if (sequence <= cursor.current) return;
            cursor.current = sequence;
          }
          retries = 0;
          if (data.type === "progress") {
            setProgressLog((log) => [...log, `[${data.stage.toUpperCase()}] ${data.message}`]);
            setStatus((current) => current === "cancelling" ? current : "running");
            setScanProgress((progress) => ({ ...progress, [data.stage]: data.status === "running" || !data.status ? "in_progress" : data.status }));
          } else if (data.type === "complete") {
            finish(data.status, data.state, data.error ?? data.message);
          } else if (data.type === "error") {
            if (data.code === "AUTH_REQUIRED") { expireSession(); return; }
            setError(data.message);
            source?.close();
          }
        } catch {
          setError("The scan stream returned an invalid event. Reconnect to resume.");
          source?.close();
        }
      };
      source.onerror = async () => {
        source?.close();
        if (!active()) return;
        try { await request("/api/v1/auth/me", { signal: controller.signal }); }
        catch (failure) {
          if (active() && failure instanceof ApiError && failure.status === 401) { expireSession(); return; }
        }
        if (!active()) return;
        if (retries >= 3) {
          setError("Connection interrupted. Reconnect to the existing scan.");
          return;
        }
        retries += 1;
        timer = setTimeout(connect, 1000 * 2 ** retries);
      };
    };
    request<ScanJob>(`/api/scans/${encodeURIComponent(scanId)}`, { signal: controller.signal })
      .then((job) => {
        if (!active()) return;
        setStatus(job.status);
        if (terminal(job.status)) finish(job.status, job.result, job.error);
        else connect();
      })
      .catch((failure: Error) => { if (active()) {
        if (failure instanceof ApiError && failure.status === 401) expireSession();
        else setError(failure.message);
      } });
    return () => {
      controller.abort();
      source?.close();
      if (timer) clearTimeout(timer);
    };
  }, [scanId, connectionVersion, authUser, authVersion, expireSession]);

  const startScan = useCallback(async (config: ScanRequest) => {
    if (!owner.current) { setError("Sign in before starting a scan."); return; }
    if (mutation.current) return;
    const issuedGeneration = generation.current;
    const controller = new AbortController();
    mutation.current = controller;
    if (!pending.current || JSON.stringify(pending.current.config) !== JSON.stringify(config)) {
      pending.current = { config, key: crypto.randomUUID() };
    }
    setCreating(true);
    setError(null);
    try {
      const job = await request<ScanJob>("/api/scans", {
        method: "POST", signal: controller.signal,
        headers: { "Content-Type": "application/json", "Idempotency-Key": pending.current.key },
        body: JSON.stringify(config),
      });
      if (controller.signal.aborted || generation.current !== issuedGeneration) return;
      pending.current = null;
      openScan(job.id);
      setHistoryVersion((value) => value + 1);
    } catch (failure) {
      if (!controller.signal.aborted) {
        if (failure instanceof ApiError && failure.status === 401) expireSession();
        else setError((failure as Error).message);
      }
    } finally {
      if (mutation.current === controller) mutation.current = null;
      if (!controller.signal.aborted) setCreating(false);
    }
  }, [openScan, expireSession]);

  const reconnect = useCallback(() => {
    if (pending.current) void startScan(pending.current.config);
    else if (scanId) { setError(null); setConnectionVersion((value) => value + 1); }
  }, [scanId, startScan]);

  const cancelScan = useCallback(async () => {
    if (!scanId || mutation.current) return;
    const controller = new AbortController();
    mutation.current = controller;
    try {
      const job = await request<ScanJob>(`/api/scans/${encodeURIComponent(scanId)}/cancel`, {
        method: "POST", signal: controller.signal,
      });
      if (controller.signal.aborted || selected.current !== scanId) return;
      setStatus(job.status);
      setHistoryVersion((value) => value + 1);
      setConnectionVersion((value) => value + 1);
    } catch (failure) {
      if (!controller.signal.aborted) {
        if (failure instanceof ApiError && failure.status === 401) expireSession();
        else setError((failure as Error).message);
      }
    } finally { if (mutation.current === controller) mutation.current = null; }
  }, [scanId, expireSession]);

  return { scanId, status, scanState, progressLog, scanProgress, error, history,
    isScanning: creating || (status !== null && !terminal(status)),
    startScan, reconnect, openScan, cancelScan,
    refreshHistory: () => setHistoryVersion((value) => value + 1),
    authUser, authReady, loginUser, logoutUser, isLoggingOut,
  };
}
