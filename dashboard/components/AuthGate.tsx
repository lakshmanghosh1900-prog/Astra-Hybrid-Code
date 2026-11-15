"use client";

import { FormEvent, useEffect, useState } from "react";
import { Dashboard } from "./Dashboard";

type AuthState = "loading" | "anonymous" | "authenticated" | "error";

async function responseMessage(response: Response, fallback: string): Promise<string> {
  try {
    const body = await response.json() as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : fallback;
  } catch {
    return fallback;
  }
}

function csrfToken(): string | undefined {
  const prefix = "astra_dashboard_csrf=";
  const value = document.cookie
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(prefix))
    ?.slice(prefix.length);
  return value ? decodeURIComponent(value) : undefined;
}

export function AuthGate() {
  const [state, setState] = useState<AuthState>("loading");
  const [loginToken, setLoginToken] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void fetch("/api/auth/session", { credentials: "same-origin", cache: "no-store" })
      .then((response) => {
        if (!active) return;
        setState(response.ok ? "authenticated" : response.status === 401 ? "anonymous" : "error");
        if (!response.ok && response.status !== 401) setError("Dashboard authentication is unavailable.");
      })
      .catch(() => {
        if (active) {
          setState("error");
          setError("Dashboard authentication is unavailable.");
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ loginToken }),
      });
      if (!response.ok) {
        setError(await responseMessage(response, "Login failed."));
        setState("anonymous");
        return;
      }
      setLoginToken("");
      setState("authenticated");
    } catch {
      setError("Dashboard authentication is unavailable.");
      setState("error");
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    setBusy(true);
    setError(undefined);
    try {
      const csrf = csrfToken();
      const response = await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: csrf ? { "X-Astra-CSRF": csrf } : undefined,
      });
      if (!response.ok) {
        setError(await responseMessage(response, "Logout failed."));
        return;
      }
      setState("anonymous");
    } catch {
      setError("Dashboard authentication is unavailable.");
      setState("error");
    } finally {
      setBusy(false);
    }
  }

  if (state === "loading") {
    return <main className="mx-auto min-h-screen max-w-2xl px-6 py-16"><p role="status">Checking dashboard session…</p></main>;
  }

  if (state !== "authenticated") {
    return <main className="mx-auto min-h-screen max-w-md px-6 py-16">
      <h1 className="text-3xl font-bold">Astra Coder</h1>
      <p className="mt-2 text-slate-400">Sign in to review tasks and independent evidence.</p>
      {error && <p role="alert" className="mt-4 rounded border border-rose-700 bg-rose-950/40 p-3 text-rose-200">{error}</p>}
      <form onSubmit={(event) => void login(event)} className="mt-6 space-y-4">
        <label className="block text-sm font-medium" htmlFor="dashboard-login-token">Dashboard login token</label>
        <input
          id="dashboard-login-token"
          type="password"
          autoComplete="current-password"
          value={loginToken}
          onChange={(event) => setLoginToken(event.target.value)}
          required
          className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
        />
        <button type="submit" disabled={busy} className="rounded-md bg-sky-600 px-4 py-2 font-medium disabled:opacity-60">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>;
  }

  return <>
    <div className="mx-auto flex max-w-7xl justify-end px-6 pt-4">
      <button type="button" onClick={() => void logout()} disabled={busy} className="rounded-md border border-slate-700 px-3 py-2 text-sm disabled:opacity-60">
        {busy ? "Signing out…" : "Sign out"}
      </button>
    </div>
    <Dashboard />
  </>;
}
