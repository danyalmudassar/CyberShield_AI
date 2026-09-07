"use client";

import React, { useState } from "react";
import { LogIn, LogOut, User, Lock, CheckCircle2, AlertCircle } from "lucide-react";

interface LoginModalProps {
  user: { email: string; role: string } | null;
  onLogin: (email: string, role: string) => void;
  onLogout: () => void;
}

export default function LoginModal({ user, onLogin, onLogout }: LoginModalProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [email, setEmail] = useState("operator@cybershield.ai");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CyberShield-Request": "1" },
        body: JSON.stringify({ email, password }),
        credentials: "same-origin",
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.detail || "Invalid credentials");
      }

      const data = await res.json();
      onLogin(data.email, data.role);
      setPassword("");
      setIsOpen(false);
    } catch (err: any) {
      setError(err.message || "Failed to authenticate");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {user ? (
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-full border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 px-3 py-1 text-xs text-emerald-700 dark:text-emerald-300 font-medium">
            <User className="h-3.5 w-3.5" />
            <span>{user.email.split("@")[0]}</span>
            <span className="rounded bg-emerald-200 dark:bg-emerald-900 px-1 py-0.2 text-[9px] uppercase font-bold">
              {user.role}
            </span>
          </div>
          <button
            type="button"
            onClick={onLogout}
            title="Log out"
            className="flex h-7 w-7 items-center justify-center rounded-full border border-neutral-200 dark:border-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-900 transition-colors text-neutral-500 hover:text-red-500"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="flex items-center gap-1.5 rounded-full border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-900 px-3 py-1 text-xs font-medium hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors"
        >
          <LogIn className="h-3.5 w-3.5 text-neutral-600 dark:text-neutral-300" />
          <span>Sign In</span>
        </button>
      )}

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div role="dialog" aria-modal="true" aria-labelledby="login-title" className="w-full max-w-sm rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-black dark:bg-white text-white dark:text-black">
                  <Lock className="h-4 w-4" />
                </div>
                <h3 id="login-title" className="text-base font-bold">SOC Login</h3>
              </div>
              <button
                type="button"
                onClick={() => { setPassword(""); setIsOpen(false); }}
                className="text-neutral-400 hover:text-neutral-600 text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              {error && (
                <div className="flex items-center gap-2 text-xs text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/30 p-2.5 rounded-lg border border-red-200 dark:border-red-900">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div>
                <label htmlFor="login-email" className="block text-xs font-medium text-neutral-500 mb-1">Email</label>
                <input
                  type="email"
                  id="login-email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-800 px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white"
                />
              </div>

              <div>
                <label htmlFor="login-password" className="block text-xs font-medium text-neutral-500 mb-1">Password</label>
                <input
                  type="password"
                  id="login-password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-800 px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => { setPassword(""); setIsOpen(false); }}
                  className="px-3 py-1.5 text-xs font-medium text-neutral-600 hover:text-black dark:text-neutral-400 dark:hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="rounded-lg bg-black dark:bg-white px-4 py-1.5 text-xs font-semibold text-white dark:text-black hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  {loading ? "Authenticating..." : "Login"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
