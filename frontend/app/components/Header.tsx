"use client";

import React, { useEffect, useState } from "react";
import { ShieldCheck, Activity, Cpu, ArrowUpRight, Sun, Moon, Monitor } from "lucide-react";
import { useTheme } from "next-themes";

import LoginModal from "./LoginModal";

interface HeaderProps {
  activeTab?: string;
  onSelectTab?: (tab: "overview" | "pisf" | "visual" | "findings" | "report") => void;
  authUser?: { email: string; role: string } | null;
  onLogin?: (email: string, role: string) => void;
  onLogout?: () => void;
}

export default function Header({ activeTab = "overview", onSelectTab, authUser = null, onLogin, onLogout }: HeaderProps) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-neutral-200 dark:border-neutral-800 bg-white/80 dark:bg-neutral-950/80 backdrop-blur-md transition-colors">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 sm:px-6 h-14">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-black dark:bg-white text-white dark:text-black transition-colors">
            <ShieldCheck className="h-4 w-4" strokeWidth={2.5} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[15px] font-bold tracking-tight text-black dark:text-white">
              CyberShield
            </span>
            <span className="text-[15px] font-bold tracking-tight text-neutral-400 dark:text-neutral-500">
              AI
            </span>
            <span className="ml-1 rounded-full border border-neutral-200 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-900 px-2 py-0.5 text-[10px] font-semibold text-neutral-500 dark:text-neutral-400 tracking-wider uppercase">
              SOC v2.0
            </span>
          </div>
        </div>

        {/* Nav links */}
        <nav className="hidden md:flex items-center gap-6">
          <button
            onClick={() => onSelectTab?.("overview")}
            className={`text-sm font-medium transition-colors ${
              activeTab === "overview"
                ? "text-black dark:text-white border-b-2 border-black dark:border-white pb-0.5"
                : "text-neutral-500 hover:text-black dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => onSelectTab?.("report")}
            className={`text-sm font-medium transition-colors ${
              activeTab === "report"
                ? "text-black dark:text-white border-b-2 border-black dark:border-white pb-0.5"
                : "text-neutral-500 hover:text-black dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            Reports
          </button>
          <button
            onClick={() => onSelectTab?.("pisf")}
            className={`text-sm font-medium transition-colors ${
              activeTab === "pisf"
                ? "text-black dark:text-white border-b-2 border-black dark:border-white pb-0.5"
                : "text-neutral-500 hover:text-black dark:text-neutral-400 dark:hover:text-white"
            }`}
          >
            PISF 2026
          </button>
        </nav>

        {/* Right tools & status */}
        <div className="flex items-center gap-2">
          {/* Status pills */}
          <div className="hidden lg:flex items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-full border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 px-3 py-1 text-xs text-neutral-600 dark:text-neutral-300">
              <Activity className="h-3 w-3 text-emerald-500" />
              <span>384K CVEs</span>
            </div>
            <div className="flex items-center gap-1.5 rounded-full border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 px-3 py-1 text-xs text-neutral-600 dark:text-neutral-300">
              <Cpu className="h-3 w-3 text-neutral-500 dark:text-neutral-400" />
              <span>AI Engine</span>
            </div>
          </div>

          {/* Light / Dark Mode Toggle */}
          {mounted ? (
            <div className="flex items-center rounded-full border border-neutral-200 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-900 p-0.5">
              <button
                onClick={() => setTheme("light")}
                title="Light mode"
                className={`flex h-6 w-6 items-center justify-center rounded-full transition-all ${
                  theme === "light"
                    ? "bg-white text-black shadow-sm"
                    : "text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
                }`}
              >
                <Sun className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => setTheme("dark")}
                title="Dark mode"
                className={`flex h-6 w-6 items-center justify-center rounded-full transition-all ${
                  theme === "dark"
                    ? "bg-neutral-800 text-white shadow-sm"
                    : "text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
                }`}
              >
                <Moon className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => setTheme("system")}
                title="System theme"
                className={`flex h-6 w-6 items-center justify-center rounded-full transition-all ${
                  theme === "system"
                    ? "bg-white dark:bg-neutral-800 text-black dark:text-white shadow-sm"
                    : "text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
                }`}
              >
                <Monitor className="h-3.5 w-3.5" />
              </button>
            </div>
          ) : (
            <div className="h-7 w-20 rounded-full border border-neutral-200 dark:border-neutral-800 bg-neutral-100 dark:bg-neutral-900" />
          )}

          <LoginModal
            user={authUser}
            onLogin={onLogin || (() => {})}
            onLogout={onLogout || (() => {})}
          />

          <a
            href="https://pkcert.gov.pk/grc-policies.asp"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:flex items-center gap-1 rounded-full bg-black dark:bg-white px-3 py-1 text-xs font-medium text-white dark:text-black hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors"
          >
            PISF 2026
            <ArrowUpRight className="h-3 w-3" />
          </a>
        </div>
      </div>
    </header>
  );
}
