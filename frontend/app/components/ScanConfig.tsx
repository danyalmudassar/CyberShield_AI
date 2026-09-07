"use client";

import React, { useState } from "react";
import {
  Search, Play, Sparkles, CheckSquare, Square, ChevronDown, Cpu,
} from "lucide-react";

import type { ExecutionMode, ScanRequest } from "../../lib/api-types";

const AVAILABLE_MODELS = [
  { id: "gemma4:31b-cloud", name: "Gemma4 31B", tag: "Ollama Cloud" },
  { id: "gemini-2.5-flash", name: "Gemini 2.5 Flash", tag: "Google AI" },
  { id: "gemini-2.5-pro", name: "Gemini 2.5 Pro", tag: "Google AI" },
  { id: "gpt-oss:120b", name: "GPT-OSS 120B", tag: "High Performance" },
  { id: "gpt-oss:20b", name: "GPT-OSS 20B", tag: "Fast" },
  { id: "nemotron-3-nano:30b", name: "Nemotron-3 Nano 30B", tag: "NVIDIA AI" },
  { id: "nemotron-3-super", name: "Nemotron-3 Super", tag: "NVIDIA AI" },
  { id: "nemotron-3-ultra", name: "Nemotron-3 Ultra", tag: "NVIDIA AI" },
  { id: "llama-3.3-70b-versatile", name: "Llama 3.3 70B", tag: "Groq Ultra-Fast" },
  { id: "deepseek-chat", name: "DeepSeek V3 / R1", tag: "DeepSeek AI" },
  { id: "gpt-4o-mini", name: "GPT-4o Mini", tag: "OpenAI" },
  { id: "offline-rules", name: "Offline Rules Engine", tag: "Deterministic" },
];

interface ScanConfigProps {
  onStartScan: (request: ScanRequest) => void;
  isScanning: boolean;
  canScan?: boolean;
}

export default function ScanConfig({ onStartScan, isScanning, canScan = true }: ScanConfigProps) {
  const [domain, setDomain] = useState("testphp.vulnweb.com");
  const [authorized, setAuthorized] = useState(false);
  const [scopeType, setScopeType] = useState("passive_only");
  const [email] = useState("");
  const [mode, setMode] = useState<ExecutionMode>("live");
  const [strictLive, setStrictLive] = useState(false);
  const [aiModel, setAiModel] = useState("gemma4:31b-cloud");

  const handleSubmit = (e: React.FormEvent, mock: boolean) => {
    e.preventDefault();
    if (!domain.trim()) return;
    const executionMode = mock ? "demo" : mode === "live" && aiModel === "offline-rules" ? "rules_only" : mode;
    if (!authorized || !canScan) return;
    onStartScan({ domain: domain.trim(), authorized, scope_type: scopeType,
      contact_email: email, execution_mode: executionMode,
      strict_live: executionMode === "live" && strictLive, ai_model: aiModel });
  };

  const selectedModel = AVAILABLE_MODELS.find((m) => m.id === aiModel);

  return (
    <div className="cs-card p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[15px] font-semibold text-black dark:text-white">Target Configuration</h2>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">PTES Phase 1 — Pre-Engagement Authorization</p>
        </div>
        <span className="rounded-full border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 px-2.5 py-1 text-[10px] font-semibold text-neutral-500 dark:text-neutral-400 tracking-wider uppercase">
          PISF 2026
        </span>
      </div>

      <form className="space-y-4" onSubmit={(event) => handleSubmit(event, false)}>
        {/* Domain input */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-neutral-700 dark:text-neutral-300 uppercase tracking-wider">
            Target Domain / IP
          </label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-neutral-400 dark:text-neutral-500" />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g. example.com"
              disabled={isScanning}
              className="cs-focus w-full rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 pl-9 pr-4 py-2.5 text-sm text-black dark:text-white placeholder:text-neutral-400 dark:placeholder:text-neutral-500 focus:border-black dark:focus:border-white focus:outline-none transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="execution-mode" className="text-xs font-medium">Execution mode</label>
          <select id="execution-mode" value={mode} onChange={(event) => setMode(event.target.value as ExecutionMode)} disabled={isScanning} className="w-full rounded-lg border bg-[var(--background)] p-2 text-sm">
            <option value="live">Live — probes and AI analysis</option>
            <option value="rules_only">Rules only — probes without AI</option>
            <option value="demo">Demo — fixtures, no target requests</option>
          </select>
          {mode === "live" && <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={strictLive} disabled={isScanning} onChange={(event) => setStrictLive(event.target.checked)} /> Fail explicitly when a live stage is unavailable</label>}
        </div>

        {/* AI Model selector */}
        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-neutral-700 dark:text-neutral-300 uppercase tracking-wider">
            <Cpu className="h-3 w-3" />
            AI Reasoning Model
          </label>
          <div className="relative">
            <select
              value={aiModel}
              onChange={(e) => { setAiModel(e.target.value); if (e.target.value === "offline-rules") setMode("rules_only"); }}
              disabled={isScanning}
              className="cs-focus w-full appearance-none rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 px-4 py-2.5 text-sm text-black dark:text-white focus:border-black dark:focus:border-white focus:outline-none transition-colors cursor-pointer disabled:opacity-50"
            >
              {AVAILABLE_MODELS.map((model) => (
                <option key={model.id} value={model.id} className="bg-white dark:bg-neutral-900 text-black dark:text-white">
                  {model.name} — {model.tag}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-neutral-400 pointer-events-none" />
          </div>
          {selectedModel && (
            <p className="text-[11px] text-neutral-400 dark:text-neutral-500">
              Provider: <span className="text-neutral-600 dark:text-neutral-300 font-medium">{selectedModel.tag}</span>
            </p>
          )}
        </div>

        {!canScan && <p className="text-xs text-neutral-500">Sign in to start a scan.</p>}

        {/* Authorization checkbox — cal.com style */}
        <button
          type="button"
          onClick={() => setAuthorized(!authorized)}
          disabled={isScanning}
          className="w-full flex items-start gap-3 rounded-lg border border-neutral-200 dark:border-neutral-800 p-3.5 text-left hover:border-neutral-300 dark:hover:border-neutral-700 transition-colors disabled:opacity-50"
        >
          <div className="mt-0.5 flex-shrink-0">
            {authorized ? (
              <CheckSquare className="h-4 w-4 text-black dark:text-white" />
            ) : (
              <Square className="h-4 w-4 text-neutral-400 dark:text-neutral-500" />
            )}
          </div>
          <div>
            <p className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">I have explicit authorization</p>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
              I confirm I have written permission to perform security testing on this domain.
            </p>
          </div>
        </button>

        {/* Scope selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-neutral-700 dark:text-neutral-300 uppercase tracking-wider">
            Scan Scope
          </label>
          <div className="grid grid-cols-2 gap-2">
            {[
              { id: "passive_only", label: "Passive Only", desc: "DNS, SSL, Headers, Threat Intel" },
              { id: "full_pentest", label: "Full Pentest", desc: "24 Active Security Probes" },
            ].map((scope) => (
              <button
                key={scope.id}
                type="button"
                onClick={() => setScopeType(scope.id)}
                disabled={isScanning}
                className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-all disabled:opacity-50 ${
                  scopeType === scope.id
                    ? "border-black bg-black text-white dark:border-white dark:bg-white dark:text-black"
                    : "border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 text-black dark:text-white hover:border-neutral-400 dark:hover:border-neutral-600"
                }`}
              >
                <span className="text-xs font-semibold">{scope.label}</span>
                <span className={`text-[10px] ${
                  scopeType === scope.id
                    ? "text-neutral-300 dark:text-neutral-700"
                    : "text-neutral-500 dark:text-neutral-400"
                }`}>
                  {scope.desc}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-2 pt-1">
          <button
            type="submit"
            disabled={!canScan || isScanning || !domain.trim() || !authorized}
            className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-black dark:bg-white px-5 py-2.5 text-sm font-semibold text-white dark:text-black hover:bg-neutral-800 dark:hover:bg-neutral-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {isScanning ? (
              <>
                <div className="h-3.5 w-3.5 border-2 border-white/30 dark:border-black/30 border-t-white dark:border-t-black rounded-full animate-spin" />
                <span>Scanning…</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-white dark:fill-black" />
                <span>Launch Security Audit</span>
              </>
            )}
          </button>
          <button
            type="button"
            onClick={(e) => handleSubmit(e, true)}
            disabled={!canScan || isScanning || !domain.trim() || !authorized}
            className="flex items-center gap-1.5 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 px-4 py-2.5 text-sm font-medium text-neutral-700 dark:text-neutral-300 hover:border-neutral-400 dark:hover:border-neutral-600 hover:text-black dark:hover:text-white transition-colors disabled:opacity-40"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Demo
          </button>
        </div>

        {!authorized && domain && (
          <p className="text-xs text-red-500 dark:text-red-400 flex items-center gap-1">
            ⚠ Authorization confirmation required before launching scan.
          </p>
        )}
      </form>
    </div>
  );
}
