"use client";

import React, { useState } from "react";
import { Globe2, ArrowRight, ShieldCheck, Sparkles } from "lucide-react";

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
  {
    id: "llama-3.3-70b-versatile",
    name: "Llama 3.3 70B",
    tag: "Groq Ultra-Fast",
  },
  { id: "deepseek-chat", name: "DeepSeek V3 / R1", tag: "DeepSeek AI" },
  { id: "gpt-4o-mini", name: "GPT-4o Mini", tag: "OpenAI" },
  { id: "offline-rules", name: "Offline Rules Engine", tag: "Deterministic" },
];

interface ScanConfigProps {
  onStartScan: (request: ScanRequest) => void;
  isScanning: boolean;
  canScan?: boolean;
}

export default function ScanConfig({
  onStartScan,
  isScanning,
  canScan = true,
}: ScanConfigProps) {
  const [domain, setDomain] = useState("testphp.vulnweb.com");
  const [authorized, setAuthorized] = useState(false);
  const [scopeType, setScopeType] = useState("passive_only");
  const [email] = useState("");
  const [mode, setMode] = useState<ExecutionMode>("demo");
  const [strictLive, setStrictLive] = useState(false);
  const [aiModel, setAiModel] = useState("gemma4:31b-cloud");

  const handleSubmit = (e: React.FormEvent, mock: boolean) => {
    e.preventDefault();
    if (!domain.trim()) return;
    const executionMode = mock
      ? "demo"
      : mode === "live" && aiModel === "offline-rules"
        ? "rules_only"
        : mode;
    if (!authorized || !canScan) return;
    onStartScan({
      domain: domain.trim(),
      authorized,
      scope_type: scopeType,
      contact_email: email,
      execution_mode: executionMode,
      strict_live: executionMode === "live" && strictLive,
      ai_model: aiModel,
    });
  };

  return (
    <section className="cs-card scan-config">
      <div className="section-heading">
        <div>
          <h2>Start an assessment</h2>
          <p>Define your target and choose how to assess it.</p>
        </div>
        <span className="section-icon">
          <Globe2 size={21} />
        </span>
      </div>
      <form
        onSubmit={(event) => handleSubmit(event, false)}
        className="assessment-form"
      >
        <div>
          <label htmlFor="target-domain">Target domain or IP address</label>
          <div className="target-input">
            <Globe2 size={18} />
            <input
              id="target-domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              required
              disabled={isScanning}
            />
          </div>
        </div>
        <fieldset disabled={isScanning}>
          <legend>Assessment mode</legend>
          <div className="mode-options">
            {[
              { id: "demo", name: "Demo", desc: "Explore with fixtures" },
              {
                id: "rules_only",
                name: "Rules only",
                desc: "Probes, without AI",
              },
              { id: "live", name: "Live + AI", desc: "Probes & AI analysis" },
            ].map((item) => (
              <label
                key={item.id}
                className={`mode-option ${mode === item.id ? "active" : ""}`}
              >
                <input
                  type="radio"
                  name="mode"
                  value={item.id}
                  checked={mode === item.id}
                  onChange={() => {
                    setMode(item.id as ExecutionMode);
                    if (item.id === "live" && aiModel === "offline-rules")
                      setAiModel("gemma4:31b-cloud");
                  }}
                />
                <strong>{item.name}</strong>
                <small>{item.desc}</small>
              </label>
            ))}
          </div>
        </fieldset>
        {mode === "demo" && (
          <p className="mode-hint">
            <Sparkles size={14} /> Offline fixtures. No network requests to the
            target.
          </p>
        )}
        {mode === "live" && (
          <>
            <div>
              <label htmlFor="ai-model">AI reasoning model</label>
              <select
                id="ai-model"
                value={aiModel}
                disabled={isScanning}
                onChange={(e) => {
                  setAiModel(e.target.value);
                  if (e.target.value === "offline-rules") setMode("rules_only");
                }}
              >
                {AVAILABLE_MODELS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name} — {m.tag}
                  </option>
                ))}
              </select>
            </div>
            <label className="simple-checkbox">
              <input
                type="checkbox"
                checked={strictLive}
                disabled={isScanning}
                onChange={(e) => setStrictLive(e.target.checked)}
              />{" "}
              Stop when a live stage is unavailable
            </label>
          </>
        )}
        <div>
          <label htmlFor="scan-scope">Assessment scope</label>
          <select
            id="scan-scope"
            value={scopeType}
            onChange={(e) => setScopeType(e.target.value)}
            disabled={isScanning}
          >
            <option value="passive_only">
              Passive · DNS, TLS, headers & threat intelligence
            </option>
            <option value="full_pentest">
              Full assessment · includes active security probes
            </option>
          </select>
        </div>
        <label className={`authorization-check ${authorized ? "checked" : ""}`}>
          <input
            type="checkbox"
            checked={authorized}
            disabled={isScanning}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          <span>
            <strong>I have explicit authorization</strong>
            <small>
              I have permission to assess this target within the selected scope.
            </small>
          </span>
          <ShieldCheck size={20} />
        </label>
        <div className="assessment-actions">
          <p>
            {!canScan
              ? "Sign in to begin."
              : !authorized
                ? "Confirm authorization to continue."
                : "Scope confirmed. Ready when you are."}
          </p>
          <button
            type="submit"
            className="primary-button"
            disabled={!canScan || isScanning || !domain.trim() || !authorized}
          >
            {isScanning
              ? "Assessment running…"
              : mode === "demo"
                ? "Start demo assessment"
                : "Start assessment"}
            <ArrowRight size={17} />
          </button>
        </div>
      </form>
    </section>
  );
}
