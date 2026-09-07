"use client";

import React, { useState } from "react";
import { AlertTriangle, ChevronDown, ChevronUp, ShieldAlert } from "lucide-react";

interface FindingsTableProps {
  findings: any[];
}

const SEV_CONFIG: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: "bg-black dark:bg-white", text: "text-white dark:text-black", border: "border-black dark:border-white", dot: "bg-white dark:bg-black" },
  HIGH:     { bg: "bg-neutral-900 dark:bg-neutral-100", text: "text-white dark:text-black", border: "border-neutral-900 dark:border-neutral-100", dot: "bg-white dark:bg-black" },
  MEDIUM:   { bg: "bg-neutral-100 dark:bg-neutral-800", text: "text-neutral-800 dark:text-neutral-200", border: "border-neutral-300 dark:border-neutral-700", dot: "bg-neutral-600 dark:bg-neutral-400" },
  LOW:      { bg: "bg-neutral-50 dark:bg-neutral-900", text: "text-neutral-600 dark:text-neutral-400", border: "border-neutral-200 dark:border-neutral-800", dot: "bg-neutral-400 dark:bg-neutral-500" },
  INFO:     { bg: "bg-white dark:bg-neutral-950", text: "text-neutral-500 dark:text-neutral-400", border: "border-neutral-200 dark:border-neutral-800", dot: "bg-neutral-300 dark:bg-neutral-600" },
};

const PROV_CONFIG: Record<string, { label: string; color: string }> = {
  DETERMINISTIC: { label: "Deterministic", color: "text-emerald-600 dark:text-emerald-400" },
  OFFLINE_VERIFIER: { label: "Deterministic scanner", color: "text-emerald-600 dark:text-emerald-400" },
  LLM_REASONING: { label: "AI Reasoning", color: "text-purple-600 dark:text-purple-400" },
  AI: { label: "AI", color: "text-purple-600 dark:text-purple-400" },
  MOCK: { label: "Mock", color: "text-amber-600 dark:text-amber-400" },
  FALLBACK: { label: "Fallback", color: "text-amber-600 dark:text-amber-400" },
};

function getSevConfig(sev: string) {
  return SEV_CONFIG[sev?.toUpperCase()] ?? SEV_CONFIG.INFO;
}

function getProvConfig(prov: string) {
  const key = Object.keys(PROV_CONFIG).find((k) => (prov || "").toUpperCase().includes(k));
  return key ? PROV_CONFIG[key] : { label: prov || "Unknown", color: "text-neutral-500 dark:text-neutral-400" };
}

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  if (!findings || findings.length === 0) {
    return (
      <div className="cs-card p-12 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-neutral-200 dark:border-neutral-800">
          <ShieldAlert className="h-5 w-5 text-neutral-400 dark:text-neutral-500" />
        </div>
        <p className="text-sm font-medium text-neutral-700 dark:text-neutral-300">No Findings Available</p>
        <p className="text-xs text-neutral-400 dark:text-neutral-500 mt-1">Check scan status and coverage; an empty list does not establish that the target is secure.</p>
      </div>
    );
  }

  const filtered = selectedSeverity === "ALL"
    ? findings
    : findings.filter((f) => f.severity?.toUpperCase() === selectedSeverity);

  const countBySev = (sev: string) => findings.filter((f) => f.severity?.toUpperCase() === sev).length;

  return (
    <div className="cs-card overflow-hidden">
      {/* Header */}
      <div className="border-b border-neutral-200 dark:border-neutral-800 px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="text-[15px] font-semibold text-black dark:text-white flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-neutral-600 dark:text-neutral-400" />
              Findings & Assessment Evidence
            </h3>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
              Mapped to OWASP Top 10, WSTG, CWE, and PISF 2026
            </p>
          </div>

          {/* Severity filter tabs */}
          <div className="flex items-center gap-1 rounded-lg border border-neutral-200 dark:border-neutral-800 p-1 bg-neutral-50 dark:bg-neutral-900">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => {
              const count = sev === "ALL" ? findings.length : countBySev(sev);
              return (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`rounded-md px-2.5 py-1 text-[10px] font-semibold transition-all ${
                    selectedSeverity === sev
                      ? "bg-white dark:bg-neutral-800 text-black dark:text-white shadow-sm border border-neutral-200 dark:border-neutral-700"
                      : "text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
                  }`}
                >
                  {sev === "ALL" ? "All" : sev.charAt(0) + sev.slice(1).toLowerCase()} {count > 0 && `(${count})`}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="cs-table w-full text-sm">
          <thead>
            <tr className="border-b border-neutral-200 dark:border-neutral-800">
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">ID</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">Severity</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 hidden sm:table-cell">Source</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">Title</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 hidden md:table-cell">CVSS</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 hidden lg:table-cell">PISF</th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
            {filtered.map((f, idx) => {
              const id = f.finding_id || f.check_id || `FINDING-${idx}`;
              const isExpanded = expandedRow === id;
              const sevCfg = getSevConfig(f.severity);
              const provCfg = getProvConfig(f.provenance || "");
              const provenance = String(f.provenance || "").toUpperCase();
              const checkStatus = String(f.check_status || "UNKNOWN").toUpperCase();
              const isDemo = /MOCK|FIXTURE|DEMO/.test(provenance) || checkStatus === "MOCK_FALLBACK";
              const isCandidate = provenance === "LLM_REASONING" || checkStatus === "UNVERIFIED_CANDIDATE";
              const verdict = isDemo ? "Demo / mock evidence" : isCandidate ? "Unverified candidate"
                : ["VULNERABLE", "CONFIRMED"].includes(checkStatus) ? "Confirmed vulnerability"
                : checkStatus === "SUCCESS" ? "Check completed" : `Check: ${checkStatus}`;

              return (
                <React.Fragment key={idx}>
                  <tr className="group transition-colors hover:bg-neutral-50/60 dark:hover:bg-neutral-900/60">
                    <td className="py-3 px-4 font-mono text-[11px] font-bold text-neutral-500 dark:text-neutral-400">{id}</td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-bold ${sevCfg.bg} ${sevCfg.text} ${sevCfg.border}`}>
                        {f.severity || "INFO"}
                      </span>
                    </td>
                    <td className="py-3 px-4 hidden sm:table-cell">
                      <span className={`text-[10px] font-semibold ${provCfg.color}`}>
                        {provCfg.label}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sm font-medium text-black dark:text-white max-w-xs">{f.title}<span className="block text-[10px] font-medium text-neutral-500 dark:text-neutral-400 mt-1">{verdict}</span></td>
                    <td className="py-3 px-4 font-mono text-xs font-semibold text-neutral-700 dark:text-neutral-300 hidden md:table-cell">
                      {f.cvss_score ?? "—"}
                    </td>
                    <td className="py-3 px-4 text-xs text-neutral-500 dark:text-neutral-400 hidden lg:table-cell">
                      {f.pisf_control || "—"}
                    </td>
                    <td className="py-3 px-4">
                      <button
                        onClick={() => setExpandedRow(isExpanded ? null : id)}
                        className="flex items-center gap-1 text-[11px] font-medium text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white transition-colors"
                      >
                        {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                        {isExpanded ? "Hide" : "View"}
                      </button>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="bg-neutral-50 dark:bg-neutral-900/60 border-b border-neutral-200 dark:border-neutral-800">
                      <td colSpan={7} className="px-4 py-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">Description</p>
                            <p className="text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed">{f.description || "—"}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">Evidence · {checkStatus}</p>
                            {f.url && <p className="text-xs break-all text-neutral-500">Observed URL: {f.url}</p>}
                            <p className="text-xs text-neutral-700 dark:text-neutral-200 font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded p-2 leading-relaxed">
                              {f.evidence || "—"}
                            </p>
                          </div>
                        </div>
                        <div className="mt-3 pt-3 border-t border-neutral-200 dark:border-neutral-800">
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-1">
                            Remediation <span className="text-emerald-600 dark:text-emerald-400 normal-case font-normal">({f.remediation_priority || "Month 1"})</span>
                          </p>
                          <p className="text-xs text-neutral-700 dark:text-neutral-300">{f.remediation || "—"}</p>
                        </div>
                        {f.owasp_top10 && (
                          <div className="mt-2 flex gap-2">
                            <span className="rounded border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950 px-2 py-0.5 text-[10px] text-neutral-600 dark:text-neutral-400">
                              {f.owasp_top10}
                            </span>
                            {f.cwe_id && (
                              <span className="rounded border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950 px-2 py-0.5 text-[10px] text-neutral-600 dark:text-neutral-400">
                                {f.cwe_id}
                              </span>
                            )}
                            {f.wstg_id && (
                              <span className="rounded border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950 px-2 py-0.5 text-[10px] text-neutral-600 dark:text-neutral-400">
                                {f.wstg_id}
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
