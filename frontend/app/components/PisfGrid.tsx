"use client";

import React from "react";
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, TrendingUp } from "lucide-react";

interface PisfGridProps {
  pisfData: any;
}

const STATUS_CONFIG = {
  PASS: {
    label: "Pass",
    bg: "bg-emerald-50 dark:bg-emerald-950/40",
    text: "text-emerald-700 dark:text-emerald-300",
    border: "border-emerald-200 dark:border-emerald-800",
    dot: "bg-emerald-500",
    Icon: CheckCircle2,
  },
  FAIL: {
    label: "Fail",
    bg: "bg-red-50 dark:bg-red-950/40",
    text: "text-red-700 dark:text-red-300",
    border: "border-red-200 dark:border-red-800",
    dot: "bg-red-500",
    Icon: XCircle,
  },
  PARTIAL: {
    label: "Partial",
    bg: "bg-amber-50 dark:bg-amber-950/40",
    text: "text-amber-700 dark:text-amber-300",
    border: "border-amber-200 dark:border-amber-800",
    dot: "bg-amber-500",
    Icon: AlertTriangle,
  },
  NOT_ASSESSABLE: {
    label: "Not assessable",
    bg: "bg-neutral-50 dark:bg-neutral-900",
    text: "text-neutral-500 dark:text-neutral-400",
    border: "border-neutral-200 dark:border-neutral-800",
    dot: "bg-neutral-300 dark:bg-neutral-600",
    Icon: HelpCircle,
  },
};

export default function PisfGrid({ pisfData }: PisfGridProps) {
  if (!pisfData || !pisfData.controls || pisfData.controls.length === 0) {
    return (
      <div className="cs-card p-12 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-neutral-200 dark:border-neutral-800">
          <TrendingUp className="h-5 w-5 text-neutral-400 dark:text-neutral-500" />
        </div>
        <p className="text-sm font-medium text-neutral-700 dark:text-neutral-300">PISF Project Technical Mapping</p>
        <p className="text-xs text-neutral-400 dark:text-neutral-500 mt-1">Technical assessment data is unavailable. Organizational compliance requires manual evidence.</p>
      </div>
    );
  }

  const controls = pisfData.controls;
  const score = pisfData.overall_score ?? pisfData.compliance_score ?? 0;
  const passCt = pisfData.compliant_controls ?? controls.filter((c: any) => c.status === "PASS").length;
  const total = pisfData.total_controls ?? controls.length;
  const assessable = pisfData.assessable_controls_count ?? controls.filter((c: any) => ["PASS", "FAIL", "PARTIAL"].includes(c.status)).length;
  const available = pisfData.status === "success" && assessable > 0;

  // Aggregate counts
  const counts = controls.reduce(
    (acc: any, c: any) => {
      acc[c.status] = (acc[c.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="cs-card overflow-hidden">
      {/* Header */}
      <div className="border-b border-neutral-200 dark:border-neutral-800 px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-[15px] font-semibold text-black dark:text-white">🇵🇰 PISF Project Technical Mapping</h3>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
              {passCt} passing technical checks · {assessable}/{total} controls assessable
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-black tracking-tighter text-black dark:text-white">
              {available ? `${score.toFixed(1)}%` : "Unavailable"}
            </div>
            <div className="text-[10px] text-neutral-400 dark:text-neutral-500 font-medium">Technical Mapping Score</div>
          </div>
        </div>

        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-3">
          Project-defined mapping; framework and cross-framework mappings remain unverified and incomplete.
          This technical assessment is not a certification. Non-assessable controls require manual organizational evidence.
        </p>
        {pisfData.status !== "success" && <p className="text-xs text-amber-700 dark:text-amber-300 mt-2">Assessment status: {pisfData.status || "unknown"}. Available evidence may be incomplete.</p>}

        {/* Mini stat pills */}
        <div className="flex gap-2 mt-3 flex-wrap">
          {Object.entries(counts).map(([status, count]) => {
            const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.NOT_ASSESSABLE;
            return (
              <span
                key={status}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-semibold ${cfg.bg} ${cfg.text} ${cfg.border}`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                {cfg.label}: {count as number}
              </span>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="cs-table w-full text-sm">
          <thead>
            <tr className="border-b border-neutral-200 dark:border-neutral-800">
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                Control
              </th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                Domain
              </th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                Status
              </th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 hidden md:table-cell">
                ISO 27001
              </th>
              <th className="py-3 px-4 text-left text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 hidden lg:table-cell">
                Evidence
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
            {controls.map((c: any, i: number) => {
              const status = (c.status || "NOT_ASSESSABLE") as keyof typeof STATUS_CONFIG;
              const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.NOT_ASSESSABLE;
              const { Icon } = cfg;
              const iso = c.international_mapping?.iso_27001 || "—";

              return (
                <tr key={i} className="group transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-900/60">
                  <td className="py-3 px-4 font-mono text-xs font-bold text-neutral-700 dark:text-neutral-300">
                    C-{String(c.control_id).padStart(2, "0")}
                  </td>
                  <td className="py-3 px-4 text-sm text-black dark:text-white font-medium">
                    {c.domain || c.name}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold badge-in ${cfg.bg} ${cfg.text} ${cfg.border}`}
                    >
                      <Icon className="h-3 w-3" />
                      {cfg.label}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-xs text-neutral-500 dark:text-neutral-400 hidden md:table-cell">
                    {iso}
                  </td>
                  <td className="py-3 px-4 text-xs text-neutral-500 dark:text-neutral-400 max-w-xs hidden lg:table-cell">
                    <span className="line-clamp-2">{c.evidence || "—"}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
