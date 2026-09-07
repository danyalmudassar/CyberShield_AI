"use client";

import React from "react";

interface BenchmarkMetric {
  target: string;
  phase: string;
  scope: string;
  recall: string;
  precision: string;
  f1: string;
  status: "baseline" | "engineered" | "cross_validation";
  highlight: string;
}

const METRICS: BenchmarkMetric[] = [
  {
    target: "DVWA Container",
    phase: "Phase 1 Baseline",
    scope: "Unauthenticated Scan",
    recall: "15.4%",
    precision: "100.0%",
    f1: "26.7%",
    status: "baseline",
    highlight: "Raw unauthenticated scanner baseline",
  },
  {
    target: "DVWA Container",
    phase: "Phase 2 Engine",
    scope: "DVWA-Tuned Auth Session + Crawler",
    recall: "92.3%",
    precision: "100.0%",
    f1: "96.0%",
    status: "engineered",
    highlight: "Target-specific tuning; not an independent holdout",
  },
  {
    target: "OWASP Juice Shop",
    phase: "Historical Comparison",
    scope: "SPA/JWT Comparison Target",
    recall: "7.1%",
    precision: "33.3%",
    f1: "11.8%",
    status: "cross_validation",
    highlight: "Limited comparison; generalization is unestablished",
  },
];

export default function BenchmarkWidget() {
  return (
    <div className="rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 p-5 shadow-sm transition-all">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4 border-b border-neutral-100 dark:border-neutral-800/60 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-neutral-400" />
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100 tracking-tight">
              Historical Benchmark Records
            </h3>
          </div>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
            Manually recorded figures from prior DVWA and Juice Shop experiments; not live verification.
          </p>
        </div>
        <span className="font-mono text-[10px] font-semibold bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 px-2.5 py-1 rounded-full border border-neutral-200 dark:border-neutral-700">
          SOURCE: HISTORICAL MANUAL RECORD
        </span>
      </div>

      <p className="text-xs text-neutral-500 dark:text-neutral-400 mb-4">
        These static figures are not recalculated for this scan or the current scanner revision.
        DVWA results include target-specific tuning. An independent holdout evaluation and reproducible,
        versioned result artifacts are still required before drawing broader performance conclusions.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {METRICS.map((m, idx) => (
          <div
            key={idx}
            className={`rounded-lg border p-4 transition-all flex flex-col justify-between ${
              m.status === "engineered"
                ? "border-emerald-500/40 bg-emerald-50/30 dark:bg-emerald-950/20"
                : m.status === "cross_validation"
                ? "border-indigo-500/40 bg-indigo-50/30 dark:bg-indigo-950/20"
                : "border-neutral-200 dark:border-neutral-800 bg-neutral-50/50 dark:bg-neutral-900/50"
            }`}
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-semibold text-neutral-900 dark:text-neutral-100">
                  {m.target}
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    m.status === "engineered"
                      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200"
                      : m.status === "cross_validation"
                      ? "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/60 dark:text-indigo-200"
                      : "bg-neutral-200 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-300"
                  }`}
                >
                  {m.phase}
                </span>
              </div>
              <p className="text-[11px] text-neutral-500 dark:text-neutral-400 font-mono mb-3">
                {m.scope}
              </p>
            </div>

            <div className="space-y-2 border-t border-neutral-200/60 dark:border-neutral-800/60 pt-3">
              <div className="grid grid-cols-3 text-center gap-1">
                <div>
                  <span className="block text-[10px] uppercase font-semibold text-neutral-400">
                    Recall
                  </span>
                  <span className="text-sm font-bold font-mono text-neutral-900 dark:text-neutral-100">
                    {m.recall}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-semibold text-neutral-400">
                    Precision
                  </span>
                  <span className="text-sm font-bold font-mono text-neutral-900 dark:text-neutral-100">
                    {m.precision}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-semibold text-neutral-400">
                    F1 Score
                  </span>
                  <span className="text-sm font-bold font-mono text-neutral-900 dark:text-neutral-100">
                    {m.f1}
                  </span>
                </div>
              </div>
              <p className="text-[10px] text-neutral-500 dark:text-neutral-400 text-center font-medium italic">
                {m.highlight}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
