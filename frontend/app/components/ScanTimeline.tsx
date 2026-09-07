"use client";

import React from "react";
import { CheckCircle2, Circle, Loader2, Shield, Globe, AlertCircle, Eye, Zap, FileText, RefreshCw } from "lucide-react";

interface Step {
  id: string;
  label: string;
  desc: string;
  icon: React.ElementType;
}

const STAGES: Step[] = [
  { id: "pre_engagement", label: "Authorization", desc: "Scope & legal", icon: Shield },
  { id: "recon", label: "Reconnaissance", desc: "DNS, SSL, Headers", icon: Globe },
  { id: "threat_intel", label: "Threat Intel", desc: "NVD, VT, Shodan", icon: AlertCircle },
  { id: "visual", label: "Visual Audit", desc: "V-001 to V-008", icon: Eye },
  { id: "pentest", label: "Active Pentest", desc: "P-001 to P-024", icon: Zap },
  { id: "report", label: "PISF & Report", desc: "Compliance matrix", icon: FileText },
];

interface ScanTimelineProps {
  progressLog: string[];
  scanProgress: Record<string, any>;
  isScanning: boolean;
  hasError?: boolean;
  onRetry?: () => void;
}

export default function ScanTimeline({ progressLog, scanProgress, isScanning, hasError, onRetry }: ScanTimelineProps) {
  const completedCount = Object.values(scanProgress).filter(
    (s) => s === "completed" || s === "live" || s === "success"
  ).length;

  return (
    <div className="cs-card p-6 space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[15px] font-semibold text-black dark:text-white">Execution Timeline</h3>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
            {isScanning
              ? `Running phase ${completedCount + 1} of ${STAGES.length}…`
              : completedCount > 0
              ? `${completedCount} of ${STAGES.length} phases complete`
              : "Awaiting scan start"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasError && onRetry && (
            <button
              onClick={onRetry}
              className="flex items-center gap-1.5 rounded-full border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/40 px-3 py-1 text-xs font-semibold text-red-700 dark:text-red-300 hover:bg-red-100 transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              <span>Retry Connection</span>
            </button>
          )}
          {isScanning && (
            <div className="flex items-center gap-1.5 rounded-full border border-neutral-200 dark:border-neutral-800 px-3 py-1 text-xs text-neutral-600 dark:text-neutral-300">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Live</span>
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 status-live" />
            </div>
          )}
        </div>
      </div>


      {/* Step indicators — cal.com horizontal timeline */}
      <div className="flex items-start gap-0">
        {STAGES.map((stage, i) => {
          const status = scanProgress[stage.id];
          const isDone = status === "completed" || status === "live" || status === "success";
          const isMock = status === "mock" || status === "mock_fallback";
          const isActive = isScanning && !isDone && !isMock && i === completedCount;
          const Icon = stage.icon;
          const isLast = i === STAGES.length - 1;

          return (
            <React.Fragment key={stage.id}>
              <div className="flex flex-col items-center gap-2 min-w-0" style={{ flex: "0 0 auto" }}>
                {/* Circle */}
                <div
                  className={`flex h-7 w-7 items-center justify-center rounded-full border-2 transition-all ${
                    isDone
                      ? "border-black bg-black dark:border-white dark:bg-white text-white dark:text-black"
                      : isMock
                      ? "border-amber-400 bg-amber-50 dark:bg-amber-950/40"
                      : isActive
                      ? "border-black dark:border-white bg-white dark:bg-neutral-900"
                      : "border-neutral-300 dark:border-neutral-700 bg-neutral-100/80 dark:bg-neutral-800/80"
                  }`}
                >
                  {isDone ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-white dark:text-black" />
                  ) : isActive ? (
                    <Loader2 className="h-3.5 w-3.5 text-black dark:text-white animate-spin" />
                  ) : isMock ? (
                    <Icon className="h-3.5 w-3.5 text-amber-500" />
                  ) : (
                    <Icon className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
                  )}
                </div>
                {/* Label */}
                <div className="flex flex-col items-center text-center w-16">
                  <span className={`text-[10px] font-semibold leading-tight ${
                    isDone || isActive ? "text-black dark:text-white" : "text-neutral-400 dark:text-neutral-500"
                  }`}>
                    {stage.label}
                  </span>
                  <span className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight mt-0.5 hidden sm:block">
                    {stage.desc}
                  </span>
                </div>
              </div>
              {/* Connector line */}
              {!isLast && (
                <div
                  className={`mt-3.5 flex-1 h-px transition-colors min-w-4 ${
                    isDone ? "bg-black dark:bg-white" : "bg-neutral-200 dark:bg-neutral-800"
                  }`}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Terminal log */}
      <div className="cs-terminal p-4 h-32 overflow-y-auto">
        <div className="text-neutral-600 dark:text-neutral-500 text-[10px] mb-2 border-b border-neutral-800 dark:border-neutral-900 pb-1.5 font-mono flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-red-500" />
          <span className="h-2 w-2 rounded-full bg-amber-500" />
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          <span className="ml-2 text-neutral-500">cybershield_orchestrator.log</span>
        </div>
        {progressLog.length === 0 ? (
          <div className="text-neutral-600 dark:text-neutral-500 italic text-[11px]">$ Awaiting scan initialization…</div>
        ) : (
          progressLog.map((log, i) => (
            <div key={i} className="text-neutral-300 py-0.5 flex items-start gap-2 text-[11px]">
              <span className="text-emerald-500 font-bold flex-shrink-0">$</span>
              <span>{log}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
