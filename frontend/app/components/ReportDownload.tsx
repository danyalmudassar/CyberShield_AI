"use client";

import React from "react";
import { Download, FileText, ExternalLink } from "lucide-react";

interface ReportDownloadProps {
  execSummary: string;
  pdfPath: string | null;
  scanId: string | null;
  reportStatus?: string;
}

export default function ReportDownload({ execSummary, pdfPath, scanId, reportStatus }: ReportDownloadProps) {
  const ready = Boolean(pdfPath && scanId && reportStatus === "success");
  const handleDownload = () => {
    if (!ready || !scanId) return;
    window.open(`/api/scans/${encodeURIComponent(scanId)}/report`, "_blank", "noopener,noreferrer");
  };

  return (
    <div className="cs-card p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-neutral-600 dark:text-neutral-400" />
          <h3 className="text-[15px] font-semibold text-black dark:text-white">Executive Summary & Audit Report</h3>
        </div>

        {ready ? (
          <button
            onClick={handleDownload}
            className="flex items-center gap-2 rounded-lg bg-black dark:bg-white px-4 py-2 text-xs font-semibold text-white dark:text-black hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            Download PDF
          </button>
        ) : (
          <span className="text-xs text-neutral-400 dark:text-neutral-500 flex items-center gap-1.5">
            <ExternalLink className="h-3 w-3" />
            {reportStatus === "error" ? "Report generation failed" : "Report unavailable or pending"}
          </span>
        )}
      </div>

      {/* Summary text block */}
      <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/60 p-4 min-h-[120px]">
        {execSummary ? (
          <p className="text-sm text-neutral-700 dark:text-neutral-300 leading-relaxed whitespace-pre-wrap">
            {execSummary}
          </p>
        ) : (
          <p className="text-sm text-neutral-400 dark:text-neutral-500 italic">
            Executive summary will be synthesized after the security audit completes.
          </p>
        )}
      </div>

      {ready && (
        <div className="flex items-center justify-between rounded-lg border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-emerald-500" />
            <span className="text-xs font-medium text-emerald-700 dark:text-emerald-300">Security assessment report ready</span>
          </div>
          <button
            onClick={handleDownload}
            className="text-xs font-semibold text-emerald-700 dark:text-emerald-300 hover:text-emerald-900 dark:hover:text-emerald-100 underline underline-offset-2 transition-colors"
          >
            Download →
          </button>
        </div>
      )}
    </div>
  );
}
