"use client";

import React, { useState } from "react";
import Header from "./components/Header";
import ScanConfig from "./components/ScanConfig";
import ScanTimeline from "./components/ScanTimeline";
import ScoreGauge from "./components/ScoreGauge";
import PisfGrid from "./components/PisfGrid";
import VisualAudit from "./components/VisualAudit";
import FindingsTable from "./components/FindingsTable";
import ReportDownload from "./components/ReportDownload";
import BenchmarkWidget from "./components/BenchmarkWidget";

import { useScan } from "./hooks/useScan";

type TabId = "overview" | "pisf" | "visual" | "findings" | "report";

const TABS: { id: TabId; label: string; icon: string }[] = [
  { id: "overview",  label: "Overview",        icon: "📊" },
  { id: "pisf",      label: "PISF 2026",       icon: "🇵🇰" },
  { id: "visual",    label: "Visual Audit",    icon: "👁" },
  { id: "findings",  label: "Vulnerabilities", icon: "🔴" },
  { id: "report",    label: "Report",          icon: "📄" },
];

export default function Home() {
  const { scanId, status, scanState, progressLog, scanProgress, error, history,
    isScanning, startScan: handleStartScan, reconnect: handleRetry, openScan,
    cancelScan, refreshHistory, authUser, authReady, loginUser, logoutUser } = useScan();
  const hasConnectionError = Boolean(error);
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  const score      = scanState?.security_score || 0;
  const findings   = scanState?.all_findings || [];
  const pisfData   = scanState?.pisf;
  const visualData = scanState?.visual;
  const execSummary = scanState?.executive_summary || "";
  const pdfPath    = scanState?.pdf_path || null;

  const handleTabSelect = (tab: TabId) => {
    setActiveTab(tab);
    setTimeout(() => {
      document.getElementById("tab-section")?.scrollIntoView({ behavior: "smooth" });
    }, 50);
  };

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] transition-colors duration-200">
      <Header
        activeTab={activeTab}
        onSelectTab={handleTabSelect}
        authUser={authUser}
        onLogin={loginUser}
        onLogout={logoutUser}
      />

      <main className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
        {/* Hero section — score + config */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2">
            <ScanConfig onStartScan={handleStartScan} isScanning={isScanning} canScan={authReady && Boolean(authUser)} />
          </div>
          <div>
            <ScoreGauge score={score} />
          </div>
        </div>

        <section className="cs-card p-4 space-y-3" aria-label="Scan history">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold">Scan history</h2>
            <button type="button" onClick={refreshHistory} className="text-xs underline">Refresh history</button>
          </div>
          {scanId && <p className="text-xs break-all">Current scan: {scanId} · {status ?? "Loading"}</p>}
          {isScanning && scanId && <button type="button" onClick={() => void cancelScan()} disabled={status === "cancelling"} className="text-xs underline disabled:opacity-50">{status === "cancelling" ? "Cancellation requested" : "Cancel scan"}</button>}
          {error && <div role="alert" className="text-xs text-red-600">{error} <button type="button" onClick={handleRetry} className="underline">Reconnect</button></div>}
          <div className="flex flex-wrap gap-2">
            {history.map((job) => <button type="button" key={job.id} onClick={() => openScan(job.id)} disabled={isScanning && job.id !== scanId} className="rounded border px-3 py-2 text-xs disabled:opacity-50">{job.config.domain} · {job.config.execution_mode} · {job.status}</button>)}
            {history.length === 0 && <p className="text-xs text-neutral-500">No saved scans yet.</p>}
          </div>
        </section>

        {/* Timeline */}
        <ScanTimeline
          progressLog={progressLog}
          scanProgress={scanProgress}
          isScanning={isScanning}
          hasError={hasConnectionError}
          onRetry={handleRetry}
        />

        {/* Verified Benchmarks Widget */}
        <BenchmarkWidget />


        {/* Fallback Banner if mock or fallback triggered */}
        {(scanState?.fallback_triggered || Object.values(scanProgress).some((s) => s === "mock_fallback" || s === "mock")) && (
          <div className="rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 p-4 flex items-center justify-between gap-3 text-xs text-amber-800 dark:text-amber-200">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-amber-500" />
              <span className="font-semibold uppercase tracking-wider text-[10px]">Mock / Fallback Active</span>
              <span className="text-amber-700 dark:text-amber-300">
                · This assessment contains demo data or a degraded execution stage.
              </span>
            </div>
            <span className="font-mono text-[10px] bg-amber-100 dark:bg-amber-900/60 px-2 py-0.5 rounded text-amber-900 dark:text-amber-100">
              CHECK FINDING PROVENANCE
            </span>
          </div>
        )}

        {/* Tabs — cal.com underline style */}

        <div id="tab-section" className="space-y-5 scroll-mt-20">
          <div className="border-b border-neutral-200 dark:border-neutral-800">
            <nav className="flex gap-0 -mb-px overflow-x-auto">
              {TABS.map((tab) => {
                const isActive = activeTab === tab.id;
                const count = tab.id === "findings" ? findings.length : null;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-1.5 px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-all ${
                      isActive
                        ? "border-black dark:border-white text-black dark:text-white"
                        : "border-transparent text-neutral-500 hover:text-neutral-800 dark:text-neutral-400 dark:hover:text-neutral-100 hover:border-neutral-300 dark:hover:border-neutral-700"
                    }`}
                  >
                    <span>{tab.icon}</span>
                    <span>{tab.label}</span>
                    {count !== null && count > 0 && (
                      <span
                        className={`ml-1 rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                          isActive
                            ? "bg-black text-white dark:bg-white dark:text-black"
                            : "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400"
                        }`}
                      >
                        {count}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Tab content */}
          <div className="min-h-[300px]">
            {activeTab === "overview" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <FindingsTable findings={findings} />
                <VisualAudit visualData={visualData} />
              </div>
            )}
            {activeTab === "pisf"     && <PisfGrid pisfData={pisfData} />}
            {activeTab === "visual"   && <VisualAudit visualData={visualData} />}
            {activeTab === "findings" && <FindingsTable findings={findings} />}
            {activeTab === "report"   && <ReportDownload execSummary={execSummary} pdfPath={pdfPath} scanId={scanId} reportStatus={scanState?.report_status} />}
          </div>
        </div>

        {/* Footer */}
        <footer className="border-t border-neutral-200 dark:border-neutral-800 pt-6 pb-2">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-neutral-400 dark:text-neutral-500">
            <p>
              CyberShield AI — Local development preview · Technical security assessment
            </p>
            <div className="flex items-center gap-4">
              <span>Manual compliance review required</span>
              <span>·</span>
              <span>Coverage depends on scan scope</span>
              <span>·</span>
              <span>OWASP Top 10 Mapped</span>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}
