"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  ArrowUpRight,
  Activity,
  Layers,
  FileCheck2,
  ShieldAlert,
  RefreshCw,
  Plus,
  Clock3,
  LoaderCircle,
  Info,
  Globe2,
} from "lucide-react";
import Header, { navigation, type TabId } from "./components/Header";
import ScanConfig from "./components/ScanConfig";
import ScanTimeline from "./components/ScanTimeline";
import ScoreGauge from "./components/ScoreGauge";
import PisfGrid from "./components/PisfGrid";
import VisualAudit from "./components/VisualAudit";
import FindingsTable from "./components/FindingsTable";
import ReportDownload from "./components/ReportDownload";
import BenchmarkWidget from "./components/BenchmarkWidget";
import { useScan } from "./hooks/useScan";
export default function Home() {
  const router = useRouter();
  const {
    scanId,
    status,
    scanState,
    progressLog,
    scanProgress,
    error,
    history,
    isScanning,
    startScan,
    reconnect,
    openScan,
    cancelScan,
    refreshHistory,
    authUser,
    authReady,
    logoutUser,
    isLoggingOut,
  } = useScan();
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  useEffect(() => {
    if (authReady && !authUser) router.replace("/login");
  }, [authReady, authUser, router]);
  const findings = scanState?.all_findings || [];
  const selectedJob = history.find((job) => job.id === scanId);
  const isDemo =
    (scanState?.execution_mode || selectedJob?.config.execution_mode) ===
    "demo";
  const confirmed = findings.filter(
    (f) =>
      ["VULNERABLE", "CONFIRMED"].includes(f.check_status) &&
      !/MOCK|FIXTURE|DEMO|LLM_REASONING/.test(f.provenance || ""),
  );
  const newAssessment = () => {
    setActiveTab("overview");
    requestAnimationFrame(() => {
      document
        .getElementById("assessment-config")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
      document.getElementById("target-domain")?.focus({ preventScroll: true });
    });
  };
  if (!authReady || !authUser)
    return (
      <div className="session-loading" role="status">
        <LoaderCircle className="animate-spin" size={24} />
        <span>
          {authReady ? "Opening sign in…" : "Opening your workspace…"}
        </span>
      </div>
    );
  return (
    <div className="app-shell">
      <Header
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        authUser={authUser}
        onLogout={() => void logoutUser()}
        isLoggingOut={isLoggingOut}
      />
      <main id="workspace" className="workspace-main">
        <div className="page-heading">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS</p>
            <h1>
              {activeTab === "overview"
                ? "Assessment overview"
                : navigation.find((n) => n.id === activeTab)?.label}
            </h1>
            <p>Understand your exposure. Prioritize what matters.</p>
          </div>
          <button
            className="primary-button"
            aria-label="New assessment"
            onClick={newAssessment}
          >
            <Plus size={17} /> New assessment
          </button>
        </div>
        <div className="metrics-strip">
          {[
            {
              label: "Saved assessments",
              value: history.length,
              detail: "In your workspace",
              icon: Layers,
            },
            {
              label: "Confirmed findings",
              value: scanState ? confirmed.length : "—",
              detail: isDemo ? "Demo findings excluded" : "Selected assessment",
              icon: ShieldAlert,
            },
            {
              label: "Assessment status",
              value: status?.replaceAll("_", " ") || "Ready",
              detail: isScanning
                ? "Assessment in progress"
                : "Select or start a scan",
              icon: Activity,
            },
            {
              label: "Report",
              value: scanState?.pdf_path ? "Available" : "Pending",
              detail: "Evidence & recommendations",
              icon: FileCheck2,
            },
          ].map(({ label, value, detail, icon: Icon }) => (
            <div className="metric" key={label}>
              <div className="metric-top">
                <span>{label}</span>
                <Icon size={17} />
              </div>
              <strong>{value}</strong>
              <small>{detail}</small>
            </div>
          ))}
        </div>
        {error && (
          <div className="form-error" role="alert">
            <Info size={18} />
            <span>{error}</span>
            <button className="text-button" onClick={reconnect}>
              Reconnect
            </button>
          </div>
        )}
        {isDemo && (
          <div className="demo-notice">
            <Info size={17} />
            <span>
              <strong>Demo assessment.</strong> Results use offline fixtures; no
              target requests are made.
            </span>
          </div>
        )}
        {activeTab === "overview" && (
          <>
            <div className="assessment-grid">
              <div id="assessment-config">
                <ScanConfig
                  onStartScan={startScan}
                  isScanning={isScanning}
                  canScan={true}
                />
              </div>
              <div className="assessment-side">
                <ScoreGauge
                  score={scanState?.security_score ?? 0}
                  available={typeof scanState?.security_score === "number"}
                  isDemo={isDemo}
                />
                <div className="scope-note">
                  <Globe2 size={19} />
                  <div>
                    <strong>Scope shapes your results</strong>
                    <p>
                      Review assessed coverage alongside every score. Unassessed
                      checks are not proof of security.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <ScanTimeline
              progressLog={progressLog}
              scanProgress={scanProgress}
              isScanning={isScanning}
              hasError={Boolean(error)}
              onRetry={reconnect}
            />
            <section className="cs-card history-section">
              <div className="section-heading">
                <div>
                  <h2>Recent assessments</h2>
                  <p>Pick up where you left off.</p>
                </div>
                <button className="secondary-button" onClick={refreshHistory}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>
              {isScanning && scanId && (
                <div className="active-scan-row">
                  <LoaderCircle size={16} className="animate-spin" />
                  <span>Assessment in progress</span>
                  <button
                    className="text-button"
                    onClick={() => void cancelScan()}
                    disabled={status === "cancelling"}
                  >
                    {status === "cancelling"
                      ? "Cancelling…"
                      : "Cancel assessment"}
                  </button>
                </div>
              )}
              {history.length ? (
                <div className="history-list">
                  {history.map((job) => (
                    <button
                      key={job.id}
                      onClick={() => openScan(job.id)}
                      disabled={isScanning && job.id !== scanId}
                      className={`history-row ${job.id === scanId ? "current" : ""}`}
                    >
                      <span className="history-icon">
                        <Globe2 size={18} />
                      </span>
                      <span className="history-target">
                        <strong>{job.config.domain}</strong>
                        <small>
                          {job.config.execution_mode.replaceAll("_", " ")} ·{" "}
                          {job.config.scope_type.replaceAll("_", " ")}
                        </small>
                      </span>
                      <span className={`status-pill status-${job.status}`}>
                        {job.status.replaceAll("_", " ")}
                      </span>
                      <ArrowUpRight size={16} />
                    </button>
                  ))}
                </div>
              ) : (
                <div className="history-empty">
                  <Clock3 size={25} />
                  <div>
                    <strong>Your assessment history starts here</strong>
                    <p>
                      Launch your first assessment to save progress and review
                      results.
                    </p>
                  </div>
                  <ArrowRight size={18} />
                </div>
              )}
            </section>
            <div className="section-heading">
              <div>
                <h2>Assessment results</h2>
                <p>
                  {scanState
                    ? "Review evidence from your selected scan."
                    : "Findings and web checks will appear after an assessment."}
                </p>
              </div>
              <button
                className="text-button"
                onClick={() => setActiveTab("findings")}
              >
                View all findings <ArrowRight size={15} />
              </button>
            </div>
            <div className="results-grid">
              <FindingsTable findings={findings} />
              <VisualAudit visualData={scanState?.visual} />
            </div>
            <details className="historical-details">
              <summary>
                Historical benchmark records{" "}
                <span>Reference only · not current scan results</span>
              </summary>
              <BenchmarkWidget />
            </details>
          </>
        )}
        {activeTab === "findings" && <FindingsTable findings={findings} />}
        {activeTab === "visual" && (
          <VisualAudit visualData={scanState?.visual} />
        )}
        {activeTab === "pisf" && <PisfGrid pisfData={scanState?.pisf} />}
        {activeTab === "report" && (
          <ReportDownload
            execSummary={scanState?.executive_summary || ""}
            pdfPath={scanState?.pdf_path || null}
            scanId={scanId}
            reportStatus={scanState?.report_status}
          />
        )}
        <footer className="workspace-footer">
          <span>CyberShield AI · Security assessment workspace</span>
          <span>Technical mapping. Manual compliance review required.</span>
        </footer>
      </main>
    </div>
  );
}
