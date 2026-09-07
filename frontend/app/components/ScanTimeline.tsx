"use client";
import { useState } from "react";
import {
  Check,
  LoaderCircle,
  Shield,
  Globe2,
  ShieldAlert,
  Eye,
  Zap,
  FileText,
  Terminal,
  ChevronDown,
  RefreshCw,
} from "lucide-react";
const stages = [
  { id: "pre_engagement", label: "Authorization", icon: Shield },
  { id: "recon", label: "Reconnaissance", icon: Globe2 },
  { id: "threat_intel", label: "Threat intelligence", icon: ShieldAlert },
  { id: "visual", label: "Web audit", icon: Eye },
  { id: "pentest", label: "Active assessment", icon: Zap },
  { id: "report", label: "Assessment report", icon: FileText },
];
export default function ScanTimeline({
  progressLog,
  scanProgress,
  isScanning,
  hasError,
  onRetry,
}: {
  progressLog: string[];
  scanProgress: Record<string, string>;
  isScanning: boolean;
  hasError?: boolean;
  onRetry?: () => void;
}) {
  const [showLog, setShowLog] = useState(false);
  const complete = (s: string) =>
    [
      "completed",
      "live",
      "success",
      "mock",
      "mock_fallback",
      "skipped",
      "partial",
      "failed",
      "error",
    ].includes(s);
  const finished = stages.filter((s) => complete(scanProgress[s.id])).length;
  return (
    <section className="cs-card execution-panel">
      <div className="section-heading">
        <div>
          <h2>Assessment activity</h2>
          <p>
            {isScanning
              ? "Your assessment is in progress."
              : finished
                ? `${finished} of ${stages.length} stages finished. Review each outcome below.`
                : "Follow each stage from authorization to your final report."}
          </p>
        </div>
        <span className="activity-label">
          {isScanning ? (
            <LoaderCircle size={14} className="animate-spin" />
          ) : (
            <span className="status-dot" />
          )}
          {isScanning ? "Running" : finished ? "Finished" : "Standby"}
        </span>
      </div>
      <ol className="stage-grid">
        {stages.map(({ id, label, icon: Icon }, index) => {
          const status = scanProgress[id];
          const done = ["completed", "live", "success"].includes(status);
          const mock = ["mock", "mock_fallback"].includes(status);
          const failed = ["failed", "error"].includes(status);
          const active =
            isScanning && ["in_progress", "running"].includes(status);
          const text = done
            ? "Complete"
            : mock
              ? "Demo fixture"
              : failed
                ? "Failed"
                : status === "skipped"
                  ? "Skipped"
                  : status === "partial"
                    ? "Partial"
                    : active
                      ? "In progress"
                      : "Waiting";
          return (
            <li
              key={id}
              className={
                done
                  ? "stage-done"
                  : active
                    ? "stage-active"
                    : mock
                      ? "stage-demo"
                      : failed
                        ? "stage-failed"
                        : ""
              }
            >
              <div className="stage-node">
                {done ? (
                  <Check size={18} />
                ) : active ? (
                  <LoaderCircle size={18} className="animate-spin" />
                ) : (
                  <Icon size={18} />
                )}
              </div>
              <strong>{label}</strong>
              <small>{text}</small>
              <span className="stage-index">0{index + 1}</span>
            </li>
          );
        })}
      </ol>
      <div className="activity-footer">
        <button
          className="text-button"
          onClick={() => setShowLog(!showLog)}
          aria-expanded={showLog}
          aria-controls="assessment-log"
        >
          <Terminal size={15} />
          {showLog ? "Hide activity log" : "View activity log"}
          <ChevronDown size={14} />
        </button>
        {hasError && onRetry && (
          <button className="text-button" onClick={onRetry}>
            <RefreshCw size={14} /> Reconnect
          </button>
        )}
        <span>{progressLog.length} events recorded</span>
      </div>
      {showLog && (
        <div
          id="assessment-log"
          className="cs-terminal activity-log"
          tabIndex={0}
          aria-label="Assessment event log"
        >
          {progressLog.length ? (
            progressLog.map((log, i) => (
              <p key={i}>
                <span>{String(i + 1).padStart(2, "0")}</span>
                {log}
              </p>
            ))
          ) : (
            <p>Waiting for the first assessment event.</p>
          )}
        </div>
      )}
    </section>
  );
}
