"use client";
import {
  Download,
  FileText,
  CheckCircle2,
  Clock3,
  ShieldCheck,
  AlertCircle,
} from "lucide-react";
export default function ReportDownload({
  execSummary,
  pdfPath,
  scanId,
  reportStatus,
}: {
  execSummary: string;
  pdfPath: string | null;
  scanId: string | null;
  reportStatus?: string;
}) {
  const ready = Boolean(pdfPath && scanId && reportStatus === "success");
  const download = () => {
    if (ready && scanId)
      window.open(
        `/api/scans/${encodeURIComponent(scanId)}/report`,
        "_blank",
        "noopener,noreferrer",
      );
  };
  return (
    <div className="report-layout">
      <article className="cs-card report-document">
        <div className="report-document-header">
          <span className="report-wordmark">
            <ShieldCheck size={20} /> CYBERSHIELD AI
          </span>
          <span>ASSESSMENT REPORT</span>
        </div>
        <div className="report-document-body">
          <p className="eyebrow">ASSESSMENT INTELLIGENCE</p>
          <h2>Executive summary</h2>
          <p className="report-deck">
            Evidence, observations and a clearer path forward.
          </p>
          <div className="report-rule" />
          {execSummary ? (
            <p className="report-summary">{execSummary}</p>
          ) : (
            <div className="report-empty">
              <FileText size={32} />
              <h3>Your report takes shape here</h3>
              <p>
                Complete an assessment to review its summary, findings and
                recommendations.
              </p>
            </div>
          )}
          <div className="report-note">
            <ShieldCheck size={17} />
            <p>
              Review finding provenance and assessment scope before acting.
              Technical control mapping does not replace a manual compliance
              review.
            </p>
          </div>
        </div>
      </article>
      <aside className="cs-card report-export">
        <span className="export-icon">
          <FileText size={25} />
        </span>
        <h2>Your assessment, documented.</h2>
        <p>Keep a PDF copy of the assessment for review and follow-up.</p>
        <div className="export-status">
          {ready ? (
            <CheckCircle2 size={17} />
          ) : reportStatus === "error" ? (
            <AlertCircle size={17} />
          ) : (
            <Clock3 size={17} />
          )}
          <span>
            {ready
              ? "PDF ready to download"
              : reportStatus === "error"
                ? "Report generation failed"
                : "Waiting for a completed report"}
          </span>
        </div>
        <button className="primary-button" onClick={download} disabled={!ready}>
          <Download size={16} /> Download PDF
        </button>
        <small>Available to the authorized scan owner.</small>
      </aside>
    </div>
  );
}
