"use client";

import React from "react";
import { Eye, CheckCircle2, XCircle, FileCode, ShieldAlert, Lock, HelpCircle } from "lucide-react";

interface VisualAuditProps {
  visualData: any;
}

function CheckBadge({
  label,
  value,
  isGoodWhenTrue = true,
  passText = "Safe",
  failText = "Risk",
}: {
  label: string;
  value: boolean | undefined;
  isGoodWhenTrue?: boolean;
  passText?: string;
  failText?: string;
}) {
  const isUnknown = typeof value !== "boolean";
  const isPass = !isUnknown && value === isGoodWhenTrue;
  return (
    <div
      className={`flex flex-col gap-2 rounded-lg border p-3 transition-colors ${
        isUnknown
          ? "border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900"
          : isPass
          ? "border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40"
          : "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/40"
      }`}
    >
      <span className="text-[9px] font-bold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">{label}</span>
      <div className={`flex items-center gap-1.5 ${isUnknown ? "text-neutral-500 dark:text-neutral-400" : isPass ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
        {isUnknown ? (<HelpCircle className="h-3.5 w-3.5" />) : isPass ? (
          <CheckCircle2 className="h-3.5 w-3.5" />
        ) : (
          <XCircle className="h-3.5 w-3.5" />
        )}
        <span className="text-xs font-semibold">{isUnknown ? "Unknown" : isPass ? passText : failText}</span>
      </div>
    </div>
  );
}

export default function VisualAudit({ visualData }: VisualAuditProps) {
  if (!visualData) {
    return (
      <div className="cs-card p-12 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-neutral-200 dark:border-neutral-800">
          <Eye className="h-5 w-5 text-neutral-400 dark:text-neutral-500" />
        </div>
        <p className="text-sm font-medium text-neutral-700 dark:text-neutral-300">HTTP/HTML Audit (V-001 to V-008)</p>
        <p className="text-xs text-neutral-400 dark:text-neutral-500 mt-1">HTTP responses and static HTML observations will appear after a scan.</p>
      </div>
    );
  }

  const complete = visualData.status === "success";
  const observed = (value: unknown) => complete && typeof value === "boolean" ? value : undefined;

  return (
    <div className="cs-card overflow-hidden">
      {/* Header */}
      <div className="border-b border-neutral-200 dark:border-neutral-800 px-6 py-4 flex items-center gap-2">
        <Eye className="h-4 w-4 text-neutral-600 dark:text-neutral-400" />
        <div>
          <h3 className="text-[15px] font-semibold text-black dark:text-white">HTTP/HTML Security Audit</h3>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">Static response checks V-001 to V-008; rendered browser behavior is not assessed.</p>
        </div>
      </div>

      <div className="p-6 space-y-5">
        {!complete && <p className="text-xs text-amber-700 dark:text-amber-300">Assessment status: {visualData.status || "unknown"}. Check results remain unknown where completion cannot be established.</p>}
        {/* Check badges grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <CheckBadge label="V-001 Admin Panel"   value={observed(visualData.admin_panel_detected)} isGoodWhenTrue={false} passText="Not observed" failText="Detected" />
          <CheckBadge label="V-002 HTTPS / HSTS"  value={observed(visualData.https_padlock)}         isGoodWhenTrue={true}  passText="Detected"    failText="Missing" />
          <CheckBadge label="V-003 CAPTCHA"        value={observed(visualData.captcha_present)}       isGoodWhenTrue={true}  passText="Detected"   failText="Absent" />
          <CheckBadge label="V-007 Cookie Consent" value={observed(visualData.cookie_consent)}        isGoodWhenTrue={true}  passText="Detected"   failText="Missing" />
          <CheckBadge label="V-008 Mixed Content"  value={observed(visualData.mixed_content)}         isGoodWhenTrue={false} passText="Not observed"       failText="Detected" />
        </div>

        {/* Detail lists */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* V-004 Third-party scripts */}
          <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <FileCode className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                V-004 Third-Party Scripts ({visualData.third_party_scripts?.length || 0})
              </span>
            </div>
            <ul className="space-y-1 max-h-32 overflow-y-auto text-xs text-neutral-600 dark:text-neutral-300">
              {visualData.third_party_scripts?.length > 0 ? (
                visualData.third_party_scripts.map((s: string, i: number) => (
                  <li key={i} className="truncate hover:text-black dark:hover:text-white transition-colors">
                    · {s}
                  </li>
                ))
              ) : (
                <li className="text-neutral-400 dark:text-neutral-500 italic">{complete ? "No external scripts observed in the response" : "Unknown — assessment incomplete"}</li>
              )}
            </ul>
          </div>

          {/* V-005 Suspicious elements */}
          <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <ShieldAlert className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                V-005 Suspicious UI
              </span>
            </div>
            <ul className="space-y-1 max-h-32 overflow-y-auto text-xs text-neutral-600 dark:text-neutral-300">
              {visualData.suspicious_elements?.length > 0 ? (
                visualData.suspicious_elements.map((s: string, i: number) => (
                  <li key={i} className="text-amber-600 dark:text-amber-400">· {s}</li>
                ))
              ) : (
                <li className="text-neutral-400 dark:text-neutral-500 italic">{complete ? "No suspicious elements observed in the response" : "Unknown — assessment incomplete"}</li>
              )}
            </ul>
          </div>

          {/* V-006 Sensitive info */}
          <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <Lock className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                V-006 Sensitive Info
              </span>
            </div>
            <ul className="space-y-1 max-h-32 overflow-y-auto text-xs text-neutral-600 dark:text-neutral-300">
              {visualData.sensitive_info_exposed?.length > 0 ? (
                visualData.sensitive_info_exposed.map((s: string, i: number) => (
                  <li key={i} className="text-red-600 dark:text-red-400">· {s}</li>
                ))
              ) : (
                <li className="text-neutral-400 dark:text-neutral-500 italic">{complete ? "No sensitive information observed in the response" : "Unknown — assessment incomplete"}</li>
              )}
            </ul>
          </div>
        </div>

        {/* Visual findings */}
        {visualData.visual_findings?.length > 0 && (
          <div className="border-t border-neutral-200 dark:border-neutral-800 pt-4">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-2">
              HTTP/HTML Observations ({visualData.visual_findings.length})
            </p>
            <div className="flex flex-wrap gap-2">
              {visualData.visual_findings.map((vf: any, i: number) => (
                <span
                  key={i}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-medium ${
                    vf.severity === "High"
                      ? "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300"
                      : "border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300"
                  }`}
                >
                  {vf.check || "Observation"}: {Array.isArray(vf.detail) ? vf.detail.join("; ") : String(vf.detail ?? "No detail supplied")}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
