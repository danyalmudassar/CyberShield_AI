"use client";
import { ShieldCheck, ArrowUpRight } from "lucide-react";
export default function ScoreGauge({
  score,
  available = false,
  isDemo = false,
}: {
  score: number;
  available?: boolean;
  isDemo?: boolean;
}) {
  const value = Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0));
  const label = !available
    ? "Awaiting assessment"
    : value >= 80
      ? "Low observed risk"
      : value >= 60
        ? "Review recommended"
        : value >= 40
          ? "Moderate observed risk"
          : "High observed risk";
  const color = !available
    ? "#8b9ba9"
    : value >= 60
      ? "#36c7af"
      : value >= 40
        ? "#f3bd5a"
        : "#fb7f85";
  return (
    <section className="posture-card" aria-label="Security posture">
      <div className="posture-heading">
        <ShieldCheck size={18} />
        <span>Security posture</span>
        <ArrowUpRight size={17} />
      </div>
      <div className="score-ring">
        <svg viewBox="0 0 160 160" aria-hidden="true">
          <circle
            cx="80"
            cy="80"
            r="67"
            fill="none"
            stroke="#263d47"
            strokeWidth="8"
          />
          <circle
            cx="80"
            cy="80"
            r="67"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            pathLength="100"
            strokeDasharray={`${available ? value : 0} 100`}
            transform="rotate(-90 80 80)"
          />
        </svg>
        <div>
          <strong>{available ? Math.round(value) : "—"}</strong>
          <span>OUT OF 100</span>
        </div>
      </div>
      <strong className="posture-rating">{label}</strong>
      <p>
        {isDemo
          ? "Illustrative score from demo fixtures."
          : available
            ? "Based on assessed controls and confirmed evidence."
            : "Launch a scan to build your security picture."}
      </p>
      <div className="posture-foot">
        <span className="status-dot" />
        {isDemo ? "Demo assessment" : "Evidence-based assessment"}
      </div>
    </section>
  );
}
