"use client";

import React from "react";
import { TrendingUp, TrendingDown, Minus, ShieldAlert } from "lucide-react";

interface ScoreGaugeProps {
  score: number;
}

export default function ScoreGauge({ score }: ScoreGaugeProps) {
  const getRating = (s: number) => {
    if (s === 0) return { label: "Awaiting Scan", Icon: ShieldAlert, color: "text-neutral-400 dark:text-neutral-500" };
    if (s >= 80) return { label: "Excellent", Icon: TrendingUp, color: "text-emerald-600 dark:text-emerald-400" };
    if (s >= 60) return { label: "Good", Icon: TrendingUp, color: "text-emerald-600 dark:text-emerald-400" };
    if (s >= 40) return { label: "Moderate Risk", Icon: Minus, color: "text-amber-600 dark:text-amber-400" };
    return { label: "High Risk", Icon: TrendingDown, color: "text-red-600 dark:text-red-400" };
  };

  const { label, Icon, color } = getRating(score);

  // Arc progress
  const radius = 60;
  const circumference = Math.PI * radius; // half circle
  const progress = score / 100;
  const strokeDashoffset = circumference - progress * circumference;

  const getStrokeColor = (s: number) => {
    if (s === 0) return "#737373";
    if (s >= 60) return "#16a34a";
    if (s >= 40) return "#d97706";
    return "#dc2626";
  };

  const strokeColor = getStrokeColor(score);

  return (
    <div className="cs-card h-full flex flex-col items-center justify-center p-6 gap-3">
      <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-widest">
        Security Posture Score
      </div>

      {/* Half-circle arc */}
      <div className="relative w-[160px] h-[88px] overflow-hidden">
        <svg
          width="160"
          height="160"
          viewBox="0 0 160 160"
          className="absolute top-0 left-0"
          style={{ transform: "rotate(-180deg)" }}
        >
          {/* Track */}
          <path
            d="M 20 80 A 60 60 0 0 1 140 80"
            fill="none"
            stroke="currentColor"
            className="text-neutral-100 dark:text-neutral-800"
            strokeWidth="10"
            strokeLinecap="round"
          />
          {/* Progress */}
          <path
            d="M 20 80 A 60 60 0 0 1 140 80"
            fill="none"
            stroke={strokeColor}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{ transition: "stroke-dashoffset 1s ease" }}
          />
        </svg>
        {/* Score number */}
        <div className="absolute bottom-0 left-0 right-0 flex flex-col items-center">
          <span className="text-5xl font-black tracking-tighter text-neutral-900 dark:text-neutral-100 leading-none count-up">
            {score > 0 ? Math.round(score) : "—"}
          </span>
          <span className="text-xs text-neutral-400 dark:text-neutral-500 font-medium">/ 100</span>
        </div>
      </div>

      <div className={`flex items-center gap-1.5 text-sm font-semibold ${color}`}>
        <Icon className="h-4 w-4" />
        <span>{label}</span>
      </div>

      {/* Mini progress bar */}
      <div className="w-full h-1 bg-neutral-100 dark:bg-neutral-800 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-1000"
          style={{ width: `${score}%`, backgroundColor: strokeColor }}
        />
      </div>
    </div>
  );
}
