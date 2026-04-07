"use client";

import { getAnomalyColor, formatScore } from "@/lib/utils";
import type { AnomalyBadgeProps } from "@/types";

export default function AnomalyBadge({ level, score }: AnomalyBadgeProps) {
  const colors = getAnomalyColor(level);

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold
        border ${colors.bg} ${colors.text} ${colors.border}
      `}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${colors.dot} animate-pulse`} />
      {level}
      {score !== undefined && (
        <span className="opacity-75 font-normal">({formatScore(score)})</span>
      )}
    </span>
  );
}
