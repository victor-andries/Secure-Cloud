"use client";

import { cn } from "@/lib/utils";
import { formatScore } from "@/lib/utils";
import type { AnomalyBadgeProps } from "@/types";

const styles: Record<string, { badge: string; dot: string }> = {
  CRITICAL: {
    badge: "bg-red-500/10 text-red-400 border border-red-500/25",
    dot:   "bg-red-500 animate-pulse",
  },
  HIGH: {
    badge: "bg-orange-500/10 text-orange-400 border border-orange-500/25",
    dot:   "bg-orange-500 animate-pulse",
  },
  MEDIUM: {
    badge: "bg-amber-500/10 text-amber-400 border border-amber-500/25",
    dot:   "bg-amber-500",
  },
  NORMAL: {
    badge: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
    dot:   "bg-emerald-500",
  },
};

const fallback = {
  badge: "bg-zinc-800 text-zinc-400 border border-zinc-700",
  dot:   "bg-zinc-500",
};

export default function AnomalyBadge({ level, score }: AnomalyBadgeProps) {
  const s = styles[level] ?? fallback;

  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-xs font-semibold", s.badge)}>
      <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", s.dot)} />
      {level}
      {score !== undefined && (
        <span className="opacity-60 font-normal">· {formatScore(score)}</span>
      )}
    </span>
  );
}
