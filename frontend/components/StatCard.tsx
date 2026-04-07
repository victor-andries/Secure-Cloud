"use client";

import type { StatCardProps } from "@/types";

const colorMap: Record<NonNullable<StatCardProps["color"]>, string> = {
  primary:   "from-primary-500/20 to-primary-600/10 border-primary-500/20",
  secondary: "from-secondary-500/20 to-secondary-600/10 border-secondary-500/20",
  danger:    "from-danger-500/20 to-danger-600/10 border-danger-500/20",
  warning:   "from-warning-500/20 to-warning-600/10 border-warning-500/20",
  success:   "from-success-500/20 to-success-600/10 border-success-500/20"
};

const iconColorMap: Record<NonNullable<StatCardProps["color"]>, string> = {
  primary:   "text-primary-400",
  secondary: "text-secondary-500",
  danger:    "text-danger-500",
  warning:   "text-warning-500",
  success:   "text-success-500"
};

export default function StatCard({ title, value, icon, trend, color = "primary" }: StatCardProps) {
  const gradientClass = colorMap[color];
  const iconClass = iconColorMap[color];

  return (
    <div
      className={`
        relative overflow-hidden rounded-2xl border bg-gradient-to-br ${gradientClass}
        backdrop-blur-sm p-6 flex flex-col gap-4 transition-transform duration-200
        hover:scale-[1.02] hover:shadow-lg hover:shadow-black/20
      `}
    >
      {/* Background decoration */}
      <div className="absolute -top-4 -right-4 w-24 h-24 rounded-full bg-white/5 blur-xl" />

      <div className="flex items-start justify-between relative z-10">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-1 tabular-nums">
            {value}
          </p>
        </div>
        <div className={`${iconClass} w-10 h-10 flex items-center justify-center rounded-xl bg-white/10`}>
          {icon}
        </div>
      </div>

      {trend && (
        <div className="flex items-center gap-1.5 relative z-10">
          <span
            className={`text-xs font-semibold ${
              trend.positive ? "text-success-500" : "text-danger-500"
            }`}
          >
            {trend.positive ? "▲" : "▼"} {Math.abs(trend.value)}%
          </span>
          <span className="text-gray-500 text-xs">{trend.label}</span>
        </div>
      )}
    </div>
  );
}
