"use client";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { StatCardProps } from "@/types";

const accentBorder: Record<NonNullable<StatCardProps["color"]>, string> = {
  primary:   "border-l-primary",
  secondary: "border-l-sky-500",
  danger:    "border-l-red-500",
  warning:   "border-l-orange-500",
  success:   "border-l-emerald-500",
};

const valueColor: Record<NonNullable<StatCardProps["color"]>, string> = {
  primary:   "text-primary",
  secondary: "text-sky-400",
  danger:    "text-red-400",
  warning:   "text-orange-400",
  success:   "text-emerald-400",
};

const iconColor: Record<NonNullable<StatCardProps["color"]>, string> = {
  primary:   "text-primary/70",
  secondary: "text-sky-500/70",
  danger:    "text-red-500/70",
  warning:   "text-orange-500/70",
  success:   "text-emerald-500/70",
};

export default function StatCard({ title, value, icon, trend, color = "primary" }: StatCardProps) {
  return (
    <Card className={cn("border-l-4 hover:border-l-[5px] transition-all duration-150", accentBorder[color])}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <p className="section-label mb-2">{title}</p>
            <p className={cn("font-heading text-3xl font-bold tabular-nums leading-none", valueColor[color])}>
              {value}
            </p>
          </div>
          <div className={cn("shrink-0 w-8 h-8 flex items-center justify-center", iconColor[color])}>
            {icon}
          </div>
        </div>

        {trend && (
          <div className="flex items-center gap-1.5 mt-4 pt-3 border-t border-border">
            <span className={cn("font-mono text-xs font-semibold", trend.positive ? "text-emerald-400" : "text-red-400")}>
              {trend.positive ? "▲" : "▼"} {Math.abs(trend.value)}%
            </span>
            <span className="text-muted-foreground text-xs">{trend.label}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
