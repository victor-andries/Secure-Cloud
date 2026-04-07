import type { AnomalyLevel } from "@/types";

/**
 * Format a byte count into a human-readable string (e.g. "1.23 MB").
 */
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Truncate an Ethereum address: 0x1234...abcd
 */
export function truncateAddress(address: string, startChars = 6, endChars = 4): string {
  if (!address) return "";
  if (address.length <= startChars + endChars) return address;
  return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
}

/**
 * Format a Unix timestamp (seconds) into a locale date-time string.
 */
export function formatTimestamp(ts: number): string {
  if (!ts) return "—";
  const ms = ts > 1e12 ? ts : ts * 1000;
  return new Date(ms).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

/**
 * Map an anomaly level to a Tailwind color class pair [bg, text].
 */
export function getAnomalyColor(level: AnomalyLevel): {
  bg: string;
  text: string;
  border: string;
  dot: string;
} {
  switch (level) {
    case "CRITICAL":
      return {
        bg: "bg-red-500/20",
        text: "text-red-400",
        border: "border-red-500/30",
        dot: "bg-red-500"
      };
    case "HIGH":
      return {
        bg: "bg-orange-500/20",
        text: "text-orange-400",
        border: "border-orange-500/30",
        dot: "bg-orange-500"
      };
    case "MEDIUM":
      return {
        bg: "bg-yellow-500/20",
        text: "text-yellow-400",
        border: "border-yellow-500/30",
        dot: "bg-yellow-500"
      };
    case "NORMAL":
    default:
      return {
        bg: "bg-green-500/20",
        text: "text-green-400",
        border: "border-green-500/30",
        dot: "bg-green-500"
      };
  }
}

/**
 * Generate a colour string for recharts based on anomaly level.
 */
export function getAnomalyChartColor(level: AnomalyLevel): string {
  switch (level) {
    case "CRITICAL": return "#ef4444";
    case "HIGH":     return "#f97316";
    case "MEDIUM":   return "#f59e0b";
    case "NORMAL":   return "#10b981";
    default:         return "#6366f1";
  }
}

/**
 * Clamp a number between min and max.
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Format a float (0–1) as a percentage string.
 */
export function formatScore(score: number): string {
  return `${(score * 100).toFixed(1)}%`;
}

/**
 * Capitalise the first letter of a string.
 */
export function capitalize(str: string): string {
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

/**
 * Safe JSON parse — returns null on error.
 */
export function safeJsonParse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}
