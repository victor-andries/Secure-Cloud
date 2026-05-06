"use client";

import { useEffect, useState, useCallback } from "react";
import { getAllAuditLogs } from "@/lib/api";
import { getAnomalyChartColor } from "@/lib/utils";
import type { AccessLog, AnomalyLevel } from "@/types";

export interface LevelCount {
  level: AnomalyLevel;
  count: number;
  fill: string;
}

const PAGE_SIZE = 25;

export function useAudit() {
  const [allLogs, setAllLogs] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [tableLoading, setTableLoading] = useState(false);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [actionFilter, setActionFilter] = useState<string>("all");

  const fetchPage = useCallback(async (p: number) => {
    setTableLoading(true);
    try {
      const res = await getAllAuditLogs(p, PAGE_SIZE);
      const logs = res.logs ?? [];
      setAllLogs(logs);
      setHasMore(logs.length === PAGE_SIZE);
      setPage(p);
    } catch (err) {
      console.error("Audit fetch error:", err);
    } finally {
      setTableLoading(false);
    }
  }, []);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAllAuditLogs(0, PAGE_SIZE);
      const logs = res.logs ?? [];
      setAllLogs(logs);
      setHasMore(logs.length === PAGE_SIZE);
      setPage(0);
    } catch (err) {
      console.error("Audit fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handlePageChange = (newPage: number) => {
    if (newPage < 0) return;
    if (newPage > page || newPage < page) fetchPage(newPage);
  };

  const filteredLogs = actionFilter === "all"
    ? allLogs
    : allLogs.filter((l) => l.action.startsWith(actionFilter));

  const stats = {
    total: allLogs.length,
    uploads: allLogs.filter((l) => l.action.startsWith("upload")).length,
    downloads: allLogs.filter((l) => l.action.startsWith("download")).length,
    blocked: allLogs.filter((l) => !l.success).length,
  };

  const levelCounts: Record<AnomalyLevel, number> = { NORMAL: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const log of allLogs) {
    const level: AnomalyLevel = log.anomalyLevel ?? (log.anomalyFlag ? "HIGH" : "NORMAL");
    levelCounts[level] += 1;
  }
  const chartData: LevelCount[] = (["NORMAL", "MEDIUM", "HIGH", "CRITICAL"] as AnomalyLevel[]).map(
    (level) => ({ level, count: levelCounts[level], fill: getAnomalyChartColor(level) })
  );

  const actionCounts: Record<string, number> = {};
  for (const log of allLogs) {
    actionCounts[log.action] = (actionCounts[log.action] ?? 0) + 1;
  }
  const actionData = Object.entries(actionCounts)
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);

  return {
    filteredLogs,
    loading,
    tableLoading,
    page,
    hasMore,
    actionFilter,
    stats,
    chartData,
    actionData,
    setActionFilter,
    fetchData,
    handlePageChange,
  };
}
