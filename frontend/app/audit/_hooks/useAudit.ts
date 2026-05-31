"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useAccount } from "wagmi";
import { getAllAuditLogs } from "@/lib/api";
import { getExistingSession, getOrCreateSession } from "@/lib/session";
import { getAnomalyChartColor } from "@/lib/utils";
import type { AccessLog, AnomalyLevel, AuditStats } from "@/types";

export interface LevelCount {
  level: AnomalyLevel;
  count: number;
  fill: string;
}

const PAGE_SIZE = 25;

export function useAudit() {
  const { address } = useAccount();
  const tableRef = useRef<HTMLDivElement>(null);
  const pageRef = useRef(0);
  const [allLogs, setAllLogs] = useState<AccessLog[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [serverStats, setServerStats] = useState<AuditStats | null>(null);
  const [serverLevelCounts, setServerLevelCounts] = useState<Record<string, number>>({});
  const [serverActionCounts, setServerActionCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [tableLoading, setTableLoading] = useState(false);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [noSession, setNoSession] = useState(false);

  const fetchPage = useCallback(async (p: number) => {
    if (!address || !getExistingSession(address)) return;
    setTableLoading(true);
    try {
      const res = await getAllAuditLogs(address, p, PAGE_SIZE);
      const logs = res.logs ?? [];
      setAllLogs(logs);
      setHasMore(res.hasMore ?? logs.length >= PAGE_SIZE);
      if (res.totalCount !== undefined) setTotalCount(res.totalCount);
      if (res.stats)        setServerStats(res.stats);
      if (res.levelCounts)  setServerLevelCounts(res.levelCounts);
      if (res.actionCounts) setServerActionCounts(res.actionCounts);
      pageRef.current = p;
      setPage(p);
    } catch (err) {
      console.error("Audit fetch error:", err);
    } finally {
      setTableLoading(false);
    }
  }, [address]);

  const fetchData = useCallback(async () => {
    if (!address) return;
    if (!getExistingSession(address)) { setLoading(false); setNoSession(true); return; }
    setNoSession(false);
    setLoading(true);
    try {
      const res = await getAllAuditLogs(address, 0, PAGE_SIZE);
      const logs = res.logs ?? [];
      setAllLogs(logs);
      setHasMore(res.hasMore ?? logs.length >= PAGE_SIZE);
      if (res.totalCount !== undefined) setTotalCount(res.totalCount);
      if (res.stats)        setServerStats(res.stats);
      if (res.levelCounts)  setServerLevelCounts(res.levelCounts);
      if (res.actionCounts) setServerActionCounts(res.actionCounts);
      pageRef.current = 0;
      setPage(0);
    } catch (err) {
      console.error("Audit fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, [address]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchPage(pageRef.current), 15_000);
    return () => clearInterval(interval);
  }, [fetchData, fetchPage]);

  const signIn = useCallback(async () => {
    if (!address) return;
    try {
      await getOrCreateSession(address);
      setNoSession(false);
      fetchData();
    } catch (err) {
      console.error("Sign-in error:", err);
    }
  }, [address, fetchData]);

  const handlePageChange = useCallback((newPage: number) => {
    if (newPage < 0) return;
    if (newPage !== pageRef.current) {
      fetchPage(newPage);
      tableRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [fetchPage]);

  const filteredLogs = actionFilter === "all"
    ? allLogs
    : allLogs.filter((l) => l.action.startsWith(actionFilter));

  const stats = {
    total:     totalCount,
    uploads:   serverStats?.uploads   ?? 0,
    downloads: serverStats?.downloads ?? 0,
    deletes:   serverStats?.deletes   ?? 0,
    blocked:   serverStats?.blocked   ?? 0,
  };

  const chartData: LevelCount[] = (["NORMAL", "MEDIUM", "HIGH", "CRITICAL"] as AnomalyLevel[]).map(
    (level) => ({ level, count: serverLevelCounts[level] ?? 0, fill: getAnomalyChartColor(level) })
  );

  const actionData = Object.entries(serverActionCounts)
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);

  return {
    filteredLogs,
    loading,
    tableLoading,
    noSession,
    page,
    hasMore,
    actionFilter,
    stats,
    chartData,
    actionData,
    tableRef,
    setActionFilter,
    fetchData,
    signIn,
    handlePageChange,
  };
}
