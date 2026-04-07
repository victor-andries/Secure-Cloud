"use client";

import { useEffect, useState, useCallback } from "react";
import StatCard from "@/components/StatCard";
import AnomalyBadge from "@/components/AnomalyBadge";
import { getAnomalyLogs, getHealth } from "@/lib/api";
import { formatTimestamp, truncateAddress } from "@/lib/utils";
import type { AccessLog, HealthResponse, AnomalyLevel } from "@/types";

interface DashboardStats {
  totalFiles: number;
  anomaliesDetected: number;
  blockchainTxs: number;
  storageUsed: string;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    totalFiles: 0,
    anomaliesDetected: 0,
    blockchainTxs: 0,
    storageUsed: "0 MB"
  });
  const [recentLogs, setRecentLogs] = useState<AccessLog[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    try {
      const [logsResponse, healthResponse] = await Promise.allSettled([
        getAnomalyLogs(0, 10),
        getHealth()
      ]);

      if (logsResponse.status === "fulfilled") {
        const anomalies = logsResponse.value.anomalies ?? [];
        setRecentLogs(anomalies);
        setStats((prev) => ({
          ...prev,
          anomaliesDetected: anomalies.length
        }));
      }

      if (healthResponse.status === "fulfilled") {
        setHealth(healthResponse.value);
      }

      // Load file count from localStorage
      const storedFiles = localStorage.getItem("uploadedFiles");
      if (storedFiles) {
        const files = JSON.parse(storedFiles) as unknown[];
        setStats((prev) => ({
          ...prev,
          totalFiles: files.length,
          blockchainTxs: files.length
        }));
      }
    } catch (err) {
      console.error("Dashboard data fetch failed:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30_000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  const serviceStatuses = health?.services;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">
          Security <span className="text-gradient">Dashboard</span>
        </h1>
        <p className="text-gray-400 mt-1">
          Real-time monitoring of encrypted storage, blockchain activity, and AI anomaly detection
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="Total Files"
          value={stats.totalFiles}
          color="primary"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          }
        />
        <StatCard
          title="Anomalies Detected"
          value={stats.anomaliesDetected}
          color="danger"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          }
        />
        <StatCard
          title="Blockchain Transactions"
          value={stats.blockchainTxs}
          color="secondary"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          }
        />
        <StatCard
          title="Storage Used"
          value={stats.storageUsed}
          color="success"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
            </svg>
          }
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity Table */}
        <div className="lg:col-span-2 glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
            <h2 className="text-white font-semibold">Recent Anomaly Events</h2>
            {loading && (
              <div className="w-4 h-4 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin" />
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  <th className="text-left px-6 py-3 font-medium">Time</th>
                  <th className="text-left px-6 py-3 font-medium">User</th>
                  <th className="text-left px-6 py-3 font-medium">Action</th>
                  <th className="text-left px-6 py-3 font-medium">IP</th>
                  <th className="text-left px-6 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-gray-600">
                      {loading ? "Loading..." : "No anomaly events recorded yet"}
                    </td>
                  </tr>
                ) : (
                  recentLogs.map((log, idx) => (
                    <tr key={idx} className="border-t border-white/5">
                      <td className="px-6 py-3 text-gray-400 whitespace-nowrap">
                        {formatTimestamp(log.timestamp)}
                      </td>
                      <td className="px-6 py-3 text-primary-400 font-mono whitespace-nowrap">
                        {truncateAddress(log.user)}
                      </td>
                      <td className="px-6 py-3 text-gray-300 capitalize">{log.action}</td>
                      <td className="px-6 py-3 text-gray-400 font-mono">{log.ipAddress}</td>
                      <td className="px-6 py-3">
                        <AnomalyBadge level={log.anomalyFlag ? "HIGH" : "NORMAL"} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Service Health */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5">
            <h2 className="text-white font-semibold">Service Health</h2>
          </div>
          <div className="p-6 flex flex-col gap-3">
            {[
              { name: "Storage Service", key: "storage" as const, port: "5001" },
              { name: "Blockchain Service", key: "blockchain" as const, port: "5002" },
              { name: "AI Detection", key: "ai_detection" as const, port: "5003" }
            ].map(({ name, key, port }) => {
              const svc = serviceStatuses?.[key];
              const ok = svc?.status === "ok";
              return (
                <div key={key} className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
                  <div>
                    <p className="text-white text-sm font-medium">{name}</p>
                    <p className="text-gray-600 text-xs">:{port}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${ok ? "bg-success-500 animate-pulse" : "bg-danger-500"}`} />
                    <span className={`text-xs font-medium ${ok ? "text-success-400" : "text-danger-400"}`}>
                      {loading ? "Checking..." : ok ? "Healthy" : "Offline"}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Overall status */}
            <div className="mt-2 p-3 rounded-xl bg-white/5 border border-white/10">
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${
                  health?.status === "ok" ? "bg-success-500 animate-pulse" :
                  health?.status === "degraded" ? "bg-warning-500 animate-pulse" :
                  "bg-gray-600"
                }`} />
                <span className="text-sm font-medium text-gray-200">
                  System: {health?.status ?? "Unknown"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
