"use client";

import { useEffect, useState, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from "recharts";
import AnomalyBadge from "@/components/AnomalyBadge";
import { getHealth, getAnomalyLogs } from "@/lib/api";
import { getAnomalyChartColor } from "@/lib/utils";
import type { HealthResponse, AccessLog, AnomalyLevel, FileRecord } from "@/types";

interface ModelStatus {
  name: string;
  loaded: boolean;
  type: string;
}

interface LevelCount {
  level: AnomalyLevel;
  count: number;
  fill: string;
}

const SEC_TABLE_PAGE_SIZE = 20;

export default function SecurityPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  // allLogs: full batch for charts; tableLogs: paginated subset for the table
  const [allLogs, setAllLogs] = useState<AccessLog[]>([]);
  const [tableLogs, setTableLogs] = useState<AccessLog[]>([]);
  const [localFiles, setLocalFiles] = useState<FileRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [tableLoading, setTableLoading] = useState(false);
  const [tablePage, setTablePage] = useState(0);
  const [tableHasMore, setTableHasMore] = useState(false);

  const fetchTablePage = useCallback(async (page: number) => {
    setTableLoading(true);
    try {
      const res = await getAnomalyLogs(page, SEC_TABLE_PAGE_SIZE);
      const logs = res.anomalies ?? [];
      setTableLogs(logs);
      setTableHasMore(logs.length === SEC_TABLE_PAGE_SIZE);
    } catch (err) {
      console.error("Security table fetch error:", err);
    } finally {
      setTableLoading(false);
    }
  }, []);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [healthRes, logsRes] = await Promise.allSettled([
        getHealth(),
        getAnomalyLogs(0, 200)         // large batch for charts
      ]);
      if (healthRes.status === "fulfilled") setHealth(healthRes.value);
      if (logsRes.status === "fulfilled") {
        const logs = logsRes.value.anomalies ?? [];
        setAllLogs(logs);
        // first page of table = first SEC_TABLE_PAGE_SIZE entries
        setTableLogs(logs.slice(0, SEC_TABLE_PAGE_SIZE));
        setTableHasMore(logs.length > SEC_TABLE_PAGE_SIZE);
        setTablePage(0);
      }
    } catch (err) {
      console.error("Security data fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    const stored = JSON.parse(localStorage.getItem("uploadedFiles") ?? "[]") as FileRecord[];
    setLocalFiles(stored);
  }, []);

  const handleTablePage = (newPage: number) => {
    if (newPage < 0) return;
    // If within the cached allLogs batch, use client-side slice
    const start = newPage * SEC_TABLE_PAGE_SIZE;
    if (start < allLogs.length) {
      const slice = allLogs.slice(start, start + SEC_TABLE_PAGE_SIZE);
      setTableLogs(slice);
      setTableHasMore(start + SEC_TABLE_PAGE_SIZE < allLogs.length || allLogs.length === 200);
      setTablePage(newPage);
    } else if (newPage > tablePage && tableHasMore) {
      // Beyond the cached batch: go to server
      setTablePage(newPage);
      fetchTablePage(newPage);
    }
  };

  // Derive model statuses from health detail
  const aiDetail = health?.services?.ai_detection?.detail as Record<string, unknown> | undefined;
  const modelStatusObj = aiDetail?.model_status as Record<string, boolean> | undefined;
  const models: ModelStatus[] = [
    { name: "Isolation Forest", loaded: modelStatusObj?.isolation_forest ?? false, type: "Ensemble" },
    { name: "Random Forest",    loaded: modelStatusObj?.random_forest    ?? false, type: "Ensemble" },
  ];

  // NORMAL/MEDIUM are never in the anomaly log (anomaly_flag=false by design).
  // Use localStorage for those, anomaly logs for HIGH/CRITICAL (covers downloads too).
  const levelCounts: Record<AnomalyLevel, number> = {
    NORMAL: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0
  };
  for (const file of localFiles) {
    const level = (file.aiLevel as AnomalyLevel) ?? "NORMAL";
    if (level === "NORMAL" || level === "MEDIUM") {
      levelCounts[level] += 1;
    }
  }
  for (const log of allLogs) {
    const level: AnomalyLevel = log.anomalyLevel ?? (log.anomalyFlag ? "HIGH" : "NORMAL");
    if (level === "HIGH" || level === "CRITICAL") {
      levelCounts[level] += 1;
    }
  }

  const chartData: LevelCount[] = (["NORMAL", "MEDIUM", "HIGH", "CRITICAL"] as AnomalyLevel[]).map((level) => ({
    level,
    count: levelCounts[level],
    fill: getAnomalyChartColor(level)
  }));

  // Action distribution
  const actionCounts: Record<string, number> = {};
  for (const log of allLogs) {
    actionCounts[log.action] = (actionCounts[log.action] ?? 0) + 1;
  }
  const actionData = Object.entries(actionCounts)
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);

  // Ensemble weights display (rescaled to the two active models)
  const weights = [
    { model: "Random Forest",    weight: 0.60, color: "bg-success-500"   },
    { model: "Isolation Forest", weight: 0.40, color: "bg-secondary-500" },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Security <span className="text-gradient">Intelligence</span>
          </h1>
          <p className="text-gray-400 mt-1">
            AI model status, anomaly distribution, and detection analytics
          </p>
        </div>
        <button
          onClick={fetchData}
          className="px-4 py-2 rounded-xl text-sm text-primary-400 bg-primary-600/10 border border-primary-500/20 hover:bg-primary-600/20 transition-all"
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* AI Model Status */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5">
            <h2 className="text-white font-semibold">AI Model Status</h2>
            <p className="text-gray-500 text-xs mt-0.5">
              {models.filter((m) => m.loaded).length}/{models.length} models loaded
            </p>
          </div>
          <div className="p-6 flex flex-col gap-3">
            {models.map((model) => (
              <div key={model.name} className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
                <div>
                  <p className="text-white text-sm font-medium">{model.name}</p>
                  <p className="text-gray-500 text-xs">{model.type}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${model.loaded ? "bg-success-500 animate-pulse" : "bg-danger-500"}`} />
                  <span className={`text-xs font-medium ${model.loaded ? "text-success-400" : "text-danger-400"}`}>
                    {loading ? "Checking..." : model.loaded ? "Loaded" : "Not loaded"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Ensemble Weights */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5">
            <h2 className="text-white font-semibold">Ensemble Weights</h2>
            <p className="text-gray-500 text-xs mt-0.5">Weighted combination for final anomaly score</p>
          </div>
          <div className="p-6 flex flex-col gap-4">
            {weights.map(({ model, weight, color }) => (
              <div key={model}>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-gray-300">{model}</span>
                  <span className="text-white font-semibold">{(weight * 100).toFixed(0)}%</span>
                </div>
                <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${color} rounded-full transition-all duration-700`}
                    style={{ width: `${weight * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Anomaly Score Distribution */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5">
            <h2 className="text-white font-semibold">Anomaly Level Distribution</h2>
          </div>
          <div className="p-6 h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} barCategoryGap="30%">
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis
                  dataKey="level"
                  tick={{ fill: "#9ca3af", fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#9ca3af", fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                  width={30}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0f1117",
                    border: "1px solid #1e2030",
                    borderRadius: "4px",
                    color: "#e4e4e8"
                  }}
                  labelStyle={{ color: "#e4e4e8" }}
                  itemStyle={{ color: "#fbbf24" }}
                  cursor={{ fill: "rgba(255,255,255,0.03)" }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={index} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Action Distribution */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/5">
            <h2 className="text-white font-semibold">Attack Action Breakdown</h2>
          </div>
          <div className="p-6 h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={actionData} layout="vertical" barCategoryGap="20%">
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#9ca3af", fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="action"
                  tick={{ fill: "#9ca3af", fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                  width={80}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0f1117",
                    border: "1px solid #1e2030",
                    borderRadius: "4px",
                    color: "#e4e4e8"
                  }}
                  labelStyle={{ color: "#e4e4e8" }}
                  itemStyle={{ color: "#fbbf24" }}
                  cursor={{ fill: "rgba(255,255,255,0.03)" }}
                />
                <Bar dataKey="count" fill="#6366f1" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Anomalies table */}
      <div className="glass rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold">Recent Anomalous Events</h2>
            <p className="text-gray-500 text-xs mt-0.5">{allLogs.length} events loaded</p>
          </div>
          {tableLoading && (
            <div className="w-4 h-4 border-2 border-primary-400/30 border-t-primary-400 rounded-full animate-spin" />
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="text-left px-6 py-3">Timestamp</th>
                <th className="text-left px-6 py-3">Action</th>
                <th className="text-left px-6 py-3">IP Address</th>
                <th className="text-left px-6 py-3">Result</th>
                <th className="text-left px-6 py-3">Threat Level</th>
              </tr>
            </thead>
            <tbody>
              {tableLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-600">
                    {loading ? "Loading..." : "No anomaly events recorded"}
                  </td>
                </tr>
              ) : (
                tableLogs.map((log, idx) => {
                  const level: AnomalyLevel = log.anomalyLevel ?? (log.anomalyFlag ? "HIGH" : "NORMAL");
                  return (
                    <tr key={idx} className="border-t border-white/5">
                      <td className="px-6 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {new Date(log.timestamp * 1000).toLocaleString()}
                      </td>
                      <td className="px-6 py-3 text-gray-300 capitalize">{log.action}</td>
                      <td className="px-6 py-3 text-gray-400 font-mono">{log.ipAddress}</td>
                      <td className="px-6 py-3">
                        <span className={`text-xs font-medium ${log.success ? "text-success-400" : "text-danger-400"}`}>
                          {log.success ? "Success" : "Blocked"}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <AnomalyBadge level={level} />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {/* Pagination */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-white/5">
          <span className="text-gray-500 text-xs font-mono">
            Page {tablePage + 1} · showing {tableLogs.length} events
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => handleTablePage(tablePage - 1)}
              disabled={tablePage === 0}
              className={`px-3 py-1 text-xs rounded border transition-colors ${
                tablePage === 0
                  ? "border-white/10 text-gray-600 cursor-not-allowed"
                  : "border-white/20 text-gray-400 hover:border-primary-400 hover:text-primary-400"
              }`}
            >
              ← Prev
            </button>
            <button
              onClick={() => handleTablePage(tablePage + 1)}
              disabled={!tableHasMore}
              className={`px-3 py-1 text-xs rounded border transition-colors ${
                !tableHasMore
                  ? "border-white/10 text-gray-600 cursor-not-allowed"
                  : "border-white/20 text-gray-400 hover:border-primary-400 hover:text-primary-400"
              }`}
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
