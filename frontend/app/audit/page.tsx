"use client";

import { useEffect, useState, useCallback } from "react";
import AnomalyBadge from "@/components/AnomalyBadge";
import { getAnomalyLogs } from "@/lib/api";
import { formatTimestamp, truncateAddress } from "@/lib/utils";
import type { AccessLog } from "@/types";

export default function AuditPage() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const PAGE_SIZE = 20;

  const fetchLogs = useCallback(async (pageNum: number) => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAnomalyLogs(pageNum, PAGE_SIZE);
      const newLogs = response.anomalies ?? [];
      if (pageNum === 0) {
        setLogs(newLogs);
      } else {
        setLogs((prev) => [...prev, ...newLogs]);
      }
      setHasMore(newLogs.length === PAGE_SIZE);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch audit logs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs(0);
  }, [fetchLogs]);

  const loadMore = useCallback(() => {
    const nextPage = page + 1;
    setPage(nextPage);
    fetchLogs(nextPage);
  }, [page, fetchLogs]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">
          Audit <span className="text-gradient">Trail</span>
        </h1>
        <p className="text-gray-400 mt-1">
          Immutable blockchain-stored anomaly-flagged access events
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: "Total Anomalies", value: logs.length, color: "text-danger-400" },
          { label: "Unique Files", value: new Set(logs.map((l) => l.fileId)).size, color: "text-warning-400" },
          { label: "Unique Users", value: new Set(logs.map((l) => l.user)).size, color: "text-primary-400" }
        ].map(({ label, value, color }) => (
          <div key={label} className="glass rounded-xl p-4 text-center">
            <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
            <p className="text-gray-500 text-xs mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-4 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="glass rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
          <h2 className="text-white font-semibold">Anomalous Access Events</h2>
          <button
            onClick={() => { setPage(0); fetchLogs(0); }}
            className="text-xs text-primary-400 hover:text-primary-300 transition-colors flex items-center gap-1"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="text-left px-6 py-3">Timestamp</th>
                <th className="text-left px-6 py-3">User</th>
                <th className="text-left px-6 py-3">File ID</th>
                <th className="text-left px-6 py-3">Action</th>
                <th className="text-left px-6 py-3">IP Address</th>
                <th className="text-left px-6 py-3">Status</th>
                <th className="text-left px-6 py-3">Anomaly</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && !loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-16 text-center text-gray-600">
                    No anomaly events recorded yet
                  </td>
                </tr>
              ) : (
                logs.map((log, idx) => (
                  <tr
                    key={idx}
                    className={`border-t border-white/5 ${
                      log.anomalyFlag ? "bg-danger-500/5" : ""
                    }`}
                  >
                    <td className="px-6 py-3 text-gray-400 whitespace-nowrap">
                      {formatTimestamp(log.timestamp)}
                    </td>
                    <td className="px-6 py-3">
                      <span className="text-primary-400 font-mono text-xs">
                        {truncateAddress(log.user)}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <span className="text-gray-400 font-mono text-xs">
                        {(log.fileId?.length ?? 0) > 12 ? `${log.fileId.slice(0, 12)}…` : (log.fileId ?? "—")}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-300 capitalize">{log.action}</td>
                    <td className="px-6 py-3 text-gray-400 font-mono">{log.ipAddress}</td>
                    <td className="px-6 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                        log.success
                          ? "bg-success-500/20 text-success-400"
                          : "bg-danger-500/20 text-danger-400"
                      }`}>
                        {log.success ? "Success" : "Failed"}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <AnomalyBadge level={log.anomalyFlag ? "HIGH" : "NORMAL"} />
                    </td>
                  </tr>
                ))
              )}
              {loading && (
                <tr>
                  <td colSpan={7} className="px-6 py-4 text-center">
                    <div className="flex items-center justify-center gap-2 text-gray-500">
                      <div className="w-4 h-4 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin" />
                      Loading...
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Load More */}
        {hasMore && !loading && (
          <div className="px-6 py-4 border-t border-white/5 text-center">
            <button
              onClick={loadMore}
              className="px-4 py-2 rounded-xl text-sm text-primary-400 hover:text-white bg-primary-600/10 hover:bg-primary-600/20 border border-primary-500/20 transition-all"
            >
              Load more
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
