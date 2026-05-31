"use client";

import AnomalyBadge from "@/components/AnomalyBadge";
import type { AnomalyLevel } from "@/types";
import { useAudit } from "./_hooks/useAudit";
import LevelDistributionChart from "./_components/LevelDistributionChart";
import ActionBreakdownChart from "./_components/ActionBreakdownChart";

const ACTION_FILTERS = [
  { value: "all",      label: "All Events" },
  { value: "upload",   label: "Uploads"    },
  { value: "download", label: "Downloads"  },
  { value: "delete",   label: "Deletes"    },
];

export default function AuditPage() {
  const {
    filteredLogs, loading, tableLoading,
    noSession, page, hasMore, actionFilter, stats,
    chartData, actionData, tableRef,
    setActionFilter, fetchData, signIn, handlePageChange,
  } = useAudit();

  if (noSession) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white">
            Audit <span className="text-gradient">Logs</span>
          </h1>
          <p className="text-gray-400 mt-1">
            Full access history — all file operations recorded on-chain
          </p>
        </div>
        <div className="glass rounded-2xl flex flex-col items-center justify-center py-20 gap-4">
          <svg className="w-10 h-10 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p className="text-gray-400 text-sm">Sign in with your wallet to view audit logs</p>
          <button
            onClick={signIn}
            className="px-5 py-2 text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors rounded-sm"
          >
            Sign In
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Audit <span className="text-gradient">Logs</span>
          </h1>
          <p className="text-gray-400 mt-1">
            Full access history — all file operations recorded on-chain
          </p>
        </div>
        <button
          onClick={fetchData}
          className="px-4 py-2 rounded-xl text-sm text-primary-400 bg-primary-600/10 border border-primary-500/20 hover:bg-primary-600/20 transition-all"
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mb-6">
        {[
          { label: "Total Events",  value: stats.total,     color: "text-white"         },
          { label: "Uploads",       value: stats.uploads,   color: "text-primary-400"   },
          { label: "Downloads",     value: stats.downloads, color: "text-secondary-400" },
          { label: "Deletes",       value: stats.deletes,   color: "text-yellow-400"    },
          { label: "Blocked",       value: stats.blocked,   color: "text-danger-400"    },
        ].map(({ label, value, color }) => (
          <div key={label} className="glass rounded-2xl px-5 py-4">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">{label}</p>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <LevelDistributionChart chartData={chartData} />
        <ActionBreakdownChart actionData={actionData} />
      </div>

      <div ref={tableRef} className="glass rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-white/5 flex flex-wrap items-center gap-3 justify-between">
          <div>
            <h2 className="text-white font-semibold">Access Events</h2>
            <p className="text-gray-500 text-xs mt-0.5">{filteredLogs.length} events on this page</p>
          </div>
          <div className="flex items-center gap-2">
            {tableLoading && (
              <div className="w-4 h-4 border-2 border-primary-400/30 border-t-primary-400 rounded-full animate-spin" />
            )}
            <div className="flex rounded-xl overflow-hidden border border-white/10">
              {ACTION_FILTERS.map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => setActionFilter(value)}
                  className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                    actionFilter === value
                      ? "bg-primary-600/30 text-primary-300"
                      : "text-gray-500 hover:text-gray-300 hover:bg-white/5"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase tracking-wider">
                <th className="text-left px-6 py-3">Timestamp</th>
                <th className="text-left px-6 py-3">File ID</th>
                <th className="text-left px-6 py-3">Action</th>
                <th className="text-left px-6 py-3">IP Address</th>
                <th className="text-left px-6 py-3">Result</th>
                <th className="text-left px-6 py-3">Threat Level</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-gray-600">
                    {loading ? "Loading..." : "No events recorded"}
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log, idx) => {
                  const level: AnomalyLevel = log.anomalyLevel ?? (log.anomalyFlag ? "HIGH" : "NORMAL");
                  return (
                    <tr key={idx} className={`border-t border-white/5 hover:bg-white/[0.02] transition-colors ${log.pending ? "opacity-60" : ""}`}>
                      <td className="px-6 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {new Date(log.timestamp * 1000).toLocaleString()}
                        {log.pending && (
                          <span className="ml-2 text-[10px] text-yellow-500/70 font-mono">confirming…</span>
                        )}
                      </td>
                      <td className="px-6 py-3 text-gray-500 font-mono text-xs truncate max-w-[120px]" title={log.fileId}>
                        {log.fileId ? log.fileId.slice(0, 8) + "…" : "—"}
                      </td>
                      <td className="px-6 py-3">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-md ${
                          log.action.startsWith("upload")   ? "bg-primary-500/10 text-primary-400" :
                          log.action.startsWith("download") ? "bg-secondary-500/10 text-secondary-400" :
                          log.action.startsWith("delete")   ? "bg-danger-500/10 text-danger-400" :
                          "bg-white/5 text-gray-400"
                        }`}>
                          {log.action.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-gray-400 font-mono text-xs">{log.ipAddress}</td>
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

        <div className="flex items-center justify-between px-6 py-3 border-t border-white/5">
          <span className="text-gray-500 text-xs font-mono">
            Page {page + 1} · {filteredLogs.length} events
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => handlePageChange(page - 1)}
              disabled={page === 0}
              className={`px-3 py-1 text-xs rounded border transition-colors ${
                page === 0
                  ? "border-white/10 text-gray-600 cursor-not-allowed"
                  : "border-white/20 text-gray-400 hover:border-primary-400 hover:text-primary-400"
              }`}
            >
              ← Prev
            </button>
            <button
              onClick={() => handlePageChange(page + 1)}
              disabled={!hasMore}
              className={`px-3 py-1 text-xs rounded border transition-colors ${
                !hasMore
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
