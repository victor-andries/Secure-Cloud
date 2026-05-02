"use client";

import { useEffect, useState, useCallback } from "react";
import StatCard from "@/components/StatCard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getHealth } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { HealthResponse } from "@/types";

interface DashboardStats {
  totalFiles: number;
  blockchainTxs: number;
  storageUsed: string;
}

const services = [
  { name: "Storage Service",    key: "storage"      as const, port: "5001" },
  { name: "Blockchain Service", key: "blockchain"   as const, port: "5002" },
  { name: "AI Detection",       key: "ai_detection" as const, port: "5003" },
];

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    totalFiles: 0,
    blockchainTxs: 0,
    storageUsed: "0 MB",
  });
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    try {
      const healthResponse = await getHealth().catch(() => null);
      if (healthResponse) setHealth(healthResponse);

      const storedFiles = localStorage.getItem("uploadedFiles");
      if (storedFiles) {
        const files = JSON.parse(storedFiles) as unknown[];
        setStats((prev) => ({
          ...prev,
          totalFiles: files.length,
          blockchainTxs: files.length,
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

      {/* Page header */}
      <div className="mb-10">
        <div className="flex items-center gap-3 mb-3">
          <span className="section-label">System Overview</span>
          <div className="flex-1 h-px bg-border" />
          {loading && (
            <span className="section-label text-primary animate-pulse">syncing…</span>
          )}
        </div>
        <h1 className="font-heading text-4xl font-bold tracking-tight text-foreground">
          Security <span className="text-primary">Dashboard</span>
        </h1>
        <p className="text-muted-foreground mt-2 text-sm">
          Real-time monitoring — encrypted storage · blockchain activity · AI anomaly detection
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-8">
        <StatCard
          title="Total Files"
          value={stats.totalFiles}
          color="primary"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          }
        />
        <StatCard
          title="Blockchain TXs"
          value={stats.blockchainTxs}
          color="secondary"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
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
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
            </svg>
          }
        />
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 gap-4">

        {/* Service health */}
        <Card>
          <CardHeader className="pb-3 border-b border-border">
            <span className="section-label block mb-1">Infrastructure</span>
            <CardTitle className="font-heading text-base">Service Health</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {services.map(({ name, key, port }) => {
              const svc = serviceStatuses?.[key];
              const ok = svc?.status === "ok";
              return (
                <div
                  key={key}
                  className="flex items-center justify-between px-4 py-3.5 border-b border-border last:border-0"
                >
                  <div>
                    <p className="text-sm font-medium text-foreground">{name}</p>
                    <p className="font-mono text-xs text-muted-foreground">:{port}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "w-2 h-2 rounded-full",
                        ok ? "bg-emerald-500 animate-pulse" : "bg-red-500"
                      )}
                    />
                    <span
                      className={cn(
                        "font-mono text-xs font-semibold tracking-wide",
                        ok ? "text-emerald-400" : "text-red-400"
                      )}
                    >
                      {loading ? "···" : ok ? "ONLINE" : "OFFLINE"}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Overall system status */}
            <div className="px-4 py-3.5 bg-muted/40">
              <div className="flex items-center justify-between">
                <span className="section-label">System Status</span>
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "w-2 h-2 rounded-full",
                      health?.status === "ok"       ? "bg-emerald-500 animate-pulse" :
                      health?.status === "degraded" ? "bg-amber-500 animate-pulse"   :
                                                      "bg-zinc-600"
                    )}
                  />
                  <span
                    className={cn(
                      "font-mono text-xs font-semibold tracking-wide uppercase",
                      health?.status === "ok"       ? "text-emerald-400" :
                      health?.status === "degraded" ? "text-amber-400"   :
                                                      "text-muted-foreground"
                    )}
                  >
                    {health?.status ?? "Unknown"}
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>
    </div>
  );
}
