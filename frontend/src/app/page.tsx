"use client";

import { useScans, useStartScan } from "@/hooks/useApi";
import { ScanWizard } from "@/components/ScanWizard";
import { ScanStatus, ScanResponse } from "@/types/api";
import { cn, formatRelativeTime, getSeverityColor } from "@/lib/utils";
import { Shield, Clock, CheckCircle, XCircle, Loader2, RefreshCw, ExternalLink } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

const STATUS_COLORS: Record<ScanStatus, string> = {
  pending: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  completed: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
};

const STATUS_ICONS: Record<ScanStatus, React.ComponentType<{ className?: string }>> = {
  pending: Clock,
  running: Loader2,
  completed: CheckCircle,
  failed: XCircle,
};

export default function Dashboard() {
  const [selectedScan, setSelectedScan] = useState<ScanResponse | null>(null);
  const { data: scans, isLoading, refetch } = useScans();
  const startScan = useStartScan();

  const handleStartScan = async (data: Parameters<typeof startScan.mutate>[0]) => {
    startScan.mutate(data, {
      onSuccess: (newScan) => {
        setSelectedScan(newScan);
        refetch();
      },
    });
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">VibeShield</h1>
              <span className="px-2 py-0.5 text-xs font-medium bg-primary/10 text-primary rounded-full">Dashboard</span>
            </div>
            <button
              onClick={() => refetch()}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              aria-label="Refresh scans"
            >
              <RefreshCw className="h-5 w-5 text-gray-500" />
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Left Panel - Scan Wizard */}
          <div className="lg:col-span-1">
            <div className="sticky top-24 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">New Scan</h2>
              <ScanWizard onScanStart={handleStartScan} />
            </div>
          </div>

          {/* Right Panel - Scan List */}
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-gray-800">
                <h2 className="text-lg font-semibold">Recent Scans</h2>
              </div>

              {isLoading ? (
                <div className="p-8 text-center text-gray-500">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-2" />
                  Loading scans...
                </div>
              ) : scans?.length === 0 ? (
                <div className="p-12 text-center">
                  <Shield className="h-16 w-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No scans yet</h3>
                  <p className="text-gray-500 dark:text-gray-400">Start a new scan using the form on the left</p>
                </div>
              ) : (
                <div className="divide-y divide-gray-200 dark:divide-gray-800">
                  {scans?.map((scan) => {
                    const StatusIcon = STATUS_ICONS[scan.status];
                    const progress = scan.progress;

                    return (
                      <Link
                        key={scan.scan_id}
                        href={`/scan/${scan.scan_id}`}
                        className={cn(
                          "block p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors",
                          selectedScan?.scan_id === scan.scan_id && "bg-primary/5 border-l-4 border-primary"
                        )}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-3 mb-2">
                              <span className={cn("px-2 py-1 rounded-full text-xs font-medium", STATUS_COLORS[scan.status])}>
                                <StatusIcon className="h-3 w-3 mr-1" />
                                {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                              </span>
                              <span className="text-sm text-gray-500 dark:text-gray-400">
                                {formatRelativeTime(scan.created_at)}
                              </span>
                            </div>
                            <p className="font-mono text-sm text-gray-900 dark:text-white truncate">{scan.target_url}</p>
                            {scan.status === "running" && (
                              <div className="mt-2 flex items-center gap-2 text-xs text-gray-500">
                                <span>Pages: {progress.pages_crawled}</span>
                                <span>•</span>
                                <span>Findings: {progress.findings_found}</span>
                                {progress.current_check && (
                                  <>
                                    <span>•</span>
                                    <span>Checking: {progress.current_check}</span>
                                  </>
                                )}
                              </div>
                            )}
                            {scan.status === "completed" && (
                              <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                                <span>Pages crawled: {progress.pages_crawled}</span>
                                <span>Findings: {progress.findings_found}</span>
                              </div>
                            )}
                            {scan.error && (
                              <p className="mt-2 text-sm text-red-600 dark:text-red-400">Error: {scan.error}</p>
                            )}
                          </div>
                          <ExternalLink className="h-5 w-5 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </div>
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}