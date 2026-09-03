"use client";

import { useParams } from "next/navigation";
import { useScan, useFindings, useFindingsStats } from "@/hooks/useApi";
import { TriageView } from "@/components/TriageView";
import { ReportView } from "@/components/ReportView";
import { ProgressLog } from "@/components/ProgressLog";
import { ScanResponse, ScanStatus, FindingResponse } from "@/types/api";
import { cn, formatRelativeTime, getSeverityColor } from "@/lib/utils";
import { Shield, ArrowLeft, Loader2, AlertCircle, CheckCircle, XCircle, Clock, Terminal, Globe, AlertTriangle } from "lucide-react";
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

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [activeTab, setActiveTab] = useState<"progress" | "findings" | "triage" | "report">("progress");

  const { data: scan, isLoading: scanLoading } = useScan(scanId);
  const { data: findings, isLoading: findingsLoading } = useFindings(scanId);
  const { data: stats } = useFindingsStats(scanId);

  if (scanLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center">
        <Loader2 className="h-12 w-12 animate-spin text-primary" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan not found</h1>
          <Link href="/" className="mt-4 text-primary hover:underline">Back to dashboard</Link>
        </div>
      </div>
    );
  }

  const StatusIcon = STATUS_ICONS[scan.status];
  const isActive = scan.status === "running";

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/" className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
                <ArrowLeft className="h-5 w-5 text-gray-500" />
              </Link>
              <div>
                <h1 className="text-xl font-bold text-gray-900 dark:text-white truncate max-w-md">{scan.target_url}</h1>
                <div className="flex items-center gap-3 mt-1">
                  <span className={cn("px-2 py-1 rounded-full text-xs font-medium", STATUS_COLORS[scan.status])}>
                    <StatusIcon className={cn("h-3 w-3 mr-1", isActive && "animate-spin")} />
                    {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  </span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    Started {formatRelativeTime(scan.created_at)}
                  </span>
                  {scan.status === "completed" && (
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      Completed {formatRelativeTime(scan.updated_at)}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="mt-4 border-t border-gray-200 dark:border-gray-800">
            <nav className="flex gap-8 overflow-x-auto" aria-label="Scan tabs">
              {[
                { id: "progress", label: "Progress", icon: Terminal },
                { id: "findings", label: "Findings", icon: AlertTriangle, count: findings?.length },
                { id: "triage", label: "Triage", icon: Shield },
                { id: "report", label: "Report", icon: Globe },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  disabled={tab.id !== "progress" && scan.status !== "completed"}
                  className={cn(
                    "flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors whitespace-nowrap",
                    activeTab === tab.id
                      ? "border-primary text-primary"
                      : "border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300",
                    tab.id !== "progress" && scan.status !== "completed" && "opacity-50 cursor-not-allowed"
                  )}
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                  {tab.count !== undefined && (
                    <span className={cn("px-2 py-0.5 text-xs rounded-full", activeTab === tab.id ? "bg-primary/20" : "bg-gray-100 dark:bg-gray-800")}>
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Progress Tab */}
        {activeTab === "progress" && (
          <ProgressLog scanId={scanId} isActive={isActive} />
        )}

        {/* Findings Tab */}
        {activeTab === "findings" && (
          <div className="space-y-6">
            {stats && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {["Critical", "High", "Medium", "Low", "Info"].map((severity) => (
                  <div
                    key={severity}
                    className={cn("p-4 rounded-lg text-center", getSeverityColor(severity).replace("text-", "bg-").replace("dark:bg-", "dark:bg-").replace("dark:text-", "dark:bg-").replace("800", "100").replace("400", "900/30"))}
                  >
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">{stats[severity as keyof typeof stats] || 0}</div>
                    <div className="text-xs font-medium">{severity}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl">
              {findingsLoading ? (
                <div className="p-8 text-center text-gray-500">Loading findings...</div>
              ) : (
                <div className="p-4">
                  {findings && findings.length > 0 ? (
                    <>
                      <h2 className="text-lg font-semibold mb-4">Findings ({findings.length})</h2>
                      <FindingsTable findings={findings} stats={stats || {} as Record<string, number>} />
                    </>
                  ) : (
                    <div className="p-12 text-center">
                      <Shield className="h-16 w-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No findings</h3>
                      <p className="text-gray-500 dark:text-gray-400">The scan completed with no security issues detected</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Triage Tab */}
        {activeTab === "triage" && scan.status === "completed" && (
          <TriageView scanId={scanId} />
        )}

        {/* Report Tab */}
        {activeTab === "report" && scan.status === "completed" && (
          <ReportView scanId={scanId} />
        )}

        {activeTab !== "progress" && scan.status !== "completed" && (
          <div className="p-8 text-center">
            <AlertCircle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Scan not completed</h3>
            <p className="text-gray-500 dark:text-gray-400">Wait for the scan to finish before viewing this section</p>
          </div>
        )}
      </main>
    </div>
  );
}

// Local FindingsTable component for this page
function FindingsTable({ findings, stats }: { findings: FindingResponse[]; stats: Record<string, number> }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-800/50">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">Severity</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">Check</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">Title</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">Score</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">Confidence</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {findings.map((finding) => (
            <tr key={finding.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
              <td className="px-4 py-3">
                <span className={cn("inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium", getSeverityColor(finding.severity))}>
                  {finding.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-sm font-mono text-gray-600 dark:text-gray-400">{finding.check}</td>
              <td className="px-4 py-3">
                <div className="font-medium text-gray-900 dark:text-gray-100 truncate max-w-xs">{finding.title}</div>
                <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">{finding.evidence.url}</div>
              </td>
              <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{finding.score}</td>
              <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{(finding.confidence * 100).toFixed(0)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}