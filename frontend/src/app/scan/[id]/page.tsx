"use client";

import { useParams } from "next/navigation";
import { useScan, useFindings, useFindingsStats } from "@/hooks/useApi";
import { TriageView } from "@/components/TriageView";
import { ReportView } from "@/components/ReportView";
import { ProgressLog } from "@/components/ProgressLog";
import { ScanResponse, ScanStatus, FindingResponse, SeverityLevel } from "@/types/api";
import { cn, formatRelativeTime, getSeverityColor } from "@/lib/utils";
import { Shield, ArrowLeft, Loader2, AlertCircle, CheckCircle, XCircle, Clock, Terminal, Globe, AlertTriangle, ChevronRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

const STATUS_COLORS: Record<ScanStatus, string> = {
  pending: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  running: "bg-primary/10 text-primary dark:bg-primary/20",
  completed: "bg-success/10 text-success dark:bg-success/20",
  failed: "bg-destructive/10 text-destructive dark:bg-destructive/20",
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
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="h-12 w-12 animate-spin text-primary" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="h-16 w-16 text-destructive mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-foreground">Scan not found</h1>
          <Link href="/" className="mt-4 text-primary hover:underline">Back to dashboard</Link>
        </div>
      </div>
    );
  }

  const StatusIcon = STATUS_ICONS[scan.status];
  const isActive = scan.status === "running";

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/" className="p-2 rounded-lg hover:bg-muted transition-colors">
                <ArrowLeft className="h-5 w-5 text-muted-foreground" />
              </Link>
              <div>
                <h1 className="text-xl font-semibold text-foreground truncate max-w-md">{scan.target_url}</h1>
                <div className="flex items-center gap-3 mt-1">
                  <span className={cn("px-3 py-1 rounded-full text-xs font-medium", STATUS_COLORS[scan.status])}>
                    <StatusIcon className={cn("h-3 w-3 mr-1", isActive && "animate-spin")} />
                    {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    Started {formatRelativeTime(scan.created_at)}
                  </span>
                  {scan.status === "completed" && (
                    <span className="text-sm text-muted-foreground">
                      Completed {formatRelativeTime(scan.updated_at)}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="mt-4 border-t border-border">
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
                      : "border-transparent text-muted-foreground hover:text-foreground",
                    tab.id !== "progress" && scan.status !== "completed" && "opacity-50 cursor-not-allowed"
                  )}
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                  {tab.count !== undefined && (
                    <span className={cn("px-2 py-0.5 text-xs rounded-full", activeTab === tab.id ? "bg-primary/20" : "bg-muted")}>
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
                {(["Critical", "High", "Medium", "Low", "Info"] as SeverityLevel[]).map((severity) => (
                  <div
                    key={severity}
                    className={cn("p-4 rounded-lg text-center border", getSeverityColor(severity).replace("bg-", "border-").replace("text-", "text-"))}
                  >
                    <div className="text-3xl font-bold text-foreground">{stats.by_severity[severity] || 0}</div>
                    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{severity}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="bg-card border border-border rounded-lg">
              {findingsLoading ? (
                <div className="p-8 text-center text-muted-foreground">Loading findings...</div>
              ) : (
                <div className="p-4">
                  {findings && findings.length > 0 ? (
                    <>
                      <h2 className="text-lg font-semibold mb-4">Findings ({findings.length})</h2>
                      <FindingsTable findings={findings} />
                    </>
                  ) : (
                    <div className="p-12 text-center">
                      <Shield className="h-16 w-16 text-muted-foreground/50 mx-auto mb-4" />
                      <h3 className="text-lg font-medium text-foreground mb-2">No findings</h3>
                      <p className="text-muted-foreground">The scan completed with no security issues detected</p>
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
            <h3 className="text-lg font-medium text-foreground mb-2">Scan not completed</h3>
            <p className="text-muted-foreground">Wait for the scan to finish before viewing this section</p>
          </div>
        )}
      </main>
    </div>
  );
}

// Local FindingsTable component for this page
function FindingsTable({ findings }: { findings: FindingResponse[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full">
        <thead className="bg-muted/50">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Check</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Title</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Score</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Confidence</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {findings.map((finding) => (
            <tr key={finding.id} className="hover:bg-muted/50">
              <td className="px-4 py-3">
                <span className={cn("inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium", getSeverityColor(finding.severity))}>
                  {finding.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-sm font-mono text-muted-foreground">{finding.check}</td>
              <td className="px-4 py-3">
                <div className="font-medium text-foreground truncate max-w-xs">{finding.title}</div>
                <div className="text-xs text-muted-foreground truncate max-w-xs">{finding.evidence.url}</div>
              </td>
              <td className="px-4 py-3 text-sm text-muted-foreground">{finding.score}</td>
              <td className="px-4 py-3 text-sm text-muted-foreground">{(finding.confidence * 100).toFixed(0)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}