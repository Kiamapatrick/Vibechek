"use client";

import { useState } from "react";
import { useTriageRuns, useStartTriage, useTriage, useCompareTriage } from "@/hooks/useApi";
import { UUID, TriageRunResponse, TriageResult, TriageCompareResponse, TriageMode } from "@/types/api";
import { cn, getSeverityColor, getSourceColor, getPriorityLabel, formatDate, formatRelativeTime } from "@/lib/utils";
import { Brain, Zap, RefreshCw, ChevronDown, ChevronUp, FileText, ExternalLink } from "lucide-react";

interface TriageViewProps {
  scanId: UUID;
}

export function TriageView({ scanId }: TriageViewProps) {
  const [activeTab, setActiveTab] = useState<"runs" | "compare">("runs");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const { data: triageRuns, isLoading: runsLoading } = useTriageRuns(scanId);
  const { data: compareData, isLoading: compareLoading } = useCompareTriage(scanId);
  const startTriage = useStartTriage();

  const handleStartTriage = (mode: TriageMode) => {
    startTriage.mutate({ scanId, mode });
  };

  const getLatestRun = (mode: TriageMode): TriageRunResponse | undefined => {
    return triageRuns?.find((r) => r.mode === mode);
  };

  const baselineRun = getLatestRun("baseline");
  const llmRun = getLatestRun("llm");

  return (
    <div className="space-y-6">
      <div className="flex gap-2 border border-border rounded-lg p-1 bg-muted/50 w-fit">
        <button
          onClick={() => setActiveTab("runs")}
          className={cn("px-4 py-2 rounded-md text-sm font-medium transition-colors",
            activeTab === "runs" ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground"
          )}
        >
          Runs
        </button>
        <button
          onClick={() => setActiveTab("compare")}
          className={cn("px-4 py-2 rounded-md text-sm font-medium transition-colors",
            activeTab === "compare" ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground"
          )}
        >
          Compare
        </button>
      </div>

      {activeTab === "runs" ? (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <h2 className="text-xl font-semibold text-foreground">Triage Runs</h2>
            <div className="flex gap-2">
              <button
                onClick={() => handleStartTriage("baseline")}
                disabled={startTriage.isPending}
                className="px-4 py-2 bg-success/10 text-success dark:bg-success/20 rounded-lg hover:bg-success/20 disabled:opacity-50 flex items-center gap-2"
              >
                <Zap className="h-4 w-4" />
                Run Baseline
              </button>
              <button
                onClick={() => handleStartTriage("llm")}
                disabled={startTriage.isPending}
                className="px-4 py-2 bg-primary/10 text-primary dark:bg-primary/20 rounded-lg hover:bg-primary/20 disabled:opacity-50 flex items-center gap-2"
              >
                <Brain className="h-4 w-4" />
                Run LLM Triage
              </button>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            {["baseline", "llm"].map((mode) => {
              const run = mode === "baseline" ? baselineRun : llmRun;
              const isRunning = run?.status === "running";
              const isCompleted = run?.status === "completed";

              return (
                <div key={mode} className="bg-card border border-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      {mode === "baseline" ? <Zap className="h-5 w-5 text-success" /> : <Brain className="h-5 w-5 text-primary" />}
                      <h3 className="font-semibold capitalize text-foreground">{mode} Triage</h3>
                      <span className={cn("px-2 py-0.5 text-xs rounded-full",
                        isRunning && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
                        isCompleted && "bg-success/10 text-success dark:bg-success/20",
                        run?.status === "failed" && "bg-destructive/10 text-destructive dark:bg-destructive/20",
                        run?.status === "pending" && "bg-muted text-muted-foreground"
                      )}>
                        {run?.status || "not run"}
                      </span>
                    </div>
                    {run && (
                      <span className="text-xs text-muted-foreground">
                        {run.completed_at ? formatRelativeTime(run.completed_at) : formatRelativeTime(run.created_at)}
                      </span>
                    )}
                  </div>

                  {run?.error && (
                    <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm">
                      Error: {run.error}
                    </div>
                  )}

                  {run?.results && run.results.length > 0 ? (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {run.results.map((result) => (
                        <TriageResultCard
                          key={result.finding_id}
                          result={result}
                          onToggle={() => setExpandedFinding(expandedFinding === result.finding_id ? null : result.finding_id)}
                          isExpanded={expandedFinding === result.finding_id}
                        />
                      ))}
                    </div>
                  ) : run?.status === "completed" ? (
                    <p className="text-muted-foreground text-sm">No findings to triage</p>
                  ) : (
                    <button
                      onClick={() => handleStartTriage(mode as TriageMode)}
                      disabled={startTriage.isPending}
                      className="w-full py-2 px-4 border border-border rounded-lg text-sm hover:bg-muted/50 disabled:opacity-50"
                    >
                      {isRunning ? "Running..." : "Run Triage"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {runsLoading && <div className="text-center text-muted-foreground">Loading triage runs...</div>}
        </div>
      ) : (
        <>
          {!compareData ? (
            <div className="text-center text-muted-foreground">Loading comparison...</div>
          ) : (
            <div className="space-y-6">
              <h2 className="text-xl font-semibold text-foreground">Baseline vs LLM Comparison</h2>

              <div className="grid gap-4 md:grid-cols-3">
                <StatCard label="Baseline Only" value={compareData.baseline_only.length} color="success" icon={Zap} />
                <StatCard label="LLM Only" value={compareData.llm_only.length} color="primary" icon={Brain} />
                <StatCard label="Changed Priority" value={compareData.changed_priority.length} color="warning" icon={RefreshCw} />
              </div>

              {compareData.changed_priority.length > 0 && (
                <div className="bg-card border border-border rounded-lg p-4">
                  <h3 className="font-semibold mb-4 text-foreground">Priority Changes</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-muted-foreground border-b border-border">
                          <th className="pb-2">Finding</th>
                          <th className="pb-2">Baseline</th>
                          <th className="pb-2">LLM</th>
                        </tr>
                      </thead>
                      <tbody>
                        {compareData.changed_priority.map((change) => (
                          <tr key={change.finding_id} className="border-b border-border">
                            <td className="py-2 font-mono text-foreground">{change.finding_id}</td>
                            <td className="py-2">{getPriorityLabel(change.baseline_priority)}</td>
                            <td className="py-2">{getPriorityLabel(change.llm_priority)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function TriageResultCard({ result, onToggle, isExpanded }: { result: TriageResult; onToggle: () => void; isExpanded: boolean }) {
  return (
    <div className="border border-border rounded-lg overflow-hidden bg-card">
      <button
        onClick={onToggle}
        className="w-full p-3 flex items-center justify-between hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <span className={cn("px-2 py-1 rounded-full text-xs font-medium", getSeverityColor(result.original_severity))}>
            {result.original_severity}
          </span>
          <div className="min-w-0">
            <p className="font-medium truncate text-foreground">{result.finding_title}</p>
            <p className="text-xs text-muted-foreground">
              Priority: {getPriorityLabel(result.revised_priority)} ({result.revised_priority}/5) •
              Exploitability: {result.exploitability}/5
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={cn("px-2 py-0.5 rounded-full text-xs", getSourceColor(result.source))}>
            {result.source}
          </span>
          <ChevronDown className={cn("h-4 w-4 text-muted-foreground transition-transform", isExpanded && "rotate-180")} />
        </div>
      </button>

      {isExpanded && (
        <div className="p-4 border-t border-border bg-muted/30 space-y-4">
          <div>
            <h4 className="font-medium mb-1 text-foreground">Explanation</h4>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">{result.explanation}</p>
          </div>
          <div>
            <h4 className="font-medium mb-1 text-foreground">Recommended Fix</h4>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">{result.fix}</p>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span>Prompt v{result.prompt_version}</span>
            <span>Finding: {result.finding_id}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color, icon: Icon }: { label: string; value: number; color: string; icon: React.ComponentType<{ className?: string }> }) {
  const colorMap: Record<string, string> = {
    success: "text-success",
    primary: "text-primary",
    warning: "text-yellow-600 dark:text-yellow-400",
  };

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <Icon className={cn("h-5 w-5", colorMap[color])} />
        <span className="text-sm font-medium text-muted-foreground">{label}</span>
      </div>
      <div className="text-3xl font-bold text-foreground">{value}</div>
    </div>
  );
}