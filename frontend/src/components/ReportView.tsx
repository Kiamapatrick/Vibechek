"use client";

import { useState } from "react";
import { useReport } from "@/hooks/useApi";
import { UUID, ReportFormat } from "@/types/api";
import { cn, formatDate } from "@/lib/utils";
import { FileText, Download, Copy, Check } from "lucide-react";

interface ReportViewProps {
  scanId: UUID;
}

export function ReportView({ scanId }: ReportViewProps) {
  const [format, setFormat] = useState<ReportFormat>("plain");
  const [copied, setCopied] = useState(false);

  const { data: report, isLoading, error } = useReport(scanId, format);

  const getReportText = (): string | null => {
    if (typeof report === "string") return report;
    if (format === "json" && typeof report === "object" && report !== null) {
      return JSON.stringify(report, null, 2);
    }
    if (format === "both" && typeof report === "object" && report !== null && "plain" in report && "json" in report) {
      const r = report as Record<string, unknown>;
      return `${r.plain}\n\n---\n\n${JSON.stringify(r.json, null, 2)}`;
    }
    return null;
  };

  const handleCopy = async () => {
    const text = getReportText();
    if (text) {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    const text = getReportText();
    if (text) {
      const blob = new Blob([text], { type: format === "json" ? "application/json" : "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vibeshield-report-${scanId.slice(0, 8)}.${format === "json" ? "json" : "txt"}`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-muted-foreground">Loading report...</div>;
  }

  if (error) {
    return (
      <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
        Failed to load report
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div className="flex gap-2 border border-border rounded-lg p-1 bg-muted/50">
          {(["plain", "json", "both"] as ReportFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={cn(
                "px-4 py-2 rounded-md text-sm font-medium transition-colors",
                format === f
                  ? "bg-background shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <button onClick={handleCopy} className="flex items-center gap-2 px-3 py-2 border border-border rounded-lg hover:bg-muted/50 text-sm">
            <Copy className="h-4 w-4" />
            {copied ? <Check className="h-4 w-4 text-success" /> : "Copy"}
          </button>
          <button onClick={handleDownload} className="flex items-center gap-2 px-3 py-2 border border-border rounded-lg hover:bg-muted/50 text-sm">
            <Download className="h-4 w-4" />
            Download
          </button>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        {format === "plain" && typeof report === "string" && (
          <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto max-h-[600px]">{report}</pre>
        )}
        {format === "json" && typeof report === "object" && (
          <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto max-h-[600px]">
            {JSON.stringify(report, null, 2)}
          </pre>
        )}
        {format === "both" && (
          <div className="grid md:grid-cols-2 gap-4 p-4">
            <div>
              <h4 className="font-medium mb-2 text-muted-foreground">Plain Text</h4>
              <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto max-h-[500px] bg-muted/30 rounded">
                {typeof report === "object" && report !== null && "plain" in report ? (report as Record<string, unknown>).plain as string : "N/A"}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-2 text-muted-foreground">JSON</h4>
              <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto max-h-[500px] bg-muted/30 rounded">
                {typeof report === "object" && report !== null && "json" in report ? JSON.stringify((report as Record<string, unknown>).json, null, 2) : "N/A"}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}