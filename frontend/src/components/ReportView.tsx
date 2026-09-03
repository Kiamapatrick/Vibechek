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

  const handleCopy = async () => {
    if (typeof report === "string") {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (typeof report === "string") {
      const blob = new Blob([report], { type: format === "json" ? "application/json" : "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vibeshield-report-${scanId.slice(0, 8)}.${format === "json" ? "json" : "txt"}`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  if (isLoading) {
    return <div className="flex items-center justify-center h-64">Loading report...</div>;
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300">
        Failed to load report
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div className="flex gap-2 border rounded-lg p-1 bg-gray-100 dark:bg-gray-800">
          {(["plain", "json", "both"] as ReportFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={cn(
                "px-4 py-2 rounded-md text-sm font-medium transition-colors",
                format === f
                  ? "bg-white dark:bg-gray-700 shadow-sm"
                  : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
              )}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <button onClick={handleCopy} className="flex items-center gap-2 px-3 py-2 border rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-sm">
            <Copy className="h-4 w-4" />
            {copied ? <Check className="h-4 w-4 text-green-500" /> : "Copy"}
          </button>
          <button onClick={handleDownload} className="flex items-center gap-2 px-3 py-2 border rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-sm">
            <Download className="h-4 w-4" />
            Download
          </button>
        </div>
      </div>

      <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
        {format === "plain" && typeof report === "string" && (
          <pre className="p-4 font-mono text-sm text-gray-100 overflow-x-auto max-h-[600px]">{report}</pre>
        )}
        {format === "json" && typeof report === "object" && (
          <pre className="p-4 font-mono text-sm text-gray-100 overflow-x-auto max-h-[600px]">
            {JSON.stringify(report, null, 2)}
          </pre>
        )}
        {format === "both" && (
          <div className="grid md:grid-cols-2 gap-4 p-4">
            <div>
              <h4 className="font-medium mb-2 text-gray-400">Plain Text</h4>
              <pre className="p-4 font-mono text-sm text-gray-100 overflow-x-auto max-h-[500px] bg-gray-800 rounded">
                {typeof report === "object" && "plain" in report ? report.plain : "N/A"}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-2 text-gray-400">JSON</h4>
              <pre className="p-4 font-mono text-sm text-gray-100 overflow-x-auto max-h-[500px] bg-gray-800 rounded">
                {typeof report === "object" && "json" in report ? JSON.stringify(report.json, null, 2) : "N/A"}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}