"use client";

import { useEffect, useRef, useState } from "react";
import { UUID } from "@/types/api";
import { cn, formatRelativeTime } from "@/lib/utils";
import { Loader2, CheckCircle, AlertCircle, XCircle, Info, AlertTriangle, Terminal } from "lucide-react";

interface ProgressLogProps {
  scanId: UUID;
  isActive: boolean;
}

const STAGE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  scan: Terminal,
  recon: Terminal,
  crawl: Globe,
  check: AlertTriangle,
  triage: Info,
  default: Info,
};

const LEVEL_ICONS = {
  info: Info,
  warning: AlertTriangle,
  error: AlertCircle,
};

const LEVEL_COLORS = {
  info: "text-blue-600 dark:text-blue-400",
  warning: "text-yellow-600 dark:text-yellow-400",
  error: "text-red-600 dark:text-red-400",
};

function Globe({ className }: { className?: string }) {
  return <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>;
}

interface LogEntry {
  timestamp: string;
  level: "info" | "warning" | "error";
  message: string;
  stage?: string;
}

export function ProgressLog({ scanId, isActive }: ProgressLogProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isActive || !scanId) return;

    const eventSource = new EventSource(`/api/scans/${scanId}/progress`);
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      setConnected(true);
    };

    eventSource.addEventListener("progress", (event) => {
      const data = JSON.parse(event.data);
      setLogs((prev) => [...prev, data]);
    });

    eventSource.addEventListener("complete", (event) => {
      const data = JSON.parse(event.data);
      setLogs((prev) => [...prev, { timestamp: new Date().toISOString(), level: data.status === "completed" ? "info" : "error", message: `Scan ${data.status}`, stage: "scan" }]);
      eventSource.close();
      setConnected(false);
    });

    eventSource.onerror = () => {
      setConnected(false);
      eventSource.close();
    };

    return () => {
      eventSource.close();
      setConnected(false);
    };
  }, [scanId, isActive]);

  // Auto-scroll to bottom
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (!isActive && logs.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500 dark:text-gray-400">
        <Terminal className="h-12 w-12 opacity-50" />
        <p className="ml-4">Start a scan to see live progress</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden h-64 flex flex-col">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-700 bg-gray-800">
        <Terminal className="h-4 w-4 text-green-400" />
        <span className="font-mono text-sm text-gray-300">Live Progress</span>
        <span className={cn("ml-2 px-2 py-0.5 text-xs rounded-full", connected ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400")}>
          {connected ? "● Connected" : "○ Disconnected"}
        </span>
        {isActive && (
          <Loader2 className="ml-auto h-4 w-4 animate-spin text-primary" />
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-sm">
        {logs.length === 0 && (
          <div className="text-gray-500 text-center py-8">Waiting for progress updates...</div>
        )}
        {logs.map((log, index) => {
          const LevelIcon = LEVEL_ICONS[log.level] || Info;
          const StageIcon = log.stage ? STAGE_ICONS[log.stage] || STAGE_ICONS.default : null;

          return (
            <div key={index} className="flex items-start gap-2 text-gray-300 hover:text-gray-100 transition-colors">
              <span className="text-gray-500 shrink-0">{formatRelativeTime(log.timestamp)}</span>
              <LevelIcon className={cn("h-3.5 w-3.5 shrink-0 mt-0.5", LEVEL_COLORS[log.level])} />
              {StageIcon && <StageIcon className="h-3.5 w-3.5 shrink-0 mt-0.5 text-gray-500" />}
              <span className="flex-1 truncate">{log.message}</span>
            </div>
          );
        })}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}