"use client";

import { useEffect, useRef, useState } from "react";
import { UUID } from "@/types/api";
import { cn, formatRelativeTime } from "@/lib/utils";
import { Loader2, CheckCircle, AlertCircle, XCircle, Info, AlertTriangle, Terminal, Wifi, WifiOff } from "lucide-react";

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
  info: "text-primary",
  warning: "text-yellow-600 dark:text-yellow-400",
  error: "text-destructive",
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

    eventSource.addEventListener("timeout", (event) => {
      const data = JSON.parse(event.data);
      setLogs((prev) => [...prev, { timestamp: new Date().toISOString(), level: "error", message: data.message, stage: "scan" }]);
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
      <div className="h-64 flex items-center justify-center text-muted-foreground bg-muted/30 rounded-lg border border-border">
        <Terminal className="h-12 w-12 opacity-50" />
        <p className="ml-4">Start a scan to see live progress</p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden h-64 flex flex-col">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border bg-muted/50">
        <Terminal className="h-4 w-4 text-primary" />
        <span className="font-medium text-sm text-foreground">Live Progress</span>
        <span className={cn("ml-2 px-2 py-0.5 text-xs rounded-full", connected ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive")}>
          {connected ? <Wifi className="h-3 w-3 mr-1" /> : <WifiOff className="h-3 w-3 mr-1" />}
          {connected ? "Connected" : "Disconnected"}
        </span>
        {isActive && (
          <Loader2 className="ml-auto h-4 w-4 animate-spin text-primary" />
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-sm">
        {logs.length === 0 && (
          <div className="text-muted-foreground text-center py-8">Waiting for progress updates...</div>
        )}
        {logs.map((log, index) => {
          const LevelIcon = LEVEL_ICONS[log.level] || Info;
          const StageIcon = log.stage ? STAGE_ICONS[log.stage] || STAGE_ICONS.default : null;

          return (
            <div key={index} className="flex items-start gap-2 text-foreground/80 hover:text-foreground transition-colors">
              <span className="text-muted-foreground shrink-0">{formatRelativeTime(log.timestamp)}</span>
              <LevelIcon className={cn("h-3.5 w-3.5 shrink-0 mt-0.5", LEVEL_COLORS[log.level])} aria-hidden="true" />
              {StageIcon && <StageIcon className="h-3.5 w-3.5 shrink-0 mt-0.5 text-muted-foreground" aria-hidden="true" />}
              <span className="flex-1 truncate">{log.message}</span>
            </div>
          );
        })}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}