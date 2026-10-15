"use client";

import { useMemo } from "react";
import { FindingResponse, SeverityLevel } from "@/types/api";
import { cn, getSeverityColor, getSeverityIcon, truncate, formatDate } from "@/lib/utils";
import { ChevronDown, ChevronUp, Search, Filter, X } from "lucide-react";
import { useState } from "react";

interface FindingsTableProps {
  findings: FindingResponse[];
  stats: Record<SeverityLevel, number>;
  onSort?: (key: keyof FindingResponse, direction: "asc" | "desc") => void;
}

const SORTABLE_COLUMNS = [
  { key: "severity", label: "Severity" },
  { key: "check", label: "Check" },
  { key: "title", label: "Title" },
  { key: "score", label: "Score" },
  { key: "confidence", label: "Confidence" },
] as const;

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

const SEVERITY_DISPLAY: Record<SeverityLevel, { label: string; icon: string }> = {
  Critical: { label: "Critical", icon: "🔴" },
  High: { label: "High", icon: "🟠" },
  Medium: { label: "Medium", icon: "🟡" },
  Low: { label: "Low", icon: "🔵" },
  Info: { label: "Info", icon: "⚪" },
};

export function FindingsTable({ findings, stats, onSort }: FindingsTableProps) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | "all">("all");
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [sortConfig, setSortConfig] = useState<{ key: keyof FindingResponse; direction: "asc" | "desc" } | null>({
    key: "severity",
    direction: "desc",
  });

  const severities: SeverityLevel[] = ["Critical", "High", "Medium", "Low", "Info"];
  const checks = useMemo(() => Array.from(new Set(findings.map((f) => f.check))), [findings]);

  const filteredFindings = useMemo(() => {
    let result = findings;

    if (search) {
      const lowerSearch = search.toLowerCase();
      result = result.filter(
        (f) =>
          f.title.toLowerCase().includes(lowerSearch) ||
          f.check.toLowerCase().includes(lowerSearch) ||
          f.id.toLowerCase().includes(lowerSearch)
      );
    }

    if (severityFilter !== "all") {
      result = result.filter((f) => f.severity === severityFilter);
    }

    if (checkFilter !== "all") {
      result = result.filter((f) => f.check === checkFilter);
    }

    if (sortConfig) {
      result = [...result].sort((a, b) => {
        if (sortConfig.key === "severity") {
          const aRank = SEVERITY_RANK[a.severity];
          const bRank = SEVERITY_RANK[b.severity];
          return sortConfig.direction === "asc" ? aRank - bRank : bRank - aRank;
        }
        const aVal = a[sortConfig.key];
        const bVal = b[sortConfig.key];
        if (aVal === undefined || bVal === undefined) return 0;
        if (aVal < bVal) return sortConfig.direction === "asc" ? -1 : 1;
        if (aVal > bVal) return sortConfig.direction === "asc" ? 1 : -1;
        return 0;
      });
    }

    return result;
  }, [findings, search, severityFilter, checkFilter, sortConfig]);

  const handleSort = (key: keyof FindingResponse) => {
    const direction: "asc" | "desc" =
      sortConfig?.key === key && sortConfig.direction === "asc" ? "desc" : "asc";
    setSortConfig({ key, direction });
    onSort?.(key, direction);
  };

  const SortIcon = ({ columnKey }: { columnKey: keyof FindingResponse }) => {
    if (sortConfig?.key !== columnKey) return <ChevronDown className="h-4 w-4 text-muted-foreground" />;
    return sortConfig.direction === "asc" ? (
      <ChevronUp className="h-4 w-4 text-primary" />
    ) : (
      <ChevronDown className="h-4 w-4 text-primary" />
    );
  };

  const hasFilters = search || severityFilter !== "all" || checkFilter !== "all";

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 p-4 bg-muted/50 border border-border rounded-lg">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings..."
            className="w-full pl-10 pr-4 py-2 border border-input bg-background focus:ring-2 focus:ring-ring focus:border-ring"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | "all")}
          className="px-4 py-2 border border-input bg-background focus:ring-2 focus:ring-ring focus:border-ring rounded-lg"
        >
          <option value="all">All Severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>
              {s} ({stats[s] || 0})
            </option>
          ))}
        </select>

        <select
          value={checkFilter}
          onChange={(e) => setCheckFilter(e.target.value)}
          className="px-4 py-2 border border-input bg-background focus:ring-2 focus:ring-ring focus:border-ring rounded-lg"
        >
          <option value="all">All Checks</option>
          {checks.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>

        {hasFilters && (
          <button
            onClick={() => {
              setSearch("");
              setSeverityFilter("all");
              setCheckFilter("all");
            }}
            className="flex items-center gap-2 px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full">
          <thead className="bg-muted/50">
            <tr>
              {SORTABLE_COLUMNS.map(({ key, label }) => (
                <th
                  key={key}
                  onClick={() => handleSort(key)}
                  className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider cursor-pointer hover:bg-muted select-none"
                >
                  <div className="flex items-center gap-1">
                    {label}
                    <SortIcon columnKey={key} />
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                  No findings match the current filters
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => {
                const severityInfo = SEVERITY_DISPLAY[finding.severity];
                return (
                  <tr key={finding.id} className="hover:bg-muted/50">
                    <td className="px-4 py-3">
                      <div className={cn("inline-flex items-center gap-2 px-3 py-2 rounded-lg font-medium text-sm", getSeverityColor(finding.severity))}>
                        <span className="text-lg">{severityInfo.icon}</span>
                        <span>{severityInfo.label}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-muted-foreground">{finding.check}</td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground truncate max-w-xs">{finding.title}</div>
                      <div className="text-xs text-muted-foreground truncate max-w-xs">{truncate(finding.evidence.url, 50)}</div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">{finding.score}</td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">{(finding.confidence * 100).toFixed(0)}%</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>
          Showing {filteredFindings.length} of {findings.length} findings
        </span>
      </div>
    </div>
  );
}