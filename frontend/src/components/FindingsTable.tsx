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

export function FindingsTable({ findings, stats }: FindingsTableProps) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | "all">("all");
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [sortConfig, setSortConfig] = useState<{ key: keyof FindingResponse; direction: "asc" | "desc" } | null>({
    key: "severity",
    direction: "desc",
  });

  const severities: SeverityLevel[] = ["Critical", "High", "Medium", "Low", "Info"];
  const checks = useMemo(() => [...new Set(findings.map((f) => f.check))], [findings]);

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
        const aVal = a[sortConfig.key];
        const bVal = b[sortConfig.key];
        if (aVal < bVal) return sortConfig.direction === "asc" ? -1 : 1;
        if (aVal > bVal) return sortConfig.direction === "asc" ? 1 : -1;
        return 0;
      });
    }

    return result;
  }, [findings, search, severityFilter, checkFilter, sortConfig]);

  const handleSort = (key: keyof FindingResponse) => {
    setSortConfig((current) => ({
      key,
      direction: current?.key === key && current.direction === "asc" ? "desc" : "asc",
    }));
  };

  const SortIcon = ({ key }: { key: keyof FindingResponse }) => {
    if (sortConfig?.key !== key) return <ChevronDown className="h-4 w-4 text-gray-400" />;
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
      <div className="flex flex-col sm:flex-row gap-4 p-4 bg-card border rounded-lg">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings..."
            className="w-full pl-10 pr-4 py-2 border rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-primary"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | "all")}
          className="px-4 py-2 border rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-primary"
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
          className="px-4 py-2 border rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-primary"
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
            className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
          >
            <X className="h-4 w-4" />
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              {[
                { key: "severity", label: "Severity" },
                { key: "check", label: "Check" },
                { key: "title", label: "Title" },
                { key: "score", label: "Score" },
                { key: "confidence", label: "Confidence" },
              ].map(({ key, label }) => (
                <th
                  key={key}
                  onClick={() => handleSort(key)}
                  className="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700/50 select-none"
                >
                  <div className="flex items-center gap-1">
                    {label}
                    <SortIcon key={key} />
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  No findings match the current filters
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => (
                <tr key={finding.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <td className="px-4 py-3">
                    <span className={cn("inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium", getSeverityColor(finding.severity))}>
                      {getSeverityIcon(finding.severity)} {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-gray-600 dark:text-gray-400">
                    {finding.check}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900 dark:text-gray-100 truncate max-w-xs">
                      {finding.title}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
                      {truncate(finding.evidence.url, 50)}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    {finding.score}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    {(finding.confidence * 100).toFixed(0)}%
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400">
        <span>
          Showing {filteredFindings.length} of {findings.length} findings
        </span>
      </div>
    </div>
  );
}