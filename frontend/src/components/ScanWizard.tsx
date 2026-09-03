"use client";

import { useState } from "react";
import { useStartScan } from "@/hooks/useApi";
import { useRouter } from "next/navigation";
import { Globe, AlertCircle, CheckCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export function ScanWizard() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(20);
  const [maxDepth, setMaxDepth] = useState(2);
  const [timeout, setTimeout] = useState(10);
  const [allowWriteTests, setAllowWriteTests] = useState(false);
  const [error, setError] = useState("");

  const { mutate: startScan, isPending } = useStartScan();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      const newScan = await startScan({
        url,
        max_pages: maxPages,
        max_depth: maxDepth,
        timeout,
        allow_write_tests: allowWriteTests,
      });
      router.push(`/scan/${newScan.scan_id}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to start scan";
      setError(message);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <label htmlFor="url" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Target URL
        </label>
        <div className="relative">
          <Globe className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 h-5 w-5" />
          <input
            id="url"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className={cn(
              "w-full pl-10 pr-4 py-3 border rounded-lg",
              "bg-white dark:bg-gray-800",
              "focus:ring-2 focus:ring-primary focus:border-transparent",
              "placeholder:text-gray-400"
            )}
          />
        </div>
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          Must include http:// or https://
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label htmlFor="maxPages" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Max Pages
          </label>
          <input
            id="maxPages"
            type="number"
            value={maxPages}
            onChange={(e) => setMaxPages(Math.max(1, Math.min(1000, parseInt(e.target.value) || 1)))}
            min="1"
            max="1000"
            className={cn(
              "w-full px-4 py-3 border rounded-lg",
              "bg-white dark:bg-gray-800",
              "focus:ring-2 focus:ring-primary focus:border-transparent"
            )}
          />
        </div>

        <div>
          <label htmlFor="maxDepth" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Max Depth
          </label>
          <input
            id="maxDepth"
            type="number"
            value={maxDepth}
            onChange={(e) => setMaxDepth(Math.max(0, Math.min(10, parseInt(e.target.value) || 0)))}
            min="0"
            max="10"
            className={cn(
              "w-full px-4 py-3 border rounded-lg",
              "bg-white dark:bg-gray-800",
              "focus:ring-2 focus:ring-primary focus:border-transparent"
            )}
          />
        </div>

        <div>
          <label htmlFor="timeout" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Timeout (seconds)
          </label>
          <input
            id="timeout"
            type="number"
            value={timeout}
            onChange={(e) => setTimeout(Math.max(1, Math.min(300, parseInt(e.target.value) || 1)))}
            min="1"
            max="300"
            className={cn(
              "w-full px-4 py-3 border rounded-lg",
              "bg-white dark:bg-gray-800",
              "focus:ring-2 focus:ring-primary focus:border-transparent"
            )}
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <input
          id="allowWriteTests"
          type="checkbox"
          checked={allowWriteTests}
          onChange={(e) => setAllowWriteTests(e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
        />
        <label htmlFor="allowWriteTests" className="text-sm text-gray-700 dark:text-gray-300">
          Allow write tests (may create test data on target)
        </label>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <AlertCircle className="h-5 w-5 text-red-500" />
          <span className="text-sm text-red-700 dark:text-red-300">{error}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={isPending || !url}
        className={cn(
          "w-full py-3 px-4 rounded-lg font-medium transition-colors",
          "focus:ring-2 focus:ring-primary focus:ring-offset-2",
          isPending || !url
            ? "bg-gray-300 text-gray-500 cursor-not-allowed dark:bg-gray-600"
            : "bg-primary text-primary-foreground hover:bg-primary/90"
        )}
      >
        {isPending ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Starting scan...
          </span>
        ) : (
          <span className="flex items-center justify-center gap-2">
            <CheckCircle className="h-5 w-5" />
            Start Scan
          </span>
        )}
      </button>
    </form>
  );
}