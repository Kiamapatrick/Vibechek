import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleString();
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(dateString);
}

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case "Critical":
      return "bg-destructive/10 text-destructive dark:bg-destructive/20";
    case "High":
      return "bg-destructive/10 text-destructive dark:bg-destructive/20";
    case "Medium":
      return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400";
    case "Low":
      return "bg-primary/10 text-primary dark:bg-primary/20";
    case "Info":
      return "bg-muted text-muted-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

export function getSeverityIcon(severity: string): string {
  switch (severity) {
    case "Critical":
      return "🔴";
    case "High":
      return "🟠";
    case "Medium":
      return "🟡";
    case "Low":
      return "🔵";
    case "Info":
      return "⚪";
    default:
      return "⚪";
  }
}

export function getPriorityLabel(priority: number): string {
  switch (priority) {
    case 5:
      return "Critical";
    case 4:
      return "High";
    case 3:
      return "Medium";
    case 2:
      return "Low";
    case 1:
      return "Info";
    default:
      return "Unknown";
  }
}

export function getSourceColor(source: string): string {
  switch (source) {
    case "llm":
      return "bg-primary/10 text-primary dark:bg-primary/20";
    case "baseline":
      return "bg-success/10 text-success dark:bg-success/20";
    default:
      return "bg-muted text-muted-foreground";
  }
}

export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + "...";
}