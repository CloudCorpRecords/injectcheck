/**
 * injectcheck types.
 *
 * A ScanReport is the result of scanning text content (a directory, a single
 * file, or a raw string) for prompt-injection patterns: content written to
 * manipulate an AI agent that later reads it. Every Finding carries the
 * evidence: file, line, rule id, severity, and a short excerpt. A report
 * never claims content is safe; CLEAN means only that no pattern matched.
 */

export type Severity = "high" | "medium" | "low";

export type Verdict = "FINDINGS" | "REVIEW" | "CLEAN";

export interface Finding {
  /** Source label: a file path, or the label passed for raw text. */
  file: string;
  /** 1-based line number within the file or text. */
  line: number;
  /** Stable rule id, e.g. "hidden-unicode", "exfil-pattern". */
  rule: string;
  severity: Severity;
  /** Short excerpt of the matched content, truncated to 120 chars. */
  excerpt: string;
  /** One-line explanation of what matched and why it matters. */
  detail: string;
}

export interface ScanReport {
  /** What was scanned: a path, or a label for raw text. */
  target: string;
  verdict: Verdict;
  /** Number of files scanned (1 for a single file or raw text). */
  filesScanned: number;
  findings: Finding[];
  counts: Record<Severity, number>;
  scannedAt: string;
}

export interface ScanOptions {
  /** Skip files larger than this many bytes. Default 1 MB. */
  maxFileBytes?: number;
  /** Stop after this many files. Default 5000. */
  maxFiles?: number;
}
