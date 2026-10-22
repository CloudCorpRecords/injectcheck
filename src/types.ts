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
  /**
   * Number of candidate text files the scan saw in the target
   * (P-079): filesScanned plus filesSkipped. For a single file or raw
   * text this is 1. Scanned versus seen is stated honestly instead
   * of letting filesScanned silently stand for the whole estate.
   */
  filesSeen: number;
  /**
   * Number of seen files that were not scanned (P-079): files over
   * the per-file size cap, files beyond the file count cap, binary
   * files with a text extension, and unreadable files. Every skipped
   * file is also named or counted in warnings.
   */
  filesSkipped: number;
  findings: Finding[];
  counts: Record<Severity, number>;
  /**
   * Scan completeness warnings (P-056, mirroring hookcheck P-049;
   * extended by P-079): a file or directory that could not be read,
   * a file skipped over the size cap, files beyond the count cap,
   * and any other truncation of the scan are reported here instead
   * of being silently skipped, in JSON and human output alike. When
   * any warning is present the scan is partial, and a CLEAN verdict
   * is floored to REVIEW: a partial scan must not present as a
   * complete clean one.
   */
  warnings: string[];
  scannedAt: string;
}

export interface ScanOptions {
  /**
   * Skip files larger than this many bytes, with a warning naming
   * each skipped file (P-079). Default 5 MiB (5,242,880 bytes),
   * raised from 1 MiB in v0.1.9 after measurement: a file of about
   * 3.5 MB scans in about a second, and about 8.8 MB in about two
   * seconds, with the shipped matchers.
   */
  maxFileBytes?: number;
  /**
   * Stop after this many files, with a warning counting the files
   * not scanned (P-079). Default 20000, raised from 5000 in v0.1.9
   * after measurement: traversal and scanning of a 10,002-file tree
   * completes in seconds; the old cap truncated it silently.
   */
  maxFiles?: number;
}
