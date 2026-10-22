#!/usr/bin/env node
/**
 * injectcheck CLI.
 *
 *   injectcheck scan [path] [--json]   scan a directory (default: .)
 *   injectcheck file <path> [--json]   scan a single file
 *   injectcheck mcp                    run the stdio MCP server
 *   injectcheck --version
 *
 * Exit codes: 0 CLEAN, 1 FINDINGS or REVIEW, 2 usage or setup error,
 * 141 when the reader closed the output pipe before the report was
 * delivered (the shell-visible equivalent of death by SIGPIPE).
 * A CLEAN verdict means no deterministic pattern matched. It never means
 * the content is proven safe.
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect. Calling process.exit() right after
 * console.log() truncates piped output once it passes one pipe buffer
 * (64 KiB on Linux), which is validation problem P-021 (the same factory
 * emit bug as actionpin P-001 and hookcheck P-017): agents, scripts, and
 * CI read through pipes, so they are exactly the consumers that were
 * silently handed a corrupt prefix of the report.
 */
import { readFileSync } from "node:fs";
import { makeReport, renderReport, scanPath, scanText, VERSION } from "./scan.js";

function exitBrokenPipe(): never {
  // The reader closed the pipe before the report was delivered. A Unix
  // writer in this position dies from SIGPIPE; exit 141 (128 + 13) is the
  // equivalent a shell reports, and it guarantees an undelivered report is
  // never mistaken for a successful run.
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

function usage(): never {
  console.error(`Usage:
  injectcheck scan [path] [--json]
  injectcheck file <path> [--json]
  injectcheck mcp
  injectcheck --version`);
  process.exit(2);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  const asJson = rest.includes("--json");
  const positional = rest.filter((a) => !a.startsWith("--"));
  try {
    if (cmd === "scan") {
      const report = scanPath(positional[0] ?? ".");
      await emit(asJson ? JSON.stringify(report, null, 2) : renderReport(report), report.verdict === "CLEAN" ? 0 : 1);
    } else if (cmd === "file") {
      if (!positional[0]) usage();
      let text: string;
      try {
        text = readFileSync(positional[0], "utf8");
      } catch {
        console.error(`error: file does not exist or is not readable: ${positional[0]}`);
        process.exitCode = 2;
        return;
      }
      const report = makeReport(positional[0], 1, scanText(text, positional[0]));
      await emit(asJson ? JSON.stringify(report, null, 2) : renderReport(report), report.verdict === "CLEAN" ? 0 : 1);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
