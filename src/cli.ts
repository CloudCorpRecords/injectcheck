#!/usr/bin/env node
/**
 * injectcheck CLI.
 *
 *   injectcheck scan [path] [--json]   scan a directory (default: .)
 *   injectcheck file <path> [--json]   scan a single file
 *   injectcheck mcp                    run the stdio MCP server
 *   injectcheck --version
 *
 * Exit codes: 0 CLEAN, 1 FINDINGS or REVIEW, 2 usage or setup error.
 * A CLEAN verdict means no deterministic pattern matched. It never means
 * the content is proven safe.
 */
import { readFileSync } from "node:fs";
import { makeReport, renderReport, scanPath, scanText, VERSION } from "./scan.js";

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
      console.log(asJson ? JSON.stringify(report, null, 2) : renderReport(report));
      process.exit(report.verdict === "CLEAN" ? 0 : 1);
    } else if (cmd === "file") {
      if (!positional[0]) usage();
      let text: string;
      try {
        text = readFileSync(positional[0], "utf8");
      } catch {
        console.error(`error: file does not exist or is not readable: ${positional[0]}`);
        process.exit(2);
      }
      const report = makeReport(positional[0], 1, scanText(text, positional[0]));
      console.log(asJson ? JSON.stringify(report, null, 2) : renderReport(report));
      process.exit(report.verdict === "CLEAN" ? 0 : 1);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}

void main();
