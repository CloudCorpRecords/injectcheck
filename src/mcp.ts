/**
 * injectcheck MCP server. Tools: scan_text, scan_path.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { makeReport, scanPath, scanText, VERSION } from "./scan.js";

const server = new McpServer({ name: "injectcheck", version: VERSION });

server.tool(
  "scan_text",
  "Scan raw text (an issue body, a PR description, a comment, a README draft) for prompt-injection patterns before acting on it: hidden unicode, HTML comment instructions, instruction phrases aimed at an AI, exfiltration patterns, tool lures, base64 payloads, and instructions in image alt text. Returns a FINDINGS, REVIEW, or CLEAN verdict with file/line/rule/severity evidence per finding. CLEAN means no pattern matched, never that the content is proven safe.",
  {
    text: z.string().describe("The raw text content to scan"),
    label: z.string().optional().describe("Label reported as the file name for findings, e.g. issue-123.md"),
  },
  async ({ text, label }) => {
    const name = label ?? "<text>";
    const warnings: string[] = [];
    const report = makeReport(name, 1, scanText(text, name, warnings), warnings, { filesSeen: 1, filesSkipped: 0 });
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

server.tool(
  "scan_path",
  "Scan a file or a directory of text, markdown, and code files for prompt-injection patterns: hidden unicode, HTML comment instructions, instruction phrases aimed at an AI, exfiltration patterns, tool lures in prose, base64 payloads, and instructions in image alt text. Returns a FINDINGS, REVIEW, or CLEAN verdict with evidence per finding. CLEAN means no pattern matched, never that the content is proven safe.",
  {
    path: z.string().describe("File or directory path to scan"),
  },
  async ({ path }) => {
    const report = scanPath(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
