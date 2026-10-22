/**
 * injectcheck core: deterministic prompt-injection scanning for content an
 * AI agent will read (issues, PR bodies, READMEs, comments, docs).
 *
 * Seven rules, each with a stable id:
 *   hidden-unicode            zero-width, bidi, tag, variation-selector chars
 *   html-comment-instruction  HTML comments carrying instruction language
 *   instruction-phrase        direct instruction phrases aimed at an AI
 *   exfil-pattern             send/post/upload verbs near credential nouns
 *   tool-lure                 shell/install lures in non-code prose files
 *   base64-blob               base64 that decodes to instruction-like text
 *   alt-text-instruction      instruction language in image alt / link titles
 *
 * Design rules:
 * - Deterministic patterns only. No model, no network.
 * - Documentation ABOUT prompt injection must not verdict FINDINGS: the
 *   patterns require actual imperative/instruction phrasing, and negated
 *   exfil language ("never send your password") is downgraded to low.
 * - A report never claims content is safe. CLEAN means no pattern matched.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import type { Finding, ScanOptions, ScanReport, Severity, Verdict } from "./types.js";

export const VERSION = "0.1.0";

export const RULES = [
  "hidden-unicode",
  "html-comment-instruction",
  "instruction-phrase",
  "exfil-pattern",
  "tool-lure",
  "base64-blob",
  "alt-text-instruction",
] as const;

/** File extensions treated as agent-read text content. */
export const TEXT_EXTENSIONS = new Set([
  ".md", ".markdown", ".mdx", ".txt", ".rst", ".text",
  ".html", ".htm",
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go",
  ".rs", ".java", ".c", ".h", ".cpp", ".sh", ".bash", ".zsh",
  ".yml", ".yaml", ".toml", ".json", ".xml", ".csv",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
]);

const PROSE_EXTENSIONS = new Set([".md", ".markdown", ".mdx", ".txt", ".rst", ".text", ".html", ".htm"]);

const MAX_BLOB_CHARS = 8192;
const MAX_DECODED_CHARS = 10000;

function excerpt(text: string): string {
  const clean = text.replace(/\s+/g, " ").trim();
  return clean.length > 120 ? clean.slice(0, 117) + "..." : clean;
}

/* ------------------------------------------------------------------ */
/* Instruction language                                                */
/* ------------------------------------------------------------------ */

/** Strong phrases: near-certain injection intent when aimed at a reader AI. */
const STRONG_PHRASES: Array<{ re: RegExp; label: string }> = [
  { re: /\bignore\s+(all\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|directions?|prompts?|context|rules?)\b/i, label: "ignore previous instructions" },
  { re: /\bdisregard\s+(the\s+|all\s+)?(above|previous|prior|earlier|preceding|instructions?|directions?)\b/i, label: "disregard the above" },
  { re: /\bforget\s+(your\s+|all\s+|the\s+)?(previous\s+|prior\s+)?(instructions?|directions?|training|rules?)\b/i, label: "forget your instructions" },
  { re: /\byou\s+are\s+now\s+(a|an|in|acting|no\s+longer)\b/i, label: "you are now" },
  { re: /\bnew\s+instructions?\s*:/i, label: "new instructions:" },
  { re: /\b(override|bypass|overwrite)\s+(your\s+|the\s+|all\s+)?(previous\s+|prior\s+)?(instructions?|system\s+prompt|rules?|safety|guardrails?)\b/i, label: "override instructions" },
  { re: /\bdo\s+not\s+(tell|inform|notify|mention\s+(this\s+)?to|reveal\s+this\s+to|alert)\s+(the\s+)?(user|human|owner|developer)\b/i, label: "do not tell the user" },
  { re: /\b(system|developer)\s+(prompt|message)\s*:\s/i, label: "fake system/developer prompt header" },
  { re: /\bact\s+as\s+(if\s+you\s+(are|were)|a\s+different|an?\s+unrestricted)\b/i, label: "act as a different agent" },
  { re: /\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?(user|human|owner)\b/i, label: "act without telling the user" },
];

/** Softer instruction language aimed second-person at an AI reader. */
const SOFT_PHRASES: Array<{ re: RegExp; label: string }> = [
  { re: /\b(attention|note|important)\s*[:,!]?\s*(ai|llm|agent|assistant|chatbot|language\s+model)\b/i, label: "direct address to an AI" },
  { re: /\b(dear|hello|hey)\s+(ai|llm|agent|assistant|chatbot)\b/i, label: "direct address to an AI" },
  { re: /\b(ai|llm|agent|assistant|chatbot|language\s+model)\s*[:,]?\s+(please\s+)?(ignore|disregard|run|execute|send|post|upload|reveal|output|print|follow)\b/i, label: "imperative addressed to an AI" },
  { re: /\byou\s+must\s+(now\s+)?(run|execute|send|post|upload|reveal|output|print|fetch|download|install|call)\b/i, label: "you must <action>" },
  { re: /\bwhen\s+you\s+(read|see|process)\s+this\b[^.\n]{0,60}\b(run|execute|send|ignore|follow)\b/i, label: "when you read this, act" },
];

/**
 * Match instruction language in a text fragment.
 * Returns the strongest severity found, or null.
 */
export function matchInstructionLanguage(text: string): { severity: Severity; label: string } | null {
  for (const { re, label } of STRONG_PHRASES) {
    if (re.test(text)) return { severity: "high", label };
  }
  for (const { re, label } of SOFT_PHRASES) {
    if (re.test(text)) return { severity: "medium", label };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Exfiltration patterns                                               */
/* ------------------------------------------------------------------ */

const EXFIL_VERB = /\b(send|post|upload|leak|exfiltrate|forward|transmit|email|share|submit|reveal|dump|publish)\b/i;
const EXFIL_NOUN = /(credentials?|secrets?|tokens?|api[\s_-]?keys?|private\s+keys?|passwords?|\.env\b|~\/\.ssh|id_rsa|aws[_ ]?(credentials?|access)|env(ironment)?\s+variables?|\.npmrc|\.aws\b|ssh\s+keys?|auth\s+tokens?|session\s+cookies?)/i;
const NEGATION = /\b(never|do\s+not|don'?t|must\s+not|should\s+not|avoid|refuse\s+to|not)\s+[^.\n]{0,30}$/i;

/**
 * Documentation context: a line that talks ABOUT the patterns (rule tables,
 * detector descriptions, quoted example phrases) rather than issuing them.
 * Hits in doc context are downgraded to low: visible, never blocking.
 */
const DOC_CONTEXT = /\b(rules?|patterns?|phrases?|verbs?|nouns?|such as|e\.g\.|detects?|detection|scans? for|scanning for|flags?|flagged|signatures?|criteria|shorthand|known-safe|risky|classifies)\b|\bexamples?(?=[\s:,)]|$)/i;

/** Strong meta markers: the line is unmistakably talking about the patterns. */
const STRONG_DOC_CONTEXT = /\b(patterns?|phrases?|such as|e\.g\.|detects?|detection|scans? for|scanning for|signatures?|shorthand|classifies)\b|\bexamples?(?=[\s:,)]|$)/i;

export function isDocContext(line: string): boolean {
  return DOC_CONTEXT.test(line);
}

/**
 * Whether an instruction phrase on this line is documentation quoting the
 * phrase rather than issuing it: a strong meta marker is present, or a
 * weaker marker appears alongside an actual quotation mark.
 */
export function isQuotedDocContext(line: string): boolean {
  return STRONG_DOC_CONTEXT.test(line) || (DOC_CONTEXT.test(line) && line.includes('"'));
}

function matchExfil(line: string): { severity: Severity; detail: string } | null {
  const verb = EXFIL_VERB.exec(line);
  const noun = EXFIL_NOUN.exec(line);
  if (!verb || !noun) return null;
  const distance = Math.abs(verb.index - noun.index);
  // Window: verb and noun within 80 chars, or the classic
  // "send the contents of X" shape anywhere on the line.
  const contentsOf = /\b(send|post|upload|share|reveal|output|print)\s+(me\s+)?(the\s+)?(full\s+)?contents?\s+of\b/i.test(line);
  if (distance > 80 && !contentsOf) return null;
  // Negated safety advice ("never send your credentials") is documentation,
  // not an instruction to exfiltrate. Report at low so it stays visible.
  const before = line.slice(0, Math.max(verb.index, noun.index));
  if (NEGATION.test(before) || /\b(never|do\s+not|don'?t|must\s+not|should\s+not)\b/i.test(line.slice(0, verb.index + verb[0].length + 4))) {
    return { severity: "low", detail: "Exfil verb near a credential noun, but phrased as a negation (safety advice shape)" };
  }
  // Documentation that describes exfil patterns (detector docs, incident
  // writeups quoting the phrases) is not itself an instruction.
  if (isDocContext(line)) {
    return { severity: "low", detail: `Exfil verb "${verb[0]}" near credential noun "${noun[0]}", but in documentation context (describing the pattern, not issuing it)` };
  }
  // Directive shape decides high vs narrative: an imperative at the start of
  // a sentence or clause, a "contents of" request, an explicit please /
  // you-must marker, or a URL destination. Third-person narrative about an
  // attack ("attackers upload secrets to public repos") is a description,
  // not an instruction to the reader, and is reported at low (medium when
  // an agent is the grammatical subject doing the sending).
  const stripped = line.replace(/^[\s>*#|\-•]+/, "");
  const imperativeStart = new RegExp(`^${verb[0]}(?![\\w.-])`, "i").test(stripped) ||
    new RegExp(`[.!?]\\s+${verb[0]}(?![\\w.-])`, "i").test(line) ||
    new RegExp(`[:,;]\\s*(please\\s+)?${verb[0]}(?![\\w.-])`, "i").test(line);
  const pleaseMarker = /\b(please|you\s+must|you\s+should|make\s+sure\s+to|remember\s+to)\b/i.test(line.slice(0, noun.index + noun[0].length));
  const urlDestination = /\b(to|at|via|into)\s+https?:\/\//i.test(line);
  const directive = contentsOf || imperativeStart || pleaseMarker || urlDestination;
  if (directive) {
    return {
      severity: "high",
      detail: `Exfil verb "${verb[0]}" within ${distance} chars of credential noun "${noun[0]}", in directive shape (imperative, contents-of request, or URL destination)`,
    };
  }
  const agentSubject = /\b(agent|assistant|ai|llm|bot)\b[^.\n]{0,40}$/i.test(line.slice(0, verb.index + verb[0].length));
  if (agentSubject) {
    return { severity: "medium", detail: `Exfil verb "${verb[0]}" near credential noun "${noun[0]}" with an agent as subject (narrative, not a direct instruction)` };
  }
  return { severity: "low", detail: `Exfil verb "${verb[0]}" near credential noun "${noun[0]}" in narrative prose (describing an action, not instructing the reader)` };
}

/* ------------------------------------------------------------------ */
/* Hidden unicode                                                      */
/* ------------------------------------------------------------------ */

interface UnicodeHit { kind: string; severity: Severity; count: number }

function matchHiddenUnicode(line: string): UnicodeHit | null {
  let zeroWidth = 0;
  let bidi = 0;
  let tags = 0;
  let variation = 0;
  for (const ch of line) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff) zeroWidth++;
    else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
    else if (cp >= 0xe0000 && cp <= 0xe007f) tags++;
    else if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) variation++;
  }
  if (tags > 0) return { kind: "unicode tag characters", severity: "high", count: tags };
  if (bidi > 0) return { kind: "bidi control characters", severity: "high", count: bidi };
  const invisible = zeroWidth + variation;
  if (invisible >= 5) return { kind: "zero-width / variation-selector characters", severity: "high", count: invisible };
  if (invisible >= 2) return { kind: "zero-width / variation-selector characters", severity: "medium", count: invisible };
  if (invisible === 1) return { kind: "zero-width / variation-selector character", severity: "low", count: 1 };
  return null;
}

/* ------------------------------------------------------------------ */
/* Tool lures (prose files, outside code fences)                       */
/* ------------------------------------------------------------------ */

const TOOL_LURES: Array<{ re: RegExp; severity: Severity; label: string }> = [
  // A real lure names a URL to fetch. The bare shorthand "curl|sh" in docs
  // that describe the pattern has no URL and must not fire.
  { re: /\bcurl\b[^|\n]{0,200}?https?:\/\/[^\s|]+[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i, severity: "high", label: "curl piped to a shell" },
  { re: /\bwget\b[^|\n]{0,200}?https?:\/\/[^\s|]+[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i, severity: "high", label: "wget piped to a shell" },
  { re: /\b(run|execute)\s+(this|the\s+following|that)\s+(shell\s+)?(command|script)\b/i, severity: "medium", label: "instruction to run a command" },
  { re: /\b(run|execute)\s*:\s*[`'"]?[a-z]/i, severity: "medium", label: "instruction to run a command" },
  { re: /\b(install|add)\s+this\s+(package|dependency|module)\s+and\s+(run|execute)\b/i, severity: "medium", label: "install a package and run it" },
  { re: /\bpaste\s+this\s+into\s+your\s+(terminal|shell|console)\b/i, severity: "medium", label: "paste into terminal" },
];

/* ------------------------------------------------------------------ */
/* Base64 blobs                                                        */
/* ------------------------------------------------------------------ */

const BASE64_RE = /[A-Za-z0-9+/]{60,}={0,2}/g;

function decodeBase64(blob: string): string | null {
  try {
    const buf = Buffer.from(blob, "base64");
    if (buf.length === 0 || buf.length > MAX_DECODED_CHARS) return null;
    const text = buf.toString("utf8");
    // Printable text check: reject binary decodes (lockfile hashes, images).
    const printable = text.replace(/[^\x20-\x7e\t\r\n]/g, "").length;
    if (text.length === 0 || printable / text.length < 0.9) return null;
    return text;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Alt text / link titles                                              */
/* ------------------------------------------------------------------ */

function matchAltText(line: string): { severity: Severity; label: string; fragment: string } | null {
  // Image alt text: ![alt](url)
  const img = /!\[([^\]]{4,})\]\([^)]*\)/.exec(line);
  if (img) {
    const hit = matchInstructionLanguage(img[1]) ?? (EXFIL_VERB.test(img[1]) && EXFIL_NOUN.test(img[1]) ? { severity: "high" as Severity, label: "exfil instruction in alt text" } : null);
    if (hit) return { ...hit, fragment: img[0] };
  }
  // Link with title: [text](url "title")
  const link = /\[[^\]]*\]\([^)\s]+\s+"([^"]{4,})"\)/.exec(line);
  if (link) {
    const hit = matchInstructionLanguage(link[1]);
    if (hit) return { ...hit, fragment: link[0] };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Per-text scanning                                                   */
/* ------------------------------------------------------------------ */

export function scanText(text: string, label = "<text>"): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  const isProse = PROSE_EXTENSIONS.has(extname(label).toLowerCase()) || label === "<text>" || !extname(label);
  let inFence = false;

  const push = (line: number, rule: string, severity: Severity, src: string, detail: string) => {
    findings.push({ file: label, line, rule, severity, excerpt: excerpt(src), detail });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;

    // hidden-unicode: anywhere, including code (that is the point of it)
    const uni = matchHiddenUnicode(line);
    if (uni) {
      push(lineNo, "hidden-unicode", uni.severity, line, `${uni.count} ${uni.kind} on one line; invisible to a human reader, visible to an agent`);
    }

    // html-comment-instruction: single-line and multi-line comments
    const commentRe = /<!--([\s\S]*?)-->/g;
    let cm: RegExpExecArray | null;
    let commentFound = false;
    while ((cm = commentRe.exec(line)) !== null) {
      commentFound = true;
      const hit = matchInstructionLanguage(cm[1]);
      const exfil = hit ? null : matchExfil(cm[1]);
      if (hit) push(lineNo, "html-comment-instruction", "high", cm[0], `HTML comment contains instruction language (${hit.label}); comments are invisible in rendered output but read by agents`);
      else if (exfil) push(lineNo, "html-comment-instruction", "high", cm[0], `HTML comment contains an exfil pattern: ${exfil.detail}`);
    }
    // Multi-line comment opener without a closer on this line: check the
    // joined comment body once, reported at the opener line.
    if (!commentFound && line.includes("<!--")) {
      const start = lines.slice(i, i + 20).join("\n");
      const end = start.indexOf("-->");
      if (end > 0) {
        const body = start.slice(start.indexOf("<!--") + 4, end);
        const hit = matchInstructionLanguage(body);
        if (hit) push(lineNo, "html-comment-instruction", "high", line, `Multi-line HTML comment contains instruction language (${hit.label})`);
      }
    }

    if (inFence) continue; // remaining rules target prose, not code samples

    // alt-text-instruction
    if (isProse) {
      const alt = matchAltText(line);
      if (alt) push(lineNo, "alt-text-instruction", alt.severity, alt.fragment, `Instruction language in image alt text or link title (${alt.label}); alt text is read by agents, rarely by humans`);
    }

    // exfil-pattern
    const exfil = matchExfil(line);
    if (exfil) push(lineNo, "exfil-pattern", exfil.severity, line, exfil.detail);

    // instruction-phrase (skip lines already claimed by a comment finding
    // to keep one finding per locus per rule family)
    const instr = matchInstructionLanguage(line);
    if (instr && !commentFound) {
      if (isQuotedDocContext(line)) {
        // Detector docs and security writeups quote these phrases to
        // describe them. Quoted-in-documentation is low, never blocking.
        push(lineNo, "instruction-phrase", "low", line, `Instruction phrase (${instr.label}) in documentation context (describing the pattern, not issuing it)`);
      } else {
        push(lineNo, "instruction-phrase", instr.severity, line, `Instruction phrase aimed at an AI reader (${instr.label})`);
      }
    }

    // tool-lure: prose files only, outside code fences
    if (isProse) {
      for (const lure of TOOL_LURES) {
        if (lure.re.test(line)) {
          push(lineNo, "tool-lure", lure.severity, line, `Tool lure in prose (${lure.label}); commands belong in code, not in text an agent is told to obey`);
          break;
        }
      }
    }

    // base64-blob: decode and re-scan the decoded text
    BASE64_RE.lastIndex = 0;
    let bm: RegExpExecArray | null;
    while ((bm = BASE64_RE.exec(line)) !== null) {
      const blob = bm[0];
      if (blob.length > MAX_BLOB_CHARS) continue;
      const decoded = decodeBase64(blob);
      if (!decoded) continue;
      const hit = matchInstructionLanguage(decoded) ?? (matchExfil(decoded) ? { severity: "high" as Severity, label: "exfil pattern" } : null);
      if (hit) {
        push(lineNo, "base64-blob", "high", blob, `Base64 blob (${blob.length} chars) decodes to instruction-like text (${hit.label}): "${excerpt(decoded)}"`);
      }
    }
  }
  return findings;
}

/* ------------------------------------------------------------------ */
/* Path scanning                                                       */
/* ------------------------------------------------------------------ */

export function collectFiles(root: string, options: ScanOptions = {}): string[] {
  const maxFiles = options.maxFiles ?? 5000;
  const out: string[] = [];
  const walk = (dir: string): void => {
    if (out.length >= maxFiles) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
      } else if (entry.isFile() && TEXT_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

export function computeVerdict(findings: Finding[]): Verdict {
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  if (high > 0 || medium >= 3) return "FINDINGS";
  if (findings.length > 0) return "REVIEW";
  return "CLEAN";
}

export function makeReport(target: string, filesScanned: number, findings: Finding[]): ScanReport {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  return {
    target,
    verdict: computeVerdict(findings),
    filesScanned,
    findings,
    counts,
    scannedAt: new Date().toISOString(),
  };
}

export function scanPath(target: string, options: ScanOptions = {}): ScanReport {
  const maxBytes = options.maxFileBytes ?? 1024 * 1024;
  let stat;
  try {
    stat = statSync(target);
  } catch {
    throw new Error(`Path does not exist or is not readable: ${target}`);
  }
  if (stat.isFile()) {
    const text = readFileSync(target, "utf8");
    return makeReport(target, 1, scanText(text, target));
  }
  if (!stat.isDirectory()) {
    throw new Error(`Path is neither a file nor a directory: ${target}`);
  }
  const files = collectFiles(target, options);
  const findings: Finding[] = [];
  let scanned = 0;
  for (const file of files) {
    try {
      const st = statSync(file);
      if (st.size > maxBytes) continue;
      const text = readFileSync(file, "utf8");
      if (text.includes("\0")) continue; // binary content with a text extension
      scanned++;
      findings.push(...scanText(text, file));
    } catch {
      // Unreadable file: skip it, never guess at its content.
    }
  }
  return makeReport(target, scanned, findings);
}

export function renderReport(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(
    `injectcheck ${report.target}: ${report.verdict} ` +
    `(${report.filesScanned} file${report.filesScanned === 1 ? "" : "s"} scanned, ` +
    `${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}: ` +
    `${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low)`,
  );
  for (const f of report.findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line} ${f.rule}: ${f.detail}`);
    lines.push(`      ${f.excerpt}`);
  }
  if (report.verdict === "CLEAN") {
    lines.push("CLEAN: no injection patterns matched. This does not prove the content is safe; it means none of the deterministic rules fired.");
  } else if (report.verdict === "REVIEW") {
    lines.push("REVIEW: weak signals matched. Read the flagged lines before letting an agent act on this content.");
  } else {
    lines.push("FINDINGS: strong injection patterns matched. Do not let an agent follow instructions from this content until a human has reviewed the flagged lines.");
  }
  return lines.join("\n");
}
