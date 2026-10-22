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

export const VERSION = "0.1.2";

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
  // Round 1 validation (P-008): the override family with the full verb and
  // noun sets. Grading choice, documented in the README: an override verb
  // plus a temporal marker (previous, preceding, prior, earlier) plus a
  // directive noun is the canonical injection shape and scores high. The
  // noun set deliberately excludes ordinary objects (versions, steps,
  // files), so "ignore previous versions and upgrade" in a changelog does
  // not fire at all.
  { re: /\b(ignore|disregard|forget|override|bypass|overwrite|discard)\s+((?:about|all|the|your|any)\s+){0,3}(previous|preceding|prior|earlier)\s+(instructions?|directions?|prompts?|orders?|tasks?|assignments?|commands?|requests?|rules?|guidelines?|context)\b/i, label: "override of previous instructions, orders, or tasks" },
  { re: /\bforget\s+everything\s+(before|above|prior)\b/i, label: "forget everything before" },
  // Same override family without a temporal marker, but with an
  // agent-directed follow-on (a new task or new instructions for the
  // reader): still the canonical shape, still high.
  { re: /\b(ignore|disregard|forget|override)\s+((?:about|all|the|your|any)\s+){0,3}(instructions?|orders?|tasks?|assignments?|commands?)\b[\s\S]{0,120}?\bnew\s+(task|instructions?|assignment)\b/i, label: "override with a new task follow-on" },
];

/** Softer instruction language aimed second-person at an AI reader. */
const SOFT_PHRASES: Array<{ re: RegExp; label: string }> = [
  { re: /\b(attention|note|important)\s*[:,!]?\s*(ai|llm|agent|assistant|chatbot|language\s+model)\b/i, label: "direct address to an AI" },
  { re: /\b(dear|hello|hey)\s+(ai|llm|agent|assistant|chatbot)\b/i, label: "direct address to an AI" },
  { re: /\b(ai|llm|agent|assistant|chatbot|language\s+model)\s*[:,]?\s+(please\s+)?(ignore|disregard|run|execute|send|post|upload|reveal|output|print|follow)\b/i, label: "imperative addressed to an AI" },
  { re: /\byou\s+must\s+(now\s+)?(run|execute|send|post|upload|reveal|output|print|fetch|download|install|call)\b/i, label: "you must <action>" },
  { re: /\bwhen\s+you\s+(read|see|process)\s+this\b[^.\n]{0,60}\b(run|execute|send|ignore|follow)\b/i, label: "when you read this, act" },
  // P-008 grading, second tier: an override verb plus a directive noun
  // with no temporal marker and no agent-directed follow-on is medium.
  // It is worth a human look, but on its own it is also how people write
  // about their own task lists, so it never reaches high alone.
  { re: /\b(ignore|disregard|forget|override)\s+((?:about|all|the|your|any)\s+){0,3}(instructions?|orders?|tasks?|assignments?|commands?)\b/i, label: "override of instructions, orders, or tasks (no temporal marker)" },
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
  // Sentence-start imperatives only. A colon before the verb ("name: Publish
  // to MCP Registry" in workflow YAML) is a key, not an imperative, and
  // treating it as one false-positived on every publish workflow we own.
  const imperativeStart = new RegExp(`^${verb[0]}(?![\\w.-])`, "i").test(stripped) ||
    new RegExp(`[.!?]\\s+${verb[0]}(?![\\w.-])`, "i").test(line);
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

/**
 * Credential-read exfil construction (P-010, P-011). The classic verb and
 * noun pairing never matches the shape real write-ups use: a credential
 * file read with cat (or a full environment dump with printenv) piped to
 * an encoder or a network sink. This matcher works on a whole fragment
 * (a normalized HTML comment body, one line, or the flattened full text),
 * so the construction matches across line breaks. A credential read with
 * no encoder and no sink does not fire: reading a key file is also what
 * legitimate setup docs describe.
 */
const CRED_READ = /\bcat\b[\s\S]{0,160}?(~\/\.ssh\/[\w.\-]+|id_rsa\b|\.aws\/credentials\b|\.aws\/[\w.\-]+|\.env\b|\.npmrc\b)/i;
const ENV_DUMP = /\bprintenv\b|\benv\s*\|/i;
const ENCODE_SINK = /\|\s*(base64|xxd|gzip|od)\b/i;
const NET_SINK = /\b(?:nc|ncat)\s+(?:-[a-z]+\s+)*[\w.\-]+\s+\d{2,5}\b|\b(?:curl|wget)\b[\s\S]{0,200}?https?:\/\//i;

export function matchExfilConstruction(text: string): string | null {
  const flat = text.replace(/\s+/g, " ");
  const cred = CRED_READ.exec(flat);
  if (cred && (ENCODE_SINK.test(flat) || NET_SINK.test(flat) || /\b(curl|wget|nc|ncat)\b/i.test(flat))) {
    return "credential file read combined with an encoder or a network tool";
  }
  const dump = ENV_DUMP.exec(flat);
  if (dump && NET_SINK.test(flat)) {
    return "environment dump piped to a network sink";
  }
  return null;
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

/**
 * Negative run-report guard (P-012): CI test summaries in PR bodies list
 * what was NOT run ("Not run: the full backend suite. CI runs them.",
 * "Did not run the e2e suite", "No tests run"). Those lines report the
 * absence of an action; they are never tool lures, whatever command-like
 * shape follows the colon.
 */
const NEGATIVE_RUN_REPORT = /\b(not\s+run|did\s+not\s+run|didn'?t\s+run|no\s+tests?\s+(were\s+)?run|not\s+rendered|not\s+executed|was\s+not\s+run|were\s+not\s+run|not\s+yet\s+run)\b/i;

export function isNegativeRunReport(line: string): boolean {
  return NEGATIVE_RUN_REPORT.test(line);
}

const TOOL_LURES: Array<{ re: RegExp; severity: Severity; label: string }> = [
  // A real lure names a URL to fetch. The bare shorthand "curl|sh" in docs
  // that describe the pattern has no URL and must not fire.
  { re: /\bcurl\b[^|\n]{0,200}?https?:\/\/[^\s|]+[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i, severity: "high", label: "curl piped to a shell" },
  { re: /\bwget\b[^|\n]{0,200}?https?:\/\/[^\s|]+[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i, severity: "high", label: "wget piped to a shell" },
  // P-011: an environment dump piped through to a network sink, the polite
  // PR prose shape. Command-shaped content presented as an instruction in
  // prose, with or without backticks and with or without code fences on
  // neighbouring lines. A bare printenv with no sink and no credential
  // filter (the ordinary debugging instruction) does not fire.
  { re: /\b(printenv|env)\b[^|\n]{0,100}?\|[^|\n]{0,120}?\|\s*(nc|ncat|curl|wget)\b/i, severity: "high", label: "environment dump piped to a network sink" },
  { re: /\b(printenv|env)\b[^|\n]{0,100}?\|\s*(nc|ncat)\s+[\w.\-]+\s+\d{2,5}\b/i, severity: "high", label: "environment dump piped to a network sink" },
  { re: /\bprintenv\b[^|\n]{0,100}?\|\s*grep\b[^|\n]{0,60}?(key|token|secret|pass)/i, severity: "medium", label: "environment dump filtered for credential words" },
  { re: /\b(run|execute)\s+(this|the\s+following|that)\s+(shell\s+)?(command|script)\b/i, severity: "medium", label: "instruction to run a command" },
  // "execute: true" is a config flag in MCP tool docs, not a command. The
  // value after the colon must not be a bare boolean literal, and a report
  // phrase like "run: the full backend suite" (P-012) is not a command
  // either, so a leading "the" is rejected too. Negative run reports are
  // filtered before this list is consulted at all.
  { re: /\b(run|execute)\s*:\s*(?!true\b|false\b|yes\b|no\b|on\b|off\b|null\b|none\b|the\b)[`'"]?[a-z]/i, severity: "medium", label: "instruction to run a command" },
  { re: /\b(install|add)\s+this\s+(package|dependency|module)\s+and\s+(run|execute)\b/i, severity: "medium", label: "install a package and run it" },
  { re: /\bpaste\s+this\s+into\s+your\s+(terminal|shell|console)\b/i, severity: "medium", label: "paste into terminal" },
];

/** First tool lure matching a prose line, or null. Shared by the line loop and the comment pass. */
export function matchToolLure(line: string): { severity: Severity; label: string } | null {
  if (isNegativeRunReport(line)) return null;
  for (const lure of TOOL_LURES) {
    if (lure.re.test(line)) return lure;
  }
  return null;
}

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

  /* HTML comments are scanned as a unit (P-010). A comment spanning lines
   * is normalized first (backslash line continuations removed, whitespace
   * collapsed) and the instruction, exfil, exfil-construction, and
   * tool-lure matchers all run on the whole body, so a payload split
   * across comment lines matches the same way it would on one line.
   * Lines covered by a comment span are skipped by the per-line prose
   * rules below: one comment yields one finding per rule family. */
  const commentSpans: Array<{ start: number; end: number }> = [];
  {
    const commentRe = /<!--([\s\S]*?)-->/g;
    let cm: RegExpExecArray | null;
    while ((cm = commentRe.exec(text)) !== null) {
      const start = text.slice(0, cm.index).split("\n").length;
      const end = start + (cm[0].match(/\n/g)?.length ?? 0);
      commentSpans.push({ start, end });
      const body = cm[1].replace(/\\\r?\n/g, " ").replace(/\s+/g, " ").trim();
      const instr = matchInstructionLanguage(body);
      const rawExfil = matchExfil(body);
      const exfil = rawExfil && rawExfil.severity !== "low" ? rawExfil : null;
      const construction = matchExfilConstruction(body);
      if (instr) {
        push(start, "html-comment-instruction", "high", cm[0], `HTML comment contains instruction language (${instr.label}); comments are invisible in rendered output but read by agents`);
      }
      if (exfil || construction) {
        push(start, "exfil-pattern", "high", cm[0], `Exfil pattern inside an HTML comment: ${exfil ? exfil.detail : construction}`);
        if (!instr) {
          push(start, "html-comment-instruction", "high", cm[0], "HTML comment contains an exfil pattern; comments are invisible in rendered output but read by agents");
        }
      } else if (!instr) {
        const lure = matchToolLure(body);
        if (lure) {
          push(start, "html-comment-instruction", "high", cm[0], `HTML comment contains a tool lure (${lure.label}); comments are invisible in rendered output but read by agents`);
        }
      }
    }
  }
  const inComment = (lineNo: number): boolean =>
    commentSpans.some((s) => lineNo >= s.start && lineNo <= s.end);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;

    // hidden-unicode: anywhere, including code (that is the point of it)
    const uni = matchHiddenUnicode(line);
    if (uni) {
      push(lineNo, "hidden-unicode", uni.severity, line, `${uni.count} ${uni.kind} on one line; invisible to a human reader, visible to an agent`);
    }

    if (inFence) continue; // remaining rules target prose, not code samples

    // Lines inside an HTML comment were already scanned as a unit above.
    const commented = inComment(lineNo);

    // alt-text-instruction
    if (isProse && !commented) {
      const alt = matchAltText(line);
      if (alt) push(lineNo, "alt-text-instruction", alt.severity, alt.fragment, `Instruction language in image alt text or link title (${alt.label}); alt text is read by agents, rarely by humans`);
    }

    // exfil-pattern: the verb and noun pairing, plus the credential-read
    // construction (cat of a credential file, or an environment dump,
    // combined with an encoder or a network sink) on the same line.
    if (!commented) {
      const exfil = matchExfil(line);
      if (exfil) push(lineNo, "exfil-pattern", exfil.severity, line, exfil.detail);
      const construction = matchExfilConstruction(line);
      if (construction && !(exfil && exfil.severity === "high")) {
        push(lineNo, "exfil-pattern", "high", line, `Exfil construction: ${construction}`);
      }
    }

    // instruction-phrase (skip lines already claimed by the comment pass
    // to keep one finding per locus per rule family)
    const instr = commented ? null : matchInstructionLanguage(line);
    if (instr) {
      if (isQuotedDocContext(line)) {
        // Detector docs and security writeups quote these phrases to
        // describe them. Quoted-in-documentation is low, never blocking.
        push(lineNo, "instruction-phrase", "low", line, `Instruction phrase (${instr.label}) in documentation context (describing the pattern, not issuing it)`);
      } else {
        push(lineNo, "instruction-phrase", instr.severity, line, `Instruction phrase aimed at an AI reader (${instr.label})`);
      }
    }

    // tool-lure: prose files only, outside code fences and comments.
    // matchToolLure applies the negative run-report guard (P-012) first.
    if (isProse && !commented) {
      const lure = matchToolLure(line);
      if (lure) {
        push(lineNo, "tool-lure", lure.severity, line, `Tool lure in prose (${lure.label}); commands belong in code, not in text an agent is told to obey`);
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

  /* Pass 2: flattened and normalized matching.
   * Attackers split phrases across lines, hide them behind leetspeak, or
   * break them with invisible characters. Normalize a copy of the whole
   * text (strip invisible chars, decode leet inside words, join lines)
   * and re-run the instruction and exfil matchers on it. Only matches
   * that pass 1 missed (spanning lines, or visible only after
   * normalization) are reported here, so nothing double-counts. */
  const cleanedLines = lines.map((l) => normalizeForMatching(l));
  const flat = cleanedLines.join(" ");
  const offsets: number[] = [];
  {
    let acc = 0;
    for (const cl of cleanedLines) { offsets.push(acc); acc += cl.length + 1; }
  }
  const lineAt = (idx: number): number => {
    let ln = 1;
    for (let i = 0; i < offsets.length; i++) {
      if (offsets[i] <= idx) ln = i + 1; else break;
    }
    return ln;
  };
  const seenKeys = new Set(findings.map((f) => `${f.rule}:${f.line}`));

  const phraseSets: Array<{ list: typeof STRONG_PHRASES; severity: Severity }> = [
    { list: STRONG_PHRASES, severity: "high" },
    { list: SOFT_PHRASES, severity: "medium" },
  ];
  for (const { list, severity } of phraseSets) {
    for (const { re, label: phraseLabel } of list) {
      const g = new RegExp(re.source, "gi");
      let m: RegExpExecArray | null;
      while ((m = g.exec(flat)) !== null) {
        const startLine = lineAt(m.index);
        const endLine = lineAt(m.index + m[0].length);
        const spans = endLine > startLine;
        const rawHit = matchInstructionLanguage(lines[startLine - 1]);
        if (!spans && rawHit) continue; // pass 1 already reported this locus
        const key = `instruction-phrase:${startLine}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        const doc = isQuotedDocContext(lines[startLine - 1]) || isQuotedDocContext(lines[endLine - 1]);
        push(
          startLine,
          "instruction-phrase",
          doc ? "low" : severity,
          lines[startLine - 1],
          `Instruction phrase (${phraseLabel}) detected ${spans ? `split across lines ${startLine}-${endLine}` : "after normalization (leetspeak or invisible characters)"}${doc ? ", in documentation context" : ""}`,
        );
      }
    }
  }

  // Exfil across lines or visible only after normalization.
  {
    const nounPositions: Array<{ index: number; text: string }> = [];
    const nounRe = new RegExp(EXFIL_NOUN.source, "gi");
    let nm: RegExpExecArray | null;
    while ((nm = nounRe.exec(flat)) !== null) nounPositions.push({ index: nm.index, text: nm[0] });
    const verbRe = new RegExp(EXFIL_VERB.source, "gi");
    let vm: RegExpExecArray | null;
    while ((vm = verbRe.exec(flat)) !== null) {
      const noun = nounPositions.find((n) => Math.abs(n.index - vm!.index) <= 80);
      if (!noun) continue;
      const startLine = lineAt(Math.min(vm.index, noun.index));
      const endLine = lineAt(Math.max(vm.index, noun.index));
      const spans = endLine > startLine;
      const rawHit = matchExfil(lines[startLine - 1]);
      if (!spans && rawHit) continue;
      const key = `exfil-pattern:${startLine}`;
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);
      const window = flat.slice(Math.max(0, vm.index - 30), Math.min(flat.length, noun.index + noun.text.length + 30));
      const hit = matchExfil(window);
      // Cross-line exfil is only reported at directive strength. Legit code
      // and workflow YAML pair POST/publish verbs with token nouns across
      // lines constantly; narrative-strength cross-line matches are noise.
      if (!hit || hit.severity !== "high") continue;
      const doc = isDocContext(lines[startLine - 1]) || isDocContext(lines[endLine - 1]);
      push(
        startLine,
        "exfil-pattern",
        doc ? "low" : "high",
        lines[startLine - 1],
        `Exfil verb "${vm[0]}" near credential noun "${noun.text}" detected ${spans ? `split across lines ${startLine}-${endLine}` : "after normalization (leetspeak or invisible characters)"}${doc ? ", in documentation context" : ""}`,
      );
    }
  }

  // Exfil construction across lines (P-010): a credential file read or an
  // environment dump on one line and its encoder or network sink on
  // another only becomes visible once the text is flattened. This covers
  // the comment-stripped layout of the W2 payload, where no single line
  // carries the whole construction.
  {
    const construction = matchExfilConstruction(flat);
    if (construction) {
      const anchor = flat.search(/\bcat\b|\bprintenv\b|\benv\s*\|/i);
      const startLine = lineAt(Math.max(0, anchor));
      const key = `exfil-pattern:${startLine}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        const doc = isDocContext(lines[startLine - 1]);
        push(
          startLine,
          "exfil-pattern",
          doc ? "low" : "high",
          lines[startLine - 1],
          `Exfil construction (${construction}) detected across lines ${doc ? ", in documentation context" : ""}`,
        );
      }
    }
  }

  return findings;
}

/**
 * Normalize a line for the pass-2 matchers: strip invisible characters
 * (zero-width, bidi, tags, variation selectors) and decode leetspeak
 * substitutions inside words that contain letters (ign0re -> ignore).
 * Version strings and pure numbers are left alone.
 */
const LEET_MAP: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
};

/** Cyrillic and Greek letters that render identically to Latin ones. */
const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
  "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
  "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
  "\u03c7": "x", "\u03c5": "u",
};

export function normalizeForMatching(line: string): string {
  const stripped = line.replace(/[\u200b-\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\ufe00-\ufe0f\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu, "");
  // Decode HTML entities (&#105;gnore) and homoglyphs (Cyrillic а) so the
  // phrase matchers see the text a renderer or a tokenizer would show.
  const decoded = stripped
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&nbsp;/g, " ");
  const latin = decoded.replace(/[\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u04bb\u03b1\u03b5\u03bf\u03c1\u03c4\u03c7\u03c5]/g, (c) => HOMOGLYPH_MAP[c] ?? c);
  return latin.replace(/[A-Za-z0-9@$]+/g, (tok) => {
    if (!/[A-Za-z]/.test(tok) || !/[013457@$]/.test(tok)) return tok;
    return tok.replace(/[013457@$]/g, (c) => LEET_MAP[c] ?? c);
  });
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
