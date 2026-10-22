# Changelog

## 0.1.0 (2026-10-21)

First release.

- `injectcheck scan [path] [--json]`: scan a directory of text, markdown, and
  code files for prompt-injection patterns.
- `injectcheck file <path> [--json]`: scan a single file.
- Seven deterministic rules: hidden-unicode, html-comment-instruction,
  instruction-phrase, exfil-pattern, tool-lure, base64-blob, and
  alt-text-instruction. Every finding reports file, line, rule id, severity,
  and an excerpt truncated to 120 chars.
- Verdicts: FINDINGS (any high, or 3+ medium), REVIEW (any other finding),
  CLEAN (no pattern matched; never a claim that content is safe).
- MCP server with `scan_text` and `scan_path` tools.
- Tuning guard: documentation that merely mentions prompt injection, and
  negated safety advice, do not verdict FINDINGS.
