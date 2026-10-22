# Changelog

## 0.1.1 (2026-10-21)

Hardening release, driven by a real-life battery run the same day as 0.1.0.

False-positive fixes (found scanning our own factory repos):

- tool-lure no longer fires on the MCP config flag `execute: true`. The
  colon form of the run/execute lure now rejects bare boolean values.
  This one bug made greenlight (147 files) verdict FINDINGS on 5 mediums;
  it now verdicts REVIEW with a single low.
- exfil-pattern no longer treats a colon before a verb as an imperative.
  "name: Publish to MCP Registry" in workflow YAML is a key, not a command.
- Cross-line exfil matches are only reported at directive strength, so
  legitimate code and workflows that pair POST/publish with token nouns
  across lines stay quiet.

Evasion coverage (second matching pass, normalized text):

- Instruction phrases and exfil requests split across lines are caught.
- Leetspeak (ign0re), zero-width-split phrases, Cyrillic/Greek homoglyphs,
  and HTML-entity encoded phrases are caught after normalization.
- README documents the honest misses: letter-spaced text, instructions
  split across separate HTML comments, doubly encoded payloads.

Result of the battery after the fixes: 7 factory repos scanned, zero high
or medium false positives (6 CLEAN, greenlight REVIEW with 1 low); the
spec document control stays REVIEW (4 low); the injected-issue fixture
stays FINDINGS with all rule families named. 63 tests, all passing.

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
