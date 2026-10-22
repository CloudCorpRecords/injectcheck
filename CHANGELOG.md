# Changelog

## 0.1.2 (2026-10-21)

Fix release closing the four in-scope problems from Round 1 real-repo
validation (ledger P-008, P-010, P-011, P-012 in the Security Wave
validation program). Every fix landed test-first with the failing payload
or false positive as a regression fixture.

- P-010: HTML comments are now scanned as a unit across lines. The whole
  comment body is normalized (line continuations removed, whitespace
  collapsed) and the instruction, exfil, and tool-lure matchers run on
  it, so the multi-line comment payload from a public write-up (a curl
  exfil of ~/.ssh/id_rsa and ~/.aws/credentials piped to base64) now
  verdicts FINDINGS with the html-comment-instruction and exfil-pattern
  rules firing, in the multi-line, continuations-removed, and collapsed
  layouts. A new exfil construction matcher pairs a credential file read
  (cat) or an environment dump with an encoder or network sink across
  line breaks, which also catches the comment-stripped layout.
- P-011: tool-lure now catches command-shaped content in polite PR
  prose: an environment dump piped through a credential-word filter to
  a network sink (the printenv and nc shape) fires with or without
  backticks. A bare printenv with no sink and no credential filter, the
  ordinary debugging instruction, does not fire.
- P-008: the instruction-phrase override family covers the full verb
  set (ignore, disregard, forget, override, bypass, overwrite, discard)
  and noun set (instructions, orders, tasks, assignments, prompts,
  context). "Forget all previous tasks", "Forget about all the
  assignments" (with a new-task follow-on), "Ignore all preceding
  orders", and "Forget everything before that" now fire. Grading is
  documented in the README: temporal marker plus directive noun is
  high; no temporal marker is high only with an agent-directed
  follow-on, otherwise medium; "ignore previous versions" in a
  changelog does not fire.
- P-012: tool-lure no longer fires on CI test-report prose. Negative
  run reports ("Not run:", "Did not run", "No tests run", "Not
  rendered") are exempt from the rule, and the run/execute colon form
  no longer treats a leading "the" as a command. Both real PostHog PR
  excerpts that false-positived in Round 1 are regression fixtures.

Tests: 85 passing (63 in 0.1.1, plus 22 new). The injected-issue
acceptance fixture still verdicts FINDINGS with all rule families, and
the spec document control still verdicts REVIEW with low findings only.

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
