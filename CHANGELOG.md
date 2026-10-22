# Changelog

## 0.1.7 (2026-10-22)

Fix release closing two injectcheck problems from the overnight
flywheel: P-066 from the Wave D self-dogfood hunt, and P-013, the
cosmetic entry open since Round 1. Every fix landed test-first:
17 new tests in test/waved.test.ts, 10 of which failed on 0.1.6
for exactly the ledger reasons before the fix (the rest are
adversarial controls and the saturation side of P-013); 161 tests
passing in total.

- P-066: the documentation-context grading recognized attribution
  only as framing sentences, so it failed on the changelog and
  report genres at estate scale: this changelog verdicts FINDINGS
  with 4 high findings on 0.1.6, all of them payloads described in
  fix notes, and 5 of the 8 overnight hunt reports verdicts
  FINDINGS with 15 high findings among them, all hand read as
  labeled evidence excerpts, method prose, or quoted tool output,
  with zero true positives. Structural attribution is now
  recognized alongside sentential framing: an evidence, output, or
  quoted label in the same bullet or paragraph; a report segment
  opening with a section label such as Method, Evidence,
  Justification, or Judgment; a finding listing that quotes another
  document's flagged line; and fix-note narration in a
  problem-numbered bullet or under a version heading (the scanner
  now catches, now scans, now fires, or does not fire). Payload
  text exhibited in those contexts, in quotation marks or backtick
  spans or as the described subject of the segment, now grades low
  for the instruction-phrase, exfil-pattern, exfil-construction,
  and tool-lure rules. Two latent defects fell out of the same
  work and are fixed here: the flattened exfil construction
  anchor reported its offset in re-collapsed coordinates, which
  misattributed its line (and therefore its context) in documents
  with indented continuation lines; and that pass deduplicated
  against claimed matcher keys rather than actual findings, which
  the corrected anchor exposed on the fence-split shape. The
  guardrails are pinned as adversarial
  controls: a bare payload under a fake version heading with no
  narrating fix language, a payload after a generic Fixed word, a
  quote behind only a neutral lead-in, and a bare payload
  paragraph in a report-shaped document all still verdict
  FINDINGS at high.
- P-013 (COSMETIC): hidden-unicode severity did not scale with
  density: exactly 2 zero-width characters in ordinary prose
  graded medium. Severity now scales with density and clustering:
  5 or more invisible characters on a line still grade high; a
  character embedded inside a word (a letter or digit on both
  sides) grades medium at any count, because splitting a word is
  the concealment shape; sparse isolated characters at word or
  sentence boundaries grade low. The sparse corpus shape now
  grades low, and the dense and in-word shapes keep their grades.

161 tests passing. Guardrails re-verified on the published binary:
A5 FINDINGS with all rule families, A6 control REVIEW with lows
only, wild payloads W1 to W8 all FINDINGS, the Wave B ordinary-text
set (65 texts) at 0 FINDINGS and 0 high findings, the Wave A
controls unchanged, and the entire accumulated corpus passing.
This changelog and both required hunt reports no longer verdict
FINDINGS; their former high findings grade low.

## 0.1.6 (2026-10-22)

Fix release closing the injectcheck problems from the overnight
flywheel Wave C (mutation) and Wave E (robustness) hunts, ledger
P-050 to P-056 in the Security Wave validation program. Every fix
landed test-first: 22 new tests in test/wavece.test.ts, 14 of which
failed on 0.1.5 for exactly the ledger reasons before the fix (the
rest are controls and the spec-pinned named-entity case); 144 tests
passing in total.

- P-051: URL-safe base64 was not decoded. Base64 detection and
  decoding now accept both alphabets (standard + and /, URL-safe
  - and _) with padding present or stripped, in comments, on plain
  lines, and in split-across-lines blobs. The decoder normalizes
  the URL-safe alphabet and restores padding before decoding.
- P-050: encoding stacks of five layers scored CLEAN. The bounded
  recursive decoding bound is raised from depth 3 to depth 6
  (MAX_DECODE_DEPTH in src/scan.ts, stated in the README limits),
  so a five-layer composed entity and base64 stack is covered with
  one layer of headroom; the bound stays finite and documented.
- P-052: HTML entities without trailing semicolons were not
  decoded. The entity decoder now handles the omitted-semicolon
  forms of the numeric references and of the common named entities
  it already handled, matching how browsers and loose parsers read
  them in text content, and the normalization pass uses the same
  decoder.
- P-054 (low): attribution framing after the quote defeated the
  P-023 documentation grading. Quoted-context detection now also
  recognizes framing that follows the quote, in the remainder of
  the quote's own line or within the same paragraph (at most the
  immediately following sentences, stopping at a blank line). The
  P-023 controls hold: a bare payload and a quote behind only a
  neutral lead-in still verdict FINDINGS at high, as does a quote
  followed by unrelated prose.
- P-053 (low): a sink binary split across a line break (n plus c)
  inside the polite lure lost both exfil findings. Lines are now
  rejoined before sink matching when the trailing fragment of one
  line and the leading token of the next combine into a known tool
  name, in the per-line pass and the flattened pass; the lure
  verdicts FINDINGS with both high findings again.
- P-056: unreadable files in a scanned directory were silently
  skipped. A scan now reports them explicitly: the report carries
  a warnings list naming each skipped file and the reason, the
  human renderer prints the warnings, and a scan with unreadable
  files floors its verdict at REVIEW instead of presenting an
  unqualified CLEAN (mirroring the hookcheck P-049 semantics).
  Unreadable directories found while walking are reported the
  same way.
- P-055 (COSMETIC): a BOM-only file scored REVIEW on a
  hidden-unicode low. A leading byte order mark is stripped
  before scanning as an encoding signature and is never counted
  as a hidden character; a BOM prefix on a payload file no
  longer adds a spurious hidden-unicode finding.

144 tests passing. Guardrails re-verified on the published binary:
A5 FINDINGS with all rule families, A6 control REVIEW with lows
only, wild payloads W1 to W8 all FINDINGS, the Wave B ordinary-text
set (65 texts) at 0 FINDINGS and 0 high findings, the Wave A
controls unchanged, and the entire accumulated corpus passing.

## 0.1.5 (2026-10-22)

Fix release closing the injectcheck problems from the overnight
flywheel Wave A (evasion expansion) and Wave B (real-repo corpus
expansion) hunts, ledger P-024 to P-030 and P-037 to P-039 in the
Security Wave validation program. Every fix landed test-first: 17 of
the 23 new tests failed on 0.1.4 for exactly the ledger reasons
before the fix; the rest are positive controls and a guardrail
regression test added during verification.

- P-024 (BLOCKER): a payload split across a code fence boundary scored
  CLEAN. The exfil construction now also recognizes a credential file
  read performed by curl or wget (not only cat), and the document-level
  pass joins prose and fence content, so the composed instruction,
  command in the fence, and collector URL in prose after it grade as
  one exfil construction at high.
- P-025: nested HTML comments hid a complete payload. Comment spans
  are now balanced: the scanner reads the raw span from the first
  opener to the last closer of a nested run.
- P-026: encoding stacks and split base64 defeated all decoding.
  Decoding is now bounded and recursive (HTML entities and base64
  composed to depth 3), applied inside comments and to decoded layers,
  and base64 split across lines with a markdown hard break is joined
  before decoding.
- P-027: a payload percent-encoded into a badge URL query string was
  not decoded or scanned. URL query values on image and link targets
  are percent-decoded and scanned like alt text.
- P-028: payloads split across markdown structures were under-graded.
  The flattened document pass assembles table rows into the exfil
  construction, and footnote or reference definitions carrying an
  imperative (or any run-this-command shape) grade at directive
  strength instead of narrative low.
- P-029: zero-width characters inside key words blinded the payload
  rules entirely. The comment pass and the flattened pass now match on
  zero-width-stripped text for every payload rule, not only for the
  density count.
- P-030: a payload addressed to a named agent framework (Claude Code
  by name) graded low as narrative. A named agent address followed by
  an imperative is a direct-address signal at medium, and it makes an
  accompanying exfil pairing directive.
- P-038: hidden-unicode counted grapheme-internal codepoints as hidden
  characters. A variation selector completing an emoji (including the
  dangling selector left in markdown anchors), a joiner inside an
  emoji ZWJ sequence, and joiners flanked by joining-script letters
  (Persian ZWNJ) are no longer counted. Genuine zero-width stuffing
  still fires, including the sparse P-013 shape.
- P-039: tool-lure fired at medium on human setup prose whose benign
  command sat in the following fence (npm install, npm run dev, a
  localhost curl). That shape now grades low, with the fence content
  checked first: a fence holding an exfil construction, a credential
  reference, or an environment dump filtered for credential words is
  never benign, so the P-024 tension holds.
- P-037: with P-038 and P-039 fixed, the real continuedev/continue
  CONTRIBUTING.md no longer verdicts FINDINGS (REVIEW, lows only).
- Guardrail repair found during verification: a payload quoted in a
  blockquote with verb-before-subject attribution ("Quoted example
  reported by researcher...") briefly graded high through the new
  construction shape. Attribution framing now also recognizes the
  reported-by form and quoted-example framing, and the per-line
  construction pass honors documentation context like the other
  passes. The Wave A quoted-payload control is a regression test.

122 tests passing. Guardrails re-verified on the published binary:
A5 FINDINGS with all rule families, A6 control REVIEW with lows only,
wild payloads W1 to W8 all FINDINGS, the Wave B ordinary-text set
(65 texts) at 0 FINDINGS and 0 high findings, and the Wave A controls
unchanged.

## 0.1.4 (2026-10-22)

Fix release closing the three injectcheck problems from Round 2
real-repo validation (ledger P-021, P-022, P-023 in the Security Wave
validation program). Every fix landed test-first.

- P-021: piped CLI output truncated at exactly 65,536 bytes in both
  renderers, the same emit bug as actionpin P-001 and hookcheck P-017
  (console.log followed by process.exit discards whatever a piped stdout
  has not drained). All reports now go through one flush-aware emit
  helper that resolves in the stdout write callback, exit codes are set
  with process.exitCode, and a reader that closes the pipe early exits
  141. Regression tests spawn the real CLI with piped stdio and require
  a report over 200 KiB to arrive whole and parse, byte-identical for
  the human renderer.
- P-022: the cross-line instruction matcher joined an AI-authorship
  disclosure ("Written with AI") with imperative-mood PR summary prose
  and reported a medium "imperative addressed to an AI" on legitimate
  payloadcms PRs 18930 and 18931. Address-shaped matches whose AI
  mention sits inside an authorship construction (written, drafted,
  generated, created, and similar, with or by an AI) are now treated as
  attribution, not address, in both the per-line and cross-line passes.
  An explicit agent address ("Note for the AI") followed by an
  imperative still fires. Both real PR openings are regression fixtures
  and now verdict CLEAN; the other 50 real texts are unchanged.
- P-023: a security write-up quoting a payload verbatim with
  attribution framing ("The attacker planted the following text in an
  issue: '...'") scored FINDINGS with 2 high findings. Payload text
  inside quotation marks or a blockquote, accompanied by attribution or
  reporting framing, now grades at the documentation level (low) for
  the instruction-phrase, exfil-pattern, and exfil-construction rules,
  in both passes. The framing is required: the same payload without it,
  or behind only a neutral lead-in, still verdicts FINDINGS.

99 tests passing. Guardrails re-verified: A5 fixture FINDINGS with all
rule families, the spec control at REVIEW with 4 low findings, wild
payloads 8 of 8 at FINDINGS, and the labeled dataset slices unchanged
(legitimate slice still zero FINDINGS).

## 0.1.3 (2026-10-21)

One grading fix found during the 0.1.2 acceptance run. On the W3
payload, tool-lure reported only the medium credential-filter finding:
the high environment-dump-to-sink pattern matched pipe segments, and
the credential filter in the payload itself contains pipe characters
('key|token|secret|pass'), so the nc sink at the end of the chain was
invisible to it. The sink pattern now spans intervening pipes, W3
reports a high tool-lure as well as the high exfil construction, and a
regression test pins the high grade in both the backticked and plain
layouts. 86 tests passing.

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
