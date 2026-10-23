# Changelog

## 0.1.17 (2026-10-23)

Production re-verification fix for SW-5, found by scanning the
real fixture with the published 0.1.16 binary.

- SW-5: the fixture note now reaches valid JSON files. 0.1.16
  attached the note in the per-line pass against the file label,
  but a valid JSON document is scanned through string extraction
  under a synthetic placeholder label, so the note never fired
  on the very file that motivated it (encode/httpx
  tests/models/whatwg.json). scanText now re-applies
  fixtureNoteFor(real label) to hidden-unicode findings in the
  extraction remap; the raw-text path is unchanged. Severity
  still unchanged, per the P-105 convention.
- Regression: test/sw5-fixture-note.test.ts gains genuinely
  valid-JSON cases (the 0.1.16 cases passed a bare line, which
  is malformed JSON and exercised only the raw fallback — that
  is how the gap shipped).
- The VERSION constant, left at 0.1.15 inside the 0.1.16
  package, now matches the package version.
- Record correction: the 0.1.16 entry below says 0.1.15 was
  never published; in fact a parallel stream published 0.1.15
  to npm, the MCP Registry, and GHCR minutes before 0.1.16
  shipped. The 0.1.16 content was built on a tree-identical
  copy of that release, so no content was lost either way.

## 0.1.16 (2026-10-23)

Production-validation fixes (stream 4, problems S4-2 and S4-5).
This release also carries the complete 0.1.15 content below, which
was finished and green locally on 2026-10-22 but never published to
any surface (npm latest stayed 0.1.14); it ships here for the first
time so no version number is reused and no work is dropped.

- SW-2 (S4-2, REAL): the concealment phrase "without notifying /
  telling / informing / alerting the user" graded high on grafana/k6
  PR #6610, maintainer prose REPORTING a silent failure as a defect
  ("leaving an incomplete results file without notifying the user.
  Returning the error lets the output manager report the failure.").
  The pattern now distinguishes an instruction to conceal from a
  problem report: directive cues in the sentence (sentence-initial
  imperative, "please", second person, "make sure / ensure", an
  agent-address header) keep it at high, while two or more
  problem-report cue classes (a failure/defect subject, descriptive
  or participial framing, remediation framing) mark the phrase as
  a defect description, which is not instruction language. Applied
  in both the per-line pass and the flattened pass. 14 new tests in
  test/sw2-concealment.test.ts: the k6 #6610 body (fetched from the
  GitHub API) and five reworded report variants produce no high;
  seven genuine concealment instructions still grade high.
- SW-5 (S4-5, LOW): hidden-unicode findings in files under a test
  or fixture path (tests/, test/, testdata/, fixtures/,
  __fixtures__/, conformance/) now name that context in the detail,
  the P-105 treatment — encode/httpx's WHATWG conformance suite
  carries bidi controls deliberately. Severity is unchanged: the
  corpus has no path-based severity grading, the scanner's own
  fixtures scan FINDINGS by design, and discounting directory
  trees would invite planting in them. 3 new tests in
  test/sw5-fixture-note.test.ts.

## 0.1.15 (2026-10-22)

Gap closure for the P-104 polite-lure limit (ledger P-160): a new
context layer matches combinations that do not rely on politeness or
injection markers. 23 new tests in test/p160.test.ts.

- Run-and-disclose lure: an agent-directed instruction to run or
  read an environment or credential source (printenv style) and
  paste, include, or send the output, aggravated by an external URL
  destination, a concealment cue, or an unrelated bug-report frame,
  now grades exfil-pattern at high. The incident polite-lure fixture
  moves from REVIEW with one low finding to FINDINGS.
- Conditional sleeper: an if or when trigger keyed on a future
  question, plus a data action over private data, plus an innocuous
  cover response (respond normally, answer as if nothing happened, a
  canned reply after answering), now grades instruction-phrase at
  high. The W17 Gemini calendar sleeper verdicts FINDINGS in all
  five layouts; it was CLEAN in all five.
- Key-substitution rendered link: a credential noun, a
  word-substitution instruction whose replacement is the other key,
  and a URL carrying a secret-named parameter now grade
  exfil-pattern at high. The W14 Slack confetti shape verdicts
  FINDINGS in all five layouts, closing the P-100 sub-shape limit.
- P-104 is narrowed, not closed: a bare polite request with a
  credential target but no aggravator signal remains undetected by
  design, and the README limits section states the narrowed
  boundary. Single signals never escalate: a credential noun near a
  send verb in narrative prose, and ordinary maintainer requests to
  run tests and paste logs, grade exactly as before.

## 0.1.14 (2026-10-22)

Emergency repair from incident validation: a phrasing variant inside
the P-010 W2 family verdicts CLEAN on 0.1.13. 6 new tests in
test/p154.test.ts; 369 tests passing in total.

- P-154 request-channel exfiltration: a hidden HTML comment that
  tells the reader to read the environment variables and secret
  files available to it and include them in a request to an external
  URL now grades exfil-pattern at high. The rule is a combination on
  flattened text (credential noun, a nearby read verb, an
  include-style transfer into a request-shaped container, an
  external URL destination, and corroboration from an agent marker,
  suppression language, or an override lead), matched in the comment
  pass, the fragment scanner, and the flattened pass.
- P-154 instruction patterns: the agent-instruction header (the W2
  marker, hyphenated or spaced) and suppression aimed at the
  instruction itself ("do not mention this comment") now count as
  strong instruction language. The suppression object set is limited
  to self-referential nouns, so ordinary changelog prose does not
  fire.
- Controls hold: the clean incident control stays CLEAN, the
  forget-instructions fixture stays FINDINGS, and the documented
  P-104 polite-lure limit keeps its REVIEW verdict at low.

## 0.1.13 (2026-10-22)

Frontier design pass (Fix Pass 2): the four payload families the
text-at-scale hunts found no pattern for, plus the large-file
performance fix. 75 new tests (71 in test/frontier.test.ts from the
verbatim W9 to W21 probe fixtures in all five layouts, 4 in
test/p080.test.ts); 363 tests passing in total. Design note:
~/workspace/security-wave/injectcheck-frontier-design.md in the
program workspace.

- P-100 render-channel exfiltration: an encode signal plus a
  render or include construction plus a credential or private-data
  noun, or a hidden container carrying private data into a rendered
  link or markdown image, now grades exfil-pattern at high (W16,
  W18, W20, W21 caught in all five layouts). One sub-shape is a
  documented limit: a bare link whose URL carries a secret-named
  parameter with only a word-substitution instruction (W14) has no
  encode or render construction and is not detected; the README
  limits section states the boundary.
- P-101 behavior hijack: suppression plus user-data movement to a
  third-party destination (W11), credential-class table contents
  transferred into a new message (W12), and recipient-field
  substitution naming a concrete third-party address (W10) now
  grade exfil-pattern at high in all layouts. Pure tool shadowing
  in the abstract, with no concrete destination, data movement, or
  suppression, is a documented limit in the README.
- P-102 one-time-code theft: a one-time or verification code noun
  plus reading the code from the mailbox plus posting it outward
  grades exfil-pattern at high (W19 in all layouts). Spoiler and
  details regions are concealed text and are scanned at full
  strength, never skipped.
- P-103 destructive instruction set: agent-goal framing plus
  destructive verbs over at least two estate-scale targets plus a
  persistence or scope marker grades instruction-phrase at high
  (W13 in all layouts). Bare fenced CLI commands with no goal
  framing stay documentation.
- P-080 large-file performance: the segment and context machinery
  is precomputed and memoized per document (segment boundaries by
  recurrence, per-segment evidence and narration facts, fence state,
  framed-quotation and structural-context memoization), per-line
  matchers reuse the precomputed normalized line, and exact fast
  paths gate the URL-query views, base64 token runs, entity
  decoding, and plain-ASCII normalization. Measured in file mode:
  the benign 20 MB shape went from 18.2 s (0.1.12) to under 10 s,
  and a hit-heavy file with no paragraph breaks went from 160 s at
  1 MB (and a timeout at 5 MB) to about 4 s at 1 MB and about 15 s
  at 5 MB, with identical verdicts.
- Guardrails held exactly: the 550-text real corpus stays REVIEW
  with 144 findings in 9 files, 0 high and 0 medium; the deepset
  legitimate slice stays at 0 FINDINGS and the injection slice is
  unchanged (22 FINDINGS, 9 REVIEW, 232 CLEAN); InjecAgent is
  unchanged (base 1 FINDINGS of 62, enhanced 62 of 62, user
  controls 17 of 17 CLEAN); W1 to W9 and W15 stay caught in all
  layouts.

## 0.1.12 (2026-10-22)

Fix release closing the grading-calibration bundle from the
overnight flywheel hunts (Hunt Swarm 2 mutation, Hunt Swarm 5
cross-dogfood, Hunt Swarm 3 text at scale): P-085, P-086, P-089,
P-093, P-094, P-095, P-098, and the cosmetic P-105. Every fix
landed test-first: 34 new tests in test/p085bundle.test.ts, 19
failing on the 0.1.11 code for the ledger reasons and 15 controls
passing before and after. 288 tests passing in total. One
pre-existing test was updated in place: the pipe suite's fixture
grew from 160 to 200 payload files, because the P-089 span dedup
below removes one duplicate finding per payload file and the
human render needs more files to exceed the 200 KiB the suite
pushes through a pipe.

- P-085: zero-width insertion into benign text let the
  hidden-unicode density signal dominate the verdict (225
  mutation runs, 35 flips to FINDINGS). Distributed invisible
  characters now grade low however many a line holds; high
  requires a cluster of five or more consecutive invisible
  characters or an encoding density, and hidden-unicode mediums
  alone never reach FINDINGS without a second signal family.
  Payloads actually hidden with zero-width characters keep
  FINDINGS through their payload rules, and tag or bidi
  characters still grade high on their own.
- P-086: case, spacing, and zero-width transforms on
  documentation-shaped text eroded the attribution cues, so
  quoted payloads graded at full severity (70 runs, all REVIEW
  to FINDINGS). Attribution, documentation, and structural cues
  are now matched on a normalized cue view of the framing text,
  and payload hits are aligned with quotation spans on the
  payload-normalized view, so the transforms cannot misalign a
  hit with the span that frames it. The cue view does not decode
  entities or leet: a cue must be visible as a cue. Adversarial
  controls hold: bare payloads under fake headings and quotes
  behind neutral lead-ins stay FINDINGS.
- P-089: a newline after an HTML comment opener doubled some
  findings, and the indented BOM-only mutant graded REVIEW
  against a CLEAN baseline. Findings are now deduplicated by
  comment span across the comment, per-line, split-blob, joined-
  blob, and flattened passes, so identical content reports
  identical counts; an indented byte order mark at the start of
  a file is still a byte order mark. One honest count change
  follows: multi-line comment payloads lose the flattened
  construction duplicate the comment pass already reported (the
  W2 shape now reports 2 highs instead of 3, verdict FINDINGS
  unchanged; the W9 comment-multi layout reports 2 instead of
  3, all five layouts still FINDINGS).
- P-093: declarative AI-security prose ("AI output is sanitized
  with DOMPurify...") drew an instruction-phrase medium as an
  imperative addressed to an AI. The pattern now requires an
  imperative shape: a verb after an AI mention followed by a
  copula, a comma, a closing bracket, or a past-tense verb is a
  noun in a declarative sentence, not an imperative.
- P-094: the tool-lure medium fired on the literal token run:
  in prose and headings. The run-colon lure now requires a
  command-shaped value (a known command word, a script path, or
  a script file), so a YAML key token quoted in prose and a
  model name, version, or date after "Latest run:" do not fire,
  while "run: curl ..." and "run: npm ..." still do.
- P-095: narrative prose quotation still defeated
  documentation-context grading (5 highs on the wave's own
  docs). Attribution now extends to narrative quotation: report
  section labels tolerate the long parenthetical of a ledger
  evidence line, a payload inside a quotation or code span in a
  segment that narrates the quotation (reporting verbs, variant
  lists in running text, evidence lines) grades low, and the
  noun phrase "environment dump" wrapped across a line break no
  longer pairs as an exfil verb. The wave's own ledger,
  SUMMARY, and fix and hunt reports now grade with no high and
  no medium findings. Adversarial controls hold: an
  unattributed bare payload paragraph in a report-shaped
  document stays FINDINGS.
- P-098: the three long-form agent incident reports in the
  550-text corpus each drew one medium. The P-093 imperative
  shape clears the two instruction-phrase mediums (a returned
  assistant run, an assistant-output noun phrase), and refusal
  narration about running a script no longer matches the
  run-a-command lure when the refusal is narrated on the same
  line. All three files now verdict CLEAN.
- P-105 (cosmetic): the hidden-unicode detail for the exact
  pattern @ + zero-width space + username now names the known
  convention (GitHub release-note mentions in dependabot PR
  bodies, a mention-ping suppression convention). No verdict
  or severity change.
- Real-text discipline on the 550-text corpus: the published
  0.1.11 binary reports 148 findings in 12 files (0 high, 4
  medium, 144 low); this release reports 144 findings in 9
  files (0 high, 0 medium, 144 low), the four P-098 mediums
  cleared, no new file flagged.

## 0.1.11 (2026-10-22)

Fix release closing three injectcheck problems from the overnight
flywheel text-at-scale hunt (Hunt Swarm 3: 550 hand-labeled real
texts, 65 wild payload fixtures): P-096, P-097, and P-099. Every
fix landed test-first: 26 new tests in test/p096p097p099.test.ts;
in the first test-first run 11 failed on the 0.1.10 code for
exactly the ledger reasons, one further test (the quoted
parameter-name shape the raw wild fixture actually uses) was added
when the first fix iteration missed that layout, and one more
(the token-response object shape) when the real OAuth file
surfaced a second pairing; the rest are controls that passed
before and after. 254 tests passing in total.

- P-096: GitHub Agentic Workflows provenance comments graded
  FINDINGS on ordinary PR and issue bodies, and a visible CI link
  label of the same token family drew a tool-lure medium. The
  only lure-shaped token was a run field whose value is a URL.
  The run-colon lure now requires a command value: a URL value is
  a link label, not a command. A provenance-shaped comment (the
  gh-aw marker, an engine field, a run URL) counts a lure inside
  it only at full command strength. Controls: a provenance
  comment carrying a real instruction still verdicts FINDINGS,
  the W2 comment curl exfil shape keeps its highs, and run-colon
  or execute-colon followed by an actual command still fires.
- P-097: fenced OAuth repro code graded FINDINGS because a
  response helper named send co-occurred with the grant-type
  string client_credentials inside a fence. The flattened exfil
  pass now discounts a pairing when both sides sit inside a
  fenced block, the credential-shaped token is an OAuth protocol
  constant, and the verb is a code identifier; a second discount
  covers the status-code response-helper shape whose whole
  window is protocol vocabulary and quoted placeholder values,
  provided no credential-file or environment marker is present.
  Controls: the same shape in prose aimed at an agent keeps
  FINDINGS, and fenced code that reads credential files and
  posts them stays FINDINGS.
- P-099: the canonical Invariant add-tool payload graded CLEAN
  in all five layouts: its channel is a tool parameter, and pass
  and read were not transfer verbs for any rule. The exfil
  analysis now covers the parameter channel as a combination: a
  concrete credential-class file target, a read directive aimed
  at it, a transfer of the contents into a named parameter,
  field, or argument (including the quoted parameter-name form
  and a name declared in a tool signature), and directive or
  suppression language as corroboration. All five wild layouts
  now verdict FINDINGS. Controls: ordinary MCP tool
  documentation, a parameter transfer of a non-credential file,
  a credential read with no parameter channel, and descriptive
  third-person narration of the same mechanics do not fire.
- Real-text discipline on the 550-text corpus: the published
  0.1.10 binary reports 152 findings in 16 files (3 high, 5
  medium, 144 low); this release reports 148 findings in 12
  files (0 high, 4 medium, 144 low), with the gh-aw, OAuth, and
  run-label families cleared and no new file flagged. The
  remaining mediums are the P-098 incident-report family, out
  of scope for this release.

## 0.1.10 (2026-10-22)

Fix release closing six injectcheck problems from the overnight
flywheel mutation hunt (Hunt Swarm 2: 3,569 semantics-preserving
mutants, parser-verified): P-081, P-082, P-083, P-084, P-087, and
P-088. One root theme: the composed normalization did not reach
every matching pass uniformly, so semantics-preserving transforms
hid payloads from some rules while others saw through them. Every
fix landed test-first: 35 new tests in test/mutation.test.ts; in
the first test-first run 18 failed on the 0.1.9 code for exactly
the ledger reasons, and one further test (the temporal-marker
gap the synonym sweep exposed) was added during the fix and
also fails on the unfixed patterns; the rest are controls that
passed before and after. 228 tests passing in total.

- P-081: HTML entity encoding (hex and decimal) of payload text
  defeated the raw-text rules in the evasion direction (REVIEW to
  CLEAN in 40 hunt runs): the entity decoder fed the flattened
  pass, so tool-lure and exfil-pattern, which read raw lines,
  silently lost content the instruction pass could still see.
- P-082: Cyrillic homoglyph (confusable) substitution dropped
  tool-lure and exfil-pattern highs (REVIEW to CLEAN in 19 runs).
  The confusable fold existed only in the flattened pass.
- The fix for both: the instruction, exfil-pairing, exfil-
  construction, and tool-lure matchers now each take the stronger
  of their raw and composed-normalized grades (zero-width
  stripping, entity decoding, the full Cyrillic and Greek
  confusable tables in both cases, emphasis unwrapping, leet
  decoding), with the raw hit winning ties and each variant
  computing its own negation and documentation downgrades first,
  so untransformed text grades exactly as before. The corpus
  parity check is exact: all 39 top-level corpus files grade
  byte-identically to 0.1.9, and the documentation-seed mutation
  flip counts (the P-086 class, out of scope here) are unchanged.
- P-083: badge and URL surfaces lacked composed normalization:
  uppercasing the badge URL or entity-encoding its surface
  defeated the percent-decode chain that detects the embedded
  instruction payload (17 runs, all FINDINGS to CLEAN). URL
  matching is now case-insensitive, runs on the entity-decoded
  and surface-normalized views of the line (surface normalization
  omits leet decoding, which would corrupt percent escapes), and
  percent-decoding composes repeatedly with the entity, base64,
  confusable, and entity layers in the decoded text.
- P-084: a base64 blob rewrapped at 24 columns inside a composed
  stack (URL-safe, padding stripped, decode instruction in a
  comment) stopped being decoded (4 runs, all FINDINGS to CLEAN):
  the composed-stack path extracted only contiguous tokens of 40
  or more characters. Extraction now also joins runs of
  whitespace-separated base64 fragments, in the recursive decoder
  and in a document-level pass, with first-fragment and
  last-fragment drop attempts for fragments glued to prose or a
  comment marker.
- P-087: wrapping a payload line in bold, italic, or a fence
  changed its segmentation and could drop its findings entirely
  (12 FINDINGS to CLEAN in 26 runs). Emphasis underscores glued
  to a line's edge words are unwrapped in the matching view (an
  underscore strictly inside a word stays, and asterisks and
  backticks are untouched, so construction distance windows do
  not move), and the flattened pass now dedups against actual
  findings instead of a raw re-match, so a payload line inside a
  fence, which the per-line pass skips by design, is no longer
  suppressed in the document pass as well. Tool-lure still does
  not fire inside fences; that boundary is unchanged.
- P-088: override-verb and lure-phrase synonym swaps outside the
  dictionary dropped instruction-phrase findings (11 FINDINGS to
  CLEAN in 19 runs). The dictionaries now cover the natural
  synonym class: overlook, dismiss, and set aside as override
  verbs in the temporal, follow-on, and bare tiers; pay no
  attention to, pay no heed to, and pay no mind to as multiword
  override phrasings; the temporal marker above alongside
  previous and prior in the generic override pattern (previously
  only the ignore-specific pattern had it, which is why a swap
  lost the w7 translation payload); disclose and divulge as
  exfil verbs; and the contents-from shape alongside
  contents-of. Benign uses keep their grades: the noun sets are
  unchanged, so prose about previous versions, styling, or
  public contents does not fire.

## 0.1.9 (2026-10-22)

Fix release closing two injectcheck problems from the overnight
flywheel: P-079 from the chaos hunt (CHAOS-05) and P-092 from the
cross-dogfood hunt (CD-2). Every fix landed test-first: 24 new
tests in test/p079p092.test.ts, 15 of which failed on 0.1.8 for
exactly the ledger reasons before the fix (the rest are controls
that passed before and after); 193 tests passing in total.

- P-079: scan coverage caps were silent, and CLEAN was reported
  over the unscanned remainder. A per-file size cap skipped files
  with no warning (a directory whose only file was 2 MB scanned
  zero files and verdicted CLEAN, and a 20 MB notes file with a
  planted injection verdicted CLEAN in scan mode while file mode
  found the planting), and a 5,000-file count cap truncated a
  6,000-file tree at exactly 5,000 files, CLEAN, warnings empty.
  Both caps are raised after measurement (size from 1 MiB to
  5 MiB, count from 5,000 to 20,000: a roughly 3.5 MB file scans
  in about a second and a 10,002-file tree traverses in seconds),
  and at whatever bound is in force the scan is now honest: files
  over the size cap, files beyond the count cap, binary files
  with a text extension, and unreadable files are all reported
  in warnings by name or count; the report carries filesSeen and
  filesSkipped alongside filesScanned (and the human renderer
  states the coverage when anything was skipped); and any
  warning floors a CLEAN verdict at REVIEW, generalizing the
  P-056 partial-scan floor, so a verdict computed over a
  partially scanned estate is never an unqualified CLEAN.
- P-092: the .json file channel was blind where scan_text was
  not; identical bytes scored CLEAN via a .json file and FINDINGS
  via scan_text, so payload text inside sibling tools' JSON
  reports (hookcheck scans, actionpin audits) was laundered to
  CLEAN or near-clean while their human renderings were caught.
  A .json file whose bytes parse as JSON is now scanned through
  its string content: every string literal is extracted in
  source order with escapes decoded, keys as well as values, and
  run through the same normalization and grading pipeline as
  prose text, with finding lines mapped back to the string's
  source line. Payload text in JSON string fields fires the same
  rules at the same severities as in a text file; benign JSON
  (package.json style config, numbers, booleans, nulls, short
  strings) stays CLEAN; documentation-shaped string content
  keeps the documentation grading of its text equivalent; and
  malformed JSON does not crash, falling back to the raw text
  scan. Extraction is bounded (200,000 strings or 8,000,000
  decoded characters) and a truncation past the bound is warned
  and floors the verdict, per the P-079 honesty rule.

193 tests passing. Guardrails re-verified on the published
binary: the cd2 corpus pair agrees at FINDINGS, a fresh
hookcheck JSON report on the A1 fixture is no longer CLEAN,
A5 still FINDINGS, A6 still controlled, the Wave D markdown
set deterministic across 3 runs, and the injectcheck corpus
section passing in full.

## 0.1.8 (2026-10-22)

Fix release closing one injectcheck problem from the overnight
flywheel: P-068, the residual sub-shape recorded by the v0.1.7
fix pass. Every fix landed test-first: 8 new tests in
test/waved.test.ts, 2 of which failed on 0.1.7 for exactly the
ledger reason before the fix (the rest are adversarial
controls); 169 tests passing in total.

- P-068: structural attribution worked when an evidence label
  and its quoted payload shared a segment, but a fenced verbatim
  quote of tool output under an "Evidence (exact):" label still
  graded high when a blank line separated the label from the
  fence: the label landed outside the payload's segment, so the
  attribution never reached it. Segment construction around
  fenced blocks now keeps a directly preceding label line
  attached to the fence's segment across a single blank line
  when the line is label-shaped: short, ending in a colon, and
  headed by an attribution word (Evidence, Output, Example,
  Quote, Excerpt, and similar words that frame the fence content
  as quoted, observed, or exhibited material). Payload text
  inside such a labeled fence now grades low for the
  instruction-phrase, exfil-pattern, and exfil-construction
  rules, the same grade as the other P-066 exhibits. The guards
  are pinned as adversarial controls: a bare payload in a fence
  with no label still verdicts FINDINGS at high; a label that is
  itself an instruction ("Run this:") followed by a payload
  fence still verdicts FINDINGS, because an instruction-shaped
  label is not attribution; instructional prose above a fence
  (the P-024 fence-split shape) still verdicts FINDINGS; a
  label two blank lines above the fence is out of reach; and a
  non-attribution colon line frames nothing.

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
