/**
 * SW-5 (production validation stream 4, problem S4-5): a direct
 * scan of encode/httpx graded hidden-unicode HIGH on
 * tests/models/whatwg.json — the WHATWG URL conformance suite,
 * whose test URLs deliberately contain bidi controls. Presence
 * detection is literally correct, and the corpus conventions do
 * not support path-based severity grading (the scanner's own repo
 * test fixtures scan FINDINGS by design; the one path-adjacent
 * precedent, P-105, annotates the known convention in the detail
 * and leaves severity unchanged). So the fixture context is named
 * in the detail for triage, exactly like P-105, and the severity
 * stays high: an agent reads test files too, and a scanner that
 * discounts whole directory trees invites planting there.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { scanText } from "../src/scan.js";

// The shape of tests/models/whatwg.json line 2311 in encode/httpx:
// a conformance input URL carrying an RLO and an LRO on purpose.
// (Written with escapes so this source file holds no raw controls.)
const FIXTURE_LINE = '    "input": "http://example.com/\u202e/foo/\u202d/bar",';

describe("SW-5: hidden-unicode in a known test-fixture file", () => {
  it("stays high but carries the fixture note under a tests/ path", () => {
    const fs = scanText(FIXTURE_LINE, "tests/models/whatwg.json");
    const uni = fs.filter((f) => f.rule === "hidden-unicode");
    assert.equal(uni.length, 1);
    assert.equal(uni[0].severity, "high");
    assert.match(uni[0].detail, /test or fixture path/);
    assert.match(uni[0].detail, /severity unchanged/);
  });

  it("carries the note under fixtures/ and testdata/ paths too", () => {
    for (const label of ["fixtures/urls.json", "testdata/urls.json", "pkg/__fixtures__/urls.json"]) {
      const uni = scanText(FIXTURE_LINE, label).filter((f) => f.rule === "hidden-unicode");
      assert.equal(uni.length, 1, label);
      assert.match(uni[0].detail, /test or fixture path/, label);
    }
  });

  it("no fixture note outside a test or fixture path", () => {
    const uni = scanText(FIXTURE_LINE, "docs/guide.md").filter((f) => f.rule === "hidden-unicode");
    assert.equal(uni.length, 1);
    assert.equal(uni[0].severity, "high");
    assert.doesNotMatch(uni[0].detail, /test or fixture path/);
  });
});
