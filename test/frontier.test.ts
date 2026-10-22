/**
 * Frontier design pass (P-100 to P-103): render-channel exfiltration,
 * behavior hijack, one-time-code theft, and the destructive
 * instruction set. Tests read the verbatim probe fixtures (W9 to W21,
 * five layouts each) from the text-at-scale inbox. Every implemented
 * branch is a combination, never a single token, and the controls pin
 * the benign shapes each branch must not fire on. W14 is the LIMIT
 * sub-shape from the design note: it stays CLEAN in every layout.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { scanText } from "../src/scan.js";
import type { Finding } from "../src/types.js";

/**
 * The verbatim probe fixtures are vendored in frontier-fixtures.json
 * (copied byte for byte from the text-at-scale fixture set) so the
 * suite is self-contained in CI. An INJECTCHECK_FIXTURE_DIR override
 * re-points the tests at a live fixture directory when one exists.
 */
const VENDORED = JSON.parse(
  readFileSync(new URL("./frontier-fixtures.json", import.meta.url), "utf8"),
) as Record<string, string>;

function fixture(name: string): string {
  const dir = process.env.INJECTCHECK_FIXTURE_DIR;
  if (dir) return readFileSync(`${dir}/${name}`, "utf8");
  const text = VENDORED[name];
  assert.ok(text !== undefined, `vendored fixture missing: ${name}`);
  return text;
}
function verdictOf(text: string, label = "x.md"): string {
  const fs = scanText(text, label);
  const high = fs.filter((f) => f.severity === "high").length;
  const medium = fs.filter((f) => f.severity === "medium").length;
  if (high > 0 || medium >= 3) return "FINDINGS";
  return fs.length > 0 ? "REVIEW" : "CLEAN";
}
function frontierHighs(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.severity === "high" &&
    /render-channel|behavior-hijack|one-time-code|destructive instruction/i.test(f.detail));
}

const LAYOUTS = ["raw", "issue", "readme", "comment-multi", "comment-collapsed"] as const;

const FRONTIER_CASES: Array<{ stem: string; name: string }> = [
  { stem: "w10-invariant-shadow", name: "W10 recipient-field substitution" },
  { stem: "w11-invariant-whatsapp", name: "W11 WhatsApp chat-history forwarding" },
  { stem: "w12-supabase-ticket", name: "W12 credential table transfer" },
  { stem: "w13-amazonq-wiper", name: "W13 destructive instruction set" },
  { stem: "w16-gitlab-duo", name: "W16 encode into image link" },
  { stem: "w18-camoleak", name: "W18 encode then render per character" },
  { stem: "w19-comet-reddit", name: "W19 one-time-code theft in spoiler" },
  { stem: "w20-echoleak", name: "W20 hidden white text reference link" },
  { stem: "w21-forcedleak", name: "W21 hidden span markdown image" },
];

for (const { stem, name } of FRONTIER_CASES) {
  describe(`frontier: ${name} (${stem})`, () => {
    for (const layout of LAYOUTS) {
      it(`${layout} layout verdicts FINDINGS with a frontier high`, () => {
        const text = fixture(`${stem}-${layout}.md`);
        const findings = scanText(text, `${stem}-${layout}.md`);
        assert.equal(verdictOf(text, `${stem}-${layout}.md`), "FINDINGS", JSON.stringify(findings));
        assert.ok(frontierHighs(findings).length >= 1, `no frontier high in ${JSON.stringify(findings)}`);
      });
    }
  });
}

describe("frontier guardrails: W9 and W15 stay caught in all layouts", () => {
  for (const stem of ["w9-invariant-add", "w15-pillar-rules"]) {
    for (const layout of LAYOUTS) {
      it(`${stem} ${layout} verdicts FINDINGS`, () => {
        const text = fixture(`${stem}-${layout}.md`);
        assert.equal(verdictOf(text, `${stem}-${layout}.md`), "FINDINGS", JSON.stringify(scanText(text, `${stem}-${layout}.md`)));
      });
    }
  }
});

describe("frontier LIMIT: W14 Slack confetti shape stays undetected by design", () => {
  for (const layout of LAYOUTS) {
    it(`w14 ${layout} does not verdict FINDINGS`, () => {
      const text = fixture(`w14-slack-confetti-${layout}.md`);
      assert.notEqual(verdictOf(text, `w14-${layout}.md`), "FINDINGS", JSON.stringify(scanText(text, `w14-${layout}.md`)));
    });
  }
});

describe("frontier controls: benign neighbours do not fire", () => {
  it("an image-encoding tutorial with no credential or private-data noun does not fire", () => {
    const text = [
      "# Embedding screenshots",
      "",
      "Encode the screenshot in base64 and include it in your reply inside an image link so the docs render offline.",
      "Render one image per step of the tutorial.",
    ].join("\n");
    const findings = scanText(text, "docs.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "docs.md"), "FINDINGS");
  });
  it("a style guide rendering product photos does not fire", () => {
    const text = "For the catalog, render one image per product photo and include a link to the full-size image in the caption.";
    const findings = scanText(text, "guide.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
  });
  it("negated privacy advice about forwarding chat history does not fire", () => {
    const text = "Privacy guide: never forward your chat history to anyone, and do not share your messages with third-party services.";
    const findings = scanText(text, "guide.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "guide.md"), "FINDINGS");
  });
  it("a debugging runbook that reads a token table with no contents transfer does not fire", () => {
    const text = [
      "# Support runbook",
      "",
      "If the tokens page spins, read the integration_tokens table in the dashboard and check the row count.",
      "Then restart the dashboard service and confirm the page loads.",
    ].join("\n");
    const findings = scanText(text, "runbook.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "runbook.md"), "FINDINGS");
  });
  it("mail-merge documentation with no third-party substitution does not fire", () => {
    const text = "The mail merge tool always puts the customer email address in the recipient field. Use the address the user gives you in the import file.";
    const findings = scanText(text, "docs.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "docs.md"), "FINDINGS");
  });
  it("sign-in help about entering a verification code does not fire", () => {
    const text = "To sign in, enter the verification code we emailed you in the one-time code field on the login page. The code expires in ten minutes.";
    const findings = scanText(text, "help.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "help.md"), "FINDINGS");
  });
  it("a security guide warning never to share a one-time code does not fire", () => {
    const text = "Security guide: support will never ask for your password. Never share your one-time code or verification code with anyone who contacts you.";
    const findings = scanText(text, "guide.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "guide.md"), "FINDINGS");
  });
  it("a fenced CLI reference with destructive commands and no agent-goal framing does not fire", () => {
    const text = [
      "# Cleanup reference",
      "",
      "Commands used by the cleanup job:",
      "",
      "```sh",
      "aws s3 rb s3://old-bucket --force",
      "aws ec2 terminate-instances --instance-ids i-0123456789",
      "aws iam delete-user --user-name temp-user",
      "```",
    ].join("\n");
    const findings = scanText(text, "reference.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "reference.md"), "FINDINGS");
  });
  it("a backup guide with a single destructive target and no goal framing does not fire", () => {
    const text = "After the restore completes, delete the old S3 buckets from the backup account and note the deletion in the run log.";
    const findings = scanText(text, "guide.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "guide.md"), "FINDINGS");
  });
  it("third-person narration about a wiper does not fire", () => {
    const text = "The incident report describes a wiper whose goal was to clean the system to a near-factory state: it deleted the file system, deleted S3 buckets and EC2 instances, and ran continuously until the host went offline.";
    const findings = scanText(text, "report.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "report.md"), "FINDINGS");
  });
  it("spoiler and details regions are scanned, not skipped: a benign spoiler stays clean", () => {
    const text = "Review with no plot points. >!The butler did it, in the library, with the candlestick.!<";
    const findings = scanText(text, "review.md");
    assert.equal(frontierHighs(findings).length, 0, JSON.stringify(findings));
    assert.notEqual(verdictOf(text, "review.md"), "FINDINGS");
  });
});
