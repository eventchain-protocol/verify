// The conformance run: every case in the conformance manifest, and nothing else.
// The manifest states what the specification requires; this file only compares.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compareHeartbeats, decodeHubKey, readStatements, statementIsSigned, verifyAof } from "../dist/index.js";

const root = new URL("../conformance/", import.meta.url);
const read = (path) => readFileSync(new URL(path, root));
const cases = read("manifest.jsonl")
  .toString("utf8")
  .split("\n")
  .filter((line) => line !== "")
  .map((line) => JSON.parse(line));

function aofResult(testCase) {
  const report = verifyAof(read(testCase.aof));
  const mints = report.lines
    .filter((line) => line.mint?.flags !== undefined)
    .map((line) => ({
      line: line.line,
      target_line: line.mint.targetLine,
      uv: line.mint.flags.userVerified,
      be: line.mint.flags.backupEligible,
      bs: line.mint.flags.backupState,
    }));
  return { lines: report.lines.map((line) => line.outcome), mints };
}

function heartbeatResult(testCase) {
  const report = compareHeartbeats({
    aof: verifyAof(read(testCase.aof)),
    heartbeats: read(testCase.heartbeats),
    hubKey: testCase.hub_key,
    topicId: testCase.topic_id,
    now: testCase.now,
    freshnessSeconds: testCase.freshness_seconds,
  });
  return { outcome: report.outcome, covered_position: report.coveredPosition };
}

function statementResult(testCase) {
  const key = decodeHubKey(testCase.hub_key);
  assert.ok(key.ok, "the manifest's Hub key must decode");
  const statements = readStatements(read(testCase.statement));
  if (!statements.ok || !statements.value[0].ok) return { outcome: "malformed" };
  const statement = statements.value[0].value;
  if (!statementIsSigned(statement, key.value)) return { outcome: "signature_invalid" };
  return { outcome: "authentic", statement_kind: statement.kind };
}

const run = { aof: aofResult, heartbeat: heartbeatResult, statement: statementResult };
const expected = {
  aof: (c) => ({ lines: c.lines, mints: c.mints ?? [] }),
  heartbeat: (c) => ({ outcome: c.outcome, covered_position: c.covered_position }),
  statement: (c) => (c.outcome === "authentic" ? { outcome: c.outcome, statement_kind: c.statement_kind } : { outcome: c.outcome }),
};

for (const testCase of cases) {
  test(testCase.id, () => {
    assert.deepEqual(run[testCase.kind](testCase), expected[testCase.kind](testCase));
  });
}
