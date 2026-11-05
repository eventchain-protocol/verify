#!/usr/bin/env node
// Command line for the verifier. Output is minified JSON; exit status is 0 when
// the check passed, 1 when it did not, 2 for a usage or IO error.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { compareHeartbeats, decodeHubKey, readStatements, statementIsSigned, verifyAof } from "./index.js";

const USAGE = `usage:
  eventchain-verify-ts aof <aof-file>
      one JSON line per AOF line: {"line":1,"outcome":"valid","event_id":"..."}
  eventchain-verify-ts heartbeat <aof-file> <heartbeat-file> --hub-key <key> --topic <id>
                                 [--freshness <seconds>] [--now <unix-seconds>]
      one JSON object; outcome is match, missing, stale, conflicting, short or not_compared
  eventchain-verify-ts statement <statement-file> --hub-key <key>
      checks a heartbeat, receipt or refusal under the Hub key`;

class UsageError extends Error {}

function read(path: string | undefined): Uint8Array {
  if (path === undefined) throw new UsageError("missing file argument");
  return readFileSync(path);
}

function required(value: string | undefined, name: string): string {
  if (value === undefined) throw new UsageError(`missing --${name}`);
  return value;
}

function print(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + "\n");
}

function aof(path: string | undefined): number {
  const report = verifyAof(read(path));
  for (const line of report.lines) {
    print(line.outcome === "malformed" ? { line: line.line, outcome: line.outcome } : { line: line.line, outcome: line.outcome, event_id: line.eventId });
  }
  return report.outcome === "valid" ? 0 : 1;
}

function heartbeat(paths: string[], options: { "hub-key"?: string; topic?: string; freshness?: string; now?: string }): number {
  const now = options.freshness !== undefined && options.now === undefined ? Math.floor(Date.now() / 1000).toString() : options.now;
  const report = compareHeartbeats({
    aof: verifyAof(read(paths[0])),
    heartbeats: read(paths[1]),
    hubKey: required(options["hub-key"], "hub-key"),
    topicId: required(options.topic, "topic"),
    freshnessSeconds: options.freshness,
    now,
  });
  print(report);
  return report.outcome === "match" ? 0 : 1;
}

function statement(path: string | undefined, hubKeyText: string | undefined): number {
  const key = decodeHubKey(required(hubKeyText, "hub-key"));
  if (!key.ok) throw new UsageError(key.reason);
  const statements = readStatements(read(path));
  if (!statements.ok) {
    print({ authentic: false, reason: `malformed: ${statements.reason}` });
    return 1;
  }
  let status = 0;
  for (const parsed of statements.value) {
    if (!parsed.ok) print({ authentic: false, reason: `malformed: ${parsed.reason}` });
    else if (!statementIsSigned(parsed.value, key.value)) print({ kind: parsed.value.kind, authentic: false, reason: "signature does not verify under the Hub key" });
    else {
      print({ kind: parsed.value.kind, authentic: true });
      continue;
    }
    status = 1;
  }
  return status;
}

function main(argv: string[]): number {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      "hub-key": { type: "string" },
      topic: { type: "string" },
      freshness: { type: "string" },
      now: { type: "string" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }
  const [command, ...rest] = positionals;
  if (command === "aof" && rest.length === 1) return aof(rest[0]);
  if (command === "heartbeat" && rest.length === 2) return heartbeat(rest, values);
  if (command === "statement" && rest.length === 1) return statement(rest[0], values["hub-key"]);
  throw new UsageError("unknown command or wrong number of arguments");
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`eventchain-verify-ts: ${message}\n`);
  if (error instanceof UsageError || (error as { code?: string }).code === "ERR_PARSE_ARGS_UNKNOWN_OPTION") process.stderr.write(USAGE + "\n");
  process.exitCode = 2;
}
