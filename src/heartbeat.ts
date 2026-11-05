// Compare a verified copy with Hub-signed heartbeats (specification appendix,
// "Verifier Outcomes for Heartbeat Evidence"; mechanism chapter, "Hub Heartbeat").

import { fractionDigits, isDecimal, scaled } from "./decimal.js";
import type { AofReport, HeartbeatEvidence, HeartbeatReport } from "./outcomes.js";
import { decodeHubKey, readStatements, statementIsSigned, type Statement } from "./statement.js";

export interface HeartbeatInput {
  /** The report of the copy being checked. */
  aof: AofReport;
  /** A JSON document holding one heartbeat or an array of them; null when none was retrieved. */
  heartbeats: Uint8Array | null;
  /** The Hub key the topic's agreed settings accept: unpadded base64url, 33-byte SEC1 compressed. */
  hubKey: string;
  /** The topic identifier from the agreed settings. */
  topicId: string;
  /** The application's freshness window in seconds. Omit to leave freshness unassessed. */
  freshnessSeconds?: string;
  /** Current time in Unix seconds. Required with `freshnessSeconds`. */
  now?: string;
}

interface Authenticated {
  index: number;
  position: bigint;
  headHash: string;
  issuedAt: string;
}

function authenticate(index: number, read: ReturnType<typeof readStatements> & { ok: true }, hubKey: Uint8Array, topicId: string): HeartbeatEvidence {
  const parsed = read.value[index]!;
  if (!parsed.ok) return { index, authenticated: false, reason: `malformed: ${parsed.reason}` };
  const statement: Statement = parsed.value;
  const evidence: HeartbeatEvidence = {
    index,
    authenticated: false,
    position: statement.members.get("position"),
    headHash: statement.members.get("head_hash"),
    issuedAt: statement.members.get("issued_at"),
  };
  if (statement.kind !== "heartbeat") return { ...evidence, reason: `statement is a ${statement.kind}, not a heartbeat` };
  if (statement.members.get("topic_id") !== topicId) return { ...evidence, reason: "heartbeat names another topic" };
  if (!statementIsSigned(statement, hubKey)) return { ...evidence, reason: "signature does not verify under the accepted Hub key" };
  return { ...evidence, authenticated: true };
}

function latestOf(heartbeats: Authenticated[]): Authenticated {
  const digits = Math.max(...heartbeats.map((heartbeat) => fractionDigits(heartbeat.issuedAt)));
  return heartbeats.reduce((latest, candidate) => {
    const a = scaled(latest.issuedAt, digits);
    const b = scaled(candidate.issuedAt, digits);
    return b > a || (b === a && candidate.position > latest.position) ? candidate : latest;
  });
}

function isStale(issuedAt: string, now: string, window: string): boolean {
  const digits = Math.max(fractionDigits(issuedAt), fractionDigits(now), fractionDigits(window));
  return scaled(now, digits) - scaled(issuedAt, digits) > scaled(window, digits);
}

/** First disagreement between two heartbeats, or between a heartbeat and the copy's valid prefix. */
function findConflict(heartbeats: Authenticated[], aof: AofReport): string | null {
  const headAt = new Map<bigint, string>();
  for (const heartbeat of heartbeats) {
    const seen = headAt.get(heartbeat.position);
    if (seen !== undefined && seen !== heartbeat.headHash) {
      return `two heartbeats under the Hub key name different entries at position ${heartbeat.position}`;
    }
    headAt.set(heartbeat.position, heartbeat.headHash);
  }
  const validPrefix = validPrefixLength(aof);
  for (const heartbeat of heartbeats) {
    if (heartbeat.position > BigInt(validPrefix)) continue;
    const line = aof.lines[Number(heartbeat.position) - 1]!;
    if (line.eventId !== heartbeat.headHash) return `the copy's entry ${heartbeat.position} is not the entry the heartbeat names`;
  }
  return null;
}

/** Number of leading lines that are all valid. */
function validPrefixLength(aof: AofReport): number {
  const firstInvalid = aof.lines.findIndex((line) => line.outcome !== "valid");
  return firstInvalid === -1 ? aof.lines.length : firstInvalid;
}

export function compareHeartbeats(input: HeartbeatInput): HeartbeatReport {
  const key = decodeHubKey(input.hubKey);
  if (!key.ok) throw new Error(key.reason);
  if (input.freshnessSeconds !== undefined) {
    if (!isDecimal(input.freshnessSeconds)) throw new Error("freshness window is not a decimal number of seconds");
    if (input.now === undefined || !isDecimal(input.now)) throw new Error("a freshness window needs the current time in Unix seconds");
  }
  const none = (detail: string, heartbeats: HeartbeatEvidence[] = []): HeartbeatReport => ({ outcome: "missing", detail, freshness: "not_assessed", heartbeats });
  if (input.heartbeats === null) return none("no heartbeat was supplied");
  const read = readStatements(input.heartbeats);
  if (!read.ok) return none(`the heartbeat document is unreadable: ${read.reason}`);

  const evidence = read.value.map((_, index) => authenticate(index, read, key.value, input.topicId));
  const authenticated: Authenticated[] = evidence
    .filter((item) => item.authenticated)
    .map((item) => ({ index: item.index, position: BigInt(item.position!), headHash: item.headHash!, issuedAt: item.issuedAt! }));
  if (authenticated.length === 0) return none("no supplied heartbeat is authenticated for this topic and Hub key", evidence);

  const latest = latestOf(authenticated);
  const freshness =
    input.freshnessSeconds === undefined ? "not_assessed" : isStale(latest.issuedAt, input.now!, input.freshnessSeconds) ? "stale" : "fresh";
  const report = (outcome: HeartbeatReport["outcome"], detail: string): HeartbeatReport => ({
    outcome,
    detail,
    coveredPosition: latest.position.toString(),
    freshness,
    heartbeats: evidence,
  });

  const conflict = findConflict(authenticated, input.aof);
  if (conflict !== null) return report("conflicting", conflict);
  const validPrefix = BigInt(validPrefixLength(input.aof));
  const total = BigInt(input.aof.lines.length);
  if (validPrefix < total && validPrefix < latest.position) {
    return report("not_compared", `the copy is not valid through entry ${latest.position}; line ${validPrefix + 1n} is ${input.aof.lines[Number(validPrefix)]!.outcome}`);
  }
  if (freshness === "stale") return report("stale", `the latest heartbeat, issued at ${latest.issuedAt}, is outside the freshness window`);
  if (latest.position > total) return report("short", `the copy has ${total} entries and the latest heartbeat covers ${latest.position}`);
  return report("match", `the copy's entry ${latest.position} is the entry the latest heartbeat names`);
}
