// Hub-signed statements: heartbeat, receipt and refusal share one shape
// (specification appendix, "Heartbeat Encoding and Retrieval" and
// "Submission, Receipt and Refusal"), so one reader checks all three.

import { base64urlDecode, utf8Decode } from "./bytes.js";
import { compressedKeyIsOnCurve, isCompressedKeyEncoding, verifyP256 } from "./crypto.js";
import { isDecimal, isInteger } from "./decimal.js";
import { canonicalize } from "./jcs.js";
import { asFlatStringObject, parseJson, type JsonValue, type Parsed } from "./strict-json.js";

export type StatementKind = "heartbeat" | "receipt" | "refusal";

export interface Statement {
  kind: StatementKind;
  /** Every member as written, for the signed message. */
  members: Map<string, string>;
  signature: Uint8Array;
}

const VERIFIER_FAULTS = ["malformed", "chain_mismatch", "key_off_curve", "signature_invalid", "attestation_fault"];
const COMMON = ["v", "kind", "topic_id", "issued_at", "signature"];

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

function memberNames(kind: StatementKind, members: Map<string, string>): Parsed<string[]> {
  if (kind === "heartbeat") return { ok: true, value: [...COMMON, "position", "head_hash"] };
  if (kind === "receipt") return { ok: true, value: [...COMMON, "submission_hash", "position", "head_hash", "count"] };
  const reason = members.get("reason");
  if (reason === undefined) return fail('missing member "reason"');
  if (reason === "head_mismatch") return { ok: true, value: [...COMMON, "submission_hash", "reason", "position", "head_hash"] };
  if (VERIFIER_FAULTS.includes(reason)) return { ok: true, value: [...COMMON, "submission_hash", "reason", "line"] };
  return fail(`unknown reason "${reason}"`);
}

function checkHash(members: Map<string, string>, name: string): string | null {
  const text = members.get(name);
  if (text === undefined) return null;
  const bytes = base64urlDecode(text);
  return bytes !== null && bytes.length === 32 ? null : `member "${name}" is not a 32-byte unpadded base64url hash`;
}

function checkInteger(members: Map<string, string>, name: string, minimum: bigint): string | null {
  const text = members.get(name);
  if (text === undefined) return null;
  if (!isInteger(text)) return `member "${name}" is not decimal digits without leading zeros`;
  return BigInt(text) >= minimum ? null : `member "${name}" is below ${minimum}`;
}

/** Read one parsed JSON value as a Hub statement, or say why it is malformed. */
export function readStatement(value: JsonValue): Parsed<Statement> {
  const flat = asFlatStringObject(value);
  if (!flat.ok) return flat;
  const members = flat.value;
  if (members.get("v") !== "1") return fail(`unsupported revision "${members.get("v")}"`);
  const kind = members.get("kind");
  if (kind !== "heartbeat" && kind !== "receipt" && kind !== "refusal") return fail(`unknown kind "${kind}"`);

  const names = memberNames(kind, members);
  if (!names.ok) return names;
  for (const name of names.value) if (!members.has(name)) return fail(`missing member "${name}"`);
  for (const name of members.keys()) if (!names.value.includes(name)) return fail(`unknown member "${name}"`);

  const faults = [
    isDecimal(members.get("issued_at")!) ? null : 'member "issued_at" is not Unix seconds in the specified form',
    checkHash(members, "head_hash"),
    checkHash(members, "submission_hash"),
    checkInteger(members, "position", kind === "heartbeat" ? 1n : 0n),
    checkInteger(members, "count", 1n),
    checkInteger(members, "line", 0n),
  ];
  const fault = faults.find((reason) => reason !== null);
  if (fault != null) return fail(fault);

  const signature = base64urlDecode(members.get("signature")!);
  if (signature === null || signature.length !== 64) return fail('member "signature" is not 64 bytes of unpadded base64url');
  return { ok: true, value: { kind, members, signature } };
}

/**
 * Read a JSON document holding one statement or an array of them, as the
 * heartbeat endpoints return. A statement that is malformed stays in the list
 * as a failure, so the caller can report it by index.
 */
export function readStatements(document: Uint8Array): Parsed<Parsed<Statement>[]> {
  const text = utf8Decode(document);
  if (text === null) return fail("not valid UTF-8");
  const json = parseJson(text, { rejectUnpairedSurrogates: true });
  if (!json.ok) return json;
  const values = json.value.type === "array" ? json.value.items : [json.value];
  return { ok: true, value: values.map(readStatement) };
}

/** Decode a Hub key given as unpadded base64url of a 33-byte SEC1 compressed point on P-256. */
export function decodeHubKey(text: string): Parsed<Uint8Array> {
  const key = base64urlDecode(text);
  if (key === null || !isCompressedKeyEncoding(key)) return fail("Hub key is not unpadded base64url of a 33-byte SEC1 compressed point");
  if (!compressedKeyIsOnCurve(key)) return fail("Hub key names no point on P-256");
  return { ok: true, value: key };
}

/** Whether the Hub key signed the statement's other members. */
export function statementIsSigned(statement: Statement, hubKey: Uint8Array): boolean {
  return verifyP256(statement.signature, canonicalize(statement.members, "signature"), hubKey);
}
