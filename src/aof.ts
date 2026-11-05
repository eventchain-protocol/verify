// Walk an AOF: framing, chain bytes, producer signatures, Mint envelopes
// (specification appendix, "Entry Specification").

import { base64urlEncode, equalBytes } from "./bytes.js";
import { compressedKeyIsOnCurve, sha256, verifyP256 } from "./crypto.js";
import { decodeEntry, type Entry } from "./entry.js";
import { canonicalize } from "./jcs.js";
import type { AofReport, Fault, LineReport, MintReport } from "./outcomes.js";
import { checkAssertion } from "./webauthn.js";

const LF = 0x0a;
const CR = 0x0d;
const GENESIS = new Uint8Array(32);

interface Framed {
  bytes: Uint8Array;
  terminated: boolean;
}

/** Split at every 0x0a. A final run of bytes with no terminator is returned unterminated. */
function frame(file: Uint8Array): Framed[] {
  const lines: Framed[] = [];
  let start = 0;
  for (let i = 0; i < file.length; i++) {
    if (file[i] !== LF) continue;
    lines.push({ bytes: file.subarray(start, i), terminated: true });
    start = i + 1;
  }
  if (start < file.length) lines.push({ bytes: file.subarray(start), terminated: false });
  return lines;
}

function judge(entry: Entry, expectedPrevious: Uint8Array): { faults: Fault[]; detail?: string; assertion?: ReturnType<typeof checkAssertion> } {
  const faults: Fault[] = [];
  let detail: string | undefined;
  if (!equalBytes(entry.prevHash, expectedPrevious)) faults.push("chain_mismatch");
  if (!compressedKeyIsOnCurve(entry.publicKey)) faults.push("key_off_curve");
  else if (!verifyP256(entry.signature, canonicalize(entry.members, "signature"), entry.publicKey)) faults.push("signature_invalid");
  let assertion: ReturnType<typeof checkAssertion> | undefined;
  if (entry.mint !== undefined) {
    assertion = checkAssertion(entry.mint);
    if (!assertion.ok) {
      faults.push("attestation_fault");
      detail = assertion.reason;
    }
  }
  return { faults, detail, assertion };
}

/**
 * Verify a whole AOF from its exact bytes. Every line before the first
 * malformed one gets a report; a malformed line rejects the file and ends the walk.
 */
export function verifyAof(file: Uint8Array): AofReport {
  const lines: LineReport[] = [];
  const validLineByEventId = new Map<string, number>();
  let previousHash: Uint8Array = GENESIS;
  let allValid = true;

  const framed = frame(file);
  for (let index = 0; index < framed.length; index++) {
    const lineNumber = index + 1;
    const { bytes, terminated } = framed[index]!;
    const malformed = (detail: string): AofReport => {
      lines.push({ line: lineNumber, outcome: "malformed", faults: [], detail });
      return { outcome: "invalid", lines, rejectedAtLine: lineNumber };
    };
    if (bytes.includes(CR)) return malformed("line contains 0x0d");
    if (!terminated) return malformed("line does not end in 0x0a");
    const decoded = decodeEntry(bytes);
    if (!decoded.ok) return malformed(decoded.reason);

    const entry = decoded.value;
    const lineHash = sha256(bytes);
    const eventId = base64urlEncode(lineHash);
    const { faults, detail, assertion } = judge(entry, previousHash);
    const report: LineReport = { line: lineNumber, outcome: faults[0] ?? "valid", faults, eventId };
    if (detail !== undefined) report.detail = detail;
    if (entry.mint !== undefined) {
      const mint: MintReport = { targetHash: entry.mint.targetHash, targetLine: validLineByEventId.get(entry.mint.targetHash) ?? null };
      if (assertion?.ok) mint.flags = assertion.value;
      report.mint = mint;
    }
    lines.push(report);
    if (faults.length === 0) validLineByEventId.set(eventId, lineNumber);
    else allValid = false;
    previousHash = lineHash;
  }
  return { outcome: allValid ? "valid" : "invalid", lines };
}
