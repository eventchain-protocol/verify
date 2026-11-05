// The Mint envelope's WebAuthn assertion checks (specification appendix,
// "WebAuthn Assertion Checks"): the steps that need no relying party.

import { concatBytes, utf8Decode } from "./bytes.js";
import { sha256, verifyP256 } from "./crypto.js";
import type { MintEnvelope } from "./entry.js";
import type { AssertionFlags } from "./outcomes.js";
import { parseJson, type Parsed } from "./strict-json.js";

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKUP_STATE = 0x10;
const FLAGS_OFFSET = 32;
const MINIMUM_AUTHENTICATOR_DATA = 37;

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

/**
 * The one string member of this name in the client data. A name that appears
 * twice has no single value, so the check that depends on it cannot hold.
 */
function soleStringMember(members: { name: string; value: { type: string; value?: unknown } }[], name: string): Parsed<string> {
  const found = members.filter((member) => member.name === name);
  if (found.length === 0) return fail(`client data has no "${name}"`);
  if (found.length > 1) return fail(`client data has more than one "${name}"`);
  const value = found[0]!.value;
  if (value.type !== "string") return fail(`client data "${name}" is not a string`);
  return { ok: true, value: value.value as string };
}

function checkClientData(envelope: MintEnvelope): Parsed<true> {
  const text = utf8Decode(envelope.clientDataJson);
  if (text === null) return fail("client data is not valid UTF-8");
  const json = parseJson(text, { rejectUnpairedSurrogates: false });
  if (!json.ok) return fail(`client data is not JSON: ${json.reason}`);
  if (json.value.type !== "object") return fail("client data is not a JSON object");
  const type = soleStringMember(json.value.members, "type");
  if (!type.ok) return type;
  if (type.value !== "webauthn.get") return fail(`client data type is "${type.value}", not "webauthn.get"`);
  const challenge = soleStringMember(json.value.members, "challenge");
  if (!challenge.ok) return challenge;
  if (challenge.value !== envelope.targetHash) return fail("client data challenge is not the target hash");
  return { ok: true, value: true };
}

/** Run the three checks. On success, return the flags the verifier must report. */
export function checkAssertion(envelope: MintEnvelope): Parsed<AssertionFlags> {
  const clientData = checkClientData(envelope);
  if (!clientData.ok) return clientData;

  const data = envelope.authenticatorData;
  if (data.length < MINIMUM_AUTHENTICATOR_DATA) return fail(`authenticator data is ${data.length} bytes, fewer than 37`);
  const flags = data[FLAGS_OFFSET]!;
  if ((flags & FLAG_USER_PRESENT) === 0) return fail("user-presence flag is not set");
  const backupEligible = (flags & FLAG_BACKUP_ELIGIBLE) !== 0;
  const backupState = (flags & FLAG_BACKUP_STATE) !== 0;
  if (backupState && !backupEligible) return fail("backup-state flag is set without backup eligibility");

  const signed = concatBytes(data, sha256(envelope.clientDataJson));
  if (!verifyP256(envelope.assertionSig, signed, envelope.attesterKey)) {
    return fail("assertion signature does not verify under the attester key");
  }
  return { ok: true, value: { userVerified: (flags & FLAG_USER_VERIFIED) !== 0, backupEligible, backupState } };
}
