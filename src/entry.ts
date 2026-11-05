// The entry object: member vocabulary per revision and field encodings
// (specification appendix, "Entry Specification").

import { base64urlDecode, utf8Decode } from "./bytes.js";
import { isCompressedKeyEncoding } from "./crypto.js";
import { asFlatStringObject, parseJson, type Parsed } from "./strict-json.js";

const BASE_MEMBERS = ["entry_id", "payload_hash", "payload_ref", "prev_hash", "public_key", "signature"] as const;
const MINT_MEMBERS = ["kind", "target_hash", "attester_key", "assertion_sig", "authenticator_data", "client_data_json"] as const;

export interface MintEnvelope {
  targetHash: string;
  attesterKey: Uint8Array;
  assertionSig: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
}

export interface Entry {
  /** Every member as written, for the signed message. */
  members: Map<string, string>;
  prevHash: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
  mint?: MintEnvelope;
}

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

/** Decode a binary member. A fixed length is enforced when given. */
function binary(members: Map<string, string>, name: string, length?: number): Parsed<Uint8Array> {
  const bytes = base64urlDecode(members.get(name)!);
  if (bytes === null) return fail(`member "${name}" is not unpadded base64url`);
  if (length !== undefined && bytes.length !== length) return fail(`member "${name}" is ${bytes.length} bytes, not ${length}`);
  return { ok: true, value: bytes };
}

function compressedKey(members: Map<string, string>, name: string): Parsed<Uint8Array> {
  const key = binary(members, name, 33);
  if (!key.ok) return key;
  if (!isCompressedKeyEncoding(key.value)) return fail(`member "${name}" is not a SEC1 compressed point`);
  return key;
}

function allowedMembers(members: Map<string, string>): Parsed<{ mint: boolean }> {
  const revision = members.get("v");
  if (revision !== undefined && revision !== "1") return fail(`unsupported revision "${revision}"`);
  const allowed = new Set<string>(BASE_MEMBERS);
  if (revision === "1") {
    allowed.add("v");
    for (const name of MINT_MEMBERS) allowed.add(name);
  }
  for (const name of members.keys()) {
    if (!allowed.has(name)) {
      return fail(revision === undefined ? `member "${name}" is outside the base revision` : `unknown member "${name}"`);
    }
  }
  for (const name of BASE_MEMBERS) if (!members.has(name)) return fail(`missing member "${name}"`);
  const present = MINT_MEMBERS.filter((name) => members.has(name));
  if (present.length !== 0 && present.length !== MINT_MEMBERS.length) return fail("partial Mint envelope");
  if (present.length !== 0 && members.get("kind") !== "mint") return fail(`unknown kind "${members.get("kind")}"`);
  return { ok: true, value: { mint: present.length !== 0 } };
}

function decodeMint(members: Map<string, string>): Parsed<MintEnvelope> {
  const target = binary(members, "target_hash", 32);
  if (!target.ok) return target;
  const attesterKey = compressedKey(members, "attester_key");
  if (!attesterKey.ok) return attesterKey;
  const assertionSig = binary(members, "assertion_sig", 64);
  if (!assertionSig.ok) return assertionSig;
  const authenticatorData = binary(members, "authenticator_data");
  if (!authenticatorData.ok) return authenticatorData;
  const clientDataJson = binary(members, "client_data_json");
  if (!clientDataJson.ok) return clientDataJson;
  return {
    ok: true,
    value: {
      targetHash: members.get("target_hash")!,
      attesterKey: attesterKey.value,
      assertionSig: assertionSig.value,
      authenticatorData: authenticatorData.value,
      clientDataJson: clientDataJson.value,
    },
  };
}

/** Read one line's bytes as an entry, or say why it is malformed. */
export function decodeEntry(line: Uint8Array): Parsed<Entry> {
  const text = utf8Decode(line);
  if (text === null) return fail("not valid UTF-8");
  const json = parseJson(text, { rejectUnpairedSurrogates: true });
  if (!json.ok) return json;
  const flat = asFlatStringObject(json.value);
  if (!flat.ok) return flat;
  const members = flat.value;
  const vocabulary = allowedMembers(members);
  if (!vocabulary.ok) return vocabulary;

  const payloadHash = binary(members, "payload_hash", 32);
  if (!payloadHash.ok) return payloadHash;
  const prevHash = binary(members, "prev_hash", 32);
  if (!prevHash.ok) return prevHash;
  const publicKey = compressedKey(members, "public_key");
  if (!publicKey.ok) return publicKey;
  const signature = binary(members, "signature", 64);
  if (!signature.ok) return signature;

  const entry: Entry = { members, prevHash: prevHash.value, publicKey: publicKey.value, signature: signature.value };
  if (vocabulary.value.mint) {
    const mint = decodeMint(members);
    if (!mint.ok) return mint;
    entry.mint = mint.value;
  }
  return { ok: true, value: entry };
}
