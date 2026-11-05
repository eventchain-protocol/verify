// RFC 8785 (JCS) for the only shape the protocol signs: a flat object of
// string members. No numbers, so none of RFC 8785's number formatting applies.

import { utf8Encode } from "./bytes.js";

const SHORT_ESCAPES = new Map<string, string>([
  ["\b", "\\b"],
  ["\t", "\\t"],
  ["\n", "\\n"],
  ["\f", "\\f"],
  ["\r", "\\r"],
  ['"', '\\"'],
  ["\\", "\\\\"],
]);

function serializeString(text: string): string {
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    const short = SHORT_ESCAPES.get(char);
    if (short !== undefined) out += short;
    else if (char < " ") out += "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0");
    else out += char;
  }
  return out + '"';
}

/**
 * The signed message: the members without the one named `exclude`, ordered by
 * name as UTF-16 code units (the order JavaScript's `<` gives strings), encoded as UTF-8.
 */
export function canonicalize(members: ReadonlyMap<string, string>, exclude: string): Uint8Array {
  const names = [...members.keys()].filter((name) => name !== exclude).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const body = names.map((name) => `${serializeString(name)}:${serializeString(members.get(name)!)}`).join(",");
  return utf8Encode(`{${body}}`);
}
