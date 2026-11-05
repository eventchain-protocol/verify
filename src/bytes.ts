// Byte helpers: strict unpadded base64url (RFC 4648 §5), UTF-8, comparison.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const VALUE_OF = new Map<string, number>([...ALPHABET].map((char, index) => [char, index]));

export function base64urlEncode(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    text += ALPHABET[b0 >> 2]!;
    text += ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    if (b1 === undefined) break;
    text += ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    if (b2 === undefined) break;
    text += ALPHABET[b2 & 0x3f]!;
  }
  return text;
}

/**
 * Decode unpadded base64url. Returns null for padding, a character outside the
 * alphabet, an impossible length, or non-zero bits after the last whole byte:
 * one byte string has exactly one accepted spelling.
 */
export function base64urlDecode(text: string): Uint8Array | null {
  if (text.length % 4 === 1) return null;
  const bytes = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let written = 0;
  for (const char of text) {
    const value = VALUE_OF.get(char);
    if (value === undefined) return null;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[written++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  if (buffer !== 0) return null;
  return bytes;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

/** Decode UTF-8, keeping a byte-order mark as a character. Returns null for invalid UTF-8. */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return null;
  }
}

export function utf8Encode(text: string): Uint8Array {
  return utf8Encoder.encode(text);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
