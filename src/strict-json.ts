// A JSON parser that keeps what JSON.parse discards: duplicate member names
// stay visible, and an escape denoting an unpaired UTF-16 surrogate is reported
// rather than passed through. The specification makes both fatal for entries
// and Hub statements, so the verifier cannot use the platform parser.

export type JsonValue =
  | { type: "string"; value: string }
  | { type: "object"; members: JsonMember[] }
  | { type: "array"; items: JsonValue[] }
  | { type: "number"; raw: string }
  | { type: "literal"; value: boolean | null };

export interface JsonMember {
  name: string;
  value: JsonValue;
}

export type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };

const MAX_DEPTH = 64;

class Fault extends Error {}

class Reader {
  position = 0;
  constructor(
    readonly text: string,
    readonly rejectUnpairedSurrogates: boolean,
  ) {}

  fail(reason: string): never {
    throw new Fault(`${reason} at character ${this.position}`);
  }

  skipWhitespace(): void {
    while (this.position < this.text.length) {
      const char = this.text[this.position];
      if (char !== " " && char !== "\t" && char !== "\n" && char !== "\r") return;
      this.position++;
    }
  }

  expect(char: string): void {
    if (this.text[this.position] !== char) this.fail(`expected '${char}'`);
    this.position++;
  }

  value(depth: number): JsonValue {
    if (depth > MAX_DEPTH) this.fail("nesting too deep");
    const char = this.text[this.position];
    if (char === '"') return { type: "string", value: this.string() };
    if (char === "{") return this.object(depth);
    if (char === "[") return this.array(depth);
    if (char === "t") return this.literal("true", true);
    if (char === "f") return this.literal("false", false);
    if (char === "n") return this.literal("null", null);
    if (char === "-" || (char !== undefined && char >= "0" && char <= "9")) return this.number();
    return this.fail("expected a JSON value");
  }

  literal(word: string, value: boolean | null): JsonValue {
    if (!this.text.startsWith(word, this.position)) this.fail("expected a JSON value");
    this.position += word.length;
    return { type: "literal", value };
  }

  number(): JsonValue {
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.position));
    if (match === null) return this.fail("malformed number");
    this.position += match[0].length;
    return { type: "number", raw: match[0] };
  }

  object(depth: number): JsonValue {
    this.expect("{");
    const members: JsonMember[] = [];
    this.skipWhitespace();
    if (this.text[this.position] === "}") {
      this.position++;
      return { type: "object", members };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"') this.fail("expected a member name");
      const name = this.string();
      this.skipWhitespace();
      this.expect(":");
      this.skipWhitespace();
      members.push({ name, value: this.value(depth + 1) });
      this.skipWhitespace();
      if (this.text[this.position] === ",") {
        this.position++;
        continue;
      }
      this.expect("}");
      return { type: "object", members };
    }
  }

  array(depth: number): JsonValue {
    this.expect("[");
    const items: JsonValue[] = [];
    this.skipWhitespace();
    if (this.text[this.position] === "]") {
      this.position++;
      return { type: "array", items };
    }
    for (;;) {
      this.skipWhitespace();
      items.push(this.value(depth + 1));
      this.skipWhitespace();
      if (this.text[this.position] === ",") {
        this.position++;
        continue;
      }
      this.expect("]");
      return { type: "array", items };
    }
  }

  string(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      const char = this.text[this.position];
      if (char === undefined) this.fail("unterminated string");
      if (char === '"') {
        this.position++;
        return out;
      }
      if (char < " ") this.fail("unescaped control character in string");
      if (char !== "\\") {
        out += char;
        this.position++;
        continue;
      }
      out += this.escape();
    }
  }

  escape(): string {
    this.position++;
    const char = this.text[this.position];
    this.position++;
    switch (char) {
      case '"':
        return '"';
      case "\\":
        return "\\";
      case "/":
        return "/";
      case "b":
        return "\b";
      case "f":
        return "\f";
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      case "u":
        return this.unicodeEscape();
      default:
        return this.fail("unknown escape");
    }
  }

  hex4(): number {
    const digits = this.text.slice(this.position, this.position + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(digits)) this.fail("malformed \\u escape");
    this.position += 4;
    return parseInt(digits, 16);
  }

  unicodeEscape(): string {
    const unit = this.hex4();
    const isHigh = unit >= 0xd800 && unit <= 0xdbff;
    const isLow = unit >= 0xdc00 && unit <= 0xdfff;
    if (!isHigh && !isLow) return String.fromCharCode(unit);
    if (isHigh && this.text.startsWith("\\u", this.position)) {
      const mark = this.position;
      this.position += 2;
      const next = this.hex4();
      if (next >= 0xdc00 && next <= 0xdfff) return String.fromCharCode(unit, next);
      this.position = mark;
    }
    if (this.rejectUnpairedSurrogates) this.fail("escape denotes an unpaired surrogate");
    return String.fromCharCode(unit);
  }
}

/** Parse one JSON text. Whitespace around the value is allowed; anything else after it is a fault. */
export function parseJson(text: string, options: { rejectUnpairedSurrogates: boolean }): Parsed<JsonValue> {
  const reader = new Reader(text, options.rejectUnpairedSurrogates);
  try {
    reader.skipWhitespace();
    const value = reader.value(0);
    reader.skipWhitespace();
    if (reader.position !== text.length) reader.fail("content after the JSON value");
    return { ok: true, value };
  } catch (error) {
    if (error instanceof Fault) return { ok: false, reason: error.message };
    throw error;
  }
}

/**
 * Read a value as the shape every signed EventChain object has: one object whose
 * members are all strings, with no name appearing twice.
 */
export function asFlatStringObject(value: JsonValue): Parsed<Map<string, string>> {
  if (value.type !== "object") return { ok: false, reason: "not a JSON object" };
  const members = new Map<string, string>();
  for (const member of value.members) {
    if (members.has(member.name)) return { ok: false, reason: `duplicate member "${member.name}"` };
    if (member.value.type !== "string") return { ok: false, reason: `member "${member.name}" is not a string` };
    members.set(member.name, member.value.value);
  }
  return { ok: true, value: members };
}
