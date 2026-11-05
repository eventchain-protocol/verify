// Exact arithmetic on the specification's decimal strings (positions, Unix
// seconds with an optional fraction). No floating point: a position or a
// timestamp is compared as written.

const DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]*[1-9]))?$/;
const INTEGER = /^(0|[1-9][0-9]*)$/;

/** ASCII decimal digits without leading zeros. */
export function isInteger(text: string): boolean {
  return INTEGER.test(text);
}

/** An integer, optionally followed by a point and fractional digits without trailing zeros. */
export function isDecimal(text: string): boolean {
  return DECIMAL.test(text);
}

export function fractionDigits(text: string): number {
  return DECIMAL.exec(text)?.[2]?.length ?? 0;
}

/** The value times 10^digits, as an integer. `digits` must cover the text's own fraction. */
export function scaled(text: string, digits: number): bigint {
  const match = DECIMAL.exec(text);
  if (match === null) throw new Error(`not a decimal: ${text}`);
  const fraction = match[2] ?? "";
  if (fraction.length > digits) throw new Error(`fraction of ${text} exceeds ${digits} digits`);
  return BigInt(match[1]! + fraction.padEnd(digits, "0"));
}
