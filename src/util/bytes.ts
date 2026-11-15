/** Byte-level helpers shared by the scanner hot path. */

export const BYTE_TAB = 9;
export const BYTE_NL = 10;
export const BYTE_CR = 13;
export const BYTE_SP = 32;
export const BYTE_DQUOTE = 34;
export const BYTE_PERIOD = 46;
export const BYTE_SLASH = 47;
export const BYTE_COLON = 58;
export const BYTE_AT = 64;
export const BYTE_LBRACKET = 91;
export const BYTE_RBRACKET = 93;
export const BYTE_LBRACE = 123;
export const BYTE_RBRACE = 125;
export const BYTE_BACKSLASH = 92;

/** ASCII lowercasing for one byte (leaves non-uppercase bytes untouched). */
export function lowerByte(c: number): number {
  return c >= 65 && c <= 90 ? c + 32 : c;
}

export function isAlpha(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

export function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}

export function isAlnum(c: number): boolean {
  return isAlpha(c) || isDigit(c);
}

/** Hex nibble value, or -1. */
export function hexNibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}

export function isHexByte(c: number): boolean {
  return hexNibble(c) >= 0;
}

/** Byte-wise ASCII case-insensitive compare of a slice and a lowercase literal. */
export function equalsIgnoreCase(b: Uint8Array, start: number, end: number, lowerLiteral: string): boolean {
  if (end - start !== lowerLiteral.length) return false;
  for (let i = 0; i < lowerLiteral.length; i++) {
    if (lowerByte(b[start + i] as number) !== lowerLiteral.charCodeAt(i)) return false;
  }
  return true;
}
