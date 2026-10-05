// STRATA-1499: strict ABI calldata decoding for the contract-allowlist policy.
//
// This module is deliberately narrower than a general ABI decoder. The policy
// engine only needs to pull a handful of arguments out of a fixed set of
// function shapes, and it must never be tricked into approving a transaction
// whose calldata it misread. So every decoder here is fail-closed:
//
// - the calldata must be exactly the canonical ABI length for the function
//   (no trailing bytes, no truncated words)
// - address words must have 12 zero bytes of padding (a non-zero high word
//   is treated as malformed, not silently masked)
// - uint256 words are read in full; there is no overflow because the value
//   is a bigint, but a caller comparing against a cap must compare bigints
//
// Anything the decoder does not recognise returns `null` and the evaluator
// turns that into a denial. Supported selectors are listed in
// `SUPPORTED_SELECTORS`; add new ones alongside their decoder.

import { toFunctionSelector } from "viem";

export const SELECTOR_MINT = toFunctionSelector("mint(address,uint256)");
export const SELECTOR_TRANSFER = toFunctionSelector("transfer(address,uint256)");
export const SELECTOR_APPROVE = toFunctionSelector("approve(address,uint256)");
export const SELECTOR_TRANSFER_FROM = toFunctionSelector("transferFrom(address,address,uint256)");
export const SELECTOR_CREATE_DEAL_TOKEN = toFunctionSelector(
  "createDealToken(string,string,address,bytes32)",
);

const WORD_HEX = 64;
const SELECTOR_HEX = 8;
const UINT256_MAX = (1n << 256n) - 1n;

export interface DecodedAmountCall {
  kind: "amount";
  selector: string;
  /** Recipient for mint/transfer/transferFrom, spender for approve. */
  recipient: string;
  /** Source account for transferFrom; undefined otherwise. */
  from?: string;
  amount: bigint;
}

export interface DecodedCreateDealTokenCall {
  kind: "createDealToken";
  selector: string;
  admin: string;
}

export type DecodedCall = DecodedAmountCall | DecodedCreateDealTokenCall;

export const SUPPORTED_SELECTORS: ReadonlySet<string> = new Set([
  SELECTOR_MINT,
  SELECTOR_TRANSFER,
  SELECTOR_APPROVE,
  SELECTOR_TRANSFER_FROM,
  SELECTOR_CREATE_DEAL_TOKEN,
]);

export function isSupportedSelector(selector: string): boolean {
  return SUPPORTED_SELECTORS.has(selector.toLowerCase());
}

/** `0x` + 40 hex. */
export function isHexAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

/** `0x` + 8 hex. */
export function isHexSelector(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{8}$/.test(value);
}

/** Non-negative decimal integer that fits in uint256. */
export function isUint256Decimal(value: unknown): value is string {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) return false;
  return BigInt(value) <= UINT256_MAX;
}

/**
 * Normalise calldata to lowercase hex without the 0x prefix, or null when
 * the input is not a well-formed hex string of whole bytes.
 */
function normalizeHex(data: unknown): string | null {
  if (typeof data !== "string") return null;
  const body = data.startsWith("0x") || data.startsWith("0X") ? data.slice(2) : null;
  if (body === null) return null;
  if (body.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(body)) return null;
  return body.toLowerCase();
}

/**
 * Returns true when the request carries no calldata at all (`undefined`,
 * `""`, `"0x"`). Malformed hex is NOT empty; it is malformed.
 */
export function isEmptyCalldata(data: unknown): boolean {
  if (data === undefined || data === null) return true;
  if (typeof data !== "string") return false;
  return data === "" || data.toLowerCase() === "0x";
}

/**
 * Extract the 4-byte selector from calldata. Returns null if the calldata is
 * not well-formed hex or shorter than 4 bytes.
 */
export function extractSelector(data: unknown): string | null {
  const hex = normalizeHex(data);
  if (hex === null || hex.length < SELECTOR_HEX) return null;
  return `0x${hex.slice(0, SELECTOR_HEX)}`;
}

function readWord(hex: string, index: number): string | null {
  const start = SELECTOR_HEX + index * WORD_HEX;
  const end = start + WORD_HEX;
  if (end > hex.length) return null;
  return hex.slice(start, end);
}

/** Address word: 12 zero bytes then 20 bytes of address. Non-zero padding is malformed. */
function readAddressWord(hex: string, index: number): string | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  if (!/^0{24}[0-9a-f]{40}$/.test(word)) return null;
  return `0x${word.slice(24)}`;
}

function readUint256Word(hex: string, index: number): bigint | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  return BigInt(`0x${word}`);
}

/** Dynamic-type head word must be an in-range, word-aligned offset. */
function readOffsetWord(hex: string, index: number, argsLength: number): number | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  const offset = BigInt(`0x${word}`);
  if (offset % 32n !== 0n) return null;
  if (offset >= BigInt(argsLength)) return null;
  return Number(offset);
}

function expectExactLength(hex: string, words: number): boolean {
  return hex.length === SELECTOR_HEX + words * WORD_HEX;
}

/**
 * Decode calldata for one of the supported selectors. Returns null for
 * anything unsupported, truncated, over-long or with non-canonical padding.
 */
export function decodeCalldata(data: unknown): DecodedCall | null {
  const hex = normalizeHex(data);
  if (hex === null || hex.length < SELECTOR_HEX) return null;
  const selector = `0x${hex.slice(0, SELECTOR_HEX)}`;

  switch (selector) {
    case SELECTOR_MINT:
    case SELECTOR_TRANSFER:
    case SELECTOR_APPROVE: {
      if (!expectExactLength(hex, 2)) return null;
      const recipient = readAddressWord(hex, 0);
      const amount = readUint256Word(hex, 1);
      if (recipient === null || amount === null) return null;
      return { kind: "amount", selector, recipient, amount };
    }
    case SELECTOR_TRANSFER_FROM: {
      if (!expectExactLength(hex, 3)) return null;
      const from = readAddressWord(hex, 0);
      const recipient = readAddressWord(hex, 1);
      const amount = readUint256Word(hex, 2);
      if (from === null || recipient === null || amount === null) return null;
      return { kind: "amount", selector, recipient, from, amount };
    }
    case SELECTOR_CREATE_DEAL_TOKEN:
      return decodeCreateDealToken(hex, selector);
    default:
      return null;
  }
}

/**
 * createDealToken(string name, string symbol, address admin, bytes32 salt)
 *
 * Head: [offset(name), offset(symbol), admin, salt] = 4 words.
 * Tail: two length-prefixed, 32-byte-padded strings at the given offsets.
 * The admin argument is static and read straight from the head. The string
 * tails are validated for structure (word-aligned offsets inside the args
 * area, lengths that fit, total length exactly consumed) so that padding
 * tricks cannot smuggle an unexpected layout past the policy.
 */
function decodeCreateDealToken(hex: string, selector: string): DecodedCreateDealTokenCall | null {
  const argsHex = hex.slice(SELECTOR_HEX);
  const argsLength = argsHex.length / 2;
  // Head (4 words) + at least one word of length for each string.
  if (argsLength < 6 * 32 || argsLength % 32 !== 0) return null;

  const nameOffset = readOffsetWord(hex, 0, argsLength);
  const symbolOffset = readOffsetWord(hex, 1, argsLength);
  const admin = readAddressWord(hex, 2);
  const salt = readWord(hex, 3);
  if (nameOffset === null || symbolOffset === null || admin === null || salt === null) return null;
  if (nameOffset < 4 * 32 || symbolOffset < 4 * 32) return null;

  const nameEnd = dynamicBytesEnd(argsHex, nameOffset);
  const symbolEnd = dynamicBytesEnd(argsHex, symbolOffset);
  if (nameEnd === null || symbolEnd === null) return null;

  // Tails must be laid out back to back (in either order) and consume the
  // whole args area with no stray bytes.
  const [first, second] =
    nameOffset <= symbolOffset
      ? [
          { start: nameOffset, end: nameEnd },
          { start: symbolOffset, end: symbolEnd },
        ]
      : [
          { start: symbolOffset, end: symbolEnd },
          { start: nameOffset, end: nameEnd },
        ];
  if (first.start !== 4 * 32) return null;
  if (second.start !== first.end) return null;
  if (second.end !== argsLength) return null;

  return { kind: "createDealToken", selector, admin };
}

/**
 * For a dynamic `bytes`/`string` tail starting at `offset` (bytes into the
 * args area), return the byte offset just past its padded payload, or null
 * if the length word is out of range or the padding is non-zero.
 */
function dynamicBytesEnd(argsHex: string, offset: number): number | null {
  const lenStart = offset * 2;
  const lenWord = argsHex.slice(lenStart, lenStart + WORD_HEX);
  if (lenWord.length !== WORD_HEX) return null;
  const length = BigInt(`0x${lenWord}`);
  if (length > BigInt(argsHex.length / 2)) return null;
  const len = Number(length);
  const paddedLen = Math.ceil(len / 32) * 32;
  const payloadStart = lenStart + WORD_HEX;
  const payloadEnd = payloadStart + paddedLen * 2;
  if (payloadEnd > argsHex.length) return null;
  const padding = argsHex.slice(payloadStart + len * 2, payloadEnd);
  if (!/^0*$/.test(padding)) return null;
  return offset + 32 + paddedLen;
}
