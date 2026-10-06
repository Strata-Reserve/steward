// STRATA-1499 / SF-1: minimal, dependency-free calldata helpers for policy
// evaluation. Deliberately strict: anything that is not well-formed hex of the
// expected length is reported as a failure so callers can fail closed. We do
// not attempt to understand dynamic ABI types; a rule declares the 0-based
// static word index of the uint256 it cares about and we read exactly that
// 32-byte word.
//
// A fuller ABI-aware decoder (per-selector argument decoding with named
// constraints) is being added alongside this module for the contract-allowlist
// policy. The two are intentionally independent for now; consolidating them is
// a follow-up once both have landed.

export const UINT256_MAX = (1n << 256n) - 1n;

const HEX_BODY = /^[0-9a-fA-F]*$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;

export type DecodeResult<T> = { ok: true; value: T } | { ok: false; reason: string };

export function isHexAddress(value: unknown): value is string {
  return typeof value === "string" && ADDRESS_RE.test(value);
}

export function isHexSelector(value: unknown): value is string {
  return typeof value === "string" && SELECTOR_RE.test(value);
}

/**
 * Validate that `data` is `0x`-prefixed, even-length hex. Returns the hex body
 * (without the prefix, lower-cased) or a reason.
 */
export function normalizeHexData(data: unknown): DecodeResult<string> {
  if (typeof data !== "string") return { ok: false, reason: "calldata is not a string" };
  if (!data.startsWith("0x") && !data.startsWith("0X")) {
    return { ok: false, reason: "calldata is missing the 0x prefix" };
  }
  const body = data.slice(2);
  if (body.length % 2 !== 0) return { ok: false, reason: "calldata has odd hex length" };
  if (!HEX_BODY.test(body)) return { ok: false, reason: "calldata contains non-hex characters" };
  return { ok: true, value: body.toLowerCase() };
}

/**
 * Extract the 4-byte function selector from calldata. Fails for empty or
 * short calldata (fewer than 4 bytes) and for malformed hex.
 */
export function extractSelector(data: unknown): DecodeResult<string> {
  const hex = normalizeHexData(data);
  if (!hex.ok) return hex;
  if (hex.value.length < 8) {
    return { ok: false, reason: "calldata shorter than 4 bytes (no function selector)" };
  }
  return { ok: true, value: `0x${hex.value.slice(0, 8)}` };
}

/**
 * Read the `argIndex`-th 32-byte static word after the selector as a uint256.
 * The word must be fully present; a truncated word is a failure, never a
 * zero-padded guess. Values are bounded by construction (32 bytes), so the
 * result is always within [0, 2^256 - 1].
 */
export function decodeUint256Arg(data: unknown, argIndex: number): DecodeResult<bigint> {
  if (!Number.isInteger(argIndex) || argIndex < 0) {
    return { ok: false, reason: `invalid argument index ${String(argIndex)}` };
  }
  const hex = normalizeHexData(data);
  if (!hex.ok) return hex;
  if (hex.value.length < 8) {
    return { ok: false, reason: "calldata shorter than 4 bytes (no function selector)" };
  }
  const start = 8 + argIndex * 64;
  const end = start + 64;
  if (hex.value.length < end) {
    return {
      ok: false,
      reason: `calldata too short for uint256 argument at index ${argIndex} (need ${end / 2} bytes, have ${hex.value.length / 2})`,
    };
  }
  const word = hex.value.slice(start, end);
  return { ok: true, value: BigInt(`0x${word}`) };
}

/**
 * Parse a decimal uint256 string (as used in policy configs). Rejects signs,
 * whitespace, exponents, hex, and anything above 2^256 - 1.
 */
export function parseUint256Decimal(value: unknown): DecodeResult<bigint> {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    return { ok: false, reason: "expected a decimal uint256 string" };
  }
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX) return { ok: false, reason: "value exceeds uint256" };
  return { ok: true, value: parsed };
}
