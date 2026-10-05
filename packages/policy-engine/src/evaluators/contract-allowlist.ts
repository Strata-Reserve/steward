// STRATA-1499: contract-allowlist policy evaluator.
//
// Restricts EVM signing to a known set of (contract, function selector)
// pairs, with optional per-selector argument constraints such as a maximum
// mint amount or a recipient allowlist. Everything is fail-closed:
//
// - target address not listed            => deny
// - calldata malformed or < 4 bytes      => deny
// - selector not listed for that target  => deny
// - constraint present but calldata does not decode to the expected shape
//   (or the selector has no decoder)      => deny, never silently ignored
// - empty calldata                       => deny unless allowNativeTransfer
// - value above maxNativeValueWei        => deny (default cap is 0)
// - config fails validation              => deny with the validation error
//
// The same validator runs at write time in the API so operators get the
// error on PUT rather than discovering it as a denial on the first sign.

import type {
  ContractAllowlistConfig,
  ContractAllowlistEntry,
  ContractAllowlistSelectorConstraints,
  PolicyResult,
  PolicyRule,
} from "@stwd/shared";
import {
  type DecodedCall,
  decodeCalldata,
  extractSelector,
  isEmptyCalldata,
  isHexAddress,
  isHexSelector,
  isSupportedSelector,
  isUint256Decimal,
  SELECTOR_CREATE_DEAL_TOKEN,
} from "../calldata";

export interface ContractAllowlistContext {
  to: string;
  value: string;
  data?: string;
}

const PREFIX = "contract-allowlist";

const AMOUNT_CONSTRAINT_KEYS = new Set(["maxAmount", "recipientAllowlist"]);
const CREATE_DEAL_TOKEN_CONSTRAINT_KEYS = new Set(["adminAllowlist"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAddressArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(isHexAddress);
}

/**
 * Validate a contract-allowlist config. Returns an error string describing
 * the first problem found, or null when the config is well-formed.
 *
 * Shared by the API (reject on PUT) and the evaluator (deny on sign).
 */
export function validateContractAllowlistConfig(config: unknown): string | null {
  if (!isRecord(config)) return "config must be an object";

  const { contracts, allowNativeTransfer, maxNativeValueWei, ...rest } = config;
  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length > 0) return `unknown config field(s): ${unknownKeys.join(", ")}`;

  if (allowNativeTransfer !== undefined && typeof allowNativeTransfer !== "boolean") {
    return "allowNativeTransfer must be a boolean";
  }
  if (maxNativeValueWei !== undefined && !isUint256Decimal(maxNativeValueWei)) {
    return "maxNativeValueWei must be a uint256 decimal string";
  }

  if (!Array.isArray(contracts) || contracts.length === 0) {
    return "contracts must be a non-empty array";
  }

  const seenAddresses = new Set<string>();
  for (const [i, entry] of contracts.entries()) {
    const where = `contracts[${i}]`;
    const err = validateEntry(entry, where);
    if (err) return err;
    const lower = (entry as ContractAllowlistEntry).address.toLowerCase();
    if (seenAddresses.has(lower)) return `${where}: duplicate address ${lower}`;
    seenAddresses.add(lower);
  }

  return null;
}

function validateEntry(entry: unknown, where: string): string | null {
  if (!isRecord(entry)) return `${where} must be an object`;
  const { address, selectors, constraints, ...rest } = entry;
  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length > 0) return `${where}: unknown field(s): ${unknownKeys.join(", ")}`;

  if (!isHexAddress(address)) return `${where}.address must be a 0x-prefixed 20-byte hex address`;

  if (!Array.isArray(selectors) || selectors.length === 0) {
    return `${where}.selectors must be a non-empty array`;
  }
  const seen = new Set<string>();
  for (const [j, sel] of selectors.entries()) {
    if (!isHexSelector(sel)) {
      return `${where}.selectors[${j}] must be a 0x-prefixed 4-byte hex selector`;
    }
    const lower = sel.toLowerCase();
    if (seen.has(lower)) return `${where}.selectors[${j}]: duplicate selector ${lower}`;
    seen.add(lower);
  }

  if (constraints === undefined) return null;
  if (!isRecord(constraints)) return `${where}.constraints must be an object keyed by selector`;

  for (const [key, value] of Object.entries(constraints)) {
    const cwhere = `${where}.constraints[${key}]`;
    if (!isHexSelector(key)) return `${cwhere}: key must be a 0x-prefixed 4-byte hex selector`;
    const lower = key.toLowerCase();
    if (!seen.has(lower)) return `${cwhere}: selector is not in this entry's selectors list`;
    if (!isSupportedSelector(lower)) {
      return `${cwhere}: no decoder for this selector; constraints cannot be enforced`;
    }
    const err = validateConstraints(lower, value, cwhere);
    if (err) return err;
  }

  return null;
}

function validateConstraints(selector: string, value: unknown, where: string): string | null {
  if (!isRecord(value)) return `${where} must be an object`;
  const keys = Object.keys(value);
  if (keys.length === 0) return `${where} must not be empty`;

  const allowed =
    selector === SELECTOR_CREATE_DEAL_TOKEN
      ? CREATE_DEAL_TOKEN_CONSTRAINT_KEYS
      : AMOUNT_CONSTRAINT_KEYS;
  for (const key of keys) {
    if (!allowed.has(key)) {
      return `${where}.${key} does not apply to selector ${selector} (allowed: ${[...allowed].join(", ")})`;
    }
  }

  const c = value as ContractAllowlistSelectorConstraints;
  if (c.maxAmount !== undefined && !isUint256Decimal(c.maxAmount)) {
    return `${where}.maxAmount must be a uint256 decimal string`;
  }
  if (c.recipientAllowlist !== undefined && !isAddressArray(c.recipientAllowlist)) {
    return `${where}.recipientAllowlist must be a non-empty array of hex addresses`;
  }
  if (c.adminAllowlist !== undefined && !isAddressArray(c.adminAllowlist)) {
    return `${where}.adminAllowlist must be a non-empty array of hex addresses`;
  }
  return null;
}

function parseValueWei(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (/^[0-9]+$/.test(trimmed)) return BigInt(trimmed);
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) return BigInt(trimmed);
  return null;
}

function includesAddress(list: string[], address: string): boolean {
  const lower = address.toLowerCase();
  return list.some((a) => a.toLowerCase() === lower);
}

export function evaluateContractAllowlist(
  rule: PolicyRule,
  ctx: ContractAllowlistContext,
): PolicyResult {
  const base = { policyId: rule.id, type: rule.type } as const;
  const deny = (reason: string): PolicyResult => ({
    ...base,
    passed: false,
    reason: `${PREFIX}: ${reason}`,
  });

  const configError = validateContractAllowlistConfig(rule.config);
  if (configError) return deny(`invalid config (${configError})`);
  const config = rule.config as unknown as ContractAllowlistConfig;

  // ── Target ────────────────────────────────────────────────────────────────
  if (!isHexAddress(ctx.to)) return deny(`target ${String(ctx.to)} is not an EVM address`);
  const entry = config.contracts.find((e) => e.address.toLowerCase() === ctx.to.toLowerCase());
  if (!entry) return deny(`target ${ctx.to} is not an allowlisted contract`);

  // ── Native value ──────────────────────────────────────────────────────────
  const value = parseValueWei(ctx.value);
  if (value === null) return deny(`value ${String(ctx.value)} is not a valid wei amount`);
  const maxValue = BigInt(config.maxNativeValueWei ?? "0");
  if (value > maxValue) return deny(`value ${value} exceeds maxNativeValueWei ${maxValue}`);

  // ── Empty calldata (plain transfer) ───────────────────────────────────────
  if (isEmptyCalldata(ctx.data)) {
    if (config.allowNativeTransfer === true) {
      return { ...base, passed: true, reason: `${PREFIX}: native transfer to ${ctx.to} allowed` };
    }
    return deny("empty calldata is not allowed (allowNativeTransfer is false)");
  }

  // ── Selector ──────────────────────────────────────────────────────────────
  const selector = extractSelector(ctx.data);
  if (selector === null) return deny("calldata is malformed or shorter than 4 bytes");
  const listed = entry.selectors.some((s) => s.toLowerCase() === selector);
  if (!listed) return deny(`selector ${selector} is not allowlisted on ${ctx.to}`);

  // ── Constraints ───────────────────────────────────────────────────────────
  const constraints = findConstraints(entry, selector);
  if (!constraints) {
    return { ...base, passed: true, reason: `${PREFIX}: ${selector} on ${ctx.to} allowed` };
  }

  const decoded = decodeCalldata(ctx.data);
  if (!decoded) {
    return deny(
      `constraints set for ${selector} but calldata does not decode to the expected shape`,
    );
  }
  const violation = checkConstraints(decoded, constraints);
  if (violation) return deny(violation);

  return {
    ...base,
    passed: true,
    reason: `${PREFIX}: ${selector} on ${ctx.to} allowed within constraints`,
  };
}

function findConstraints(
  entry: ContractAllowlistEntry,
  selector: string,
): ContractAllowlistSelectorConstraints | undefined {
  if (!entry.constraints) return undefined;
  for (const [key, value] of Object.entries(entry.constraints)) {
    if (key.toLowerCase() === selector) return value;
  }
  return undefined;
}

function checkConstraints(
  decoded: DecodedCall,
  constraints: ContractAllowlistSelectorConstraints,
): string | null {
  if (decoded.kind === "amount") {
    if (constraints.adminAllowlist !== undefined) {
      return `adminAllowlist does not apply to ${decoded.selector}`;
    }
    if (constraints.maxAmount !== undefined && decoded.amount > BigInt(constraints.maxAmount)) {
      return `amount ${decoded.amount} exceeds maxAmount ${constraints.maxAmount} for ${decoded.selector}`;
    }
    if (
      constraints.recipientAllowlist !== undefined &&
      !includesAddress(constraints.recipientAllowlist, decoded.recipient)
    ) {
      return `recipient ${decoded.recipient} is not in recipientAllowlist for ${decoded.selector}`;
    }
    return null;
  }

  // createDealToken
  if (constraints.maxAmount !== undefined || constraints.recipientAllowlist !== undefined) {
    return `maxAmount/recipientAllowlist do not apply to ${decoded.selector}`;
  }
  if (
    constraints.adminAllowlist !== undefined &&
    !includesAddress(constraints.adminAllowlist, decoded.admin)
  ) {
    return `admin ${decoded.admin} is not in adminAllowlist for ${decoded.selector}`;
  }
  return null;
}
