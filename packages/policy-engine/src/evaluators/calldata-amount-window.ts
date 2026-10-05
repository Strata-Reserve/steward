// STRATA-1499 / SF-1: calldata-amount-window policy evaluator.
//
// Caps the SUM of a decoded uint256 calldata argument for calls to a given
// (contract, selector) over a rolling window. Built for the Strata deal-token
// minter: `DealTokenV1.mint(address,uint256)` (0x40c10f19) is uncapped on
// chain, so the signer is the only place a volume ceiling can live.
//
// Everything about this evaluator fails closed:
//   - malformed config                        -> deny
//   - target contract listed, calldata is
//     present but not parseable as a selector -> deny
//   - amount argument missing / truncated     -> deny
//   - no history lookup wired into the engine -> deny
//   - history lookup throws                   -> deny
//   - a prior row we cannot decode            -> deny (we cannot prove the sum)
//   - sum + amount > maxPerWindow             -> deny, or manual approval when
//                                                `overCap: "manual-approval"`
//
// Empty calldata (`undefined`, `""`, `"0x"`) carries no selector and so can
// never be the capped call; it follows `unmatched` like any other non-matching
// selector. Calldata that is present but shorter than 4 bytes or not valid hex
// is denied: we cannot prove what it is.
//
// The window sum is computed server-side from this agent's own prior signing
// records. Which statuses count is decided by the lookup the API binds (see
// `createCalldataHistoryLookup`); nothing in the request body is trusted as a
// total.

import type { CalldataAmountWindowRule, PolicyResult, PolicyRule, SignRequest } from "@stwd/shared";
import {
  decodeUint256Arg,
  extractSelector,
  isHexAddress,
  isHexSelector,
  parseUint256Decimal,
} from "../calldata-decoder";

/** A prior signing record relevant to a window-sum query. */
export interface CalldataHistoryRow {
  to: string;
  data: string | null | undefined;
  chainId: number;
}

export interface CalldataHistoryQuery {
  /** Lower-cased target contract address. */
  contract: string;
  /** Lower-cased 4-byte selector (0x + 8 hex). */
  selector: string;
  chainId: number;
  /** Inclusive lower bound on the row's creation time. */
  since: Date;
}

/**
 * Returns the agent's prior signing records matching the query. The engine
 * owner (API) binds this to the current agent and excludes the row reserved
 * for the request under evaluation. Must throw (not return []) on any storage
 * error so the evaluator denies instead of under-counting.
 */
export type CalldataHistoryLookup = (query: CalldataHistoryQuery) => Promise<CalldataHistoryRow[]>;

export interface CalldataAmountWindowContext {
  request: SignRequest;
  calldataHistoryLookup?: CalldataHistoryLookup;
  /** Injectable clock for tests. */
  now?: Date;
}

const MAX_WINDOW_SECONDS = 365 * 86400;
const MAX_ARG_INDEX = 64;

type ValidatedRule = Omit<CalldataAmountWindowRule, "contract" | "selector" | "maxPerWindow"> & {
  contract: string;
  selector: string;
  maxPerWindow: bigint;
};

type ValidatedConfig = {
  rules: ValidatedRule[];
  unmatched: "pass" | "deny";
  overCap: "reject" | "manual-approval";
};

type ValidationResult = { ok: true; config: ValidatedConfig } | { ok: false; error: string };

/**
 * Validate a raw `calldata-amount-window` config (see
 * `CalldataAmountWindowConfig` in `@stwd/shared` for the declared shape).
 * Shared by the API (write time) and the evaluator (evaluation time) so a
 * config that slips past one cannot slip past the other.
 */
export function validateCalldataAmountWindowConfig(raw: unknown): ValidationResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, error: "config must be an object" };
  }
  const cfg = raw as Record<string, unknown>;

  if (!Array.isArray(cfg.rules) || cfg.rules.length === 0) {
    return { ok: false, error: "rules must be a non-empty array" };
  }

  const unmatched = cfg.unmatched ?? "pass";
  if (unmatched !== "pass" && unmatched !== "deny") {
    return { ok: false, error: 'unmatched must be "pass" or "deny"' };
  }
  const overCap = cfg.overCap ?? "reject";
  if (overCap !== "reject" && overCap !== "manual-approval") {
    return { ok: false, error: 'overCap must be "reject" or "manual-approval"' };
  }

  const rules: ValidatedRule[] = [];
  for (let i = 0; i < cfg.rules.length; i++) {
    const r = cfg.rules[i];
    const at = `rules[${i}]`;
    if (typeof r !== "object" || r === null || Array.isArray(r)) {
      return { ok: false, error: `${at} must be an object` };
    }
    const rule = r as Record<string, unknown>;
    if (!isHexAddress(rule.contract)) {
      return { ok: false, error: `${at}.contract must be a 0x-prefixed 20-byte address` };
    }
    if (!isHexSelector(rule.selector)) {
      return { ok: false, error: `${at}.selector must be a 0x-prefixed 4-byte selector` };
    }
    if (
      typeof rule.amountArgIndex !== "number" ||
      !Number.isInteger(rule.amountArgIndex) ||
      rule.amountArgIndex < 0 ||
      rule.amountArgIndex > MAX_ARG_INDEX
    ) {
      return {
        ok: false,
        error: `${at}.amountArgIndex must be an integer in [0, ${MAX_ARG_INDEX}]`,
      };
    }
    const max = parseUint256Decimal(rule.maxPerWindow);
    if (!max.ok) {
      return { ok: false, error: `${at}.maxPerWindow: ${max.reason}` };
    }
    if (
      typeof rule.windowSeconds !== "number" ||
      !Number.isInteger(rule.windowSeconds) ||
      rule.windowSeconds <= 0 ||
      rule.windowSeconds > MAX_WINDOW_SECONDS
    ) {
      return {
        ok: false,
        error: `${at}.windowSeconds must be an integer in [1, ${MAX_WINDOW_SECONDS}]`,
      };
    }
    if (
      rule.chainId !== undefined &&
      (typeof rule.chainId !== "number" || !Number.isInteger(rule.chainId) || rule.chainId <= 0)
    ) {
      return { ok: false, error: `${at}.chainId must be a positive integer when present` };
    }
    rules.push({
      contract: rule.contract.toLowerCase(),
      selector: rule.selector.toLowerCase(),
      amountArgIndex: rule.amountArgIndex,
      maxPerWindow: max.value,
      windowSeconds: rule.windowSeconds,
      ...(rule.chainId !== undefined ? { chainId: rule.chainId } : {}),
    });
  }

  return { ok: true, config: { rules, unmatched, overCap } };
}

export async function evaluateCalldataAmountWindow(
  rule: PolicyRule,
  ctx: CalldataAmountWindowContext,
): Promise<PolicyResult> {
  const base = { policyId: rule.id, type: rule.type } as const;
  const deny = (reason: string): PolicyResult => ({
    ...base,
    passed: false,
    reason: `calldata-amount-window: ${reason}`,
  });

  const validated = validateCalldataAmountWindowConfig(rule.config);
  if (!validated.ok) return deny(`invalid config (${validated.error})`);
  const config = validated.config;

  const to = typeof ctx.request.to === "string" ? ctx.request.to.toLowerCase() : "";
  const chainId = ctx.request.chainId;

  const contractRules = config.rules.filter(
    (r) => r.contract === to && (r.chainId === undefined || r.chainId === chainId),
  );

  if (contractRules.length === 0) {
    return config.unmatched === "deny"
      ? deny(`target ${ctx.request.to} is not covered by any rule (unmatched: deny)`)
      : { ...base, passed: true, reason: "calldata-amount-window: target not covered by any rule" };
  }

  // The target IS governed by this policy. Empty calldata has no selector and
  // provably is not the capped call: it is "unmatched". Anything else we
  // cannot interpret is denied.
  const hasData =
    typeof ctx.request.data === "string" &&
    ctx.request.data !== "" &&
    ctx.request.data.toLowerCase() !== "0x";
  if (!hasData) {
    return config.unmatched === "deny"
      ? deny(`call to ${ctx.request.to} has no calldata (unmatched: deny)`)
      : { ...base, passed: true, reason: "calldata-amount-window: no calldata, no rule applies" };
  }
  const selector = extractSelector(ctx.request.data);
  if (!selector.ok) {
    return deny(`call to governed contract ${ctx.request.to}: ${selector.reason}`);
  }

  const matching = contractRules.filter((r) => r.selector === selector.value);
  if (matching.length === 0) {
    return config.unmatched === "deny"
      ? deny(`selector ${selector.value} on ${ctx.request.to} is not covered by any rule`)
      : {
          ...base,
          passed: true,
          reason: `calldata-amount-window: selector ${selector.value} not covered by any rule`,
        };
  }

  if (!ctx.calldataHistoryLookup) {
    return deny("no history lookup available; cannot compute window sum");
  }
  const now = ctx.now ?? new Date();

  for (const r of matching) {
    const amount = decodeUint256Arg(ctx.request.data, r.amountArgIndex);
    if (!amount.ok) return deny(`cannot decode amount argument: ${amount.reason}`);

    const since = new Date(now.getTime() - r.windowSeconds * 1000);
    let rows: CalldataHistoryRow[];
    try {
      rows = await ctx.calldataHistoryLookup({
        contract: r.contract,
        selector: r.selector,
        chainId,
        since,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return deny(`history lookup failed (${msg})`);
    }
    if (!Array.isArray(rows)) return deny("history lookup returned a non-array");

    let sum = 0n;
    for (const row of rows) {
      // Defensive re-check: the lookup is trusted to filter, but a wider
      // result set must never widen the sum silently or be skipped silently.
      if (typeof row.to !== "string" || row.to.toLowerCase() !== r.contract) continue;
      if (row.chainId !== chainId) continue;
      const rowSelector = extractSelector(row.data);
      if (!rowSelector.ok) {
        return deny(
          `prior transaction to ${r.contract} has undecodable calldata (${rowSelector.reason})`,
        );
      }
      if (rowSelector.value !== r.selector) continue;
      const prior = decodeUint256Arg(row.data, r.amountArgIndex);
      if (!prior.ok) {
        return deny(`prior transaction to ${r.contract} has undecodable amount (${prior.reason})`);
      }
      sum += prior.value;
    }

    const projected = sum + amount.value;
    if (projected > r.maxPerWindow) {
      const reason =
        `calldata-amount-window: ${r.selector} on ${r.contract} would reach ${projected} ` +
        `over ${r.windowSeconds}s (prior ${sum} + this ${amount.value}), cap ${r.maxPerWindow}`;
      return config.overCap === "manual-approval"
        ? { ...base, passed: false, reason, disposition: "manual-approval" }
        : { ...base, passed: false, reason, disposition: "reject" };
    }
  }

  return {
    ...base,
    passed: true,
    reason: `calldata-amount-window: ${selector.value} on ${ctx.request.to} within window cap`,
  };
}
