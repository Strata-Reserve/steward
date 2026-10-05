// STRATA-1499 / SF-1: calldata-amount-window evaluator + decoder tests.

import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import {
  decodeUint256Arg,
  extractSelector,
  normalizeHexData,
  parseUint256Decimal,
  UINT256_MAX,
} from "../calldata-decoder";
import { PolicyEngine } from "../engine";
import { evaluatePolicy } from "../evaluators";
import {
  type CalldataHistoryLookup,
  type CalldataHistoryQuery,
  type CalldataHistoryRow,
  evaluateCalldataAmountWindow,
  validateCalldataAmountWindowConfig,
} from "../evaluators/calldata-amount-window";

const TOKEN = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const RECIPIENT = "0x3333333333333333333333333333333333333333";
const SELECTOR_MINT = "0x40c10f19"; // mint(address,uint256)
const SELECTOR_TRANSFER = "0xa9059cbb"; // transfer(address,uint256)
const CHAIN = 8453;
const NOW = new Date("2026-10-05T12:00:00Z");

function word(value: bigint | string): string {
  const hex = typeof value === "bigint" ? value.toString(16) : value.replace(/^0x/, "");
  return hex.padStart(64, "0");
}

function mintCalldata(amount: bigint, to = RECIPIENT, selector = SELECTOR_MINT): string {
  return `${selector}${word(to)}${word(amount)}`;
}

function rule(config: Record<string, unknown>, overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: "mint-cap-1",
    type: "calldata-amount-window",
    enabled: true,
    config,
    ...overrides,
  };
}

function mintCapConfig(
  maxPerWindow: string,
  extra: Record<string, unknown> = {},
  ruleExtra: Record<string, unknown> = {},
) {
  return {
    rules: [
      {
        contract: TOKEN,
        selector: SELECTOR_MINT,
        amountArgIndex: 1,
        maxPerWindow,
        windowSeconds: 86400,
        ...ruleExtra,
      },
    ],
    ...extra,
  };
}

function request(overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    agentId: "agent-1",
    tenantId: "tenant-1",
    to: TOKEN,
    value: "0",
    data: mintCalldata(100n),
    chainId: CHAIN,
    ...overrides,
  };
}

function row(amount: bigint, overrides: Partial<CalldataHistoryRow> = {}): CalldataHistoryRow {
  return { to: TOKEN, data: mintCalldata(amount), chainId: CHAIN, ...overrides };
}

function lookupOf(rows: CalldataHistoryRow[], seen: CalldataHistoryQuery[] = []) {
  const lookup: CalldataHistoryLookup = async (query) => {
    seen.push(query);
    return rows;
  };
  return lookup;
}

// ─── Decoder ────────────────────────────────────────────────────────────────

describe("calldata-decoder", () => {
  it("normalizes well-formed hex and rejects everything else", () => {
    expect(normalizeHexData("0xABcd")).toEqual({ ok: true, value: "abcd" });
    expect(normalizeHexData("0X00")).toEqual({ ok: true, value: "00" });
    expect(normalizeHexData("abcd").ok).toBe(false);
    expect(normalizeHexData("0xabc").ok).toBe(false);
    expect(normalizeHexData("0xzz").ok).toBe(false);
    expect(normalizeHexData(42).ok).toBe(false);
    expect(normalizeHexData(undefined).ok).toBe(false);
  });

  it("extracts a lower-cased selector and fails on short / empty calldata", () => {
    expect(extractSelector("0x40C10F19ff")).toEqual({ ok: true, value: "0x40c10f19" });
    expect(extractSelector("0x40c10f")).toEqual({
      ok: false,
      reason: "calldata shorter than 4 bytes (no function selector)",
    });
    expect(extractSelector("0x").ok).toBe(false);
    expect(extractSelector("").ok).toBe(false);
    expect(extractSelector(null).ok).toBe(false);
  });

  it("reads the exact static word for the requested index", () => {
    const data = mintCalldata(12345n);
    expect(decodeUint256Arg(data, 1)).toEqual({ ok: true, value: 12345n });
    expect(decodeUint256Arg(data, 0)).toEqual({ ok: true, value: BigInt(RECIPIENT) });
  });

  it("fails on a truncated word instead of zero-padding", () => {
    const data = mintCalldata(12345n).slice(0, -2);
    const result = decodeUint256Arg(data, 1);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("too short");
  });

  it("fails on an index past the end and on invalid indexes", () => {
    const data = mintCalldata(1n);
    expect(decodeUint256Arg(data, 2).ok).toBe(false);
    expect(decodeUint256Arg(data, -1).ok).toBe(false);
    expect(decodeUint256Arg(data, 1.5).ok).toBe(false);
    expect(decodeUint256Arg(data, Number.NaN).ok).toBe(false);
  });

  it("decodes the full uint256 range without overflow", () => {
    const data = `${SELECTOR_MINT}${word(RECIPIENT)}${"f".repeat(64)}`;
    expect(decodeUint256Arg(data, 1)).toEqual({ ok: true, value: UINT256_MAX });
  });

  it("parses decimal uint256 strings strictly", () => {
    expect(parseUint256Decimal("0")).toEqual({ ok: true, value: 0n });
    expect(parseUint256Decimal(UINT256_MAX.toString())).toEqual({ ok: true, value: UINT256_MAX });
    expect(parseUint256Decimal((UINT256_MAX + 1n).toString()).ok).toBe(false);
    expect(parseUint256Decimal("-1").ok).toBe(false);
    expect(parseUint256Decimal("1e18").ok).toBe(false);
    expect(parseUint256Decimal("0x10").ok).toBe(false);
    expect(parseUint256Decimal(" 1").ok).toBe(false);
    expect(parseUint256Decimal(1).ok).toBe(false);
    expect(parseUint256Decimal("").ok).toBe(false);
  });
});

// ─── Config validation ──────────────────────────────────────────────────────

describe("validateCalldataAmountWindowConfig", () => {
  it("accepts a minimal valid config and normalizes case", () => {
    const result = validateCalldataAmountWindowConfig(
      mintCapConfig("1000", {}, { contract: TOKEN.toUpperCase().replace("0X", "0x") }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config.unmatched).toBe("pass");
      expect(result.config.overCap).toBe("reject");
      expect(result.config.rules[0]?.contract).toBe(TOKEN.toLowerCase());
      expect(result.config.rules[0]?.maxPerWindow).toBe(1000n);
    }
  });

  const bad: Array<[string, unknown]> = [
    ["non-object", "nope"],
    ["null", null],
    ["array", []],
    ["missing rules", {}],
    ["empty rules", { rules: [] }],
    ["unmatched enum", mintCapConfig("1", { unmatched: "allow" })],
    ["overCap enum", mintCapConfig("1", { overCap: "queue" })],
    ["rule not object", { rules: ["x"] }],
    ["contract short", mintCapConfig("1", {}, { contract: "0x1234" })],
    ["contract missing prefix", mintCapConfig("1", {}, { contract: TOKEN.slice(2) })],
    ["selector short", mintCapConfig("1", {}, { selector: "0x40c1" })],
    ["selector long", mintCapConfig("1", {}, { selector: "0x40c10f19aa" })],
    ["argIndex negative", mintCapConfig("1", {}, { amountArgIndex: -1 })],
    ["argIndex float", mintCapConfig("1", {}, { amountArgIndex: 1.5 })],
    ["argIndex string", mintCapConfig("1", {}, { amountArgIndex: "1" })],
    ["argIndex too large", mintCapConfig("1", {}, { amountArgIndex: 65 })],
    ["maxPerWindow number", mintCapConfig("1", {}, { maxPerWindow: 1 })],
    ["maxPerWindow negative", mintCapConfig("-1")],
    ["maxPerWindow overflow", mintCapConfig((UINT256_MAX + 1n).toString())],
    ["windowSeconds zero", mintCapConfig("1", {}, { windowSeconds: 0 })],
    ["windowSeconds float", mintCapConfig("1", {}, { windowSeconds: 1.5 })],
    ["windowSeconds too large", mintCapConfig("1", {}, { windowSeconds: 366 * 86400 })],
    ["chainId zero", mintCapConfig("1", {}, { chainId: 0 })],
    ["chainId string", mintCapConfig("1", {}, { chainId: "8453" })],
  ];
  for (const [label, config] of bad) {
    it(`rejects ${label}`, () => {
      const result = validateCalldataAmountWindowConfig(config);
      expect(result.ok).toBe(false);
    });
  }
});

// ─── Evaluator ──────────────────────────────────────────────────────────────

describe("calldata-amount-window evaluator", () => {
  it("passes when prior sum + this amount is within the cap", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(400n) }),
      calldataHistoryLookup: lookupOf([row(300n), row(300n)]),
      now: NOW,
    });
    expect(result.passed).toBe(true);
    expect(result.reason).toContain("within window cap");
  });

  it("passes when the projected sum equals the cap exactly", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(400n) }),
      calldataHistoryLookup: lookupOf([row(600n)]),
      now: NOW,
    });
    expect(result.passed).toBe(true);
  });

  it("denies the request that crosses the cap and reports the sums", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(401n) }),
      calldataHistoryLookup: lookupOf([row(600n)]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.disposition).toBe("reject");
    expect(result.reason).toContain("prior 600");
    expect(result.reason).toContain("this 401");
    expect(result.reason).toContain("cap 1000");
  });

  it("denies a single request above the cap even with empty history", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(1001n) }),
      calldataHistoryLookup: lookupOf([]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
  });

  it("queries history scoped to the rule's contract, selector, chain and window", async () => {
    const seen: CalldataHistoryQuery[] = [];
    await evaluateCalldataAmountWindow(
      rule(mintCapConfig("1000", {}, { contract: TOKEN.toUpperCase().replace("0X", "0x") })),
      {
        request: request({ to: TOKEN.toUpperCase().replace("0X", "0x") }),
        calldataHistoryLookup: lookupOf([], seen),
        now: NOW,
      },
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({
      contract: TOKEN.toLowerCase(),
      selector: SELECTOR_MINT,
      chainId: CHAIN,
      since: new Date(NOW.getTime() - 86400 * 1000),
    });
  });

  it("never trusts the request for totals: a request-supplied sum field is ignored", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: {
        ...request({ data: mintCalldata(500n) }),
        priorSum: "0",
        windowSum: 0,
      } as SignRequest,
      calldataHistoryLookup: lookupOf([row(600n)]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
  });

  it("denies when no history lookup is wired in", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request(),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("no history lookup");
  });

  it("denies when the history lookup throws", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request(),
      calldataHistoryLookup: async () => {
        throw new Error("connection reset");
      },
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("history lookup failed");
    expect(result.reason).toContain("connection reset");
  });

  it("denies when the history lookup returns a non-array", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request(),
      calldataHistoryLookup: (async () => null) as unknown as CalldataHistoryLookup,
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("non-array");
  });

  it("denies when a prior row has undecodable calldata", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(1n) }),
      calldataHistoryLookup: lookupOf([row(1n, { data: "0x40c10f19abcd" })]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("prior transaction");
  });

  it("denies when a prior row has no calldata at all", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(1n) }),
      calldataHistoryLookup: lookupOf([row(1n, { data: null })]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
  });

  it("ignores wider lookup results that do not match contract / selector / chain", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(500n) }),
      calldataHistoryLookup: lookupOf([
        row(900n, { to: OTHER }),
        row(900n, { chainId: 1 }),
        row(900n, { data: mintCalldata(900n, RECIPIENT, SELECTOR_TRANSFER) }),
        row(400n),
      ]),
      now: NOW,
    });
    expect(result.passed).toBe(true);
  });

  it("denies when the request amount word is truncated", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data: mintCalldata(1n).slice(0, -8) }),
      calldataHistoryLookup: lookupOf([]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("cannot decode amount");
  });

  it("denies malformed calldata to a governed contract regardless of unmatched", async () => {
    for (const data of ["0x40c1", "0xzz", "40c10f19"]) {
      const result = await evaluateCalldataAmountWindow(
        rule(mintCapConfig("1000", { unmatched: "pass" })),
        { request: request({ data }), calldataHistoryLookup: lookupOf([]), now: NOW },
      );
      expect(result.passed).toBe(false);
    }
  });

  it("handles a sum that overflows past the cap without wrapping", async () => {
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig(UINT256_MAX.toString())), {
      request: request({ data: mintCalldata(UINT256_MAX) }),
      calldataHistoryLookup: lookupOf([row(1n)]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
  });

  it("does not pad a short recipient word into a plausible amount (hostile calldata)", async () => {
    // Selector + one 32-byte word only: argIndex 1 is absent.
    const data = `${SELECTOR_MINT}${word(RECIPIENT)}`;
    const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
      request: request({ data }),
      calldataHistoryLookup: lookupOf([]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
  });

  describe("unmatched handling", () => {
    it("passes a call to an unlisted contract by default", async () => {
      const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
        request: request({ to: OTHER, data: mintCalldata(10n ** 30n) }),
        now: NOW,
      });
      expect(result.passed).toBe(true);
      expect(result.reason).toContain("not covered");
    });

    it("denies a call to an unlisted contract with unmatched: deny", async () => {
      const result = await evaluateCalldataAmountWindow(
        rule(mintCapConfig("1000", { unmatched: "deny" })),
        { request: request({ to: OTHER }), now: NOW },
      );
      expect(result.passed).toBe(false);
    });

    it("passes an unlisted selector on a listed contract by default", async () => {
      const result = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
        request: request({ data: mintCalldata(10n ** 30n, RECIPIENT, SELECTOR_TRANSFER) }),
        now: NOW,
      });
      expect(result.passed).toBe(true);
    });

    it("denies an unlisted selector on a listed contract with unmatched: deny", async () => {
      const result = await evaluateCalldataAmountWindow(
        rule(mintCapConfig("1000", { unmatched: "deny" })),
        {
          request: request({ data: mintCalldata(1n, RECIPIENT, SELECTOR_TRANSFER) }),
          now: NOW,
        },
      );
      expect(result.passed).toBe(false);
    });

    it("treats empty calldata to a listed contract as unmatched", async () => {
      for (const data of [undefined, "", "0x"]) {
        const pass = await evaluateCalldataAmountWindow(rule(mintCapConfig("1000")), {
          request: request({ data }),
          now: NOW,
        });
        expect(pass.passed).toBe(true);
        const deny = await evaluateCalldataAmountWindow(
          rule(mintCapConfig("1000", { unmatched: "deny" })),
          { request: request({ data }), now: NOW },
        );
        expect(deny.passed).toBe(false);
      }
    });

    it("does not apply a rule pinned to another chain", async () => {
      const result = await evaluateCalldataAmountWindow(
        rule(mintCapConfig("1000", {}, { chainId: 1 })),
        {
          request: request({ chainId: CHAIN, data: mintCalldata(10n ** 30n) }),
          now: NOW,
        },
      );
      expect(result.passed).toBe(true);
    });
  });

  it("denies on malformed config even when the request would otherwise be unmatched", async () => {
    const result = await evaluateCalldataAmountWindow(rule({ rules: [] }), {
      request: request({ to: OTHER }),
      calldataHistoryLookup: lookupOf([]),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("invalid config");
  });

  it("evaluates every matching rule and fails on the tightest one", async () => {
    const config = {
      rules: [
        {
          contract: TOKEN,
          selector: SELECTOR_MINT,
          amountArgIndex: 1,
          maxPerWindow: "1000000",
          windowSeconds: 7 * 86400,
        },
        {
          contract: TOKEN,
          selector: SELECTOR_MINT,
          amountArgIndex: 1,
          maxPerWindow: "100",
          windowSeconds: 3600,
        },
      ],
    };
    const seen: CalldataHistoryQuery[] = [];
    const result = await evaluateCalldataAmountWindow(rule(config), {
      request: request({ data: mintCalldata(101n) }),
      calldataHistoryLookup: lookupOf([], seen),
      now: NOW,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("cap 100");
    expect(seen).toHaveLength(2);
  });

  it("returns disposition manual-approval when configured", async () => {
    const result = await evaluateCalldataAmountWindow(
      rule(mintCapConfig("1000", { overCap: "manual-approval" })),
      {
        request: request({ data: mintCalldata(1001n) }),
        calldataHistoryLookup: lookupOf([]),
        now: NOW,
      },
    );
    expect(result.passed).toBe(false);
    expect(result.disposition).toBe("manual-approval");
  });

  it("hard-denies config and lookup failures even with overCap manual-approval", async () => {
    const noLookup = await evaluateCalldataAmountWindow(
      rule(mintCapConfig("1000", { overCap: "manual-approval" })),
      { request: request(), now: NOW },
    );
    expect(noLookup.passed).toBe(false);
    expect(noLookup.disposition).toBeUndefined();

    const badConfig = await evaluateCalldataAmountWindow(
      rule({ rules: [], overCap: "manual-approval" }),
      { request: request(), calldataHistoryLookup: lookupOf([]), now: NOW },
    );
    expect(badConfig.passed).toBe(false);
    expect(badConfig.disposition).toBeUndefined();
  });

  it("passes when the policy itself is disabled (per evaluator contract)", async () => {
    const result = await evaluatePolicy(rule(mintCapConfig("1"), { enabled: false }), {
      request: request({ data: mintCalldata(10n ** 30n) }),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    });
    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Policy disabled");
  });
});

// ─── Engine integration ─────────────────────────────────────────────────────

describe("PolicyEngine with calldata-amount-window", () => {
  const engine = new PolicyEngine();

  function evaluate(policies: PolicyRule[], req: SignRequest, rows: CalldataHistoryRow[]) {
    return engine.evaluate(policies, {
      request: req,
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      calldataHistoryLookup: lookupOf(rows),
      now: NOW,
    });
  }

  it("approves under the cap", async () => {
    const result = await evaluate(
      [rule(mintCapConfig("1000"))],
      request({ data: mintCalldata(1n) }),
      [row(999n)],
    );
    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("hard-rejects over the cap by default", async () => {
    const result = await evaluate(
      [rule(mintCapConfig("1000"))],
      request({ data: mintCalldata(2n) }),
      [row(999n)],
    );
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("queues for manual approval over the cap when overCap is manual-approval", async () => {
    const result = await evaluate(
      [rule(mintCapConfig("1000", { overCap: "manual-approval" }))],
      request({ data: mintCalldata(2n) }),
      [row(999n)],
    );
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("does not queue when a hard policy also fails", async () => {
    const whitelist: PolicyRule = {
      id: "wl",
      type: "approved-addresses",
      enabled: true,
      config: { mode: "whitelist", addresses: [OTHER] },
    };
    const result = await evaluate(
      [rule(mintCapConfig("1000", { overCap: "manual-approval" })), whitelist],
      request({ data: mintCalldata(2n) }),
      [row(999n)],
    );
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("rejects when the engine has no lookup at all (API did not bind one)", async () => {
    const result = await engine.evaluate([rule(mintCapConfig("1000"))], {
      request: request(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    });
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("keeps the existing auto-approve-threshold queueing behaviour", async () => {
    const auto: PolicyRule = {
      id: "auto",
      type: "auto-approve-threshold",
      enabled: true,
      config: { threshold: "0" },
    };
    const result = await evaluate([auto, rule(mintCapConfig("1000"))], request({ value: "1" }), []);
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("simulate() forwards the lookup for transaction requests", async () => {
    const result = await engine.simulate([rule(mintCapConfig("1000"))], {
      request: { ...request({ data: mintCalldata(2n) }), kind: "transaction" },
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      calldataHistoryLookup: lookupOf([row(999n)]),
      now: NOW,
    });
    expect(result.approved).toBe(false);
  });
});
