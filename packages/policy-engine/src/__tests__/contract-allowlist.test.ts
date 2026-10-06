// STRATA-1499: contract-allowlist evaluator + calldata decoder tests.

import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { encodeFunctionData, parseAbi } from "viem";
import {
  decodeCalldata,
  extractSelector,
  isEmptyCalldata,
  SELECTOR_APPROVE,
  SELECTOR_CREATE_DEAL_TOKEN,
  SELECTOR_MINT,
  SELECTOR_TRANSFER,
  SELECTOR_TRANSFER_FROM,
} from "../calldata";
import { PolicyEngine } from "../engine";
import { evaluatePolicy } from "../evaluators";
import {
  evaluateContractAllowlist,
  validateContractAllowlistConfig,
} from "../evaluators/contract-allowlist";

const ABI = parseAbi([
  "function mint(address to, uint256 amount)",
  "function transfer(address to, uint256 amount)",
  "function approve(address spender, uint256 amount)",
  "function transferFrom(address from, address to, uint256 amount)",
  "function createDealToken(string name, string symbol, address admin, bytes32 salt)",
]);

const TOKEN = "0x1111111111111111111111111111111111111111";
const FACTORY = "0x2222222222222222222222222222222222222222";
const SAFE = "0x3333333333333333333333333333333333333333";
const OTHER = "0x4444444444444444444444444444444444444444";
const STRANGER = "0x5555555555555555555555555555555555555555";
const UINT256_MAX = (1n << 256n) - 1n;

function mintData(to: string, amount: bigint): string {
  return encodeFunctionData({
    abi: ABI,
    functionName: "mint",
    args: [to as `0x${string}`, amount],
  });
}

function createDealTokenData(admin: string, name = "Deal", symbol = "DEAL"): string {
  return encodeFunctionData({
    abi: ABI,
    functionName: "createDealToken",
    args: [name, symbol, admin as `0x${string}`, `0x${"ab".repeat(32)}`],
  });
}

function rule(config: Record<string, unknown>, enabled = true): PolicyRule {
  return { id: "ca-1", type: "contract-allowlist", enabled, config };
}

function minterConfig(overrides: Record<string, unknown> = {}) {
  return {
    contracts: [
      {
        address: FACTORY,
        selectors: [SELECTOR_CREATE_DEAL_TOKEN],
        constraints: { [SELECTOR_CREATE_DEAL_TOKEN]: { adminAllowlist: [SAFE] } },
      },
      {
        address: TOKEN,
        selectors: [SELECTOR_MINT],
        constraints: {
          [SELECTOR_MINT]: { maxAmount: "1000000", recipientAllowlist: [SAFE, OTHER] },
        },
      },
    ],
    ...overrides,
  };
}

function evaluate(
  config: Record<string, unknown>,
  ctx: { to: string; value?: string; data?: string },
) {
  return evaluateContractAllowlist(rule(config), { value: "0", ...ctx });
}

// ─── Selectors ───────────────────────────────────────────────────────────────

describe("calldata selectors", () => {
  it("match the canonical 4-byte ids", () => {
    expect(SELECTOR_MINT).toBe("0x40c10f19");
    expect(SELECTOR_TRANSFER).toBe("0xa9059cbb");
    expect(SELECTOR_APPROVE).toBe("0x095ea7b3");
    expect(SELECTOR_TRANSFER_FROM).toBe("0x23b872dd");
    expect(SELECTOR_CREATE_DEAL_TOKEN).toBe("0x0bab7086");
  });
});

// ─── Decoder ─────────────────────────────────────────────────────────────────

describe("decodeCalldata", () => {
  it("decodes mint(address,uint256)", () => {
    const decoded = decodeCalldata(mintData(SAFE, 42n));
    expect(decoded).toEqual({
      kind: "amount",
      selector: SELECTOR_MINT,
      recipient: SAFE,
      amount: 42n,
    });
  });

  it("decodes transfer / approve with the same shape", () => {
    const t = decodeCalldata(
      encodeFunctionData({ abi: ABI, functionName: "transfer", args: [OTHER, 7n] }),
    );
    expect(t).toMatchObject({
      kind: "amount",
      selector: SELECTOR_TRANSFER,
      recipient: OTHER,
      amount: 7n,
    });
    const a = decodeCalldata(
      encodeFunctionData({ abi: ABI, functionName: "approve", args: [OTHER, 9n] }),
    );
    expect(a).toMatchObject({
      kind: "amount",
      selector: SELECTOR_APPROVE,
      recipient: OTHER,
      amount: 9n,
    });
  });

  it("decodes transferFrom(address,address,uint256) with from + recipient", () => {
    const d = decodeCalldata(
      encodeFunctionData({ abi: ABI, functionName: "transferFrom", args: [SAFE, OTHER, 5n] }),
    );
    expect(d).toEqual({
      kind: "amount",
      selector: SELECTOR_TRANSFER_FROM,
      from: SAFE,
      recipient: OTHER,
      amount: 5n,
    });
  });

  it("decodes uint256 max without loss", () => {
    const d = decodeCalldata(mintData(SAFE, UINT256_MAX));
    expect(d?.kind === "amount" && d.amount).toBe(UINT256_MAX);
  });

  it("decodes createDealToken admin regardless of string lengths", () => {
    for (const [name, symbol] of [
      ["", ""],
      ["A", "B"],
      ["x".repeat(31), "y".repeat(32)],
      ["z".repeat(33), "w".repeat(100)],
    ]) {
      const d = decodeCalldata(createDealTokenData(SAFE, name, symbol));
      expect(d).toEqual({
        kind: "createDealToken",
        selector: SELECTOR_CREATE_DEAL_TOKEN,
        admin: SAFE,
      });
    }
  });

  it("accepts uppercase hex and 0X prefix", () => {
    const upper = `0X${mintData(SAFE, 1n).slice(2).toUpperCase()}`;
    expect(decodeCalldata(upper)).toMatchObject({ recipient: SAFE, amount: 1n });
  });

  it("returns null for unsupported selectors", () => {
    expect(decodeCalldata(`0xdeadbeef${"00".repeat(64)}`)).toBeNull();
  });

  it("returns null for non-hex, odd-length and non-string input", () => {
    expect(decodeCalldata("0x40c10f1g")).toBeNull();
    expect(decodeCalldata("0x40c10f190")).toBeNull();
    expect(decodeCalldata(123)).toBeNull();
    expect(decodeCalldata(undefined)).toBeNull();
    expect(decodeCalldata("40c10f19")).toBeNull();
  });

  describe("hostile calldata", () => {
    it("rejects truncated mint (short last word)", () => {
      const good = mintData(SAFE, 1n);
      expect(decodeCalldata(good.slice(0, -2))).toBeNull();
      expect(decodeCalldata(good.slice(0, 10 + 64))).toBeNull();
      expect(decodeCalldata(SELECTOR_MINT)).toBeNull();
    });

    it("rejects over-long mint (trailing bytes)", () => {
      expect(decodeCalldata(`${mintData(SAFE, 1n)}00`)).toBeNull();
      expect(decodeCalldata(`${mintData(SAFE, 1n)}${"00".repeat(32)}`)).toBeNull();
    });

    it("rejects non-zero padding in the address word", () => {
      const good = mintData(SAFE, 1n);
      // flip the first padding nibble of the recipient word
      const tampered = `${good.slice(0, 10)}f${good.slice(11)}`;
      expect(decodeCalldata(tampered)).toBeNull();
      // and the last padding byte, right before the address
      const tampered2 = `${good.slice(0, 10 + 22)}01${good.slice(10 + 24)}`;
      expect(decodeCalldata(tampered2)).toBeNull();
    });

    it("rejects createDealToken with out-of-range offsets", () => {
      const good = createDealTokenData(SAFE);
      const hugeOffset = `${good.slice(0, 10)}${"ff".repeat(32)}${good.slice(10 + 64)}`;
      expect(decodeCalldata(hugeOffset)).toBeNull();
      const unaligned = `${good.slice(0, 10)}${(0x81).toString(16).padStart(64, "0")}${good.slice(10 + 64)}`;
      expect(decodeCalldata(unaligned)).toBeNull();
      const intoHead = `${good.slice(0, 10)}${(0x20).toString(16).padStart(64, "0")}${good.slice(10 + 64)}`;
      expect(decodeCalldata(intoHead)).toBeNull();
    });

    it("rejects createDealToken with a length word that overruns the data", () => {
      const good = createDealTokenData(SAFE, "Deal", "DEAL");
      // name tail starts at head word 4: 10 + 4*64; its length word is first
      const lenStart = 10 + 4 * 64;
      const tampered = `${good.slice(0, lenStart)}${(1000).toString(16).padStart(64, "0")}${good.slice(lenStart + 64)}`;
      expect(decodeCalldata(tampered)).toBeNull();
    });

    it("rejects createDealToken with trailing bytes or non-zero string padding", () => {
      const good = createDealTokenData(SAFE, "Deal", "DEAL");
      expect(decodeCalldata(`${good}${"00".repeat(32)}`)).toBeNull();
      // "Deal" occupies 4 bytes of a 32 byte word; dirty the padding
      const payloadStart = 10 + 4 * 64 + 64;
      const dirty = `${good.slice(0, payloadStart + 8)}ff${good.slice(payloadStart + 10)}`;
      expect(decodeCalldata(dirty)).toBeNull();
    });

    it("rejects createDealToken with non-zero padding in the admin word", () => {
      const good = createDealTokenData(SAFE);
      const adminWord = 10 + 2 * 64;
      const tampered = `${good.slice(0, adminWord)}01${good.slice(adminWord + 2)}`;
      expect(decodeCalldata(tampered)).toBeNull();
    });
  });
});

describe("extractSelector / isEmptyCalldata", () => {
  it("extracts lowercased selector from valid calldata", () => {
    expect(extractSelector("0x40C10F19aa")).toBe("0x40c10f19");
  });
  it("returns null when shorter than 4 bytes or malformed", () => {
    expect(extractSelector("0x40c10f")).toBeNull();
    expect(extractSelector("0x40c10f1")).toBeNull();
    expect(extractSelector("zz")).toBeNull();
  });
  it("treats undefined, empty and 0x as empty but not malformed hex", () => {
    expect(isEmptyCalldata(undefined)).toBe(true);
    expect(isEmptyCalldata("")).toBe(true);
    expect(isEmptyCalldata("0x")).toBe(true);
    expect(isEmptyCalldata("0x00")).toBe(false);
    expect(isEmptyCalldata("0xzz")).toBe(false);
  });
});

// ─── Config validation ───────────────────────────────────────────────────────

describe("validateContractAllowlistConfig", () => {
  it("accepts the Strata minter example", () => {
    expect(validateContractAllowlistConfig(minterConfig())).toBeNull();
  });

  it("accepts optional native-transfer fields", () => {
    expect(
      validateContractAllowlistConfig(
        minterConfig({ allowNativeTransfer: true, maxNativeValueWei: "1000" }),
      ),
    ).toBeNull();
  });

  const bad: Array<[string, unknown, string]> = [
    ["non-object", "nope", "must be an object"],
    ["missing contracts", {}, "contracts must be a non-empty array"],
    ["empty contracts", { contracts: [] }, "contracts must be a non-empty array"],
    [
      "unknown top-level key",
      { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT] }], foo: 1 },
      "unknown config field",
    ],
    [
      "bad allowNativeTransfer",
      minterConfig({ allowNativeTransfer: "yes" }),
      "allowNativeTransfer",
    ],
    ["bad maxNativeValueWei", minterConfig({ maxNativeValueWei: "0x10" }), "maxNativeValueWei"],
    ["negative maxNativeValueWei", minterConfig({ maxNativeValueWei: "-1" }), "maxNativeValueWei"],
    [
      "overflow maxNativeValueWei",
      minterConfig({ maxNativeValueWei: (UINT256_MAX + 1n).toString() }),
      "maxNativeValueWei",
    ],
    ["bad address", { contracts: [{ address: "0x123", selectors: [SELECTOR_MINT] }] }, "address"],
    [
      "empty selectors",
      { contracts: [{ address: TOKEN, selectors: [] }] },
      "selectors must be a non-empty array",
    ],
    ["bad selector", { contracts: [{ address: TOKEN, selectors: ["0x40c10f1"] }] }, "selectors[0]"],
    [
      "duplicate selector",
      { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT, "0x40C10F19"] }] },
      "duplicate selector",
    ],
    [
      "duplicate address",
      {
        contracts: [
          { address: TOKEN, selectors: [SELECTOR_MINT] },
          { address: TOKEN.toUpperCase().replace("0X", "0x"), selectors: [SELECTOR_TRANSFER] },
        ],
      },
      "duplicate address",
    ],
    [
      "unknown entry key",
      { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT], extra: true }] },
      "unknown field",
    ],
    [
      "constraints not object",
      { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT], constraints: [] }] },
      "constraints must be an object",
    ],
    [
      "constraint key not a selector",
      { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT], constraints: { mint: {} } }] },
      "key must be",
    ],
    [
      "constraint for unlisted selector",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_TRANSFER]: { maxAmount: "1" } },
          },
        ],
      },
      "not in this entry's selectors",
    ],
    [
      "constraint for undecodable selector",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: ["0xdeadbeef"],
            constraints: { "0xdeadbeef": { maxAmount: "1" } },
          },
        ],
      },
      "no decoder",
    ],
    [
      "empty constraint object",
      {
        contracts: [
          { address: TOKEN, selectors: [SELECTOR_MINT], constraints: { [SELECTOR_MINT]: {} } },
        ],
      },
      "must not be empty",
    ],
    [
      "adminAllowlist on mint",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_MINT]: { adminAllowlist: [SAFE] } },
          },
        ],
      },
      "does not apply",
    ],
    [
      "maxAmount on createDealToken",
      {
        contracts: [
          {
            address: FACTORY,
            selectors: [SELECTOR_CREATE_DEAL_TOKEN],
            constraints: { [SELECTOR_CREATE_DEAL_TOKEN]: { maxAmount: "1" } },
          },
        ],
      },
      "does not apply",
    ],
    [
      "maxAmount not decimal",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_MINT]: { maxAmount: "1e6" } },
          },
        ],
      },
      "maxAmount",
    ],
    [
      "maxAmount overflow",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_MINT]: { maxAmount: (UINT256_MAX + 1n).toString() } },
          },
        ],
      },
      "maxAmount",
    ],
    [
      "recipientAllowlist empty",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_MINT]: { recipientAllowlist: [] } },
          },
        ],
      },
      "recipientAllowlist",
    ],
    [
      "recipientAllowlist bad entry",
      {
        contracts: [
          {
            address: TOKEN,
            selectors: [SELECTOR_MINT],
            constraints: { [SELECTOR_MINT]: { recipientAllowlist: ["safe"] } },
          },
        ],
      },
      "recipientAllowlist",
    ],
    [
      "adminAllowlist bad entry",
      {
        contracts: [
          {
            address: FACTORY,
            selectors: [SELECTOR_CREATE_DEAL_TOKEN],
            constraints: { [SELECTOR_CREATE_DEAL_TOKEN]: { adminAllowlist: [1] } },
          },
        ],
      },
      "adminAllowlist",
    ],
  ];

  for (const [label, config, needle] of bad) {
    it(`rejects ${label}`, () => {
      const err = validateContractAllowlistConfig(config);
      expect(err).not.toBeNull();
      expect(err).toContain(needle);
    });
  }
});

// ─── Evaluator ───────────────────────────────────────────────────────────────

describe("contract-allowlist evaluator", () => {
  it("allows a capped mint to an allowlisted recipient", () => {
    const r = evaluate(minterConfig(), { to: TOKEN, data: mintData(SAFE, 1000000n) });
    expect(r.passed).toBe(true);
    expect(r.reason).toContain("within constraints");
  });

  it("allows createDealToken with the Safe as admin", () => {
    const r = evaluate(minterConfig(), { to: FACTORY, data: createDealTokenData(SAFE) });
    expect(r.passed).toBe(true);
  });

  it("matches target and selector case-insensitively", () => {
    const upperTo = `0x${TOKEN.slice(2).toUpperCase()}`;
    const upperData = `0x${mintData(SAFE, 1n).slice(2).toUpperCase()}`;
    const r = evaluate(minterConfig(), { to: upperTo, data: upperData });
    expect(r.passed).toBe(true);
  });

  it("denies when the evaluator config is malformed", () => {
    const r = evaluate({ contracts: [] }, { to: TOKEN, data: mintData(SAFE, 1n) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("invalid config");
  });

  it("denies a target that is not listed", () => {
    const r = evaluate(minterConfig(), { to: STRANGER, data: mintData(SAFE, 1n) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not an allowlisted contract");
  });

  it("denies a non-EVM target", () => {
    const r = evaluate(minterConfig(), { to: "11111111111111111111111111111111", data: "0x" });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not an EVM address");
  });

  it("denies empty calldata by default", () => {
    for (const data of [undefined, "", "0x"]) {
      const r = evaluate(minterConfig(), { to: TOKEN, data });
      expect(r.passed).toBe(false);
      expect(r.reason).toContain("empty calldata");
    }
  });

  it("allows empty calldata only with allowNativeTransfer and value within cap", () => {
    const cfg = minterConfig({ allowNativeTransfer: true, maxNativeValueWei: "100" });
    expect(evaluate(cfg, { to: TOKEN, data: "0x", value: "100" }).passed).toBe(true);
    const over = evaluate(cfg, { to: TOKEN, data: "0x", value: "101" });
    expect(over.passed).toBe(false);
    expect(over.reason).toContain("exceeds maxNativeValueWei");
  });

  it("denies any native value on a contract call by default", () => {
    const r = evaluate(minterConfig(), { to: TOKEN, data: mintData(SAFE, 1n), value: "1" });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("exceeds maxNativeValueWei 0");
  });

  it("accepts value as decimal or hex string, denies garbage", () => {
    const cfg = minterConfig({ maxNativeValueWei: "255" });
    expect(evaluate(cfg, { to: TOKEN, data: mintData(SAFE, 1n), value: "0xff" }).passed).toBe(true);
    expect(evaluate(cfg, { to: TOKEN, data: mintData(SAFE, 1n), value: "0x100" }).passed).toBe(
      false,
    );
    const bad = evaluate(cfg, { to: TOKEN, data: mintData(SAFE, 1n), value: "ten" });
    expect(bad.passed).toBe(false);
    expect(bad.reason).toContain("not a valid wei amount");
    expect(evaluate(cfg, { to: TOKEN, data: mintData(SAFE, 1n), value: "-1" }).passed).toBe(false);
  });

  it("denies calldata shorter than 4 bytes or malformed", () => {
    for (const data of ["0x40", "0x40c10f", "0x40c10f1", "0xzz"]) {
      const r = evaluate(minterConfig(), { to: TOKEN, data });
      expect(r.passed).toBe(false);
      expect(r.reason).toContain("malformed or shorter");
    }
  });

  it("denies a selector that is not listed for the target", () => {
    const r = evaluate(minterConfig(), {
      to: TOKEN,
      data: encodeFunctionData({ abi: ABI, functionName: "transfer", args: [SAFE, 1n] }),
    });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not allowlisted on");
  });

  it("denies a listed selector on the wrong contract", () => {
    const r = evaluate(minterConfig(), { to: FACTORY, data: mintData(SAFE, 1n) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain(`${SELECTOR_MINT} is not allowlisted`);
  });

  it("denies mint above maxAmount", () => {
    const r = evaluate(minterConfig(), { to: TOKEN, data: mintData(SAFE, 1000001n) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("exceeds maxAmount");
  });

  it("denies mint at uint256 max (overflow attempt)", () => {
    const r = evaluate(minterConfig(), { to: TOKEN, data: mintData(SAFE, UINT256_MAX) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("exceeds maxAmount");
  });

  it("denies mint to a recipient outside the allowlist", () => {
    const r = evaluate(minterConfig(), { to: TOKEN, data: mintData(STRANGER, 1n) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not in recipientAllowlist");
  });

  it("denies createDealToken with a non-allowlisted admin", () => {
    const r = evaluate(minterConfig(), { to: FACTORY, data: createDealTokenData(STRANGER) });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not in adminAllowlist");
  });

  it("denies when constraints exist but calldata does not decode (hostile shapes)", () => {
    const good = mintData(SAFE, 1n);
    const hostile = [
      good.slice(0, -2), // truncated
      `${good}00`, // trailing byte
      `${good.slice(0, 10)}f${good.slice(11)}`, // dirty address padding
      SELECTOR_MINT, // bare selector
    ];
    for (const data of hostile) {
      const r = evaluate(minterConfig(), { to: TOKEN, data });
      expect(r.passed).toBe(false);
      expect(r.reason).toContain("does not decode");
    }
  });

  it("allows a listed selector without constraints even if the engine cannot decode it", () => {
    const cfg = { contracts: [{ address: TOKEN, selectors: ["0xdeadbeef"] }] };
    const r = evaluate(cfg, { to: TOKEN, data: "0xdeadbeef0102" });
    expect(r.passed).toBe(true);
  });

  it("allows a listed decodable selector without constraints regardless of args", () => {
    const cfg = { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT] }] };
    expect(evaluate(cfg, { to: TOKEN, data: mintData(STRANGER, UINT256_MAX) }).passed).toBe(true);
  });

  it("enforces transferFrom recipient + amount constraints", () => {
    const cfg = {
      contracts: [
        {
          address: TOKEN,
          selectors: [SELECTOR_TRANSFER_FROM],
          constraints: {
            [SELECTOR_TRANSFER_FROM]: { maxAmount: "10", recipientAllowlist: [SAFE] },
          },
        },
      ],
    };
    const ok = encodeFunctionData({
      abi: ABI,
      functionName: "transferFrom",
      args: [OTHER, SAFE, 10n],
    });
    expect(evaluate(cfg, { to: TOKEN, data: ok }).passed).toBe(true);
    const badTo = encodeFunctionData({
      abi: ABI,
      functionName: "transferFrom",
      args: [SAFE, OTHER, 1n],
    });
    expect(evaluate(cfg, { to: TOKEN, data: badTo }).passed).toBe(false);
    const badAmt = encodeFunctionData({
      abi: ABI,
      functionName: "transferFrom",
      args: [OTHER, SAFE, 11n],
    });
    expect(evaluate(cfg, { to: TOKEN, data: badAmt }).passed).toBe(false);
  });

  it("treats approve spender as the recipient for allowlist purposes", () => {
    const cfg = {
      contracts: [
        {
          address: TOKEN,
          selectors: [SELECTOR_APPROVE],
          constraints: { [SELECTOR_APPROVE]: { recipientAllowlist: [SAFE] } },
        },
      ],
    };
    const ok = encodeFunctionData({ abi: ABI, functionName: "approve", args: [SAFE, UINT256_MAX] });
    expect(evaluate(cfg, { to: TOKEN, data: ok }).passed).toBe(true);
    const bad = encodeFunctionData({ abi: ABI, functionName: "approve", args: [STRANGER, 1n] });
    expect(evaluate(cfg, { to: TOKEN, data: bad }).passed).toBe(false);
  });
});

// ─── Engine integration ──────────────────────────────────────────────────────

describe("contract-allowlist through evaluatePolicy / PolicyEngine", () => {
  function signRequest(overrides: Partial<SignRequest> = {}): SignRequest {
    return {
      agentId: "minter",
      tenantId: "strata",
      to: TOKEN,
      value: "0",
      data: mintData(SAFE, 1n),
      chainId: 8453,
      ...overrides,
    };
  }

  function ctx(request: SignRequest) {
    return {
      request,
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    };
  }

  it("is wired into evaluatePolicy", async () => {
    const ok = await evaluatePolicy(rule(minterConfig()), ctx(signRequest()));
    expect(ok.passed).toBe(true);
    expect(ok.type).toBe("contract-allowlist");
    const bad = await evaluatePolicy(
      rule(minterConfig()),
      ctx(signRequest({ data: mintData(SAFE, 10n ** 9n) })),
    );
    expect(bad.passed).toBe(false);
  });

  it("is a hard policy: a failure rejects rather than queuing for manual approval", async () => {
    const engine = new PolicyEngine();
    const policies: PolicyRule[] = [
      rule(minterConfig()),
      { id: "auto", type: "auto-approve-threshold", enabled: true, config: { threshold: "0" } },
    ];
    const res = await engine.evaluate(policies, ctx(signRequest({ data: mintData(STRANGER, 1n) })));
    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
  });

  it("approves a compliant mint alongside other policies", async () => {
    const engine = new PolicyEngine();
    const policies: PolicyRule[] = [
      rule(minterConfig()),
      { id: "chains", type: "allowed-chains", enabled: true, config: { chains: ["eip155:8453"] } },
    ];
    const res = await engine.evaluate(policies, ctx(signRequest()));
    expect(res.approved).toBe(true);
  });

  it("is skipped by proxy simulation (no on-chain target to match)", async () => {
    const engine = new PolicyEngine();
    const res = await engine.simulate([rule(minterConfig())], {
      ...ctx(signRequest()),
      request: { kind: "proxy", method: "POST", url: "https://example.invalid" },
    });
    expect(res.results.find((r) => r.type === "contract-allowlist")).toBeUndefined();
  });

  it("follows the disabled-rule contract (passes when enabled=false)", async () => {
    const r = await evaluatePolicy(rule({ contracts: [] }, false), ctx(signRequest()));
    expect(r.passed).toBe(true);
    expect(r.reason).toBe("Policy disabled");
  });
});
