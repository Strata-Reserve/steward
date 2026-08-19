import { describe, expect, test } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { PolicyEngine } from "../engine";

const request: SignRequest = {
  tenantId: "strata",
  agentId: "midas",
  to: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  value: "0",
  data: "0xa9059cbb",
  chainId: 84532,
  broadcast: true,
};

const manual: PolicyRule = {
  id: "manual-transfer",
  type: "manual-approval",
  enabled: true,
  config: { actions: ["wallet_action_transfer"] },
};

const chain: PolicyRule = {
  id: "base-sepolia-only",
  type: "allowed-chains",
  enabled: true,
  config: { chains: ["eip155:84532"] },
};

async function evaluate(
  policies: PolicyRule[],
  overrides: Partial<SignRequest> = {},
  action = "wallet_action_transfer",
) {
  return new PolicyEngine().evaluate(policies, {
    request: { ...request, ...overrides },
    action,
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
  });
}

const token = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const recipient = "0x261386fc1A1c6045fE24Ff71354f584Baa94730A";
function transferData(selector = "0xa9059cbb", amount = "1000000") {
  return `${selector}${recipient.toLowerCase().slice(2).padStart(64, "0")}${BigInt(amount).toString(16).padStart(64, "0")}`;
}
const rate: PolicyRule = {
  id: "one-per-hour",
  type: "rate-limit",
  enabled: true,
  config: { maxTxPerHour: 1, maxTxPerDay: 1 },
};
const contract: PolicyRule = {
  id: "usdc-transfer-only",
  type: "contract-allowlist",
  enabled: true,
  config: {
    contracts: [
      {
        address: token,
        selectors: ["0xa9059cbb"],
        constraints: {
          "0xa9059cbb": {
            recipientAllowlist: [recipient],
            maxNativeValueWei: "0",
            maxAmount: "1000000",
          },
        },
      },
    ],
  },
};

describe("STRATA-1097 first-class action manual approval", () => {
  test("all hard rules pass, then matching action independently requires manual approval", async () => {
    const result = await evaluate([chain, manual]);
    expect(result).toMatchObject({ approved: false, requiresManualApproval: true });
    expect(result.results).toContainEqual(
      expect.objectContaining({
        policyId: "manual-transfer",
        passed: false,
        requiresManualApproval: true,
      }),
    );
  });

  test("wrong selector is a terminal hard rejection with no approvable verdict", async () => {
    const result = await evaluate([chain, contract, manual], {
      to: token,
      data: transferData("0x095ea7b3"),
    });
    expect(result).toMatchObject({ approved: false, requiresManualApproval: false });
    expect(result.results).toContainEqual(
      expect.objectContaining({ policyId: "usdc-transfer-only", passed: false }),
    );
  });

  test("permitted selector/recipient/amount reaches manual approval rather than auto-sign", async () => {
    const result = await evaluate([chain, contract, manual], { to: token, data: transferData() });
    expect(result).toMatchObject({ approved: false, requiresManualApproval: true });
  });

  test("rate-limit failure is terminal and cannot be rescued by manual review", async () => {
    const result = await new PolicyEngine().evaluate([chain, rate, manual], {
      request,
      action: "wallet_action_transfer",
      recentTxCount1h: 1,
      recentTxCount24h: 1,
      spentToday: 0n,
      spentThisWeek: 0n,
    });
    expect(result).toMatchObject({ approved: false, requiresManualApproval: false });
    expect(result.results).toContainEqual(
      expect.objectContaining({ policyId: "one-per-hour", passed: false }),
    );
  });

  test("hard failure is terminal and cannot be rescued by the manual policy", async () => {
    const result = await evaluate([chain, manual], { chainId: 1 });
    expect(result).toMatchObject({ approved: false, requiresManualApproval: false });
    expect(result.results).toContainEqual(
      expect.objectContaining({ policyId: "base-sepolia-only", passed: false }),
    );
  });

  test("non-matching action is not forced into this approval policy", async () => {
    const result = await evaluate([chain, manual], {}, "wallet_action_send_calls");
    expect(result).toMatchObject({ approved: true, requiresManualApproval: false });
  });

  test("disabled manual policy cannot require approval", async () => {
    const result = await evaluate([chain, { ...manual, enabled: false }]);
    expect(result).toMatchObject({ approved: true, requiresManualApproval: false });
  });

  test("zero policies preserves Steward's current fail-closed definition", async () => {
    const result = await evaluate([]);
    expect(result).toEqual({ approved: false, results: [], requiresManualApproval: false });
  });
});
