import { describe, expect, it } from "bun:test";
import { isValidApplicationProposalId } from "../services/application-boundary";
import {
  APPLICATION_EXECUTION_EVIDENCE_UNAVAILABLE,
  toApplicationProposalReadModel,
} from "../services/application-proposals";

describe("application proposal read service contract", () => {
  it("maps immutable proposal acceptance to non-terminal unknown execution evidence", () => {
    const proposal = toApplicationProposalReadModel({
      id: `atp_${"a".repeat(40)}`,
      intentId: `ati_${"b".repeat(40)}`,
      status: "proposed",
      createdAt: new Date("2026-08-12T16:00:00.000Z"),
      walletId: `aw_${"c".repeat(40)}`,
      resourceKind: "wallet_owner",
      resourceId: "party_inv_123",
    });

    expect(proposal).toEqual({
      id: `atp_${"a".repeat(40)}`,
      intentId: `ati_${"b".repeat(40)}`,
      status: "proposed",
      terminal: false,
      recordedAt: "2026-08-12T16:00:00.000Z",
      resource: {
        kind: "wallet_owner",
        id: "party_inv_123",
        walletId: `aw_${"c".repeat(40)}`,
      },
      executionEvidence: {
        status: "unknown",
        evidence: null,
        reason: APPLICATION_EXECUTION_EVIDENCE_UNAVAILABLE,
      },
    });
    expect(JSON.stringify(proposal)).not.toMatch(/executed|confirmed|broadcast|signed|succeeded/);
  });

  it("maps only a canonical broadcast execution row to broadcast evidence", () => {
    const base = {
      id: `atp_${"a".repeat(40)}`,
      intentId: `ati_${"b".repeat(40)}`,
      status: "proposed" as const,
      createdAt: new Date("2026-10-30T16:00:00.000Z"),
      walletId: `aw_${"c".repeat(40)}`,
      resourceKind: "wallet_owner" as const,
      resourceId: "party_inv_123",
    };
    const execution = {
      executionId: `ape_${"d".repeat(40)}`,
      chainId: 84532,
      toAddress: `0x${"e".repeat(40)}`,
      recipientAddress: `0x${"f".repeat(40)}`,
      amount: "1000",
    };
    const broadcast = toApplicationProposalReadModel({
      ...base,
      execution: { ...execution, status: "broadcast", txHash: `0x${"1".repeat(64)}` },
    });
    expect(broadcast.terminal).toBe(false);
    expect(broadcast.executionEvidence).toEqual({
      status: "broadcast",
      reason: null,
      evidence: {
        executionId: execution.executionId,
        network: { namespace: "eip155", chainId: 84532 },
        txHash: `0x${"1".repeat(64)}`,
        to: execution.toAddress,
        call: {
          function: "mint(address,uint256)",
          recipient: execution.recipientAddress,
          amount: "1000",
        },
      },
    });
    for (const [status, reason] of [
      ["executing", "execution_in_progress"],
      ["indeterminate", "execution_outcome_indeterminate"],
    ] as const) {
      const model = toApplicationProposalReadModel({
        ...base,
        execution: { ...execution, status, txHash: null },
      });
      expect(model.executionEvidence).toEqual({ status, evidence: null, reason });
    }
    // A broadcast status without a hash never claims evidence.
    expect(
      toApplicationProposalReadModel({
        ...base,
        execution: { ...execution, status: "broadcast", txHash: null },
      }).executionEvidence.evidence,
    ).toBeNull();
  });

  it("maps a durable human rejection to the only terminal read, with no execution claim", () => {
    const base = {
      id: `atp_${"a".repeat(40)}`,
      intentId: `ati_${"b".repeat(40)}`,
      status: "proposed" as const,
      createdAt: new Date("2026-11-09T16:00:00.000Z"),
      walletId: `aw_${"c".repeat(40)}`,
      resourceKind: "wallet_owner" as const,
      resourceId: "party_inv_123",
    };
    const rejection = {
      rejectionId: `apr_${"d".repeat(40)}`,
      reason: "not approved",
      rejectedAt: new Date("2026-11-09T17:00:00.000Z"),
    };
    const model = toApplicationProposalReadModel({ ...base, rejection });
    expect(model).toEqual({
      id: base.id,
      intentId: base.intentId,
      status: "rejected",
      terminal: true,
      recordedAt: "2026-11-09T16:00:00.000Z",
      resource: { kind: "wallet_owner", id: "party_inv_123", walletId: base.walletId },
      executionEvidence: {
        status: "rejected",
        reason: "proposal_rejected",
        evidence: {
          rejectionId: rejection.rejectionId,
          reason: "not approved",
          rejectedAt: "2026-11-09T17:00:00.000Z",
        },
      },
    });
    expect(JSON.stringify(model)).not.toMatch(/broadcast|txHash|executed|confirmed|signed/);
    // The DB makes rejection and execution mutually exclusive; if both were
    // ever present the read never claims rejection over an execution row.
    const both = toApplicationProposalReadModel({
      ...base,
      rejection,
      execution: {
        executionId: `ape_${"e".repeat(40)}`,
        status: "indeterminate",
        chainId: 84532,
        txHash: null,
        toAddress: `0x${"e".repeat(40)}`,
        recipientAddress: `0x${"f".repeat(40)}`,
        amount: "1",
      },
    });
    expect(both.terminal).toBe(false);
    expect(both.executionEvidence.status).toBe("indeterminate");
  });

  it("accepts only the canonical proposal identifier shape", () => {
    expect(isValidApplicationProposalId(`atp_${"0".repeat(40)}`)).toBe(true);
    for (const candidate of [
      `ati_${"0".repeat(40)}`,
      `atp_${"A".repeat(40)}`,
      `atp_${"g".repeat(40)}`,
      `atp_${"0".repeat(39)}`,
      `atp_${"0".repeat(41)}`,
      "atp_",
      "../atp_0000000000000000000000000000000000000000",
      null,
    ]) {
      expect(isValidApplicationProposalId(candidate), String(candidate)).toBe(false);
    }
  });
});
