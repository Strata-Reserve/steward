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
