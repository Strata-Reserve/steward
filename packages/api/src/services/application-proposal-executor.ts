/**
 * STRATA-1515 exec-gap-a: tenant-level executor for application proposals.
 *
 * An application proposal is inert (ADR 0005): the application principal can
 * only prepare and propose. This module is the separate privileged command
 * that consumes an accepted proposal: policy engine -> Vault sign + broadcast
 * -> immutable `application_proposal_executions` linkage row. Only tenant-level
 * callers (tenant API key or owner/admin session) reach it; application
 * credentials are refused by the global guard before any handler runs.
 *
 * Safety properties:
 * - Chain is pinned to Base Sepolia 84532. Any other chain is refused before
 *   any reservation, policy evaluation or key use (DB CHECK repeats this).
 * - The protected production minter is never driven from here.
 * - Exactly-once: the transactions row is reserved under the deterministic
 *   executionRef `application-proposal:<proposalId>` (unique per tenant/agent),
 *   so concurrent or repeated calls never sign twice. A repeated call after a
 *   successful broadcast (or after a human approved a queued transaction)
 *   only reconciles the linkage row from the recorded txHash.
 */
import {
  applicationProposalExecutions,
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  approvalQueue,
  type Transaction,
  transactions,
} from "@stwd/db";
import type { PolicyResult, SignRequest } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import { ApplicationBoundaryError } from "./application-boundary";
import { db, getPolicySet, getTransactionStats, policyEngine, priceOracle, vault } from "./context";
import { isProtectedMinter } from "./prod-minter-boundary";

export const APPLICATION_EXECUTION_CHAIN_ID = 84532 as const;
const TX_HASH_RE = /^0x[0-9a-f]{64}$/;

export function applicationProposalExecutionRef(proposalId: string): string {
  return `application-proposal:${proposalId}`;
}

export type ApplicationProposalExecutionOutcome =
  | {
      kind: "executed";
      proposalId: string;
      transactionId: string;
      txHash: string;
      chainId: typeof APPLICATION_EXECUTION_CHAIN_ID;
      replay: boolean;
    }
  | { kind: "pending_approval"; proposalId: string; transactionId: string; results: PolicyResult[] }
  | { kind: "processing"; proposalId: string; transactionId: string }
  | { kind: "rejected"; proposalId: string; transactionId: string; results: PolicyResult[] }
  | { kind: "failed"; proposalId: string; transactionId: string };

type StoredIntent = {
  network?: { namespace?: unknown; chainId?: unknown };
  transaction?: { to?: unknown; value?: unknown; data?: unknown };
};

/** Shape-check the immutable prepared intent. Anything unexpected is refused. */
export function signPayloadFromIntent(intent: unknown): {
  to: string;
  value: string;
  data?: string;
  chainId: number;
} {
  const stored = intent as StoredIntent;
  const chainId = stored?.network?.chainId;
  const to = stored?.transaction?.to;
  const value = stored?.transaction?.value;
  const data = stored?.transaction?.data;
  if (
    stored?.network?.namespace !== "eip155" ||
    typeof chainId !== "number" ||
    typeof to !== "string" ||
    !/^0x[0-9a-f]{40}$/.test(to) ||
    typeof value !== "string" ||
    !/^\d+$/.test(value) ||
    (data !== undefined && (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(data)))
  ) {
    throw new ApplicationBoundaryError(409, "intent_invalid", "Prepared intent is not executable");
  }
  return { to, value, ...(data !== undefined ? { data } : {}), chainId };
}

export function assertApplicationExecutionChain(chainId: number): void {
  if (chainId !== APPLICATION_EXECUTION_CHAIN_ID) {
    throw new ApplicationBoundaryError(
      409,
      "chain_not_admitted",
      `Application proposal execution is restricted to chainId ${APPLICATION_EXECUTION_CHAIN_ID}`,
    );
  }
}

async function loadProposal(tenantId: string, proposalId: string) {
  const [row] = await db
    .select({
      proposalId: applicationTransactionProposals.id,
      principalId: applicationTransactionProposals.principalId,
      intent: applicationTransactionIntents.intent,
      intentExpiresAt: applicationTransactionIntents.expiresAt,
      stewardAgentId: applicationWallets.stewardAgentId,
    })
    .from(applicationTransactionProposals)
    .innerJoin(
      applicationTransactionIntents,
      and(
        eq(applicationTransactionIntents.tenantId, applicationTransactionProposals.tenantId),
        eq(applicationTransactionIntents.principalId, applicationTransactionProposals.principalId),
        eq(applicationTransactionIntents.id, applicationTransactionProposals.intentId),
      ),
    )
    .innerJoin(
      applicationWallets,
      and(
        eq(applicationWallets.tenantId, applicationTransactionIntents.tenantId),
        eq(applicationWallets.principalId, applicationTransactionIntents.principalId),
        eq(applicationWallets.id, applicationTransactionIntents.walletId),
      ),
    )
    .where(
      and(
        eq(applicationTransactionProposals.tenantId, tenantId),
        eq(applicationTransactionProposals.id, proposalId),
      ),
    );
  return row;
}

async function findLinkage(tenantId: string, principalId: string, proposalId: string) {
  const [row] = await db
    .select()
    .from(applicationProposalExecutions)
    .where(
      and(
        eq(applicationProposalExecutions.tenantId, tenantId),
        eq(applicationProposalExecutions.principalId, principalId),
        eq(applicationProposalExecutions.proposalId, proposalId),
      ),
    );
  return row;
}

async function findReservation(tenantId: string, agentId: string, executionRef: string) {
  const [row] = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.tenantId, tenantId),
        eq(transactions.agentId, agentId),
        eq(transactions.executionRef, executionRef),
      ),
    );
  return row;
}

function samePayload(row: Transaction, payload: ReturnType<typeof signPayloadFromIntent>) {
  const rowData = row.data === null || row.data === "" || row.data === "0x" ? null : row.data;
  const want = payload.data === undefined || payload.data === "0x" ? null : payload.data;
  return (
    row.toAddress.toLowerCase() === payload.to &&
    row.value === payload.value &&
    (rowData?.toLowerCase() ?? null) === want &&
    row.chainId === payload.chainId
  );
}

async function writeLinkage(input: {
  tenantId: string;
  principalId: string;
  proposalId: string;
  transactionId: string;
  txHash: string;
  executedBy: string;
}) {
  const txHash = input.txHash.toLowerCase();
  if (!TX_HASH_RE.test(txHash)) {
    throw new ApplicationBoundaryError(500, "tx_hash_invalid", "Broadcast returned no valid hash");
  }
  await db
    .insert(applicationProposalExecutions)
    .values({
      tenantId: input.tenantId,
      principalId: input.principalId,
      proposalId: input.proposalId,
      transactionId: input.transactionId,
      chainId: APPLICATION_EXECUTION_CHAIN_ID,
      txHash,
      executedBy: input.executedBy,
    })
    .onConflictDoNothing();
  const winner = await findLinkage(input.tenantId, input.principalId, input.proposalId);
  if (!winner || winner.transactionId !== input.transactionId || winner.txHash !== txHash) {
    throw new ApplicationBoundaryError(409, "execution_conflict", "Execution linkage conflict");
  }
  return winner;
}

/** Map an already-reserved transactions row to an outcome, reconciling linkage when broadcast. */
async function fromReservation(
  row: Transaction,
  ctx: { tenantId: string; principalId: string; proposalId: string; executedBy: string },
): Promise<ApplicationProposalExecutionOutcome> {
  if (
    (row.status === "signed" || row.status === "broadcast" || row.status === "confirmed") &&
    row.txHash
  ) {
    const linkage = await writeLinkage({ ...ctx, transactionId: row.id, txHash: row.txHash });
    return {
      kind: "executed",
      proposalId: ctx.proposalId,
      transactionId: row.id,
      txHash: linkage.txHash,
      chainId: APPLICATION_EXECUTION_CHAIN_ID,
      replay: true,
    };
  }
  if (row.status === "rejected") {
    return {
      kind: "rejected",
      proposalId: ctx.proposalId,
      transactionId: row.id,
      results: row.policyResults ?? [],
    };
  }
  if (row.status === "failed")
    return { kind: "failed", proposalId: ctx.proposalId, transactionId: row.id };
  const [queued] = await db
    .select({ id: approvalQueue.id })
    .from(approvalQueue)
    .where(eq(approvalQueue.txId, row.id));
  return queued
    ? {
        kind: "pending_approval",
        proposalId: ctx.proposalId,
        transactionId: row.id,
        results: row.policyResults ?? [],
      }
    : { kind: "processing", proposalId: ctx.proposalId, transactionId: row.id };
}

export async function executeApplicationProposal(input: {
  tenantId: string;
  proposalId: string;
  executedBy: string;
}): Promise<ApplicationProposalExecutionOutcome> {
  const { tenantId, proposalId, executedBy } = input;
  const proposal = await loadProposal(tenantId, proposalId);
  if (!proposal)
    throw new ApplicationBoundaryError(404, "proposal_not_found", "Proposal not found");
  const ctx = { tenantId, principalId: proposal.principalId, proposalId, executedBy };

  const existing = await findLinkage(tenantId, proposal.principalId, proposalId);
  if (existing) {
    return {
      kind: "executed",
      proposalId,
      transactionId: existing.transactionId,
      txHash: existing.txHash,
      chainId: APPLICATION_EXECUTION_CHAIN_ID,
      replay: true,
    };
  }

  const payload = signPayloadFromIntent(proposal.intent);
  assertApplicationExecutionChain(payload.chainId);
  const agentId = proposal.stewardAgentId;
  if (isProtectedMinter(tenantId, agentId)) {
    throw new ApplicationBoundaryError(
      403,
      "protected_signer",
      "Protected signer is not executable here",
    );
  }
  const executionRef = applicationProposalExecutionRef(proposalId);

  const reserved = await findReservation(tenantId, agentId, executionRef);
  if (reserved) {
    if (!samePayload(reserved, payload)) {
      throw new ApplicationBoundaryError(409, "execution_conflict", "Reservation payload mismatch");
    }
    return fromReservation(reserved, ctx);
  }

  if (proposal.intentExpiresAt.getTime() <= Date.now()) {
    throw new ApplicationBoundaryError(409, "intent_expired", "Prepared intent has expired");
  }

  // Deterministic configuration error before anything is reserved or decrypted.
  vault.assertChainRpcReady(APPLICATION_EXECUTION_CHAIN_ID);

  const txId = crypto.randomUUID();
  const inserted = await db
    .insert(transactions)
    .values({
      id: txId,
      agentId,
      tenantId,
      executionRef,
      status: "pending",
      toAddress: payload.to,
      value: payload.value,
      data: payload.data,
      chainId: APPLICATION_EXECUTION_CHAIN_ID,
      policyResults: [],
    })
    .onConflictDoNothing({
      target: [transactions.tenantId, transactions.agentId, transactions.executionRef],
    })
    .returning({ id: transactions.id });
  if (inserted.length === 0) {
    const winner = await findReservation(tenantId, agentId, executionRef);
    if (!winner)
      throw new ApplicationBoundaryError(500, "reservation_failed", "Reservation failed; retry");
    return fromReservation(winner, ctx);
  }

  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: payload.to,
    value: payload.value,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    chainId: APPLICATION_EXECUTION_CHAIN_ID,
    broadcast: true,
    executionRef,
  };
  const policySet = await getPolicySet(tenantId, agentId);
  const stats = await getTransactionStats(agentId);
  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    if (evaluation.requiresManualApproval) {
      // Human Steward approver signs via the existing approve route; a later
      // execute call reconciles the linkage from the recorded txHash.
      await db.transaction(async (tx) => {
        await tx
          .update(transactions)
          .set({ policyResults: evaluation.results })
          .where(eq(transactions.id, txId));
        await tx
          .insert(approvalQueue)
          .values({ id: crypto.randomUUID(), txId, agentId, status: "pending" });
      });
      return {
        kind: "pending_approval",
        proposalId,
        transactionId: txId,
        results: evaluation.results,
      };
    }
    await db
      .update(transactions)
      .set({ status: "rejected", policyResults: evaluation.results })
      .where(eq(transactions.id, txId));
    return { kind: "rejected", proposalId, transactionId: txId, results: evaluation.results };
  }

  let txHash: string;
  try {
    txHash = await vault.signTransaction(signRequest, {
      txId,
      policyResults: evaluation.results,
      status: "signed",
    });
  } catch (error) {
    // Ambiguous after the signer was invoked: terminal, never re-signed under this ref.
    await db
      .update(transactions)
      .set({ status: "failed", policyResults: evaluation.results })
      .where(and(eq(transactions.id, txId), eq(transactions.status, "pending")));
    throw error;
  }
  await db
    .update(transactions)
    .set({ status: "signed", txHash, policyResults: evaluation.results, signedAt: new Date() })
    .where(eq(transactions.id, txId));
  const linkage = await writeLinkage({ ...ctx, transactionId: txId, txHash });
  return {
    kind: "executed",
    proposalId,
    transactionId: txId,
    txHash: linkage.txHash,
    chainId: APPLICATION_EXECUTION_CHAIN_ID,
    replay: false,
  };
}
