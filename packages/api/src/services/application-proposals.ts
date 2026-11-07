/**
 * Proposal-only persistence authority.
 *
 * Static security invariant: this module imports database schemas only. It must
 * never import Vault, signing, RPC, approval, broadcast, or execution modules.
 */
import {
  applicationIdempotencyRecords,
  applicationPrincipalResources,
  applicationProposalExecutions,
  applicationProposalReadCompatibility,
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  getDb,
} from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";
import {
  ApplicationBoundaryError,
  type ApplicationPrincipalContext,
  canonicalJson,
  deterministicId,
  sha256,
} from "./application-boundary";

export type PrepareApplicationTransactionCommand = {
  idempotencyKey: string;
  walletId: string;
  chainId: number;
  to: string;
  value: string;
  data?: string;
};

export const APPLICATION_EXECUTION_EVIDENCE_UNAVAILABLE = "no_canonical_execution_linkage" as const;

type ApplicationProposalExecutionRecord = {
  status: "executing" | "broadcast" | "indeterminate";
  chainId: number;
  txHash: string | null;
  toAddress: string;
  recipientAddress: string;
  amount: string;
  executionId: string;
};

type ApplicationProposalReadRecord = {
  id: string;
  intentId: string;
  status: "proposed";
  createdAt: Date;
  walletId: string;
  resourceKind: "wallet_owner";
  resourceId: string;
  execution?: ApplicationProposalExecutionRecord | null;
};

/**
 * The proposal row proves proposal acceptance only. Execution evidence comes
 * exclusively from the canonical `application_proposal_executions` row written
 * by the admin execute command (STRATA-1515 exec gap A, migration 0031):
 *
 *   - no row          -> `unknown` / `no_canonical_execution_linkage` (unchanged)
 *   - `broadcast`     -> `broadcast` with the exact tx hash, chain and call
 *   - `executing` / `indeterminate` -> no hash is claimed; the consumer must
 *     keep the work open and reconcile.
 *
 * `terminal` stays false: broadcast is not confirmation.
 */
export function toApplicationProposalReadModel(record: ApplicationProposalReadRecord) {
  const execution = record.execution ?? null;
  return {
    id: record.id,
    intentId: record.intentId,
    status: record.status,
    terminal: false as const,
    recordedAt: record.createdAt.toISOString(),
    resource: {
      kind: record.resourceKind,
      id: record.resourceId,
      walletId: record.walletId,
    },
    executionEvidence: executionEvidenceFor(execution),
  };
}

function executionEvidenceFor(execution: ApplicationProposalExecutionRecord | null) {
  if (execution === null) {
    return {
      status: "unknown" as const,
      evidence: null,
      reason: APPLICATION_EXECUTION_EVIDENCE_UNAVAILABLE,
    };
  }
  if (execution.status === "broadcast" && execution.txHash !== null) {
    return {
      status: "broadcast" as const,
      evidence: {
        executionId: execution.executionId,
        network: { namespace: "eip155" as const, chainId: execution.chainId },
        txHash: execution.txHash,
        to: execution.toAddress,
        call: {
          function: "mint(address,uint256)" as const,
          recipient: execution.recipientAddress,
          amount: execution.amount,
        },
      },
      reason: null,
    };
  }
  return {
    status: execution.status === "executing" ? ("executing" as const) : ("indeterminate" as const),
    evidence: null,
    reason:
      execution.status === "executing"
        ? ("execution_in_progress" as const)
        : ("execution_outcome_indeterminate" as const),
  };
}

export async function readApplicationProposalStatus(
  principal: ApplicationPrincipalContext,
  proposalId: string,
) {
  const hasExplicitReadCapability = principal.capabilities.includes("transaction:proposal:read");

  const [record] = await getDb()
    .select({
      id: applicationTransactionProposals.id,
      intentId: applicationTransactionProposals.intentId,
      status: applicationTransactionProposals.status,
      createdAt: applicationTransactionProposals.createdAt,
      walletId: applicationWallets.id,
      resourceKind: applicationWallets.resourceKind,
      resourceId: applicationWallets.resourceId,
      compatibilityProposalId: applicationProposalReadCompatibility.proposalId,
      executionId: applicationProposalExecutions.id,
      executionStatus: applicationProposalExecutions.status,
      executionChainId: applicationProposalExecutions.chainId,
      executionTxHash: applicationProposalExecutions.txHash,
      executionTo: applicationProposalExecutions.toAddress,
      executionRecipient: applicationProposalExecutions.recipientAddress,
      executionAmount: applicationProposalExecutions.amount,
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
    .innerJoin(
      applicationPrincipalResources,
      and(
        eq(applicationPrincipalResources.tenantId, applicationWallets.tenantId),
        eq(applicationPrincipalResources.principalId, applicationWallets.principalId),
        eq(applicationPrincipalResources.resourceKind, applicationWallets.resourceKind),
        eq(applicationPrincipalResources.resourceId, applicationWallets.resourceId),
      ),
    )
    .leftJoin(
      applicationProposalReadCompatibility,
      and(
        eq(applicationProposalReadCompatibility.tenantId, applicationTransactionProposals.tenantId),
        eq(
          applicationProposalReadCompatibility.principalId,
          applicationTransactionProposals.principalId,
        ),
        eq(applicationProposalReadCompatibility.proposalId, applicationTransactionProposals.id),
        eq(applicationProposalReadCompatibility.resourceKind, applicationWallets.resourceKind),
        eq(applicationProposalReadCompatibility.resourceId, applicationWallets.resourceId),
        eq(applicationProposalReadCompatibility.source, "pre_0026_transaction_proposal"),
      ),
    )
    .leftJoin(
      applicationProposalExecutions,
      and(
        eq(applicationProposalExecutions.tenantId, applicationTransactionProposals.tenantId),
        eq(applicationProposalExecutions.principalId, applicationTransactionProposals.principalId),
        eq(applicationProposalExecutions.proposalId, applicationTransactionProposals.id),
      ),
    )
    .where(
      and(
        eq(applicationTransactionProposals.tenantId, principal.tenantId),
        eq(applicationTransactionProposals.principalId, principal.id),
        eq(applicationTransactionProposals.id, proposalId),
        hasExplicitReadCapability
          ? undefined
          : sql`${applicationProposalReadCompatibility.proposalId} IS NOT NULL`,
      ),
    );

  // Wrong tenant, principal, resource assignment, compatibility binding, and
  // unknown proposal are deliberately indistinguishable to the caller.
  if (!record) {
    throw new ApplicationBoundaryError(404, "proposal_not_found", "Proposal not found");
  }
  const execution =
    record.executionId !== null &&
    record.executionStatus !== null &&
    record.executionChainId !== null &&
    record.executionTo !== null &&
    record.executionRecipient !== null &&
    record.executionAmount !== null
      ? {
          executionId: record.executionId,
          status: record.executionStatus,
          chainId: record.executionChainId,
          txHash: record.executionTxHash,
          toAddress: record.executionTo,
          recipientAddress: record.executionRecipient,
          amount: record.executionAmount,
        }
      : null;
  return {
    proposal: toApplicationProposalReadModel({ ...record, execution }),
    authorizationBasis: hasExplicitReadCapability
      ? ("explicit_capability" as const)
      : ("pre_0026_proposal_compatibility" as const),
  };
}

export async function prepareApplicationTransaction(
  principal: ApplicationPrincipalContext,
  command: PrepareApplicationTransactionCommand,
) {
  const db = getDb();
  const [wallet] = await db
    .select()
    .from(applicationWallets)
    .where(
      and(
        eq(applicationWallets.tenantId, principal.tenantId),
        eq(applicationWallets.principalId, principal.id),
        eq(applicationWallets.id, command.walletId),
      ),
    );
  if (!wallet) throw new ApplicationBoundaryError(404, "wallet_not_found", "Wallet not found");

  const intent = {
    version: "1",
    kind: "evm_transaction",
    wallet: {
      id: wallet.id,
      resourceKind: wallet.resourceKind,
      resourceId: wallet.resourceId,
      address: wallet.addresses.evm,
    },
    network: { namespace: "eip155", chainId: command.chainId },
    transaction: {
      to: command.to.toLowerCase(),
      value: BigInt(command.value).toString(),
      ...(command.data !== undefined ? { data: command.data.toLowerCase() } : {}),
    },
  };
  const requestHash = sha256(canonicalJson(intent));
  const intentId = deterministicId(
    "ati",
    "application-transaction-intent",
    principal.tenantId,
    principal.id,
    command.idempotencyKey,
  );
  const expiresAt = new Date(
    Math.min(principal.expiresAt.getTime(), Date.now() + 24 * 60 * 60_000),
  );

  return db.transaction(async (tx) => {
    const insertedIdempotency = await tx
      .insert(applicationIdempotencyRecords)
      .values({
        tenantId: principal.tenantId,
        principalId: principal.id,
        operation: "transaction_prepare",
        idempotencyKey: command.idempotencyKey,
        requestHash,
        responseId: intentId,
      })
      .onConflictDoNothing({
        target: [
          applicationIdempotencyRecords.tenantId,
          applicationIdempotencyRecords.principalId,
          applicationIdempotencyRecords.operation,
          applicationIdempotencyRecords.idempotencyKey,
        ],
      })
      .returning({ responseId: applicationIdempotencyRecords.responseId });
    const [idempotency] = await tx
      .select()
      .from(applicationIdempotencyRecords)
      .where(
        and(
          eq(applicationIdempotencyRecords.tenantId, principal.tenantId),
          eq(applicationIdempotencyRecords.principalId, principal.id),
          eq(applicationIdempotencyRecords.operation, "transaction_prepare"),
          eq(applicationIdempotencyRecords.idempotencyKey, command.idempotencyKey),
        ),
      );
    if (!idempotency)
      throw new ApplicationBoundaryError(500, "idempotency_missing", "Idempotency record missing");
    if (idempotency.requestHash !== requestHash || idempotency.responseId !== intentId) {
      throw new ApplicationBoundaryError(
        409,
        "idempotency_conflict",
        "Idempotency key was already used for a different transaction",
      );
    }
    if (insertedIdempotency.length > 0) {
      await tx.insert(applicationTransactionIntents).values({
        id: intentId,
        tenantId: principal.tenantId,
        principalId: principal.id,
        credentialKeyId: principal.credentialKeyId,
        walletId: wallet.id,
        requestHash,
        intent,
        expiresAt,
      });
    }
    const [preparedTransaction] = await tx
      .select()
      .from(applicationTransactionIntents)
      .where(
        and(
          eq(applicationTransactionIntents.tenantId, principal.tenantId),
          eq(applicationTransactionIntents.principalId, principal.id),
          eq(applicationTransactionIntents.id, intentId),
        ),
      );
    if (!preparedTransaction) {
      throw new ApplicationBoundaryError(
        500,
        "intent_persistence_failed",
        "Prepared transaction persistence failed",
      );
    }
    if (
      preparedTransaction.requestHash !== requestHash ||
      preparedTransaction.walletId !== wallet.id
    ) {
      throw new ApplicationBoundaryError(
        409,
        "intent_identity_collision",
        "Prepared transaction identity collision",
      );
    }
    return { preparedTransaction, requestHash, created: insertedIdempotency.length > 0 };
  });
}

export async function proposeApplicationTransaction(
  principal: ApplicationPrincipalContext,
  command: { idempotencyKey: string; preparedTransactionId: string },
) {
  return getDb().transaction(async (tx) => {
    // The intent row is the compare-and-set lock. It serializes competing
    // proposal commands so exactly one immutable proposal can reference it.
    const [intent] = await tx
      .select()
      .from(applicationTransactionIntents)
      .where(
        and(
          eq(applicationTransactionIntents.tenantId, principal.tenantId),
          eq(applicationTransactionIntents.principalId, principal.id),
          eq(applicationTransactionIntents.id, command.preparedTransactionId),
        ),
      )
      .for("update");
    if (!intent) {
      throw new ApplicationBoundaryError(
        404,
        "prepared_transaction_not_found",
        "Prepared transaction not found",
      );
    }
    if (intent.expiresAt.getTime() <= Date.now()) {
      throw new ApplicationBoundaryError(
        409,
        "prepared_transaction_expired",
        "Prepared transaction expired",
      );
    }

    const requestHash = sha256(
      canonicalJson({ version: "1", intentId: intent.id, intentHash: intent.requestHash }),
    );
    const [existingProposal] = await tx
      .select()
      .from(applicationTransactionProposals)
      .where(
        and(
          eq(applicationTransactionProposals.tenantId, principal.tenantId),
          eq(applicationTransactionProposals.principalId, principal.id),
          eq(applicationTransactionProposals.intentId, intent.id),
        ),
      );
    const proposalId =
      existingProposal?.id ??
      deterministicId(
        "atp",
        "application-transaction-proposal",
        principal.tenantId,
        principal.id,
        command.idempotencyKey,
      );

    const insertedIdempotency = await tx
      .insert(applicationIdempotencyRecords)
      .values({
        tenantId: principal.tenantId,
        principalId: principal.id,
        operation: "transaction_propose",
        idempotencyKey: command.idempotencyKey,
        requestHash,
        responseId: proposalId,
      })
      .onConflictDoNothing({
        target: [
          applicationIdempotencyRecords.tenantId,
          applicationIdempotencyRecords.principalId,
          applicationIdempotencyRecords.operation,
          applicationIdempotencyRecords.idempotencyKey,
        ],
      })
      .returning({ responseId: applicationIdempotencyRecords.responseId });
    const [idempotency] = await tx
      .select()
      .from(applicationIdempotencyRecords)
      .where(
        and(
          eq(applicationIdempotencyRecords.tenantId, principal.tenantId),
          eq(applicationIdempotencyRecords.principalId, principal.id),
          eq(applicationIdempotencyRecords.operation, "transaction_propose"),
          eq(applicationIdempotencyRecords.idempotencyKey, command.idempotencyKey),
        ),
      );
    if (!idempotency) {
      throw new ApplicationBoundaryError(500, "idempotency_missing", "Idempotency record missing");
    }
    if (idempotency.requestHash !== requestHash || idempotency.responseId !== proposalId) {
      throw new ApplicationBoundaryError(
        409,
        "idempotency_conflict",
        "Idempotency key was already used for a different proposal",
      );
    }
    if (insertedIdempotency.length > 0 && !existingProposal) {
      await tx.insert(applicationTransactionProposals).values({
        id: proposalId,
        tenantId: principal.tenantId,
        principalId: principal.id,
        credentialKeyId: principal.credentialKeyId,
        intentId: intent.id,
        requestHash,
        status: "proposed",
      });
    }
    const [proposal] = await tx
      .select()
      .from(applicationTransactionProposals)
      .where(
        and(
          eq(applicationTransactionProposals.tenantId, principal.tenantId),
          eq(applicationTransactionProposals.principalId, principal.id),
          eq(applicationTransactionProposals.id, proposalId),
        ),
      );
    if (!proposal) {
      throw new ApplicationBoundaryError(
        500,
        "proposal_persistence_failed",
        "Proposal persistence failed",
      );
    }
    if (proposal.requestHash !== requestHash || proposal.intentId !== intent.id) {
      throw new ApplicationBoundaryError(
        409,
        "proposal_identity_collision",
        "Proposal identity collision",
      );
    }
    return {
      proposal,
      intentId: intent.id,
      requestHash,
      created: insertedIdempotency.length > 0 && !existingProposal,
    };
  });
}
