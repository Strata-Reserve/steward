/**
 * STRATA-1515 exec gap (option A): execute one approved application proposal.
 *
 * Application principals stay proposal-only. They never gain sign, approve, or
 * broadcast authority, and no `/application/*` route reaches this module. The
 * ONLY caller is a tenant owner/admin human session on the tenant-auth admin
 * namespace (`/application-principals/...`), and that call IS the approval.
 *
 * What is signed is never caller-supplied: the exact immutable intent row the
 * principal prepared is re-read, re-validated, and re-checked against:
 *
 *   - the application boundary: principal not revoked/expired, the resource
 *     assignment and wallet binding still exist, the intent has not expired;
 *   - an immutable, admin-created executor-signer binding for
 *     (tenant, principal, chain) with an explicit contract allowlist;
 *   - an env kill switch (`STEWARD_APPLICATION_EXECUTION_CHAIN_IDS`, default
 *     empty = disabled) so no chain executes unless the deployment opts in;
 *   - a strict call shape: value 0 and exactly `mint(address,uint256)` whose
 *     recipient is the proposal's own assigned wallet;
 *   - the existing policy engine over the signer agent's policy set.
 *
 * Single execution is a database fact: one execution row per proposal (unique
 * index) and one reserved `transactions` row per execution ref (STRATA-1486
 * unique index), both inserted in one transaction BEFORE the key is touched.
 * Any failure after the vault is invoked is recorded as `indeterminate` and is
 * never retried automatically, because an RPC can accept a transaction and
 * still throw.
 */
import {
  agents,
  applicationExecutorSigners,
  applicationPrincipalResources,
  applicationPrincipals,
  applicationProposalExecutions,
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  getDb,
  transactions,
} from "@stwd/db";
import type { PolicyResult, SignRequest } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import { enforceRateLimit, recordVaultSpend } from "../middleware/redis-enforcement";
import { ApplicationBoundaryError, deterministicId } from "./application-boundary";
import {
  describeRpcError,
  getPolicySet,
  getTransactionStats,
  policyEngine,
  priceOracle,
  vault,
} from "./context";
import { decodeMint, isPersistedProtectedAgent, isProtectedMinter } from "./prod-minter-boundary";

export const APPLICATION_EXECUTION_CHAIN_IDS_ENV = "STEWARD_APPLICATION_EXECUTION_CHAIN_IDS";
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export class ApplicationExecutionError extends ApplicationBoundaryError {}

function fail(status: 403 | 404 | 409 | 500, code: string, message: string): never {
  throw new ApplicationExecutionError(status, code, message);
}

/** Exact allowlist of chain ids the deployment admits. Unset/empty = feature off. */
export function applicationExecutionChainIds(
  env: Record<string, string | undefined> = process.env,
): ReadonlySet<number> {
  const raw = env[APPLICATION_EXECUTION_CHAIN_IDS_ENV];
  if (raw === undefined || raw.trim() === "") return new Set();
  const ids = new Set<number>();
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!/^[1-9][0-9]{0,9}$/.test(trimmed)) {
      throw new Error(`${APPLICATION_EXECUTION_CHAIN_IDS_ENV} must be comma-separated chain ids`);
    }
    ids.add(Number(trimmed));
  }
  return ids;
}

export function applicationExecutionRef(proposalId: string): string {
  return `application-proposal:${proposalId}`;
}

type StoredIntent = {
  kind?: unknown;
  wallet?: { id?: unknown; address?: unknown };
  network?: { namespace?: unknown; chainId?: unknown };
  transaction?: { to?: unknown; value?: unknown; data?: unknown };
};

export type ExecutorSignerBindingInput = {
  tenantId: string;
  principalId: string;
  chainId: number;
  signerAgentId: string;
  allowedTargets: string[];
  createdBy: string;
};

/** Create the immutable executor-signer binding. Admin-only; never overwritten. */
export async function createExecutorSignerBinding(input: ExecutorSignerBindingInput) {
  const db = getDb();
  const [principal] = await db
    .select()
    .from(applicationPrincipals)
    .where(
      and(
        eq(applicationPrincipals.tenantId, input.tenantId),
        eq(applicationPrincipals.id, input.principalId),
      ),
    );
  if (!principal) fail(404, "principal_not_found", "Application principal not found");
  if (principal.revokedAt || principal.expiresAt.getTime() <= Date.now()) {
    fail(409, "principal_inactive", "Application principal is inactive");
  }
  const [agent] = await db
    .select({ id: agents.id })
    .from(agents)
    .where(and(eq(agents.tenantId, input.tenantId), eq(agents.id, input.signerAgentId)));
  if (!agent) fail(404, "signer_not_found", "Signer agent not found");
  await assertOrdinarySigner(input.tenantId, input.signerAgentId);
  const [applicationWallet] = await db
    .select({ id: applicationWallets.id })
    .from(applicationWallets)
    .where(
      and(
        eq(applicationWallets.tenantId, input.tenantId),
        eq(applicationWallets.stewardAgentId, input.signerAgentId),
      ),
    );
  if (applicationWallet) {
    // An application wallet's own key must never become the executor: the
    // recipient and the signer would collapse into one authority.
    fail(409, "signer_is_application_wallet", "Signer may not be an application wallet");
  }
  const targets = [...new Set(input.allowedTargets.map((t) => t.toLowerCase()))].sort();
  const inserted = await db
    .insert(applicationExecutorSigners)
    .values({
      tenantId: input.tenantId,
      principalId: input.principalId,
      chainId: input.chainId,
      signerAgentId: input.signerAgentId,
      allowedTargets: targets,
      createdBy: input.createdBy,
    })
    .onConflictDoNothing()
    .returning();
  if (inserted.length === 0) {
    fail(409, "binding_exists", "Executor signer binding already exists and is immutable");
  }
  return inserted[0]!;
}

async function assertOrdinarySigner(tenantId: string, agentId: string) {
  // The protected production minter has its own manifest + permit ceremony.
  // This path must never become a second door to it.
  if (isProtectedMinter(tenantId, agentId) || (await isPersistedProtectedAgent(agentId))) {
    fail(403, "protected_signer_refused", "Protected signer cannot execute application proposals");
  }
}

type ExecutionRow = typeof applicationProposalExecutions.$inferSelect;

export function toApplicationExecutionView(row: ExecutionRow) {
  return {
    id: row.id,
    proposalId: row.proposalId,
    principalId: row.principalId,
    status: row.status,
    chainId: row.chainId,
    to: row.toAddress,
    recipient: row.recipientAddress,
    amount: row.amount,
    txHash: row.txHash,
    transactionId: row.transactionId,
    executionRef: row.executionRef,
    approvedBy: row.approvedBy,
    policyResults: row.policyResults,
    failureReason: row.failureReason,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export type ExecuteApplicationProposalResult = {
  execution: ReturnType<typeof toApplicationExecutionView>;
  replay: boolean;
};

export async function executeApplicationProposal(input: {
  tenantId: string;
  principalId: string;
  proposalId: string;
  approvedBy: string;
  env?: Record<string, string | undefined>;
}): Promise<ExecuteApplicationProposalResult> {
  const db = getDb();

  // Replay first: an existing execution is reported, never re-signed.
  const [existing] = await db
    .select()
    .from(applicationProposalExecutions)
    .where(
      and(
        eq(applicationProposalExecutions.tenantId, input.tenantId),
        eq(applicationProposalExecutions.principalId, input.principalId),
        eq(applicationProposalExecutions.proposalId, input.proposalId),
      ),
    );
  if (existing) return { execution: toApplicationExecutionView(existing), replay: true };

  // Application boundary: the exact proposal -> intent -> wallet -> assigned
  // resource chain, all in the principal's tenant scope.
  const [record] = await db
    .select({
      proposal: applicationTransactionProposals,
      intent: applicationTransactionIntents,
      wallet: applicationWallets,
      principal: applicationPrincipals,
    })
    .from(applicationTransactionProposals)
    .innerJoin(
      applicationPrincipals,
      and(
        eq(applicationPrincipals.tenantId, applicationTransactionProposals.tenantId),
        eq(applicationPrincipals.id, applicationTransactionProposals.principalId),
      ),
    )
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
    .where(
      and(
        eq(applicationTransactionProposals.tenantId, input.tenantId),
        eq(applicationTransactionProposals.principalId, input.principalId),
        eq(applicationTransactionProposals.id, input.proposalId),
      ),
    );
  if (!record) fail(404, "proposal_not_found", "Proposal not found");
  const { proposal, intent, wallet, principal } = record;
  const now = Date.now();
  if (proposal.status !== "proposed") fail(409, "proposal_not_executable", "Proposal is not open");
  if (principal.revokedAt) fail(409, "principal_revoked", "Application principal is revoked");
  if (principal.expiresAt.getTime() <= now) {
    fail(409, "principal_expired", "Application principal is expired");
  }
  if (intent.expiresAt.getTime() <= now) {
    fail(409, "intent_expired", "Prepared transaction expired before execution");
  }

  // Exact stored intent shape. Nothing here is taken from the HTTP caller.
  const stored = intent.intent as StoredIntent;
  const chainId = stored.network?.chainId;
  const to = stored.transaction?.to;
  const value = stored.transaction?.value;
  const data = stored.transaction?.data;
  if (
    stored.kind !== "evm_transaction" ||
    stored.network?.namespace !== "eip155" ||
    typeof chainId !== "number" ||
    !Number.isInteger(chainId) ||
    stored.wallet?.id !== wallet.id ||
    typeof to !== "string" ||
    !ADDRESS_RE.test(to) ||
    value !== "0" ||
    typeof data !== "string"
  ) {
    fail(409, "intent_shape_refused", "Prepared transaction shape is not executable");
  }
  const mint = decodeMint(data);
  if (!mint) fail(409, "intent_call_refused", "Only mint(address,uint256) is executable");
  if (mint.recipient.toLowerCase() !== wallet.addresses.evm.toLowerCase()) {
    fail(409, "recipient_mismatch", "Mint recipient is not the proposal's assigned wallet");
  }
  if (mint.amount <= 0n) fail(409, "amount_refused", "Mint amount must be positive");

  const enabledChains = applicationExecutionChainIds(input.env);
  if (!enabledChains.has(chainId)) {
    fail(403, "chain_not_enabled", `Application execution is not enabled for chain ${chainId}`);
  }

  const [binding] = await db
    .select()
    .from(applicationExecutorSigners)
    .where(
      and(
        eq(applicationExecutorSigners.tenantId, input.tenantId),
        eq(applicationExecutorSigners.principalId, input.principalId),
        eq(applicationExecutorSigners.chainId, chainId),
      ),
    );
  if (!binding) fail(403, "executor_unbound", "No executor signer is bound for this chain");
  if (!binding.allowedTargets.includes(to.toLowerCase())) {
    fail(403, "target_not_allowed", "Contract is not in the executor signer allowlist");
  }
  await assertOrdinarySigner(input.tenantId, binding.signerAgentId);

  const executionRef = applicationExecutionRef(proposal.id);
  const signRequest: SignRequest = {
    tenantId: input.tenantId,
    agentId: binding.signerAgentId,
    to: to.toLowerCase(),
    value: "0",
    data: data.toLowerCase(),
    chainId,
    broadcast: true,
    executionRef,
  };

  // Deterministic configuration preflight before anything is reserved.
  try {
    vault.assertChainRpcReady(chainId);
  } catch (error) {
    fail(500, "rpc_not_ready", describeRpcError(error));
  }

  const policySet = await getPolicySet(input.tenantId, binding.signerAgentId);
  const rateLimit = await enforceRateLimit(binding.signerAgentId, policySet);
  if (!rateLimit.allowed) fail(409, "rate_limited", rateLimit.reason ?? "Rate limit exceeded");
  const stats = await getTransactionStats(binding.signerAgentId);
  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });
  // Hard policy failure refuses with no reservation. A soft
  // auto-approve-threshold miss is satisfied by this human approval itself.
  if (!evaluation.approved && !evaluation.requiresManualApproval) {
    throw Object.assign(
      new ApplicationExecutionError(403, "policy_rejected", "Execution rejected by policy"),
      { policyResults: evaluation.results },
    );
  }
  const policyResults: PolicyResult[] = evaluation.results;

  const executionId = deterministicId(
    "ape",
    "application-proposal-execution",
    input.tenantId,
    input.principalId,
    proposal.id,
  );
  const txId = crypto.randomUUID();

  const reservation = await db.transaction(async (tx) => {
    // Re-lock the principal row so a concurrent revoke serializes against us.
    const [locked] = await tx
      .select({ revokedAt: applicationPrincipals.revokedAt })
      .from(applicationPrincipals)
      .where(
        and(
          eq(applicationPrincipals.tenantId, input.tenantId),
          eq(applicationPrincipals.id, input.principalId),
        ),
      )
      .for("update");
    if (!locked || locked.revokedAt) return { revoked: true as const };
    // Single-execution arbiter first: the execution_ref unique index on
    // transactions (STRATA-1486) admits exactly one reservation per proposal.
    const reserved = await tx
      .insert(transactions)
      .values({
        id: txId,
        agentId: binding.signerAgentId,
        tenantId: input.tenantId,
        executionRef,
        status: "approved",
        toAddress: signRequest.to,
        value: "0",
        data: signRequest.data,
        chainId,
        policyResults,
      })
      .onConflictDoNothing({
        target: [transactions.tenantId, transactions.agentId, transactions.executionRef],
      })
      .returning({ id: transactions.id });
    if (reserved.length === 0) return { winner: true as const };
    const inserted = await tx
      .insert(applicationProposalExecutions)
      .values({
        id: executionId,
        tenantId: input.tenantId,
        principalId: input.principalId,
        proposalId: proposal.id,
        signerAgentId: binding.signerAgentId,
        chainId,
        transactionId: txId,
        executionRef,
        toAddress: signRequest.to,
        recipientAddress: mint.recipient.toLowerCase(),
        amount: mint.amount.toString(),
        approvedBy: input.approvedBy,
        policyResults,
      })
      .onConflictDoNothing()
      .returning();
    if (inserted.length === 0) throw new Error("application execution reservation collided");
    return { row: inserted[0]! };
  });
  if ("revoked" in reservation) fail(409, "principal_revoked", "Application principal is revoked");
  if ("winner" in reservation) {
    const [winner] = await db
      .select()
      .from(applicationProposalExecutions)
      .where(
        and(
          eq(applicationProposalExecutions.tenantId, input.tenantId),
          eq(applicationProposalExecutions.principalId, input.principalId),
          eq(applicationProposalExecutions.proposalId, proposal.id),
        ),
      );
    if (!winner) fail(500, "execution_reservation_failed", "Execution reservation failed");
    return { execution: toApplicationExecutionView(winner), replay: true };
  }

  let txHash: string;
  try {
    txHash = await vault.signTransaction(signRequest, {
      txId,
      policyResults,
      status: "broadcast",
    });
  } catch (error) {
    // Ambiguous: the RPC may have accepted it. Terminal, never re-armed.
    const reason = describeRpcError(error).slice(0, 500);
    await db
      .update(transactions)
      .set({ status: "failed" })
      .where(and(eq(transactions.id, txId), eq(transactions.status, "approved")))
      .catch(() => undefined);
    const [row] = await db
      .update(applicationProposalExecutions)
      .set({ status: "indeterminate", failureReason: reason, updatedAt: new Date() })
      .where(
        and(
          eq(applicationProposalExecutions.id, executionId),
          eq(applicationProposalExecutions.status, "executing"),
        ),
      )
      .returning();
    return {
      execution: toApplicationExecutionView(row ?? { ...reservation.row, status: "indeterminate" }),
      replay: false,
    };
  }

  const [row] = await db
    .update(applicationProposalExecutions)
    .set({ status: "broadcast", txHash, updatedAt: new Date() })
    .where(
      and(
        eq(applicationProposalExecutions.id, executionId),
        eq(applicationProposalExecutions.status, "executing"),
      ),
    )
    .returning();
  recordVaultSpend(binding.signerAgentId, input.tenantId, "0", chainId).catch(() => undefined);
  if (!row) fail(500, "execution_record_failed", "Broadcast succeeded but recording failed");
  return { execution: toApplicationExecutionView(row), replay: false };
}
