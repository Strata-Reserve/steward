import { type Context, Hono } from "hono";
import { requireApplicationCapability } from "../middleware/application-principal";
import {
  ApplicationBoundaryError,
  ensureApplicationWallet,
  isValidApplicationReference,
  prepareApplicationTransaction,
  proposeApplicationTransaction,
  readApplicationWalletAddress,
} from "../services/application-boundary";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  isValidAddress,
  safeJsonParse,
} from "../services/context";

export const applicationRoutes = new Hono<{ Variables: AppVariables }>();
type AppContext = Context<{ Variables: AppVariables }>;

function requestMetadata(c: AppContext) {
  return {
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  };
}

async function auditApplicationAction(
  c: AppContext,
  action: string,
  resourceType: string,
  resourceId: string,
  metadata: Record<string, unknown> = {},
) {
  const principal = c.get("applicationPrincipal")!;
  await writeAuditEvent({
    tenantId: principal.tenantId,
    actorType: "application",
    actorId: principal.id,
    action,
    resourceType,
    resourceId,
    metadata: { auditIdentity: principal.id, ...metadata },
    ...requestMetadata(c),
  });
}

function forbidden(c: AppContext, capability: string) {
  return c.json<ApiResponse>(
    { ok: false, error: `Missing application capability: ${capability}` },
    403,
  );
}

function commandError(c: AppContext, error: unknown) {
  if (error instanceof ApplicationBoundaryError) {
    return c.json<ApiResponse>({ ok: false, error: error.message }, error.status);
  }
  throw error;
}

applicationRoutes.post("/wallets/ensure", async (c) => {
  if (!requireApplicationCapability(c, "ensure_wallet")) return forbidden(c, "ensure_wallet");
  const principal = c.get("applicationPrincipal")!;
  const body = await safeJsonParse<{ ownerReference?: string; chainFamily?: "evm" | "solana" }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (!isValidApplicationReference(body.ownerReference)) {
    return c.json<ApiResponse>({ ok: false, error: "ownerReference is invalid" }, 400);
  }
  if (body.chainFamily !== "evm" && body.chainFamily !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: 'chainFamily must be "evm" or "solana"' }, 400);
  }
  try {
    const result = await ensureApplicationWallet(principal, body.ownerReference, body.chainFamily);
    await auditApplicationAction(
      c,
      "application.wallet.ensure",
      "application_wallet",
      result.wallet.id,
      {
        ownerReference: body.ownerReference,
        chainFamily: body.chainFamily,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      { ok: true, data: { wallet: result.wallet, replay: !result.created } },
      result.created ? 201 : 200,
    );
  } catch (error) {
    if (error instanceof ApplicationBoundaryError && error.code === "owner_not_assigned") {
      await auditApplicationAction(
        c,
        "application.wallet.ensure.denied",
        "owner_reference",
        body.ownerReference,
        {
          reason: error.code,
        },
      );
    }
    return commandError(c, error);
  }
});

applicationRoutes.get("/wallets/:walletId/address", async (c) => {
  if (!requireApplicationCapability(c, "read_wallet_address"))
    return forbidden(c, "read_wallet_address");
  try {
    const wallet = await readApplicationWalletAddress(
      c.get("applicationPrincipal")!,
      c.req.param("walletId"),
    );
    await auditApplicationAction(
      c,
      "application.wallet_address.read",
      "application_wallet",
      wallet.id,
    );
    return c.json<ApiResponse>({ ok: true, data: wallet });
  } catch (error) {
    return commandError(c, error);
  }
});

applicationRoutes.post("/transactions/prepare", async (c) => {
  if (!requireApplicationCapability(c, "prepare_transaction"))
    return forbidden(c, "prepare_transaction");
  const body = await safeJsonParse<{
    idempotencyKey?: string;
    walletId?: string;
    network?: { type?: "evm"; chainId?: number };
    transaction?: { to?: string; value?: string; data?: string };
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (!isValidApplicationReference(body.idempotencyKey)) {
    return c.json<ApiResponse>({ ok: false, error: "idempotencyKey is invalid" }, 400);
  }
  if (typeof body.walletId !== "string")
    return c.json<ApiResponse>({ ok: false, error: "walletId is required" }, 400);
  if (body.network?.type !== "evm") {
    return c.json<ApiResponse>(
      { ok: false, error: "This contract currently prepares EVM transactions only" },
      400,
    );
  }
  if (!Number.isSafeInteger(body.network.chainId) || (body.network.chainId ?? 0) <= 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "network.chainId must be a positive integer" },
      400,
    );
  }
  const tx = body.transaction;
  if (!tx || !isValidAddress(tx.to))
    return c.json<ApiResponse>({ ok: false, error: "transaction.to is invalid" }, 400);
  if (typeof tx.value !== "string" || !/^\d+$/.test(tx.value)) {
    return c.json<ApiResponse>(
      { ok: false, error: "transaction.value must be an unsigned decimal string" },
      400,
    );
  }
  if (tx.data !== undefined && !/^0x(?:[0-9a-fA-F]{2})*$/.test(tx.data)) {
    return c.json<ApiResponse>(
      { ok: false, error: "transaction.data must be even-length hex" },
      400,
    );
  }
  try {
    const result = await prepareApplicationTransaction(c.get("applicationPrincipal")!, {
      idempotencyKey: body.idempotencyKey,
      walletId: body.walletId,
      chainId: body.network.chainId!,
      to: tx.to!,
      value: tx.value,
      ...(tx.data !== undefined ? { data: tx.data } : {}),
    });
    await auditApplicationAction(
      c,
      "application.transaction.prepare",
      "application_transaction_intent",
      result.preparedTransaction.id,
      {
        walletId: body.walletId,
        requestHash: result.requestHash,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      {
        ok: true,
        data: { preparedTransaction: result.preparedTransaction, replay: !result.created },
      },
      result.created ? 201 : 200,
    );
  } catch (error) {
    return commandError(c, error);
  }
});

applicationRoutes.post("/transactions/propose", async (c) => {
  if (!requireApplicationCapability(c, "propose_transaction"))
    return forbidden(c, "propose_transaction");
  const body = await safeJsonParse<{ idempotencyKey?: string; preparedTransactionId?: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (!isValidApplicationReference(body.idempotencyKey)) {
    return c.json<ApiResponse>({ ok: false, error: "idempotencyKey is invalid" }, 400);
  }
  if (typeof body.preparedTransactionId !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "preparedTransactionId is required" }, 400);
  }
  try {
    const result = await proposeApplicationTransaction(c.get("applicationPrincipal")!, {
      idempotencyKey: body.idempotencyKey,
      preparedTransactionId: body.preparedTransactionId,
    });
    await auditApplicationAction(
      c,
      "application.transaction.propose",
      "application_transaction_proposal",
      result.proposal.id,
      {
        intentId: result.intentId,
        requestHash: result.requestHash,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      { ok: true, data: { proposal: result.proposal, replay: !result.created } },
      result.created ? 202 : 200,
    );
  } catch (error) {
    return commandError(c, error);
  }
});
