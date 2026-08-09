import { applicationWallets, getDb } from "@stwd/db";
import { and, eq } from "drizzle-orm";
import {
  ApplicationBoundaryError,
  type ApplicationPrincipalContext,
  canonicalJson,
  deterministicId,
  sha256,
} from "./application-boundary";
import { vault } from "./context";

const RESOURCE_KIND = "wallet_owner" as const;

function mapVaultError(error: unknown): never {
  const code = error instanceof Error ? error.message : "application_wallet_failed";
  if (code === "application_wallet_owner_not_assigned") {
    throw new ApplicationBoundaryError(
      403,
      "owner_not_assigned",
      "Resource is not assigned to this principal",
    );
  }
  if (code.includes("idempotency_conflict")) {
    throw new ApplicationBoundaryError(
      409,
      "idempotency_conflict",
      "Idempotency key was already used for a different request",
    );
  }
  if (code.includes("collision")) {
    throw new ApplicationBoundaryError(
      409,
      "deterministic_identity_collision",
      "Deterministic wallet identity is occupied by another resource",
    );
  }
  throw new ApplicationBoundaryError(
    500,
    "wallet_ensure_failed",
    "Failed to ensure application wallet",
  );
}

export async function ensureApplicationWallet(
  principal: ApplicationPrincipalContext,
  resourceId: string,
  idempotencyKey: string,
) {
  const requestHash = sha256(
    canonicalJson({
      version: "1",
      operation: "wallet_ensure",
      resourceKind: RESOURCE_KIND,
      resourceId,
    }),
  );
  const walletId = deterministicId(
    "aw",
    "application-wallet",
    principal.tenantId,
    principal.id,
    RESOURCE_KIND,
    resourceId,
  );
  const agentId = deterministicId(
    "appw",
    "application-wallet-agent",
    principal.tenantId,
    principal.id,
    RESOURCE_KIND,
    resourceId,
  ).slice(0, 64);
  try {
    const result = await vault.ensureApplicationWallet({
      tenantId: principal.tenantId,
      principalId: principal.id,
      resourceKind: RESOURCE_KIND,
      resourceId,
      idempotencyKey,
      requestHash,
      walletId,
      agentId,
      name: `Application wallet ${resourceId}`,
    });
    return { ...result, requestHash };
  } catch (error) {
    return mapVaultError(error);
  }
}

export async function readApplicationWalletAddress(
  principal: ApplicationPrincipalContext,
  walletId: string,
) {
  const [wallet] = await getDb()
    .select({
      id: applicationWallets.id,
      resourceKind: applicationWallets.resourceKind,
      resourceId: applicationWallets.resourceId,
      addresses: applicationWallets.addresses,
    })
    .from(applicationWallets)
    .where(
      and(
        eq(applicationWallets.tenantId, principal.tenantId),
        eq(applicationWallets.principalId, principal.id),
        eq(applicationWallets.id, walletId),
      ),
    );
  if (!wallet) throw new ApplicationBoundaryError(404, "wallet_not_found", "Wallet not found");
  return wallet;
}
