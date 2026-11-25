/**
 * STRATA-1673 S1 (plan §1.3): runtime brakes for the protected minter.
 *
 *   POST /vault/:agentId/protected-minter/tokens/:token/revoke   { reason }
 *   POST /vault/:agentId/protected-minter/suspend                { reason }
 *   POST /vault/:agentId/protected-minter/resume                 {}
 *   GET  /vault/:agentId/protected-minter/tokens
 *
 * Mutations require a verified human owner/admin session AND a pinned
 * manifest approver (same rule as protected approval). They take effect on
 * the next /sign and again at permit/key-use time; no restart.
 *
 * Revoking a token is terminal (DB trigger) and refuses every later mint to
 * it, human-approved or read-back. Suspending the agent stops automatic
 * read-back signing only; every mint then queues for a human (fail closed).
 * Manifest tokens cannot be revoked here (they are deployment config); the
 * on-chain brake is Safe revokeRole(MINTER_ROLE, signer).
 */

import { protectedMinterControls, protectedMinterTokens } from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { trackAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  requireHumanOwnerAdmin,
  safeJsonParse,
} from "../services/context";
import {
  getProtectedMinterManifest,
  isProtectedMinter,
  isProtectedMinterApprover,
} from "../services/prod-minter-boundary";

export const protectedMinterRoutes = new Hono<{ Variables: AppVariables }>();

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function refuse(
  c: Context<{ Variables: AppVariables }>,
  error: string,
  status: 400 | 403 | 404 | 409 = 403,
) {
  return c.json<ApiResponse>({ ok: false, error: `Protected signer: ${error}` }, status);
}

/** Returns the approving userId, or a refusal response. */
function requireApprover(
  c: Context<{ Variables: AppVariables }>,
  tenantId: string,
  agentId: string,
): { userId: string } | { response: Response } {
  if (!isProtectedMinter(tenantId, agentId)) {
    return { response: refuse(c, "agent is not the protected minter", 404) };
  }
  const userId = requireHumanOwnerAdmin(c);
  if (!userId) {
    return { response: refuse(c, "requires an authenticated human owner/admin session") };
  }
  if (!isProtectedMinterApprover(userId)) {
    return { response: refuse(c, "user is not in the pinned manifest allowlist") };
  }
  return { userId };
}

async function reasonFrom(c: Context<{ Variables: AppVariables }>): Promise<string | null> {
  const body = await safeJsonParse<{ reason?: unknown }>(c);
  const reason = typeof body?.reason === "string" ? body.reason.trim() : "";
  return reason.length > 0 && reason.length <= 1000 ? reason : null;
}

protectedMinterRoutes.get("/:agentId/protected-minter/tokens", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  if (!isProtectedMinter(tenantId, agentId) || !requireHumanOwnerAdmin(c)) {
    return refuse(c, "requires an authenticated human owner/admin session");
  }
  const rows = await db
    .select()
    .from(protectedMinterTokens)
    .where(
      and(eq(protectedMinterTokens.tenantId, tenantId), eq(protectedMinterTokens.agentId, agentId)),
    );
  const [control] = await db
    .select()
    .from(protectedMinterControls)
    .where(
      and(
        eq(protectedMinterControls.tenantId, tenantId),
        eq(protectedMinterControls.agentId, agentId),
      ),
    );
  return c.json<ApiResponse>({
    ok: true,
    data: {
      tokens: rows,
      suspendedAt: control?.protectedMintingSuspendedAt ?? null,
    },
  });
});

protectedMinterRoutes.post("/:agentId/protected-minter/tokens/:token/revoke", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const auth = requireApprover(c, tenantId, agentId);
  if ("response" in auth) return auth.response;
  const token = c.req.param("token");
  if (!ADDRESS_RE.test(token)) return refuse(c, "token must be an EVM address", 400);
  const reason = await reasonFrom(c);
  if (!reason) return refuse(c, "a non-empty reason (<= 1000 chars) is required", 400);
  const manifest = getProtectedMinterManifest();
  if (!manifest) return refuse(c, "manifest not installed");
  if (manifest.verifiedTokens.some((t) => t.address.toLowerCase() === token.toLowerCase())) {
    return refuse(
      c,
      "manifest tokens are deployment config; remove from the manifest or revoke MINTER_ROLE via the Safe",
      409,
    );
  }
  const revokedAt = new Date();
  const updated = await db
    .update(protectedMinterTokens)
    .set({
      status: "revoked",
      revokedAt,
      revokedBy: `user:${auth.userId}`,
      revokeReason: reason,
    })
    .where(
      and(
        eq(protectedMinterTokens.tenantId, tenantId),
        eq(protectedMinterTokens.agentId, agentId),
        eq(protectedMinterTokens.chainId, manifest.chainId),
        eq(protectedMinterTokens.tokenAddress, token.toLowerCase()),
        eq(protectedMinterTokens.status, "active"),
      ),
    )
    .returning({ id: protectedMinterTokens.id });
  if (updated.length === 0) {
    // Not admitted yet: record a revoked tombstone so it can never be
    // self-admitted later.
    const inserted = await db
      .insert(protectedMinterTokens)
      .values({
        id: crypto.randomUUID(),
        tenantId,
        agentId,
        chainId: manifest.chainId,
        tokenAddress: token.toLowerCase(),
        deployTxHash: `0x${"0".repeat(64)}`,
        deployExecutionRef: "revoked-before-admission",
        status: "revoked",
        revokedAt,
        revokedBy: `user:${auth.userId}`,
        revokeReason: reason,
      })
      .onConflictDoNothing()
      .returning({ id: protectedMinterTokens.id });
    if (inserted.length === 0) return refuse(c, "token is already revoked", 409);
  }
  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: auth.userId,
    action: "vault.protected_minter.token_revoked",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { chainId: manifest.chainId, token: token.toLowerCase(), reason },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
  return c.json<ApiResponse>({ ok: true, data: { token: token.toLowerCase(), status: "revoked" } });
});

protectedMinterRoutes.post("/:agentId/protected-minter/suspend", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const auth = requireApprover(c, tenantId, agentId);
  if ("response" in auth) return auth.response;
  const reason = await reasonFrom(c);
  if (!reason) return refuse(c, "a non-empty reason (<= 1000 chars) is required", 400);
  const now = new Date();
  await db
    .insert(protectedMinterControls)
    .values({
      tenantId,
      agentId,
      protectedMintingSuspendedAt: now,
      suspendedBy: `user:${auth.userId}`,
      suspendReason: reason,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [protectedMinterControls.tenantId, protectedMinterControls.agentId],
      set: {
        protectedMintingSuspendedAt: now,
        suspendedBy: `user:${auth.userId}`,
        suspendReason: reason,
        updatedAt: now,
      },
    });
  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: auth.userId,
    action: "vault.protected_minter.suspended",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { reason },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
  return c.json<ApiResponse>({ ok: true, data: { suspendedAt: now.toISOString() } });
});

protectedMinterRoutes.post("/:agentId/protected-minter/resume", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const auth = requireApprover(c, tenantId, agentId);
  if ("response" in auth) return auth.response;
  const now = new Date();
  await db
    .update(protectedMinterControls)
    .set({ protectedMintingSuspendedAt: null, suspendedBy: `user:${auth.userId}`, updatedAt: now })
    .where(
      and(
        eq(protectedMinterControls.tenantId, tenantId),
        eq(protectedMinterControls.agentId, agentId),
      ),
    );
  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: auth.userId,
    action: "vault.protected_minter.resumed",
    resourceType: "agent",
    resourceId: agentId,
    metadata: {},
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
  return c.json<ApiResponse>({ ok: true, data: { suspendedAt: null } });
});
