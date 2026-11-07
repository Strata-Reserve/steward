import {
  applicationPrincipalCredentials,
  applicationPrincipalResources,
  applicationPrincipals,
  applicationProposalExecutions,
} from "@stwd/db";
import { and, eq, isNull } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { z } from "zod";
import { clearApplicationSelectorKnownGood } from "../middleware/application-principal";
import {
  APPLICATION_CAPABILITIES,
  generateApplicationCredential,
  isValidApplicationProposalId,
  isValidApplicationReference,
  parseFutureExpiry,
} from "../services/application-boundary";
import {
  ApplicationExecutionError,
  createExecutorSignerBinding,
  executeApplicationProposal,
  toApplicationExecutionView,
} from "../services/application-executions";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  requireHumanOwnerAdmin,
  requireTenantLevel,
  safeJsonParse,
} from "../services/context";

export const applicationPrincipalAdminRoutes = new Hono<{ Variables: AppVariables }>();

const capabilitySchema = z.enum(APPLICATION_CAPABILITIES);
const resourceSchema = z
  .object({ kind: z.literal("wallet_owner"), id: z.string().min(1).max(255) })
  .strict();
const createSchema = z
  .object({
    name: z.string().trim().min(1).max(255),
    capabilities: z.array(capabilitySchema).min(1).max(5),
    resources: z.array(resourceSchema).min(1).max(100),
    expiresAt: z.string(),
    credentialExpiresAt: z.string(),
  })
  .strict();
const rotateSchema = z.object({ credentialExpiresAt: z.string() }).strict();

function requestMetadata(c: Context<{ Variables: AppVariables }>) {
  return {
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  };
}

applicationPrincipalAdminRoutes.post("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Application principal creation requires tenant administrator access" },
      403,
    );
  }
  const raw = await safeJsonParse<unknown>(c);
  const parsed = createSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid application principal request" }, 400);
  }
  const body = parsed.data;
  if (!body.resources.every((resource) => isValidApplicationReference(resource.id))) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid assigned resource id" }, 400);
  }
  const expiresAt = parseFutureExpiry(body.expiresAt);
  if (!expiresAt) {
    return c.json<ApiResponse>(
      { ok: false, error: "expiresAt must be a future ISO timestamp" },
      400,
    );
  }
  const credentialExpiresAt = parseFutureExpiry(body.credentialExpiresAt, expiresAt);
  if (!credentialExpiresAt) {
    return c.json<ApiResponse>(
      { ok: false, error: "credentialExpiresAt must be future and no later than expiresAt" },
      400,
    );
  }

  const tenantId = c.get("tenantId");
  const principalId = `app_${crypto.randomUUID().replaceAll("-", "")}`;
  const capabilities = [...new Set(body.capabilities)].sort();
  const resources = [
    ...new Map(
      body.resources.map((resource) => [`${resource.kind}:${resource.id}`, resource]),
    ).values(),
  ];
  const credential = generateApplicationCredential();

  await db.transaction(async (tx) => {
    await tx.insert(applicationPrincipals).values({
      id: principalId,
      tenantId,
      name: body.name,
      capabilities,
      expiresAt,
    });
    await tx.insert(applicationPrincipalResources).values(
      resources.map((resource) => ({
        tenantId,
        principalId,
        resourceKind: resource.kind,
        resourceId: resource.id,
      })),
    );
    await tx.insert(applicationPrincipalCredentials).values({
      keyId: credential.keyId,
      tenantId,
      principalId,
      secretHash: credential.secretHash,
      expiresAt: credentialExpiresAt,
    });
  });

  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "application_principal.create",
    resourceType: "application_principal",
    resourceId: principalId,
    metadata: {
      capabilities,
      resources,
      expiresAt: expiresAt.toISOString(),
      credentialKeyId: credential.keyId,
    },
    ...requestMetadata(c),
  });

  return c.json<ApiResponse>(
    {
      ok: true,
      data: {
        principal: {
          id: principalId,
          name: body.name,
          capabilities,
          resources,
          expiresAt: expiresAt.toISOString(),
          auditIdentity: principalId,
        },
        credential: {
          keyId: credential.keyId,
          secret: credential.secret,
          expiresAt: credentialExpiresAt.toISOString(),
        },
      },
    },
    201,
  );
});

applicationPrincipalAdminRoutes.post("/:principalId/rotate", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Credential rotation requires tenant administrator access" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const principalId = c.req.param("principalId");
  const [principal] = await db
    .select()
    .from(applicationPrincipals)
    .where(
      and(eq(applicationPrincipals.tenantId, tenantId), eq(applicationPrincipals.id, principalId)),
    );
  if (!principal)
    return c.json<ApiResponse>({ ok: false, error: "Application principal not found" }, 404);
  if (principal.revokedAt || principal.expiresAt.getTime() <= Date.now()) {
    return c.json<ApiResponse>({ ok: false, error: "Application principal is inactive" }, 409);
  }
  const raw = await safeJsonParse<unknown>(c);
  const parsed = rotateSchema.safeParse(raw);
  if (!parsed.success)
    return c.json<ApiResponse>({ ok: false, error: "Invalid rotation request" }, 400);
  const credentialExpiresAt = parseFutureExpiry(
    parsed.data.credentialExpiresAt,
    principal.expiresAt,
  );
  if (!credentialExpiresAt) {
    return c.json<ApiResponse>(
      { ok: false, error: "credentialExpiresAt must be future and no later than principal expiry" },
      400,
    );
  }
  const credential = generateApplicationCredential();
  const rotatedAt = new Date();
  const supersededKeyIds = await db
    .select({ keyId: applicationPrincipalCredentials.keyId })
    .from(applicationPrincipalCredentials)
    .where(
      and(
        eq(applicationPrincipalCredentials.tenantId, tenantId),
        eq(applicationPrincipalCredentials.principalId, principalId),
        isNull(applicationPrincipalCredentials.revokedAt),
      ),
    );
  await db.transaction(async (tx) => {
    await tx
      .update(applicationPrincipalCredentials)
      .set({ revokedAt: rotatedAt })
      .where(
        and(
          eq(applicationPrincipalCredentials.tenantId, tenantId),
          eq(applicationPrincipalCredentials.principalId, principalId),
          isNull(applicationPrincipalCredentials.revokedAt),
        ),
      );
    await tx.insert(applicationPrincipalCredentials).values({
      keyId: credential.keyId,
      tenantId,
      principalId,
      secretHash: credential.secretHash,
      expiresAt: credentialExpiresAt,
    });
  });
  // Superseded key IDs must lose known-good standing, or a rotated-away
  // credential keeps a prioritised share of the auth rate-limit budget forever.
  // It is already DENIED by the auth gate - this governs resource budget, not
  // authority.
  for (const superseded of supersededKeyIds) clearApplicationSelectorKnownGood(superseded.keyId);
  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "application_principal.credential.rotate",
    resourceType: "application_principal",
    resourceId: principalId,
    metadata: { credentialKeyId: credential.keyId, expiresAt: credentialExpiresAt.toISOString() },
    ...requestMetadata(c),
  });
  return c.json<ApiResponse>({
    ok: true,
    data: {
      keyId: credential.keyId,
      secret: credential.secret,
      expiresAt: credentialExpiresAt.toISOString(),
    },
  });
});

applicationPrincipalAdminRoutes.post("/:principalId/revoke", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Principal revocation requires tenant administrator access" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const principalId = c.req.param("principalId");
  const [principal] = await db
    .select()
    .from(applicationPrincipals)
    .where(
      and(eq(applicationPrincipals.tenantId, tenantId), eq(applicationPrincipals.id, principalId)),
    );
  if (!principal)
    return c.json<ApiResponse>({ ok: false, error: "Application principal not found" }, 404);
  const revokedAt = principal.revokedAt ?? new Date();
  if (!principal.revokedAt) {
    const revokedKeyIds = await db
      .select({ keyId: applicationPrincipalCredentials.keyId })
      .from(applicationPrincipalCredentials)
      .where(
        and(
          eq(applicationPrincipalCredentials.tenantId, tenantId),
          eq(applicationPrincipalCredentials.principalId, principalId),
        ),
      );
    await db.transaction(async (tx) => {
      await tx
        .update(applicationPrincipals)
        .set({ revokedAt })
        .where(
          and(
            eq(applicationPrincipals.tenantId, tenantId),
            eq(applicationPrincipals.id, principalId),
          ),
        );
      await tx
        .update(applicationPrincipalCredentials)
        .set({ revokedAt })
        .where(
          and(
            eq(applicationPrincipalCredentials.tenantId, tenantId),
            eq(applicationPrincipalCredentials.principalId, principalId),
            isNull(applicationPrincipalCredentials.revokedAt),
          ),
        );
    });
    // Revoked credentials must lose known-good standing. They are already
    // DENIED by the auth gate; this releases their prioritised share of the
    // auth rate-limit budget so a revoked key cannot hold it indefinitely.
    for (const revoked of revokedKeyIds) clearApplicationSelectorKnownGood(revoked.keyId);
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "application_principal.revoke",
      resourceType: "application_principal",
      resourceId: principalId,
      metadata: { revokedAt: revokedAt.toISOString() },
      ...requestMetadata(c),
    });
  }
  return c.json<ApiResponse>({
    ok: true,
    data: { id: principalId, revokedAt: revokedAt.toISOString() },
  });
});

// ─── Application proposal execution (STRATA-1515 exec gap A) ──────────────────
//
// Application principals remain proposal-only. Execution lives here, on the
// tenant-auth admin namespace, and only a verified human owner/admin session
// can trigger it: that request is the approval. See
// services/application-executions.ts for the full guard list.

const PRINCIPAL_ID_RE = /^app_[0-9a-zA-Z]{1,60}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const executorSignerSchema = z
  .object({
    // Shape only. The 84532 hard pin is enforced (and audited as a refusal)
    // in createExecutorSignerBinding and by the 0031 CHECK constraint.
    chainId: z.number().int().positive().max(2_147_483_647),
    signerAgentId: z.string().min(1).max(64),
    allowedTargets: z.array(z.string().regex(ADDRESS_RE)).min(1).max(100),
  })
  .strict();

function executionErrorResponse(c: Context<{ Variables: AppVariables }>, error: unknown) {
  if (error instanceof ApplicationExecutionError) {
    const policyResults = (error as { policyResults?: unknown }).policyResults;
    return c.json<ApiResponse>(
      {
        ok: false,
        error: error.message,
        data: { code: error.code, ...(policyResults ? { policyResults } : {}) },
      },
      error.status,
    );
  }
  throw error;
}

applicationPrincipalAdminRoutes.post("/:principalId/executor-signers", async (c) => {
  const userId = requireHumanOwnerAdmin(c);
  if (!userId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Executor signer binding requires a human owner/admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const principalId = c.req.param("principalId");
  if (!PRINCIPAL_ID_RE.test(principalId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid principal id" }, 400);
  }
  const parsed = executorSignerSchema.safeParse(await safeJsonParse<unknown>(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid executor signer request" }, 400);
  }
  try {
    const binding = await createExecutorSignerBinding({
      tenantId,
      principalId,
      chainId: parsed.data.chainId,
      signerAgentId: parsed.data.signerAgentId,
      allowedTargets: parsed.data.allowedTargets,
      createdBy: `user:${userId}`,
    });
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "application_principal.executor_signer.bind",
      resourceType: "application_principal",
      resourceId: principalId,
      metadata: {
        chainId: binding.chainId,
        signerAgentId: binding.signerAgentId,
        allowedTargets: binding.allowedTargets,
      },
      ...requestMetadata(c),
    });
    return c.json<ApiResponse>({ ok: true, data: { binding } }, 201);
  } catch (error) {
    return executionErrorResponse(c, error);
  }
});

applicationPrincipalAdminRoutes.post("/:principalId/proposals/:proposalId/execute", async (c) => {
  const userId = requireHumanOwnerAdmin(c);
  if (!userId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Proposal execution requires a human owner/admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const principalId = c.req.param("principalId");
  const proposalId = c.req.param("proposalId");
  if (!PRINCIPAL_ID_RE.test(principalId) || !isValidApplicationProposalId(proposalId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid proposal reference" }, 400);
  }
  try {
    const result = await executeApplicationProposal({
      tenantId,
      principalId,
      proposalId,
      approvedBy: `user:${userId}`,
    });
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: userId,
      action: result.replay
        ? "application.transaction_proposal.execute.replay"
        : "application.transaction_proposal.execute",
      resourceType: "application_transaction_proposal",
      resourceId: proposalId,
      metadata: {
        principalId,
        executionId: result.execution.id,
        status: result.execution.status,
        chainId: result.execution.chainId,
        txHash: result.execution.txHash,
      },
      ...requestMetadata(c),
    });
    const status = result.execution.status === "broadcast" ? (result.replay ? 200 : 201) : 202;
    return c.json<ApiResponse>({ ok: true, data: result }, status);
  } catch (error) {
    if (error instanceof ApplicationExecutionError) {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: userId,
        action: "application.transaction_proposal.execute.denied",
        resourceType: "application_transaction_proposal",
        resourceId: proposalId,
        metadata: { principalId, reason: error.code },
        ...requestMetadata(c),
      });
    }
    return executionErrorResponse(c, error);
  }
});

applicationPrincipalAdminRoutes.get("/:principalId/proposals/:proposalId/execution", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant administrator access required" }, 403);
  }
  const proposalId = c.req.param("proposalId");
  if (!isValidApplicationProposalId(proposalId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid proposal reference" }, 400);
  }
  const [row] = await db
    .select()
    .from(applicationProposalExecutions)
    .where(
      and(
        eq(applicationProposalExecutions.tenantId, c.get("tenantId")),
        eq(applicationProposalExecutions.principalId, c.req.param("principalId")),
        eq(applicationProposalExecutions.proposalId, proposalId),
      ),
    );
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Execution not found" }, 404);
  return c.json<ApiResponse>({ ok: true, data: { execution: toApplicationExecutionView(row) } });
});
