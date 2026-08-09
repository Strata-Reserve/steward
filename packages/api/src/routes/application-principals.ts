import { applicationPrincipalCredentials, applicationPrincipals } from "@stwd/db";
import { and, eq, isNull } from "drizzle-orm";
import { type Context, Hono } from "hono";
import {
  APPLICATION_CAPABILITIES,
  generateApplicationCredential,
  isApplicationCapability,
  isValidApplicationReference,
  parseFutureExpiry,
} from "../services/application-boundary";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  isNonEmptyString,
  requireTenantLevel,
  safeJsonParse,
} from "../services/context";

export const applicationPrincipalAdminRoutes = new Hono<{ Variables: AppVariables }>();

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
  const body = await safeJsonParse<{
    name?: string;
    capabilities?: unknown[];
    ownerReferences?: unknown[];
    expiresAt?: string;
    credentialExpiresAt?: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (!isNonEmptyString(body.name) || body.name.trim().length > 255) {
    return c.json<ApiResponse>({ ok: false, error: "name must be 1-255 characters" }, 400);
  }
  if (
    !Array.isArray(body.capabilities) ||
    body.capabilities.length === 0 ||
    !body.capabilities.every(isApplicationCapability)
  ) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `capabilities must contain only: ${APPLICATION_CAPABILITIES.join(", ")}`,
      },
      400,
    );
  }
  if (
    !Array.isArray(body.ownerReferences) ||
    body.ownerReferences.length === 0 ||
    body.ownerReferences.length > 100 ||
    !body.ownerReferences.every(isValidApplicationReference)
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "ownerReferences must contain 1-100 valid owner references" },
      400,
    );
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
  const ownerReferences = [...new Set(body.ownerReferences)].sort();
  const credential = generateApplicationCredential();

  await db.transaction(async (tx) => {
    await tx.insert(applicationPrincipals).values({
      id: principalId,
      tenantId,
      name: body.name!.trim(),
      auditIdentity: principalId,
      capabilities,
      ownerReferences,
      expiresAt,
    });
    await tx.insert(applicationPrincipalCredentials).values({
      keyId: credential.keyId,
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
      ownerReferences,
      expiresAt: expiresAt.toISOString(),
      keyId: credential.keyId,
    },
    ...requestMetadata(c),
  });

  return c.json<ApiResponse>(
    {
      ok: true,
      data: {
        principal: {
          id: principalId,
          name: body.name.trim(),
          capabilities,
          ownerReferences,
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
      and(eq(applicationPrincipals.id, principalId), eq(applicationPrincipals.tenantId, tenantId)),
    );
  if (!principal)
    return c.json<ApiResponse>({ ok: false, error: "Application principal not found" }, 404);
  if (principal.revokedAt || principal.expiresAt.getTime() <= Date.now()) {
    return c.json<ApiResponse>({ ok: false, error: "Application principal is inactive" }, 409);
  }
  const body = await safeJsonParse<{ credentialExpiresAt?: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const credentialExpiresAt = parseFutureExpiry(body.credentialExpiresAt, principal.expiresAt);
  if (!credentialExpiresAt) {
    return c.json<ApiResponse>(
      { ok: false, error: "credentialExpiresAt must be future and no later than principal expiry" },
      400,
    );
  }
  const credential = generateApplicationCredential();
  const rotatedAt = new Date();
  await db.transaction(async (tx) => {
    await tx
      .update(applicationPrincipalCredentials)
      .set({ revokedAt: rotatedAt })
      .where(
        and(
          eq(applicationPrincipalCredentials.principalId, principalId),
          isNull(applicationPrincipalCredentials.revokedAt),
        ),
      );
    await tx.insert(applicationPrincipalCredentials).values({
      keyId: credential.keyId,
      principalId,
      secretHash: credential.secretHash,
      expiresAt: credentialExpiresAt,
    });
  });
  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "application_principal.credential.rotate",
    resourceType: "application_principal",
    resourceId: principalId,
    metadata: { keyId: credential.keyId, expiresAt: credentialExpiresAt.toISOString() },
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
      and(eq(applicationPrincipals.id, principalId), eq(applicationPrincipals.tenantId, tenantId)),
    );
  if (!principal)
    return c.json<ApiResponse>({ ok: false, error: "Application principal not found" }, 404);
  const revokedAt = principal.revokedAt ?? new Date();
  if (!principal.revokedAt) {
    await db.transaction(async (tx) => {
      await tx
        .update(applicationPrincipals)
        .set({ revokedAt })
        .where(eq(applicationPrincipals.id, principalId));
      await tx
        .update(applicationPrincipalCredentials)
        .set({ revokedAt })
        .where(
          and(
            eq(applicationPrincipalCredentials.principalId, principalId),
            isNull(applicationPrincipalCredentials.revokedAt),
          ),
        );
    });
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
