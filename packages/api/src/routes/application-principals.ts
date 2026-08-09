import {
  applicationPrincipalCredentials,
  applicationPrincipalResources,
  applicationPrincipals,
} from "@stwd/db";
import { and, eq, isNull } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { z } from "zod";
import {
  APPLICATION_CAPABILITIES,
  generateApplicationCredential,
  isValidApplicationReference,
  parseFutureExpiry,
} from "../services/application-boundary";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
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
    capabilities: z.array(capabilitySchema).min(1).max(4),
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
