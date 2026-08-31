import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const PLATFORM_KEY = "platform-email-config-key";
const TENANT_ID = "platform-email-config-tenant";

// Each callback test owns its OWN tenant. The pre-existing test ends with a
// DELETE, so sharing a tenant would make these depend on execution order.
const CALLBACK_TENANT_IDS = [
  "callback-only-tenant",
  "callback-preserve-tenant",
  "callback-strict-tenant",
  "callback-validate-tenant",
  "callback-nobase-tenant",
] as const;
const [
  CALLBACK_ONLY_TENANT,
  CALLBACK_PRESERVE_TENANT,
  CALLBACK_STRICT_TENANT,
  CALLBACK_VALIDATE_TENANT,
  CALLBACK_NOBASE_TENANT,
] = CALLBACK_TENANT_IDS;

const PATCH_HEADERS = {
  "Content-Type": "application/json",
  "X-Steward-Platform-Key": PLATFORM_KEY,
};

/**
 * Assert a 400 AND the reason it was refused. Status alone does not
 * discriminate: the pre-change handler rejected EVERY callback-only body with
 * "apiKey and from are required", so a bare `toBe(400)` would pass against the
 * old code for entirely the wrong reason.
 */
async function expectRejection(response: Response, matcher: RegExp): Promise<void> {
  expect(response.status).toBe(400);
  const body = (await response.json()) as { ok: boolean; error: string };
  expect(body.ok).toBe(false);
  expect(body.error).toMatch(matcher);
}

describe("platform tenant email config routes", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
    process.env.STEWARD_MASTER_PASSWORD = "platform-email-config-master-password";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const dbHandle = getDb();
    await dbHandle.insert(tenants).values({
      id: TENANT_ID,
      name: "Platform Email Config Tenant",
      apiKeyHash: "hash",
    });
    for (const id of CALLBACK_TENANT_IDS) {
      await dbHandle.insert(tenants).values({
        id,
        name: `Callback Tenant ${id}`,
        apiKeyHash: "hash",
      });
    }

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.DATABASE_URL;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_PLATFORM_KEYS;
  });

  it("patches, reads, and deletes tenant email config", async () => {
    const patchResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        apiKey: "tenant-resend-api-key",
        from: "Tenant <login@tenant.example.com>",
        replyTo: "help@tenant.example.com",
        templateId: "elizacloud",
        subjectOverride: "Tenant Sign In",
      }),
    });

    expect(patchResponse.status).toBe(200);
    const patchBody = (await patchResponse.json()) as {
      ok: boolean;
      data: {
        from: string;
        replyTo?: string;
        templateId?: string;
        subjectOverride?: string;
        hasApiKey: boolean;
      };
    };
    expect(patchBody.ok).toBe(true);
    expect(patchBody.data.hasApiKey).toBe(true);
    expect(patchBody.data.from).toBe("Tenant <login@tenant.example.com>");

    const dbHandle = getDb();
    const [storedConfig] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(storedConfig?.emailConfig?.apiKeyEncrypted).toBeDefined();
    expect(storedConfig?.emailConfig?.apiKeyEncrypted).not.toContain("tenant-resend-api-key");

    const getResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
    });

    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as {
      ok: boolean;
      data: {
        emailConfig: {
          from: string;
          replyTo?: string;
          templateId?: string;
          subjectOverride?: string;
        } | null;
        hasApiKey: boolean;
      };
    };
    expect(getBody.ok).toBe(true);
    expect(getBody.data.hasApiKey).toBe(true);
    expect(getBody.data.emailConfig).toEqual({
      provider: "resend",
      from: "Tenant <login@tenant.example.com>",
      replyTo: "help@tenant.example.com",
      templateId: "elizacloud",
      subjectOverride: "Tenant Sign In",
    });

    const deleteResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "DELETE",
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
    });

    expect(deleteResponse.status).toBe(200);
    const deleteBody = (await deleteResponse.json()) as { ok: boolean };
    expect(deleteBody.ok).toBe(true);

    const [afterDelete] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(afterDelete?.emailConfig ?? null).toBeNull();
  });

  it("callback-only PATCH succeeds without apiKey or from", async () => {
    const response = await platformRoutes.request(`/tenants/${CALLBACK_ONLY_TENANT}/email-config`, {
      method: "PATCH",
      headers: PATCH_HEADERS,
      body: JSON.stringify({
        magicLinkBaseUrl: "https://app.stratareserve.co",
        magicLinkCallbackPath: "/auth/callback",
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { magicLinkBaseUrl?: string; magicLinkCallbackPath?: string; hasApiKey: boolean };
    };
    expect(body.ok).toBe(true);
    expect(body.data.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
    expect(body.data.magicLinkCallbackPath).toBe("/auth/callback");
    // No credential was supplied and none existed.
    expect(body.data.hasApiKey).toBe(false);
  });

  it("callback-only PATCH leaves the encrypted provider credential byte-identical", async () => {
    // Seed a full credential config the normal way.
    const seed = await platformRoutes.request(`/tenants/${CALLBACK_PRESERVE_TENANT}/email-config`, {
      method: "PATCH",
      headers: PATCH_HEADERS,
      body: JSON.stringify({
        apiKey: "preserve-me-resend-key",
        from: "Preserve <login@preserve.example.com>",
        replyTo: "help@preserve.example.com",
        templateId: "elizacloud",
        subjectOverride: "Preserve Sign In",
      }),
    });
    expect(seed.status).toBe(200);

    const dbHandle = getDb();
    const [before] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, CALLBACK_PRESERVE_TENANT));
    const encryptedBefore = before?.emailConfig?.apiKeyEncrypted;
    expect(encryptedBefore).toBeDefined();

    const patch = await platformRoutes.request(
      `/tenants/${CALLBACK_PRESERVE_TENANT}/email-config`,
      {
        method: "PATCH",
        headers: PATCH_HEADERS,
        body: JSON.stringify({
          magicLinkBaseUrl: "https://app.stratareserve.co",
          magicLinkCallbackPath: "/auth/callback",
        }),
      },
    );
    expect(patch.status).toBe(200);

    const [after] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, CALLBACK_PRESERVE_TENANT));

    // THE load-bearing assertion: the ciphertext is carried across verbatim.
    // Compared as an opaque string; never decrypted here or in the route.
    expect(after?.emailConfig?.apiKeyEncrypted).toBe(encryptedBefore as string);

    // Every unspecified provider field survives unchanged.
    expect(after?.emailConfig?.provider).toBe("resend");
    expect(after?.emailConfig?.from).toBe("Preserve <login@preserve.example.com>");
    expect(after?.emailConfig?.replyTo).toBe("help@preserve.example.com");
    expect(after?.emailConfig?.templateId).toBe("elizacloud");
    expect(after?.emailConfig?.subjectOverride).toBe("Preserve Sign In");

    // ...and the new routing landed.
    expect(after?.emailConfig?.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
    expect(after?.emailConfig?.magicLinkCallbackPath).toBe("/auth/callback");

    const get = await platformRoutes.request(`/tenants/${CALLBACK_PRESERVE_TENANT}/email-config`, {
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });
    const getBody = (await get.json()) as { data: { hasApiKey: boolean } };
    expect(getBody.data.hasApiKey).toBe(true);
  });

  it("credential replacement keeps the existing strict validation", async () => {
    const apiKeyOnly = await platformRoutes.request(
      `/tenants/${CALLBACK_STRICT_TENANT}/email-config`,
      {
        method: "PATCH",
        headers: PATCH_HEADERS,
        body: JSON.stringify({ apiKey: "only-the-key" }),
      },
    );
    await expectRejection(apiKeyOnly, /apiKey and from are required/);

    const fromOnly = await platformRoutes.request(
      `/tenants/${CALLBACK_STRICT_TENANT}/email-config`,
      {
        method: "PATCH",
        headers: PATCH_HEADERS,
        body: JSON.stringify({ from: "Only <only@example.com>" }),
      },
    );
    await expectRejection(fromOnly, /apiKey and from are required/);

    // An empty body specifies nothing at all: not a credential update, not a
    // routing update. It must be refused rather than silently succeeding.
    const empty = await platformRoutes.request(`/tenants/${CALLBACK_STRICT_TENANT}/email-config`, {
      method: "PATCH",
      headers: PATCH_HEADERS,
      body: JSON.stringify({}),
    });
    // Distinct message: "nothing was specified", NOT the credential error.
    await expectRejection(empty, /Provide apiKey \+ from|magicLinkBaseUrl\/magicLinkCallbackPath/);
  });

  it("rejects unsafe magic-link base URLs and callback paths", async () => {
    const badBases = [
      "http://app.stratareserve.co",
      "https://user:pass@app.stratareserve.co",
      "https://app.stratareserve.co/prefix",
      "https://app.stratareserve.co/?next=1",
      "https://app.stratareserve.co/#frag",
      "not-a-url",
    ];
    for (const magicLinkBaseUrl of badBases) {
      const response = await platformRoutes.request(
        `/tenants/${CALLBACK_VALIDATE_TENANT}/email-config`,
        { method: "PATCH", headers: PATCH_HEADERS, body: JSON.stringify({ magicLinkBaseUrl }) },
      );
      await expectRejection(response, /magicLinkBaseUrl must be an https origin/);
    }

    const badPaths = [
      "//evil.example",
      "auth/callback",
      "https://evil.example/auth/callback",
      "/auth/callback?next=1",
      "/auth/callback#frag",
      "/auth/call back",
    ];
    for (const magicLinkCallbackPath of badPaths) {
      const response = await platformRoutes.request(
        `/tenants/${CALLBACK_VALIDATE_TENANT}/email-config`,
        {
          method: "PATCH",
          headers: PATCH_HEADERS,
          body: JSON.stringify({
            magicLinkBaseUrl: "https://app.stratareserve.co",
            magicLinkCallbackPath,
          }),
        },
      );
      await expectRejection(response, /magicLinkCallbackPath must be a same-origin absolute path/);
    }

    // Nothing above may have been persisted.
    const dbHandle = getDb();
    const [row] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, CALLBACK_VALIDATE_TENANT));
    expect(row?.emailConfig ?? null).toBeNull();
  });

  it("refuses a callback path when the tenant has no base URL (no silent no-op)", async () => {
    const response = await platformRoutes.request(
      `/tenants/${CALLBACK_NOBASE_TENANT}/email-config`,
      {
        method: "PATCH",
        headers: PATCH_HEADERS,
        body: JSON.stringify({ magicLinkCallbackPath: "/auth/callback" }),
      },
    );

    // The path has no effect without a base URL, so a 200 here would be a lie.
    await expectRejection(response, /magicLinkCallbackPath requires magicLinkBaseUrl/);

    const dbHandle = getDb();
    const [row] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, CALLBACK_NOBASE_TENANT));
    expect(row?.emailConfig ?? null).toBeNull();
  });
});
