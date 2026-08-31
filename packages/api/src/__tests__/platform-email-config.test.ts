import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const PLATFORM_KEY = "platform-email-config-key";
const TENANT_ID = "platform-email-config-tenant";

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

  // ─── STRATA-1218 ──────────────────────────────────────────────────────────
  // A platform admin must be able to set the non-secret magic-link routing
  // fields WITHOUT holding (or destroying) the tenant's Resend secret.
  describe("STRATA-1218 magic-link config merge", () => {
    const patch = (body: unknown) =>
      platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Platform-Key": PLATFORM_KEY,
        },
        body: JSON.stringify(body),
      });

    const readStored = async () => {
      const [row] = await getDb()
        .select({ emailConfig: tenantConfigs.emailConfig })
        .from(tenantConfigs)
        .where(eq(tenantConfigs.tenantId, TENANT_ID));
      return row?.emailConfig ?? null;
    };

    const seedProviderConfig = async () => {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
      const seeded = await patch({
        apiKey: "strata-resend-secret",
        from: "Strata Reserve <login@stratareserve.co>",
        replyTo: "support@stratareserve.co",
        templateId: "strata",
        subjectOverride: "Sign in to Strata Reserve",
      });
      expect(seeded.status).toBe(200);
      const stored = await readStored();
      // Guard: the fixture really does have an encrypted key to preserve.
      expect(stored?.apiKeyEncrypted).toBeDefined();
      return stored;
    };

    it("sets magic-link fields without apiKey/from and preserves the encrypted secret", async () => {
      const before = await seedProviderConfig();

      const res = await patch({
        magicLinkBaseUrl: "https://app.stratareserve.co",
        magicLinkCallbackPath: "/auth/callback",
      });

      // Previously this returned 400 "apiKey and from are required".
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { magicLinkBaseUrl?: string; magicLinkCallbackPath?: string; hasApiKey: boolean };
      };
      expect(body.ok).toBe(true);
      expect(body.data.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
      expect(body.data.magicLinkCallbackPath).toBe("/auth/callback");
      expect(body.data.hasApiKey).toBe(true);

      const after = await readStored();
      expect(after?.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
      expect(after?.magicLinkCallbackPath).toBe("/auth/callback");

      // Every pre-existing provider/secret field is byte-identical.
      expect(after?.apiKeyEncrypted).toBe(before?.apiKeyEncrypted);
      expect(after?.provider).toBe("resend");
      expect(after?.from).toBe("Strata Reserve <login@stratareserve.co>");
      expect(after?.replyTo).toBe("support@stratareserve.co");
      // Branding must be untouched by this change.
      expect(after?.templateId).toBe("strata");
      expect(after?.subjectOverride).toBe("Sign in to Strata Reserve");
    });

    it("produces a magic link resolving to app.stratareserve.co/auth/callback", async () => {
      await seedProviderConfig();
      await patch({
        magicLinkBaseUrl: "https://app.stratareserve.co",
        magicLinkCallbackPath: "/auth/callback",
      });

      const stored = await readStored();
      // Mirrors EmailAuth's buildMagicLink: new URL(callbackPath, baseUrl).
      const resolved = new URL(
        stored?.magicLinkCallbackPath as string,
        stored?.magicLinkBaseUrl as string,
      );
      expect(resolved.origin).toBe("https://app.stratareserve.co");
      expect(resolved.pathname).toBe("/auth/callback");
      expect(resolved.toString()).toBe("https://app.stratareserve.co/auth/callback");
    });

    it("merges partial updates without clobbering the other magic-link field", async () => {
      await seedProviderConfig();
      await patch({
        magicLinkBaseUrl: "https://app.stratareserve.co",
        magicLinkCallbackPath: "/auth/callback",
      });

      const res = await patch({ subjectOverride: "Your Strata login link" });
      expect(res.status).toBe(200);

      const after = await readStored();
      expect(after?.subjectOverride).toBe("Your Strata login link");
      expect(after?.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
      expect(after?.magicLinkCallbackPath).toBe("/auth/callback");
      expect(after?.apiKeyEncrypted).toBeDefined();
    });

    it("strips a trailing slash from magicLinkBaseUrl", async () => {
      await seedProviderConfig();
      const res = await patch({ magicLinkBaseUrl: "https://app.stratareserve.co/" });
      expect(res.status).toBe(200);
      expect((await readStored())?.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
    });

    it("allows a magic-link-only tenant with no per-tenant Resend key", async () => {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));

      const res = await patch({ magicLinkBaseUrl: "https://app.stratareserve.co" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: { hasApiKey: boolean } };
      expect(body.data.hasApiKey).toBe(false);

      const stored = await readStored();
      expect(stored?.magicLinkBaseUrl).toBe("https://app.stratareserve.co");
      expect(stored?.apiKeyEncrypted).toBeUndefined();
    });

    it("rejects invalid magicLinkBaseUrl and magicLinkCallbackPath values", async () => {
      await seedProviderConfig();
      const before = await readStored();

      const rejected = [
        // http downgrade — the link carries a login token.
        { magicLinkBaseUrl: "http://app.stratareserve.co" },
        { magicLinkBaseUrl: "not-a-url" },
        { magicLinkBaseUrl: "javascript:alert(1)" },
        // Origin must be bare: path/query/fragment/credentials belong elsewhere.
        { magicLinkBaseUrl: "https://app.stratareserve.co/some/path" },
        { magicLinkBaseUrl: "https://user:pw@app.stratareserve.co" },
        { magicLinkBaseUrl: "https://app.stratareserve.co?next=x" },
        // Callback path must not escape the app origin.
        { magicLinkCallbackPath: "auth/callback" },
        { magicLinkCallbackPath: "https://evil.com/steal" },
        { magicLinkCallbackPath: "//evil.com/steal" },
        { magicLinkCallbackPath: "/\\evil.com/steal" },
        // Empty strings are not a way to blank a field.
        { magicLinkBaseUrl: "" },
        { magicLinkCallbackPath: "   " },
      ];

      for (const body of rejected) {
        const res = await patch(body);
        expect({ body, status: res.status }).toEqual({ body, status: 400 });
      }

      // Nothing was mutated by any rejected request.
      expect(await readStored()).toEqual(before);
    });

    it("rejects an empty patch body", async () => {
      await seedProviderConfig();
      const res = await patch({});
      expect(res.status).toBe(400);
    });

    // The DB write alone is not enough: EmailAuth is memoized per tenant, so a
    // stale cache would keep minting links at the OLD origin after a PATCH.
    it("evicts the per-tenant EmailAuth cache so new links use the new origin", async () => {
      const { clearEmailAuthTenantCacheForTests, getEmailAuthForTenant, initAuthStores } =
        await import("../routes/auth");

      await initAuthStores(false);
      clearEmailAuthTenantCacheForTests();

      // Deliberately a magic-link-ONLY tenant (no per-tenant Resend key).
      // Building an EmailAuth from an encrypted key would initialize auth.ts's
      // process-wide `_emailKeyStore` singleton under THIS file's master
      // password, which then breaks sibling test files that use a different
      // one (bun runs them in a single process). The magic-link path needs no
      // decryption, so this proves eviction without that global side effect.
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
      await patch({
        magicLinkBaseUrl: "https://old.stratareserve.co",
        magicLinkCallbackPath: "/auth/old",
      });

      const first = await getEmailAuthForTenant(TENANT_ID);
      expect((first as any).baseUrl).toBe("https://old.stratareserve.co");
      expect((first as any).callbackPath).toBe("/auth/old");

      // Positive control: the cache is real, so a repeat read is the SAME
      // instance. This proves the next assertion tests eviction, not a
      // trivially uncached lookup.
      expect(await getEmailAuthForTenant(TENANT_ID)).toBe(first);

      // PATCH through the route must invalidate that memoized instance.
      const res = await patch({
        magicLinkBaseUrl: "https://app.stratareserve.co",
        magicLinkCallbackPath: "/auth/callback",
      });
      expect(res.status).toBe(200);

      const second = await getEmailAuthForTenant(TENANT_ID);
      expect(second).not.toBe(first);
      expect((second as any).baseUrl).toBe("https://app.stratareserve.co");
      expect((second as any).callbackPath).toBe("/auth/callback");

      clearEmailAuthTenantCacheForTests();
    });
  });
});
