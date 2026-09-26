import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "@stwd/vault";
import { eq } from "drizzle-orm";
import {
  clearEmailAuthTenantCacheForTests,
  getEmailAuthForTenant,
  initAuthStores,
  invalidateEmailAuthForTenant,
} from "../routes/auth";

const TEST_TENANT_ID = "tenant-email-config-test";
const MASTER_PASSWORD = "tenant-email-config-master-password";

describe("getEmailAuthForTenant", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
    process.env.APP_URL = "https://app.example.com";
    process.env.EMAIL_FROM = "Global <login@example.com>";
    process.env.RESEND_API_KEY = "global-resend-key";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await initAuthStores(false);

    const dbHandle = getDb();
    await dbHandle.insert(tenants).values({
      id: TEST_TENANT_ID,
      name: "Tenant Email Config Test",
      apiKeyHash: "hash",
    });
  });

  afterAll(async () => {
    clearEmailAuthTenantCacheForTests();
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.APP_URL;
    delete process.env.EMAIL_FROM;
    delete process.env.RESEND_API_KEY;
  });

  it("falls back to the global env config when tenant emailConfig is unset", async () => {
    clearEmailAuthTenantCacheForTests();

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Global <login@example.com>");
    expect((auth as any).templateId).toBeUndefined();
    expect((auth as any).baseUrl).toBe("https://app.example.com");
    expect((auth as any).callbackPath).toBe("/auth/callback/email");
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");
    expect(provider.replyTo).toBeUndefined();
  });

  it("uses the tenant-specific config when emailConfig is set", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "Tenant <login@tenant.example.com>",
        replyTo: "help@tenant.example.com",
        templateId: "elizacloud",
        subjectOverride: "Tenant Sign In",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Tenant <login@tenant.example.com>");
    expect((auth as any).replyTo).toBe("help@tenant.example.com");
    expect((auth as any).templateId).toBe("elizacloud");
    expect((auth as any).subjectOverride).toBe("Tenant Sign In");
    expect(provider.from).toBe("Tenant <login@tenant.example.com>");
    expect(provider.replyTo).toBe("help@tenant.example.com");
    // Without magicLinkBaseUrl set, baseUrl should fall back to APP_URL
    expect((auth as any).baseUrl).toBe("https://app.example.com");
    expect((auth as any).callbackPath).toBe("/auth/callback/email");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses tenant magicLinkBaseUrl when set, with default callback path", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "Waifu <noreply@waifu.fun>",
        magicLinkBaseUrl: "https://waifu.fun",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

    expect((auth as any).baseUrl).toBe("https://waifu.fun");
    // Defaults to /auth/email/verify when magicLinkBaseUrl is set
    expect((auth as any).callbackPath).toBe("/auth/email/verify");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses tenant magicLinkBaseUrl + custom callbackPath when both set", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "App <noreply@app.example>",
        magicLinkBaseUrl: "https://app.example.com/",
        magicLinkCallbackPath: "/login/email-callback",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

    // Trailing slash gets stripped from baseUrl
    expect((auth as any).baseUrl).toBe("https://app.example.com");
    expect((auth as any).callbackPath).toBe("/login/email-callback");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses global Resend creds + per-tenant magicLinkBaseUrl when no apiKeyEncrypted", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    // Magic-link-only tenant config (no per-tenant Resend key).
    // This is the waifu.fun shape: tenant doesn't bring its own Resend
    // account, just wants its own magic-link landing URL.
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        magicLinkBaseUrl: "https://waifu.fun",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    // Magic-link target overridden to the tenant's domain
    expect((auth as any).baseUrl).toBe("https://waifu.fun");
    expect((auth as any).callbackPath).toBe("/auth/email/verify");
    // Provider falls back to the global Resend key
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  // STRATA-1448: production Strata tenant is magic-link-only (global Resend
  // key, own magicLinkBaseUrl). Its templateId/subjectOverride/replyTo were
  // dropped on the global-provider path, so users got "Sign in to Steward".
  it("honors templateId/subjectOverride/replyTo on the global-provider path (STRATA-1448)", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        templateId: "strata",
        replyTo: "support@stratareserve.example",
        magicLinkBaseUrl: "https://app.stratareserve.example",
        magicLinkCallbackPath: "/auth/callback",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    // Branding survives even though the tenant has no apiKeyEncrypted
    expect((auth as any).templateId).toBe("strata");
    expect((auth as any).subjectOverride).toBeUndefined();
    expect((auth as any).replyTo).toBe("support@stratareserve.example");
    // Global sender identity is unchanged (no per-tenant key)
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");
    expect(provider.replyTo).toBe("support@stratareserve.example");
    // Safe callback handling unchanged
    expect((auth as any).baseUrl).toBe("https://app.stratareserve.example");
    expect((auth as any).callbackPath).toBe("/auth/callback");

    // End-to-end render: swap in a capturing provider so no network is touched.
    const sent: Array<{ subject: string; text: string; html?: string }> = [];
    (auth as any).provider = {
      send: async (_to: string, subject: string, text: string, html?: string) => {
        sent.push({ subject, text, html });
      },
    };
    await auth.sendMagicLink("investor@example.com");

    expect(sent).toHaveLength(1);
    expect(sent[0].subject).toBe("Sign in to Strata Reserve");
    expect(sent[0].subject).not.toContain("Steward");
    expect(sent[0].html).toContain("Sign in to Strata Reserve");
    expect(sent[0].html).not.toContain("Sign in to Steward");
    expect(sent[0].html).toContain("https://app.stratareserve.example/auth/callback?token=");
    expect(sent[0].text).toContain("https://app.stratareserve.example/auth/callback?token=");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("applies subjectOverride on the global-provider path", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        templateId: "strata",
        subjectOverride: "Your Strata sign-in link",
        magicLinkBaseUrl: "https://app.stratareserve.example",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    expect((auth as any).subjectOverride).toBe("Your Strata sign-in link");

    const sent: Array<{ subject: string }> = [];
    (auth as any).provider = {
      send: async (_to: string, subject: string) => {
        sent.push({ subject });
      },
    };
    await auth.sendMagicLink("investor@example.com");
    expect(sent[0].subject).toBe("Your Strata sign-in link");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("still renders the default Steward template when the tenant has no templateId", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: { magicLinkBaseUrl: "https://waifu.fun" },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    expect((auth as any).templateId).toBeUndefined();
    expect((auth as any).replyTo).toBeUndefined();
    expect((auth as any).provider.replyTo).toBeUndefined();

    const sent: Array<{ subject: string; html?: string }> = [];
    (auth as any).provider = {
      send: async (_to: string, subject: string, _text: string, html?: string) => {
        sent.push({ subject, html });
      },
    };
    await auth.sendMagicLink("user@example.com");
    expect(sent[0].subject).toBe("Sign in to Steward");
    expect(sent[0].html).toContain("https://waifu.fun/auth/email/verify?token=");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });
});
