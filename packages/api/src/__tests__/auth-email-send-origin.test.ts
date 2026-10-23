import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { MockEmailInbox } from "@stwd/auth";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { authRoutes, clearEmailAuthTenantCacheForTests, initAuthStores } from "../routes/auth";

/**
 * STRATA-1596: a tenant served from several origins (Strata staging app +
 * the public markets demo, same Steward tenant) must get a magic link that
 * lands on the origin the user started from, not on the single stored
 * `magicLinkBaseUrl`. The request Origin is only honoured when it is an exact
 * entry in the tenant's `allowedOrigins`.
 */

const TENANT_ID = "tenant-send-origin-test";
const STORED_BASE = "https://staging.example.test";
const OTHER_ALLOWED = "https://markets.example.test";
const NOT_ALLOWED = "https://evil.example.test";

async function sendMagicLink(email: string, origin?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT_ID,
  };
  if (origin !== undefined) headers.Origin = origin;
  return authRoutes.request("/email/send", {
    method: "POST",
    headers,
    body: JSON.stringify({ email }),
  });
}

async function setTenantConfig(values: {
  magicLinkBaseUrl?: string;
  magicLinkCallbackPath?: string;
  allowedOrigins: string[];
}): Promise<void> {
  const db = getDb();
  await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
  await db.insert(tenantConfigs).values({
    tenantId: TENANT_ID,
    allowedOrigins: values.allowedOrigins,
    emailConfig: values.magicLinkBaseUrl
      ? {
          magicLinkBaseUrl: values.magicLinkBaseUrl,
          ...(values.magicLinkCallbackPath
            ? { magicLinkCallbackPath: values.magicLinkCallbackPath }
            : {}),
        }
      : undefined,
  });
  clearEmailAuthTenantCacheForTests();
}

function lastLink(email: string): string {
  const msg = MockEmailInbox.last(email);
  if (!msg?.magicLink) throw new Error(`no magic link captured for ${email}`);
  return msg.magicLink;
}

describe("POST /email/send magic-link origin (STRATA-1596)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "send-origin-test-master-password";
    process.env.APP_URL = "https://steward.example.test";
    process.env.EMAIL_FROM = "Test <login@example.test>";
    process.env.EMAIL_PROVIDER = "mock";
    delete process.env.RESEND_API_KEY;

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await initAuthStores(true);

    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Send Origin Test", apiKeyHash: "hash" })
      .onConflictDoNothing();
  });

  afterAll(async () => {
    clearEmailAuthTenantCacheForTests();
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.APP_URL;
    delete process.env.EMAIL_FROM;
    delete process.env.EMAIL_PROVIDER;
  });

  beforeEach(() => {
    MockEmailInbox.clear();
  });

  it("builds the link against the request Origin when it is in allowedOrigins", async () => {
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: [STORED_BASE, OTHER_ALLOWED],
    });
    const email = "markets-user@example.test";
    const res = await sendMagicLink(email, OTHER_ALLOWED);
    expect(res.status).toBe(200);
    const link = lastLink(email);
    expect(link.startsWith(`${OTHER_ALLOWED}/auth/callback?`)).toBe(true);
    // MockEmailInbox's link regex stops at `&`, so read the email param from the body.
    expect(MockEmailInbox.last(email)?.text).toContain("email=markets-user%40example.test");
  });

  it("keeps the stored magicLinkBaseUrl when the request Origin matches it", async () => {
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: [STORED_BASE, OTHER_ALLOWED],
    });
    const email = "staging-user@example.test";
    expect((await sendMagicLink(email, STORED_BASE)).status).toBe(200);
    expect(lastLink(email).startsWith(`${STORED_BASE}/auth/callback?`)).toBe(true);
  });

  it("ignores an Origin that is not in allowedOrigins", async () => {
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: [STORED_BASE, OTHER_ALLOWED],
    });
    const email = "attacker-target@example.test";
    expect((await sendMagicLink(email, NOT_ALLOWED)).status).toBe(200);
    const link = lastLink(email);
    expect(link.startsWith(`${STORED_BASE}/auth/callback?`)).toBe(true);
    expect(link).not.toContain("evil.example.test");
  });

  it("does not treat a wildcard allowlist as permission to use an arbitrary Origin", async () => {
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: ["*"],
    });
    const email = "wildcard-target@example.test";
    expect((await sendMagicLink(email, NOT_ALLOWED)).status).toBe(200);
    expect(lastLink(email).startsWith(`${STORED_BASE}/auth/callback?`)).toBe(true);
  });

  it("ignores a non-https Origin even when it is allowlisted", async () => {
    const httpOrigin = "http://localhost:5173";
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: [STORED_BASE, httpOrigin],
    });
    const email = "local-dev@example.test";
    expect((await sendMagicLink(email, httpOrigin)).status).toBe(200);
    expect(lastLink(email).startsWith(`${STORED_BASE}/auth/callback?`)).toBe(true);
  });

  it("falls back to the stored base when no Origin header is present", async () => {
    await setTenantConfig({
      magicLinkBaseUrl: STORED_BASE,
      magicLinkCallbackPath: "/auth/callback",
      allowedOrigins: [STORED_BASE, OTHER_ALLOWED],
    });
    const email = "no-origin@example.test";
    expect((await sendMagicLink(email)).status).toBe(200);
    expect(lastLink(email).startsWith(`${STORED_BASE}/auth/callback?`)).toBe(true);
  });

  it("leaves tenants without magicLinkBaseUrl on Steward's own callback", async () => {
    await setTenantConfig({ allowedOrigins: [OTHER_ALLOWED] });
    const email = "steward-callback@example.test";
    expect((await sendMagicLink(email, OTHER_ALLOWED)).status).toBe(200);
    const link = lastLink(email);
    expect(link.startsWith("https://steward.example.test/auth/callback/email?")).toBe(true);
    expect(link).not.toContain(OTHER_ALLOWED);
  });
});
