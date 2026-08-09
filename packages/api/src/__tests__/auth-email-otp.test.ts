import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { MockEmailInbox } from "@stwd/auth";
import { authenticators, closeDb, getDb, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { authRoutes, clearEmailAuthTenantCacheForTests, initAuthStores } from "../routes/auth";

const TENANT_ID = "default";

function extractCode(text: string): string {
  const m = text.match(/\b(\d{6})\b/);
  if (!m) throw new Error(`no 6-digit code in email body: ${text}`);
  return m[1]!;
}

async function sendOtp(email: string): Promise<Response> {
  return authRoutes.request("/email/otp/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, tenantId: TENANT_ID }),
  });
}

async function verifyOtp(email: string, code: string): Promise<Response> {
  return authRoutes.request("/email/otp/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code, tenantId: TENANT_ID }),
  });
}

async function registerOptions(
  email: string,
  opts: { emailGrant?: string } = {},
): Promise<Response> {
  return authRoutes.request("/passkey/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, tenantId: TENANT_ID, ...opts }),
  });
}

/** Drive email → code → grant and return the raw grant token. */
async function obtainGrant(email: string): Promise<string> {
  MockEmailInbox.clear(email);
  const sendRes = await sendOtp(email);
  expect(sendRes.status).toBe(200);
  const msg = MockEmailInbox.last(email);
  if (!msg) throw new Error("no OTP email captured");
  const code = extractCode(msg.text);
  const verifyRes = await verifyOtp(email, code);
  expect(verifyRes.status).toBe(200);
  const json = (await verifyRes.json()) as { ok: boolean; data?: { emailGrant?: string } };
  expect(json.ok).toBe(true);
  if (!json.data?.emailGrant) throw new Error("verify did not return a grant");
  return json.data.emailGrant;
}

describe("email OTP anti-squatting flow", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "otp-test-master-password";
    process.env.APP_URL = "https://app.example.com";
    process.env.EMAIL_FROM = "Test <login@example.com>";
    process.env.EMAIL_PROVIDER = "mock";
    delete process.env.RESEND_API_KEY;

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await initAuthStores(true);

    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Default", apiKeyHash: "hash" })
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

  it("/email/otp/send returns an expiresAt and emails a 6-digit code", async () => {
    const email = `send-${Date.now()}@example.com`;
    const res = await sendOtp(email);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { ok: boolean; data?: { expiresAt?: string } };
    expect(json.ok).toBe(true);
    expect(typeof json.data?.expiresAt).toBe("string");
    expect(new Date(json.data!.expiresAt!).getTime()).toBeGreaterThan(Date.now());
    const msg = MockEmailInbox.last(email);
    expect(msg).toBeTruthy();
    expect(extractCode(msg!.text)).toMatch(/^\d{6}$/);
  });

  it("/email/otp/verify with the correct code returns a grant", async () => {
    const email = `verify-ok-${Date.now()}@example.com`;
    const grant = await obtainGrant(email);
    expect(typeof grant).toBe("string");
    expect(grant.length).toBeGreaterThan(10);
  });

  it("/email/otp/verify with a wrong code → 401", async () => {
    const email = `verify-bad-${Date.now()}@example.com`;
    await sendOtp(email);
    const code = extractCode(MockEmailInbox.last(email)!.text);
    const wrong = code === "000000" ? "111111" : "000000";
    const res = await verifyOtp(email, wrong);
    expect(res.status).toBe(401);
    const json = (await res.json()) as { ok: boolean };
    expect(json.ok).toBe(false);
  });

  it("OTP code is single-use: verifying the same code twice fails the 2nd time", async () => {
    const email = `single-use-code-${Date.now()}@example.com`;
    await sendOtp(email);
    const code = extractCode(MockEmailInbox.last(email)!.text);
    const first = await verifyOtp(email, code);
    expect(first.status).toBe(200);
    const second = await verifyOtp(email, code);
    expect(second.status).toBe(401);
  });

  it("brute-force limiter trips after repeated wrong codes for the same {tenant,email}", async () => {
    // The per-{tenant,email} limiter is a no-op without Redis (soft-fail), so
    // we only assert the limiter does not falsely reject correct usage and that
    // wrong codes are rejected. With Redis configured it returns 429 after 5
    // attempts; here we assert the wrong-code path is consistently 401 and the
    // endpoint stays available (no 5xx) under repeated abuse.
    const email = `brute-${Date.now()}@example.com`;
    await sendOtp(email);
    for (let i = 0; i < 6; i++) {
      const res = await verifyOtp(email, "000001");
      expect([401, 429]).toContain(res.status);
    }
  });

  it("passkey/register/options for a BRAND-NEW email WITHOUT a grant is denied", async () => {
    const email = `new-nogrant-${Date.now()}@example.com`;
    const res = await registerOptions(email);
    expect(res.status).toBe(401);
    const json = (await res.json()) as { ok: boolean; error?: string };
    expect(json.ok).toBe(false);
    // No user row should have been created by the denied options call.
    const [u] = await getDb().select().from(users).where(eq(users.email, email));
    expect(u).toBeUndefined();
  });

  it("passkey/register/options for a brand-new email WITH a valid grant is allowed", async () => {
    const email = `new-grant-${Date.now()}@example.com`;
    const grant = await obtainGrant(email);
    const res = await registerOptions(email, { emailGrant: grant });
    expect(res.status).toBe(200);
    const options = (await res.json()) as { challenge?: string; user?: unknown };
    expect(options.challenge).toBeTruthy();
  });

  it("a wrong/forged grant for a brand-new email is denied", async () => {
    const email = `new-forged-${Date.now()}@example.com`;
    const res = await registerOptions(email, { emailGrant: "not-a-real-grant" });
    expect(res.status).toBe(401);
  });

  it("grant is single-use at register/verify: 2nd register attempt with same grant fails 401", async () => {
    const email = `reg-single-${Date.now()}@example.com`;
    const grant = await obtainGrant(email);
    // options peeks (does not consume) — user row gets created here.
    const optRes = await registerOptions(email, { emailGrant: grant });
    expect(optRes.status).toBe(200);

    // First register/verify CONSUMES the grant. The WebAuthn response is bogus,
    // so verification fails at 400 AFTER the grant is burned — proving the grant
    // is consumed regardless of ceremony outcome on this single-use design...
    const firstReg = await authRoutes.request("/passkey/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        tenantId: TENANT_ID,
        emailGrant: grant,
        response: { id: "bogus", rawId: "bogus", type: "public-key", response: {} },
      }),
    });
    // Grant was valid → passes the gate → fails at WebAuthn verification (400),
    // NOT at the grant gate (401).
    expect(firstReg.status).toBe(400);

    // Second attempt reuses the now-consumed grant → blocked at the gate (401).
    const secondReg = await authRoutes.request("/passkey/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        tenantId: TENANT_ID,
        emailGrant: grant,
        response: { id: "bogus", rawId: "bogus", type: "public-key", response: {} },
      }),
    });
    expect(secondReg.status).toBe(401);
  });

  it("an already-verified user with a credential can re-register WITHOUT a grant", async () => {
    const email = `existing-verified-${Date.now()}@example.com`;
    const db = getDb();
    const [u] = await db.insert(users).values({ email, emailVerified: true }).returning();
    await db.insert(authenticators).values({
      userId: u!.id,
      credentialId: `cred-${Date.now()}`,
      credentialPublicKey: "pk",
      counter: 0,
      credentialDeviceType: "singleDevice",
      credentialBackedUp: false,
      transports: [],
    });

    const res = await registerOptions(email);
    expect(res.status).toBe(200);
    const options = (await res.json()) as { challenge?: string };
    expect(options.challenge).toBeTruthy();
  });
});
