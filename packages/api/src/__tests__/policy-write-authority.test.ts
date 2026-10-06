/**
 * STRATA-1499 (SF-1 Lane A) — policy-write and key-material-write authority.
 *
 * A leaked tenant API key could previously both sign (`/vault/:id/sign`) and
 * rewrite the signer's policies (`PUT /agents/:id/policies`) or export its key
 * (`/vault/:id/export`), so one key was unbounded authority. These writes now
 * require a human owner/admin session by default; the tenant API key is only
 * accepted when `STEWARD_ALLOW_API_KEY_POLICY_WRITES=true` is explicitly set,
 * and an agent token is never accepted.
 *
 * Self-contained against in-memory PGLite (same pattern as
 * `vault-sign-execution-ref.test.ts`) so it runs with or without an third-party
 * Postgres. `setPGLiteOverride` makes the DB unique index the real arbiter and
 * the in-process `app` observe the same rows.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { closeDb, getDb, policies, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT_ID = "pw-auth-tenant";
const AGENT_ID = "pw-auth-agent";
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();

let app: Hono;
let tenantKey: string;

function tenantHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT_ID,
    "X-Steward-Key": tenantKey,
  };
}

function bearerHeaders(token: string) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

async function ownerSession() {
  return signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT_ID, userId: OWNER_USER_ID },
    "1h",
  );
}

async function memberSession() {
  return signAccessToken(
    { address: `0x${"2".repeat(40)}`, tenantId: TENANT_ID, userId: MEMBER_USER_ID },
    "1h",
  );
}

async function agentToken() {
  return signAgentToken({ agentId: AGENT_ID, tenantId: TENANT_ID }, "1h");
}

const SAMPLE_POLICY = [
  {
    type: "spending-limit",
    enabled: true,
    config: { maxPerTx: "1", maxPerDay: "1", maxPerWeek: "1" },
  },
];

async function putPolicies(headers: Record<string, string>) {
  return app.request(`/agents/${AGENT_ID}/policies`, {
    method: "PUT",
    headers,
    body: JSON.stringify(SAMPLE_POLICY),
  });
}

async function exportKey(headers: Record<string, string>) {
  return app.request(`/vault/${AGENT_ID}/export`, {
    method: "POST",
    headers,
    body: "{}",
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "pw-auth-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "pw-auth-audit-key-32-bytes-minimum-aaaaaaaa";
  delete process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());

  const kp = generateApiKey();
  tenantKey = kp.key;
  await db.insert(tenants).values({ id: TENANT_ID, name: "PW Auth", apiKeyHash: kp.hash });
  await db.insert(users).values([
    { id: OWNER_USER_ID, email: `owner-${OWNER_USER_ID}@example.test` },
    { id: MEMBER_USER_ID, email: `member-${MEMBER_USER_ID}@example.test` },
  ]);
  await db.insert(userTenants).values([
    { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
    { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
  ]);

  ({ app } = await import("../app"));

  // Create the agent through the API with an owner session so it has an
  // encrypted EVM key (so the later owner-session export reaches the vault
  // rather than failing agent-existence checks).
  const owner = await ownerSession();
  const created = await app.request("/agents", {
    method: "POST",
    headers: bearerHeaders(owner),
    body: JSON.stringify({ id: AGENT_ID, name: "PW Auth Agent" }),
  });
  if (created.status !== 200) {
    throw new Error(`fixture POST /agents → ${created.status}: ${await created.text()}`);
  }
});

afterAll(async () => {
  delete process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES;
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

beforeEach(async () => {
  delete process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES;
  await getDb().delete(policies).where(eq(policies.agentId, AGENT_ID));
});

describe("PUT /agents/:agentId/policies authority", () => {
  it("rejects the tenant API key by default (403) and writes nothing", async () => {
    const res = await putPolicies(tenantHeaders());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toContain("owner/admin session");
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(0);
  });

  it("rejects an agent token by default even for its own agent (403)", async () => {
    const res = await putPolicies(bearerHeaders(await agentToken()));
    expect(res.status).toBe(403);
    // Agent tokens pass the scope check for their own agent, then fail authority.
    expect(((await res.json()) as { error: string }).error).toContain("owner/admin session");
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(0);
  });

  it("rejects a member session (403)", async () => {
    const res = await putPolicies(bearerHeaders(await memberSession()));
    expect(res.status).toBe(403);
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(0);
  });

  it("allows an owner session (200) and persists the policy", async () => {
    const res = await putPolicies(bearerHeaders(await ownerSession()));
    expect(res.status).toBe(200);
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.type).toBe("spending-limit");
  });

  it("allows the tenant API key when STEWARD_ALLOW_API_KEY_POLICY_WRITES=true (200)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES = "true";
    const res = await putPolicies(tenantHeaders());
    expect(res.status).toBe(200);
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(1);
  });

  it("still rejects an agent token even with the opt-in on (403)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES = "true";
    const res = await putPolicies(bearerHeaders(await agentToken()));
    expect(res.status).toBe(403);
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
    expect(rows).toHaveLength(0);
  });

  it("preserves the cross-agent scope message for an agent token targeting another agent", async () => {
    const token = await signAgentToken({ agentId: "some-other-agent", tenantId: TENANT_ID }, "1h");
    const res = await app.request(`/agents/${AGENT_ID}/policies`, {
      method: "PUT",
      headers: bearerHeaders(token),
      body: JSON.stringify(SAMPLE_POLICY),
    });
    expect(res.status).toBe(403);
    // Scope check runs before the authority check so the more specific message wins.
    expect(((await res.json()) as { error: string }).error).toContain("scope does not match");
  });
});

describe("POST /vault/:agentId/export authority", () => {
  it("rejects the tenant API key by default (403)", async () => {
    const res = await exportKey(tenantHeaders());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toContain("owner/admin session");
  });

  it("rejects an agent token by default (403)", async () => {
    const res = await exportKey(bearerHeaders(await agentToken()));
    expect(res.status).toBe(403);
  });

  it("rejects a member session (403)", async () => {
    const res = await exportKey(bearerHeaders(await memberSession()));
    expect(res.status).toBe(403);
  });

  it("reaches the vault for an owner session (not a 403 authority failure)", async () => {
    const res = await exportKey(bearerHeaders(await ownerSession()));
    // Owner clears the authority gate; the export itself returns 200 (key
    // present) or a non-403 error. The point is authority no longer blocks it.
    expect(res.status).not.toBe(403);
  });

  it("allows the tenant API key when STEWARD_ALLOW_API_KEY_POLICY_WRITES=true (not 403)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES = "true";
    const res = await exportKey(tenantHeaders());
    expect(res.status).not.toBe(403);
  });

  it("still rejects an agent token even with the opt-in on (403)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_POLICY_WRITES = "true";
    const res = await exportKey(bearerHeaders(await agentToken()));
    expect(res.status).toBe(403);
  });
});
