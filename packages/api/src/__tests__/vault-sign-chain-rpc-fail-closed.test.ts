/**
 * STRATA-1499 — a missing Base RPC endpoint is a deterministic configuration
 * error that is detected BEFORE anything is reserved or claimed.
 *
 * Uses the REAL vault (no signTransaction mock) with RPC_URL_84532 unset. The
 * API route runs `vault.assertChainRpcReady()` before reserving an
 * executionRef row or consuming a pending approval, so `/sign` writes no row
 * and `/approve` leaves the approval pending (REVIEW-STEWARD-27 F1). No
 * network is touched: the resolver throws before viem's `http()` transport is
 * constructed. A later "fixed" endpoint is simulated with a broadcaster spy:
 * the same request must then succeed exactly once, and replay / repeated
 * approval must never re-invoke it.
 */

import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { approvalQueue, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT = "chain-rpc-tenant";
const AGENT = "chain-rpc-agent";
const TO = "0x000000000000000000000000000000000000dEaD";
const FIXED_HASH = `0x${"1".repeat(64)}`;

let app: Hono;
let apiKey: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let fixedSpy: Mock<(request: SignRequest, options?: unknown) => Promise<string>> | undefined;

function headers() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT,
    "X-Steward-Key": apiKey,
  };
}

function sign(executionRef: string) {
  return app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ to: TO, value: "1", data: "0xabcdef", chainId: 84532, executionRef }),
  });
}

function approve(txId: string) {
  return app.request(`/vault/${AGENT}/approve/${txId}`, {
    method: "POST",
    headers: headers(),
    body: "{}",
  });
}

async function rowsForRef(ref: string) {
  return getDb()
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.tenantId, TENANT),
        eq(transactions.agentId, AGENT),
        eq(transactions.executionRef, ref),
      ),
    );
}

function setChainUrls(urls: Record<number, string | undefined>) {
  (
    vault as unknown as { config: { chainRpcUrls: Record<number, string | undefined> } }
  ).config.chainRpcUrls = urls;
}

/** Operator "fixes" the endpoint; the vault's broadcaster is a counting spy. */
function installFixedEndpoint() {
  setChainUrls({ 84532: "https://explicit-sepolia.invalid/v2/FIXED_KEY" });
  let calls = 0;
  fixedSpy = spyOn(vault, "signTransaction").mockImplementation(async () => {
    calls += 1;
    return FIXED_HASH;
  });
  return () => calls;
}

function restoreFixedEndpoint() {
  fixedSpy?.mockRestore();
  fixedSpy = undefined;
  setChainUrls({ 8453: undefined, 84532: undefined });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "chain-rpc-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "chain-rpc-audit-key-32-bytes-minimum-aaaaaaa";
  // Generic RPC_URL is set and must be ignored; per-chain Base keys are unset.
  process.env.RPC_URL = "https://generic.example.com/rpc";
  delete process.env.RPC_URL_8453;
  delete process.env.RPC_URL_84532;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  apiKey = k.key;
  await db.insert(tenants).values({ id: TENANT, name: "Chain RPC", apiKeyHash: k.hash });

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  const res = await app.request("/agents", {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (res.status !== 200) throw new Error(`POST /agents → ${res.status}: ${await res.text()}`);
});

afterAll(async () => {
  fixedSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
  delete process.env.RPC_URL;
});

describe.serial("Base sign/approve fail closed without RPC_URL_84532 (STRATA-1499)", () => {
  it("/sign with executionRef fails closed BEFORE reserving: no row, and the same request succeeds once after the fix", async () => {
    const ref = "strata:no-rpc:sign-1";
    const first = await sign(ref);
    expect(first.status).toBe(500);
    const b1 = (await first.json()) as { ok: boolean; error: string; data?: unknown };
    expect(b1.ok).toBe(false);
    expect(b1.error).toContain("RPC endpoint not configured for chainId 84532");
    expect(b1.error).toContain("RPC_URL_84532");
    expect(b1.error).not.toContain("generic.example.com");
    expect(b1.error).not.toContain("base.org");

    // F1: a configuration error reserves nothing.
    expect(await rowsForRef(ref)).toHaveLength(0);
    const lookup404 = await app.request(`/vault/${AGENT}/actions/by-ref/${ref}`, {
      headers: headers(),
    });
    expect(lookup404.status).toBe(404);

    // Retry with the endpoint still missing: still nothing.
    expect((await sign(ref)).status).toBe(500);
    expect(await rowsForRef(ref)).toHaveLength(0);

    const calls = installFixedEndpoint();
    try {
      const fixed = await sign(ref);
      expect(fixed.status).toBe(200);
      const fb = (await fixed.json()) as { data: { txId: string; txHash: string } };
      expect(fb.data.txHash).toBe(FIXED_HASH);
      expect(calls()).toBe(1);
      const rows = await rowsForRef(ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(fb.data.txId);
      expect(rows[0]?.status).toBe("signed");

      // Replay under the same ref: same action, no re-sign, no new row.
      const replay = await sign(ref);
      expect(replay.status).toBe(200);
      const rb = (await replay.json()) as { data: { txId: string; replayed: boolean } };
      expect(rb.data.txId).toBe(fb.data.txId);
      expect(rb.data.replayed).toBe(true);
      expect(calls()).toBe(1);
      expect(await rowsForRef(ref)).toHaveLength(1);

      const lookup = await app.request(`/vault/${AGENT}/actions/by-ref/${ref}`, {
        headers: headers(),
      });
      expect(lookup.status).toBe(200);
      const lb = (await lookup.json()) as { data: { txId: string; status: string } };
      expect(lb.data.txId).toBe(fb.data.txId);
      expect(lb.data.status).toBe("signed");
    } finally {
      restoreFixedEndpoint();
    }
  });

  it("approval with a missing endpoint leaves the claim pending and the tx unchanged; the same approval succeeds once after the fix", async () => {
    const ref = "strata:no-rpc:approve-1";
    const policyId = "chain-rpc-threshold";
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: AGENT,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "0" }, // value "1" exceeds → manual approval
      });
    try {
      // Queueing for approval is allowed to proceed only when the chain is
      // ready, so install the endpoint for the enqueue, then remove it.
      const enqueueCalls = installFixedEndpoint();
      const first = await sign(ref);
      restoreFixedEndpoint();
      expect(first.status).toBe(202);
      expect(enqueueCalls()).toBe(0);
      const b1 = (await first.json()) as { data: { txId: string; status: string } };
      expect(b1.data.status).toBe("pending_approval");
      const txId = b1.data.txId;

      // Approve with the endpoint missing → preflight rejects before the claim.
      const a1 = await approve(txId);
      expect(a1.status).toBe(500);
      const ab = (await a1.json()) as { error: string };
      expect(ab.error).toContain("RPC_URL_84532");

      const queue = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
      expect(queue).toHaveLength(1);
      expect(queue[0]?.status).toBe("pending"); // F1: claim NOT consumed
      expect(queue[0]?.resolvedAt).toBeNull();
      let rows = await rowsForRef(ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(txId);
      expect(rows[0]?.status).toBe("pending"); // F1: row unchanged
      expect(rows[0]?.txHash).toBeNull();

      // Operator fixes the endpoint: the SAME approval succeeds exactly once.
      const calls = installFixedEndpoint();
      const a2 = await approve(txId);
      expect(a2.status).toBe(200);
      expect(((await a2.json()) as { data: { txHash: string } }).data.txHash).toBe(FIXED_HASH);
      expect(calls()).toBe(1);

      rows = await rowsForRef(ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.status).toBe("signed");
      expect(rows[0]?.txHash).toBe(FIXED_HASH);

      // Second approval: 409, nothing re-broadcast.
      const a3 = await approve(txId);
      expect(a3.status).toBe(409);
      expect(calls()).toBe(1);

      // /sign replay under the same ref resolves to the same action.
      const replay = await sign(ref);
      const rb = (await replay.json()) as {
        data: { txId: string; status: string; replayed: boolean };
      };
      expect(rb.data.txId).toBe(txId);
      expect(rb.data.replayed).toBe(true);
      expect(calls()).toBe(1);

      const queueAfter = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(queueAfter).toHaveLength(1);
      expect(queueAfter[0]?.status).toBe("approved");
    } finally {
      restoreFixedEndpoint();
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
  });
});
