/**
 * STRATA-1499 — a missing/changed Base RPC endpoint cannot clear an approval
 * claim, mint a new executionRef row, or re-broadcast an unknown tx.
 *
 * Uses the REAL vault (no signTransaction mock) with RPC_URL_84532 unset, so
 * the vault throws from the resolver before any key is decrypted, client is
 * built, or row is written. No network is touched. A later "fixed" endpoint is
 * simulated by swapping in a working broadcaster spy; nothing may invoke it.
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
  it("/sign with executionRef fails closed, binds the ref to a hashless failed row, and never mints a second row", async () => {
    const ref = "strata:no-rpc:sign-1";
    const first = await sign(ref);
    expect(first.status).toBe(500);
    const b1 = (await first.json()) as { ok: boolean; error: string; data?: unknown };
    expect(b1.ok).toBe(false);
    expect(b1.error).toContain("RPC endpoint not configured for chainId 84532");
    expect(b1.error).toContain("RPC_URL_84532");
    expect(b1.error).not.toContain("generic.example.com");
    expect(b1.error).not.toContain("base.org");

    const rows = await rowsForRef(ref);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("failed");
    expect(rows[0]?.txHash).toBeNull();
    const txId = rows[0]?.id as string;

    // Replay under the same ref: same action, still failed, no new row.
    const replay = await sign(ref);
    expect(replay.status).toBe(500);
    const b2 = (await replay.json()) as {
      data: { txId: string; status: string; replayed: boolean };
    };
    expect(b2.data.txId).toBe(txId);
    expect(b2.data.status).toBe("failed");
    expect(b2.data.replayed).toBe(true);
    expect(await rowsForRef(ref)).toHaveLength(1);

    // by-ref lookup returns the same action.
    const lookup = await app.request(`/vault/${AGENT}/actions/by-ref/${ref}`, {
      headers: headers(),
    });
    expect(lookup.status).toBe(200);
    const lb = (await lookup.json()) as { data: { txId: string; status: string; txHash?: string } };
    expect(lb.data.txId).toBe(txId);
    expect(lb.data.status).toBe("failed");
    expect(lb.data.txHash).toBeUndefined();
  });

  it("approval with a missing endpoint consumes the claim without signing; a fixed endpoint later cannot re-open it or re-broadcast", async () => {
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
      const first = await sign(ref);
      expect(first.status).toBe(202);
      const b1 = (await first.json()) as { data: { txId: string; status: string } };
      expect(b1.data.status).toBe("pending_approval");
      const txId = b1.data.txId;

      // Approve → real vault throws from the resolver before signing.
      const a1 = await approve(txId);
      expect(a1.status).toBe(500);
      const ab = (await a1.json()) as { error: string };
      expect(ab.error).toContain("RPC_URL_84532");

      const queue = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
      expect(queue).toHaveLength(1);
      expect(queue[0]?.status).toBe("approved"); // claim consumed, never released
      let rows = await rowsForRef(ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(txId);
      expect(rows[0]?.status).toBe("failed");
      expect(rows[0]?.txHash).toBeNull();

      // Operator "fixes" the endpoint: simulate a broadcaster that would now
      // succeed. Nothing below may invoke it.
      let calls = 0;
      fixedSpy = spyOn(vault, "signTransaction").mockImplementation(async () => {
        calls += 1;
        return `0x${"1".repeat(64)}`;
      });

      const a2 = await approve(txId);
      expect(a2.status).toBe(409);
      expect(calls).toBe(0);

      const replay = await sign(ref);
      expect(replay.status).toBe(500);
      const rb = (await replay.json()) as {
        data: { txId: string; status: string; replayed: boolean };
      };
      expect(rb.data.txId).toBe(txId);
      expect(rb.data.status).toBe("failed");
      expect(rb.data.replayed).toBe(true);
      expect(calls).toBe(0);

      const lookup = await app.request(`/vault/${AGENT}/actions/by-ref/${ref}`, {
        headers: headers(),
      });
      const lb = (await lookup.json()) as {
        data: { txId: string; status: string; txHash?: string };
      };
      expect(lb.data.txId).toBe(txId);
      expect(lb.data.status).toBe("failed");
      expect(lb.data.txHash).toBeUndefined();

      rows = await rowsForRef(ref);
      expect(rows).toHaveLength(1);
      const queueAfter = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(queueAfter).toHaveLength(1);
      expect(queueAfter[0]?.status).toBe("approved");
    } finally {
      fixedSpy?.mockRestore();
      fixedSpy = undefined;
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
  });
});
