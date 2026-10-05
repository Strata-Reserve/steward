/**
 * STRATA-1486 — stable execution reference on POST /vault/:agentId/sign.
 *
 * Runs against an in-memory PGLite so the DB unique index is the real arbiter.
 * `vault.signTransaction` is replaced with a fake that mimics the real
 * upsert-and-return-hash behaviour, so every "broadcast" is observable as a
 * spy call and no RPC is ever touched.
 */

import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { approvalQueue, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT_A = "exec-ref-tenant-a";
const TENANT_B = "exec-ref-tenant-b";
const AGENT_A = "exec-ref-agent-a";
const AGENT_B = "exec-ref-agent-b";
const TO = "0x000000000000000000000000000000000000dEaD";

let app: Hono;
let keyA: string;
let keyB: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let signSpy: Mock<(request: SignRequest, options?: unknown) => Promise<string>>;
let signCalls: SignRequest[] = [];

function headers(tenant: string, key: string) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": tenant,
    "X-Steward-Key": key,
  };
}

function sign(
  body: Record<string, unknown>,
  opts: {
    tenant?: string;
    key?: string;
    agent?: string;
    extraHeaders?: Record<string, string>;
  } = {},
) {
  const tenant = opts.tenant ?? TENANT_A;
  const key = opts.key ?? keyA;
  const agent = opts.agent ?? AGENT_A;
  return app.request(`/vault/${agent}/sign`, {
    method: "POST",
    headers: { ...headers(tenant, key), ...(opts.extraHeaders ?? {}) },
    body: JSON.stringify(body),
  });
}

function basePayload(executionRef?: string) {
  return {
    to: TO,
    value: "1",
    data: "0xabcdef",
    chainId: 84532,
    ...(executionRef ? { executionRef } : {}),
  };
}

async function rowsForRef(tenantId: string, agentId: string, ref: string) {
  return getDb()
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.tenantId, tenantId),
        eq(transactions.agentId, agentId),
        eq(transactions.executionRef, ref),
      ),
    );
}

async function createAgent(tenant: string, key: string, agentId: string) {
  const res = await app.request("/agents", {
    method: "POST",
    headers: headers(tenant, key),
    body: JSON.stringify({ id: agentId, name: agentId }),
  });
  if (res.status !== 200)
    throw new Error(`POST /agents ${agentId} → ${res.status}: ${await res.text()}`);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "exec-ref-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "exec-ref-audit-key-32-bytes-minimum-aaaaaaaa";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const a = generateApiKey();
  const b = generateApiKey();
  keyA = a.key;
  keyB = b.key;
  await db.insert(tenants).values([
    { id: TENANT_A, name: "Exec Ref A", apiKeyHash: a.hash },
    { id: TENANT_B, name: "Exec Ref B", apiKeyHash: b.hash },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  await createAgent(TENANT_A, keyA, AGENT_A);
  await createAgent(TENANT_B, keyB, AGENT_B);

  // Fail-closed (STRATA-1499): an agent with no policy set cannot sign. These
  // execution-ref tests exercise the sign/replay state machine, not policy
  // enforcement, so seed a permissive (always-pass) rule on both agents. Tests
  // that assert a policy outcome insert their own rule and clean it up.
  const MAX_UINT = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
  await getDb()
    .insert(policies)
    .values([
      {
        id: "exec-ref-permissive-a",
        agentId: AGENT_A,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: MAX_UINT, maxPerDay: MAX_UINT, maxPerWeek: MAX_UINT },
      },
      {
        id: "exec-ref-permissive-b",
        agentId: AGENT_B,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: MAX_UINT, maxPerDay: MAX_UINT, maxPerWeek: MAX_UINT },
      },
    ]);

  // Fake signer: mirrors the real vault's "upsert row by txId, return hash"
  // contract without touching any RPC. Each call == one broadcast.
  signSpy = spyOn(vault, "signTransaction").mockImplementation(
    async (request: SignRequest, options: unknown = {}) => {
      const opts = options as { txId?: string; policyResults?: unknown[]; status?: string };
      signCalls.push(request);
      const txId = opts.txId ?? crypto.randomUUID();
      const hash = `0x${signCalls.length.toString(16).padStart(64, "0")}`;
      const now = new Date();
      await getDb()
        .insert(transactions)
        .values({
          id: txId,
          agentId: request.agentId,
          status: "signed",
          toAddress: request.to,
          value: request.value,
          data: request.data,
          chainId: request.chainId,
          txHash: hash,
          policyResults: (opts.policyResults as never) ?? [],
          signedAt: now,
          createdAt: now,
        })
        .onConflictDoUpdate({
          target: transactions.id,
          set: { status: "signed", txHash: hash, signedAt: now },
        });
      return hash;
    },
  );
});

afterAll(async () => {
  signSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe.serial("vault sign executionRef (STRATA-1486)", () => {
  it("is backward compatible: requests without executionRef behave as before", async () => {
    signCalls = [];
    const r1 = await sign(basePayload());
    const r2 = await sign(basePayload());
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    const b1 = (await r1.json()) as {
      data: { txId: string; txHash: string; executionRef?: string };
    };
    const b2 = (await r2.json()) as { data: { txId: string; txHash: string } };
    expect(b1.data.txHash).toStartWith("0x");
    expect(b1.data.executionRef).toBeUndefined();
    expect(b1.data.txId).not.toBe(b2.data.txId);
    expect(signCalls).toHaveLength(2);
    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, b1.data.txId));
    expect(row?.executionRef).toBeNull();
    expect(row?.tenantId).toBeNull();
  });

  it("rejects malformed references and header/body mismatches without signing", async () => {
    signCalls = [];
    const bad = await sign(basePayload("has space"));
    expect(bad.status).toBe(400);
    const tooLong = await sign(basePayload("a".repeat(129)));
    expect(tooLong.status).toBe(400);
    const notString = await sign({ ...basePayload(), executionRef: 42 });
    expect(notString.status).toBe(400);
    const mismatch = await sign(basePayload("t:intent:1"), {
      extraHeaders: { "Idempotency-Key": "t:intent:2" },
    });
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as { error: string }).error).toContain("must match");
    expect(signCalls).toHaveLength(0);
  });

  it("accepts the reference via Idempotency-Key header and stores it on the action", async () => {
    signCalls = [];
    const ref = "strata:intent-hdr:step-1";
    const res = await sign(basePayload(), { extraHeaders: { "Idempotency-Key": ref } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: { txId: string; txHash: string; executionRef: string };
    };
    expect(body.data.executionRef).toBe(ref);
    const rows = await rowsForRef(TENANT_A, AGENT_A, ref);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.id).toBe(body.data.txId);
    expect(rows[0]?.txHash).toBe(body.data.txHash);
    expect(rows[0]?.status).toBe("signed");
    expect(signCalls).toHaveLength(1);
    expect(signCalls[0]?.executionRef).toBe(ref);
  });

  it("replays an identical request (same ref + same payload) without signing again", async () => {
    signCalls = [];
    const ref = "strata:intent-replay:step-1";
    const first = await sign(basePayload(ref));
    expect(first.status).toBe(200);
    const b1 = (await first.json()) as { data: { txId: string; txHash: string } };
    expect(signCalls).toHaveLength(1);

    // Same payload, cosmetically different: checksum case + header instead of body.
    const replay = await sign(
      { to: TO.toLowerCase(), value: "1", data: "0xABCDEF", chainId: 84532 },
      { extraHeaders: { "Idempotency-Key": ref } },
    );
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    const b2 = (await replay.json()) as {
      ok: boolean;
      data: { txId: string; txHash: string; status: string; replayed: boolean };
    };
    expect(b2.ok).toBe(true);
    expect(b2.data.txId).toBe(b1.data.txId);
    expect(b2.data.txHash).toBe(b1.data.txHash);
    expect(b2.data.status).toBe("signed");
    expect(b2.data.replayed).toBe(true);
    expect(signCalls).toHaveLength(1);
    expect(await rowsForRef(TENANT_A, AGENT_A, ref)).toHaveLength(1);
  });

  it("returns 409 for the same ref with a different payload and never signs", async () => {
    signCalls = [];
    const ref = "strata:intent-conflict:step-1";
    const first = await sign(basePayload(ref));
    expect(first.status).toBe(200);
    const b1 = (await first.json()) as { data: { txId: string } };
    expect(signCalls).toHaveLength(1);

    for (const variant of [
      { ...basePayload(ref), value: "2" },
      { ...basePayload(ref), data: "0x1234" },
      { ...basePayload(ref), chainId: 8453 },
      { ...basePayload(ref), to: "0x0000000000000000000000000000000000000001" },
    ]) {
      const res = await sign(variant);
      expect(res.status).toBe(409);
      const body = (await res.json()) as { ok: boolean; data: { txId: string; status: string } };
      expect(body.ok).toBe(false);
      expect(body.data.txId).toBe(b1.data.txId);
      expect(body.data.status).toBe("conflict");
    }
    expect(signCalls).toHaveLength(1);
    expect(await rowsForRef(TENANT_A, AGENT_A, ref)).toHaveLength(1);
  });

  it("concurrent identical requests create exactly one action and at most one broadcast (×25)", async () => {
    for (let i = 0; i < 25; i++) {
      signCalls = [];
      const ref = `strata:intent-race:${i}`;
      const fanout = 6;
      const responses = await Promise.all(
        Array.from({ length: fanout }, () => sign(basePayload(ref))),
      );
      const bodies = (await Promise.all(responses.map((r) => r.json()))) as Array<{
        ok: boolean;
        data: { txId: string; txHash?: string; status?: string };
      }>;

      const statuses = responses.map((r) => r.status);
      // Every caller gets a non-error outcome: the winner's 200 or a replay
      // (200 once signed, 202 "processing" if it raced ahead of the signer).
      for (const s of statuses) expect([200, 202]).toContain(s);
      expect(statuses.filter((s) => s === 200).length).toBeGreaterThanOrEqual(1);

      const txIds = new Set(bodies.map((b) => b.data.txId));
      expect(txIds.size).toBe(1);
      expect(signCalls).toHaveLength(1);

      const rows = await rowsForRef(TENANT_A, AGENT_A, ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.status).toBe("signed");
      expect(rows[0]?.txHash).toStartWith("0x");
      const hashes = new Set(bodies.map((b) => b.data.txHash).filter(Boolean));
      expect(hashes.size).toBe(1);
    }
  });

  it("queues under policy, replays as pending_approval, then approve broadcasts once onto the same action", async () => {
    signCalls = [];
    const ref = "strata:intent-approve:step-1";
    const policyId = "exec-ref-auto-approve";
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: AGENT_A,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "0" }, // value "1" exceeds → manual approval
      });
    try {
      const first = await sign(basePayload(ref));
      expect(first.status).toBe(202);
      const b1 = (await first.json()) as {
        ok: boolean;
        data: { txId: string; status: string; executionRef: string };
      };
      expect(b1.ok).toBe(false);
      expect(b1.data.status).toBe("pending_approval");
      expect(b1.data.executionRef).toBe(ref);
      expect(signCalls).toHaveLength(0);

      // Replay while pending → same action, still pending, nothing queued twice.
      const replay = await sign(basePayload(ref));
      expect(replay.status).toBe(202);
      const b2 = (await replay.json()) as { data: { txId: string; status: string } };
      expect(b2.data.txId).toBe(b1.data.txId);
      expect(b2.data.status).toBe("pending_approval");
      const queue = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, b1.data.txId));
      expect(queue).toHaveLength(1);
      expect(signCalls).toHaveLength(0);

      // Lookup reflects pending state.
      const lookupPending = await app.request(`/vault/${AGENT_A}/actions/by-ref/${ref}`, {
        headers: headers(TENANT_A, keyA),
      });
      expect(lookupPending.status).toBe(200);
      expect(((await lookupPending.json()) as { data: { status: string } }).data.status).toBe(
        "pending_approval",
      );

      // Approve → exactly one broadcast, hash lands on the same row.
      const approve = await app.request(`/vault/${AGENT_A}/approve/${b1.data.txId}`, {
        method: "POST",
        headers: headers(TENANT_A, keyA),
        body: "{}",
      });
      expect(approve.status).toBe(200);
      const ab = (await approve.json()) as { data: { txId: string; txHash: string } };
      expect(ab.data.txId).toBe(b1.data.txId);
      expect(signCalls).toHaveLength(1);
      expect(signCalls[0]?.executionRef).toBe(ref);

      const rows = await rowsForRef(TENANT_A, AGENT_A, ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(b1.data.txId);
      expect(rows[0]?.status).toBe("signed");
      expect(rows[0]?.txHash).toBe(ab.data.txHash);

      // Second approve is a no-op (409), replay returns the broadcast action, no new sign.
      const approveAgain = await app.request(`/vault/${AGENT_A}/approve/${b1.data.txId}`, {
        method: "POST",
        headers: headers(TENANT_A, keyA),
        body: "{}",
      });
      expect(approveAgain.status).toBe(409);
      const replayAfter = await sign(basePayload(ref));
      expect(replayAfter.status).toBe(200);
      const b3 = (await replayAfter.json()) as { data: { txId: string; txHash: string } };
      expect(b3.data.txId).toBe(b1.data.txId);
      expect(b3.data.txHash).toBe(ab.data.txHash);
      expect(signCalls).toHaveLength(1);
    } finally {
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
  });

  it("STRATA-1499: an approval that fails after invoking the broadcaster is terminal — no second approval or replay can sign", async () => {
    signCalls = [];
    const ref = "strata:intent-approval-ambiguous:step-1";
    const policyId = "exec-ref-auto-approve-ambiguous";
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: AGENT_A,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "0" },
      });
    try {
      const first = await sign(basePayload(ref));
      expect(first.status).toBe(202);
      const b1 = (await first.json()) as { data: { txId: string; status: string } };
      expect(b1.data.status).toBe("pending_approval");
      expect(signCalls).toHaveLength(0);

      // Broadcaster is invoked (RPC may have accepted the tx) but the call
      // throws before any hash is persisted → ambiguous outcome.
      signSpy.mockImplementationOnce(async (request: SignRequest) => {
        signCalls.push(request);
        throw new Error("request timed out waiting for RPC response");
      });
      const approve = await app.request(`/vault/${AGENT_A}/approve/${b1.data.txId}`, {
        method: "POST",
        headers: headers(TENANT_A, keyA),
        body: "{}",
      });
      expect([500, 502]).toContain(approve.status);
      expect(signCalls).toHaveLength(1);

      // Claim stays consumed; the action is terminal and hashless.
      const queue = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, b1.data.txId));
      expect(queue).toHaveLength(1);
      expect(queue[0]?.status).not.toBe("pending");
      const rows = await rowsForRef(TENANT_A, AGENT_A, ref);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.status).toBe("failed");
      expect(rows[0]?.txHash).toBeNull();

      // A second human approval cannot sign.
      const approveAgain = await app.request(`/vault/${AGENT_A}/approve/${b1.data.txId}`, {
        method: "POST",
        headers: headers(TENANT_A, keyA),
        body: "{}",
      });
      expect(approveAgain.status).toBe(409);
      expect(signCalls).toHaveLength(1);

      // A /sign replay under the same ref cannot sign either.
      const replay = await sign(basePayload(ref));
      expect(replay.status).toBe(500);
      const b2 = (await replay.json()) as {
        data: { txId: string; status: string; txHash?: string; replayed: boolean };
      };
      expect(b2.data.txId).toBe(b1.data.txId);
      expect(b2.data.status).toBe("failed");
      expect(b2.data.txHash).toBeUndefined();
      expect(b2.data.replayed).toBe(true);
      expect(signCalls).toHaveLength(1);

      // Lookup shows the hashless, non-retryable state.
      const lookup = await app.request(`/vault/${AGENT_A}/actions/by-ref/${ref}`, {
        headers: headers(TENANT_A, keyA),
      });
      expect(lookup.status).toBe(200);
      const lb = (await lookup.json()) as { data: { status: string; txHash?: string } };
      expect(lb.data.status).toBe("failed");
      expect(lb.data.txHash).toBeUndefined();

      const after = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, b1.data.txId));
      expect(after).toHaveLength(1);
      expect(after[0]?.status).toBe("failed");
      expect(after[0]?.txHash).toBeNull();
    } finally {
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
  });

  it("binds a policy rejection to the reference and replays it as 403 without re-evaluating", async () => {
    signCalls = [];
    const ref = "strata:intent-rejected:step-1";
    const policyId = "exec-ref-whitelist";
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: AGENT_A,
        type: "approved-addresses",
        enabled: true,
        config: { mode: "whitelist", addresses: ["0x0000000000000000000000000000000000000001"] },
      });
    try {
      const first = await sign(basePayload(ref));
      expect(first.status).toBe(403);
    } finally {
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
    // Policy removed: a fresh request would now pass, but the reference is
    // already bound to the rejected action → replay, not re-sign.
    const replay = await sign(basePayload(ref));
    expect(replay.status).toBe(403);
    const b2 = (await replay.json()) as { data: { status: string; replayed: boolean } };
    expect(b2.data.status).toBe("rejected");
    expect(b2.data.replayed).toBe(true);
    expect(signCalls).toHaveLength(0);
    expect(await rowsForRef(TENANT_A, AGENT_A, ref)).toHaveLength(1);
  });

  it("records a signing failure on the reserved action and never re-signs under that reference", async () => {
    signCalls = [];
    const ref = "strata:intent-failed:step-1";
    signSpy.mockImplementationOnce(async () => {
      throw new Error("insufficient funds for gas * price + value");
    });
    const first = await sign(basePayload(ref));
    expect(first.status).toBe(502);
    const replay = await sign(basePayload(ref));
    expect(replay.status).toBe(500);
    const b2 = (await replay.json()) as { data: { status: string; txHash?: string } };
    expect(b2.data.status).toBe("failed");
    expect(b2.data.txHash).toBeUndefined();
    expect(signCalls).toHaveLength(0);
    const lookup = await app.request(`/vault/${AGENT_A}/actions/by-ref/${ref}`, {
      headers: headers(TENANT_A, keyA),
    });
    expect(((await lookup.json()) as { data: { status: string } }).data.status).toBe("failed");
  });

  it("GET /actions/by-ref returns status, txHash, txId and timestamps", async () => {
    signCalls = [];
    const ref = "strata:intent-lookup:step-1";
    const first = await sign(basePayload(ref));
    expect(first.status).toBe(200);
    const b1 = (await first.json()) as { data: { txId: string; txHash: string } };

    const res = await app.request(`/vault/${AGENT_A}/actions/by-ref/${ref}`, {
      headers: headers(TENANT_A, keyA),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        txId: string;
        executionRef: string;
        status: string;
        txHash: string;
        chainId: number;
        createdAt: string;
        signedAt: string;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.txId).toBe(b1.data.txId);
    expect(body.data.executionRef).toBe(ref);
    expect(body.data.status).toBe("signed");
    expect(body.data.txHash).toBe(b1.data.txHash);
    expect(body.data.chainId).toBe(84532);
    expect(typeof body.data.createdAt).toBe("string");
    expect(typeof body.data.signedAt).toBe("string");

    const missing = await app.request(`/vault/${AGENT_A}/actions/by-ref/does-not-exist`, {
      headers: headers(TENANT_A, keyA),
    });
    expect(missing.status).toBe(404);
    const invalid = await app.request(
      `/vault/${AGENT_A}/actions/by-ref/${encodeURIComponent("bad ref!")}`,
      {
        headers: headers(TENANT_A, keyA),
      },
    );
    expect(invalid.status).toBe(400);
    expect(signCalls).toHaveLength(1);
  });

  it("never leaks or collides across tenants", async () => {
    signCalls = [];
    const ref = "strata:intent-shared:step-1";
    const a = await sign(basePayload(ref));
    expect(a.status).toBe(200);
    const ba = (await a.json()) as { data: { txId: string } };

    // Tenant B cannot read tenant A's action (agent not in tenant B).
    const crossRead = await app.request(`/vault/${AGENT_A}/actions/by-ref/${ref}`, {
      headers: headers(TENANT_B, keyB),
    });
    expect(crossRead.status).toBe(404);
    // Tenant B cannot drive tenant A's agent at all.
    const crossSign = await sign(basePayload(ref), { tenant: TENANT_B, key: keyB });
    expect(crossSign.status).toBe(404);

    // The same reference string under tenant B's own agent is an independent action.
    const b = await sign(basePayload(ref), { tenant: TENANT_B, key: keyB, agent: AGENT_B });
    expect(b.status).toBe(200);
    const bb = (await b.json()) as { data: { txId: string } };
    expect(bb.data.txId).not.toBe(ba.data.txId);
    expect(signCalls).toHaveLength(2);
    expect(await rowsForRef(TENANT_A, AGENT_A, ref)).toHaveLength(1);
    expect(await rowsForRef(TENANT_B, AGENT_B, ref)).toHaveLength(1);

    const readB = await app.request(`/vault/${AGENT_B}/actions/by-ref/${ref}`, {
      headers: headers(TENANT_B, keyB),
    });
    expect(((await readB.json()) as { data: { txId: string } }).data.txId).toBe(bb.data.txId);
  });

  it("agent tokens cannot read another agent's reference", async () => {
    const { signAgentToken } = await import("@stwd/auth");
    const token = await signAgentToken({ agentId: AGENT_B, tenantId: TENANT_B }, "1h");
    const res = await app.request(`/vault/${AGENT_A}/actions/by-ref/strata:intent-shared:step-1`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect([401, 403, 404]).toContain(res.status);
  });
});
