/**
 * STRATA-1515 exec-gap-a: application proposal executor.
 *
 * PGLite in memory (or a LOCAL Postgres when EXECUTOR_PG_URL is set by the
 * integration wrapper). `vault.signTransaction` is replaced with a fake so no
 * key reaches an RPC and nothing is ever broadcast. Base Sepolia 84532 only.
 */
import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  applicationProposalExecutions,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT_ID = "exec-gap-a-tenant";
const BASE_SEPOLIA = 84532;
const TOKEN = `0x${"ab".repeat(20)}`;
const MINT_DATA = `0x40c10f19${"0".repeat(24)}${"cd".repeat(20)}${"0".repeat(63)}1`;

let app: Hono;
let tenantKey: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let signSpy: Mock<(request: SignRequest, options?: unknown) => Promise<string>>;
const signCalls: SignRequest[] = [];
let issued: { principal: { id: string }; credential: { keyId: string; secret: string } };
let walletId: string;
let counter = 0;

function tenantHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT_ID,
    "X-Steward-Key": tenantKey,
  };
}

function appHeaders(idempotencyKey?: string) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Application-Key-Id": issued.credential.keyId,
    "X-Steward-Application-Secret": issued.credential.secret,
    ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
  };
}

async function propose(chainId = BASE_SEPOLIA, value = "0"): Promise<string> {
  const n = ++counter;
  const prepare = await app.request("/application/transactions/prepare", {
    method: "POST",
    headers: appHeaders(`exec-gap-a:prepare:${n}`),
    body: JSON.stringify({
      walletId,
      network: { type: "evm", chainId },
      transaction: { to: TOKEN, value, data: MINT_DATA },
    }),
  });
  expect(prepare.status).toBe(201);
  const prepared = (await prepare.json()) as { data: { preparedTransaction: { id: string } } };
  const proposed = await app.request("/application/transactions/propose", {
    method: "POST",
    headers: appHeaders(`exec-gap-a:propose:${n}`),
    body: JSON.stringify({ preparedTransactionId: prepared.data.preparedTransaction.id }),
  });
  expect(proposed.status).toBe(202);
  return ((await proposed.json()) as { data: { proposal: { id: string } } }).data.proposal.id;
}

function execute(proposalId: string, headers: Record<string, string> = tenantHeaders()) {
  return app.request(`/vault/application-proposals/${proposalId}/execute`, {
    method: "POST",
    headers,
    body: "{}",
  });
}

async function readProposal(proposalId: string) {
  const res = await app.request(`/application/transactions/proposals/${proposalId}`, {
    headers: appHeaders(),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { data: { proposal: any } }).data.proposal;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "exec-gap-a-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "exec-gap-a-audit-key-32-bytes-minimum-aaaaaaaa";
  // Synthetic, never dialled: signTransaction is replaced below.
  process.env.RPC_URL_84532 = "https://exec-gap-a-sepolia.invalid/v2/UNUSED";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const key = generateApiKey();
  tenantKey = key.key;
  await db.insert(tenants).values({ id: TENANT_ID, name: "exec-gap-a", apiKeyHash: key.hash });
  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));

  signSpy = spyOn(vault, "signTransaction").mockImplementation(
    async (request: SignRequest, options: unknown = {}) => {
      signCalls.push(request);
      const opts = options as { txId?: string };
      const hash = `0x${signCalls.length.toString(16).padStart(64, "0")}`;
      await getDb()
        .update(transactions)
        .set({ status: "signed", txHash: hash, signedAt: new Date() })
        .where(eq(transactions.id, opts.txId ?? ""));
      return hash;
    },
  );

  const res = await app.request("/application-principals", {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      name: "Strata exec-gap-a",
      capabilities: [
        "wallet:ensure",
        "wallet:address:read",
        "transaction:prepare",
        "transaction:propose",
        "transaction:proposal:read",
      ],
      resources: [{ kind: "wallet_owner", id: "party_exec_gap_a" }],
      expiresAt: "2030-01-01T00:00:00.000Z",
      credentialExpiresAt: "2029-01-01T00:00:00.000Z",
    }),
  });
  expect(res.status).toBe(201);
  issued = ((await res.json()) as { data: typeof issued }).data;
  const ensure = await app.request("/application/wallets/ensure", {
    method: "POST",
    headers: appHeaders("exec-gap-a:ensure"),
    body: JSON.stringify({ resourceId: "party_exec_gap_a" }),
  });
  expect(ensure.status).toBe(201);
  walletId = ((await ensure.json()) as { data: { wallet: { id: string } } }).data.wallet.id;
}, 120000);

afterAll(async () => {
  signSpy?.mockRestore();
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "RPC_URL_84532",
  ])
    delete process.env[k];
});

describe.serial("STRATA-1515 application proposal executor", () => {
  it("before execution the read model stays proposal-only with unknown evidence", async () => {
    const proposalId = await propose();
    const proposal = await readProposal(proposalId);
    expect(proposal.terminal).toBe(false);
    expect(proposal.executionEvidence).toEqual({
      status: "unknown",
      evidence: null,
      reason: "no_canonical_execution_linkage",
    });
  });

  it("policy -> vault broadcast -> linkage; read model reports the recorded txHash on 84532", async () => {
    signCalls.length = 0;
    const proposalId = await propose();
    const res = await execute(proposalId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: any };
    expect(body.data).toMatchObject({
      kind: "executed",
      proposalId,
      chainId: BASE_SEPOLIA,
      replay: false,
    });
    expect(body.data.txHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signCalls).toHaveLength(1);
    expect(signCalls[0]).toMatchObject({
      chainId: BASE_SEPOLIA,
      to: TOKEN,
      value: "0",
      data: MINT_DATA,
      broadcast: true,
      executionRef: `application-proposal:${proposalId}`,
    });

    const [linkage] = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.proposalId, proposalId));
    expect(linkage).toMatchObject({ chainId: BASE_SEPOLIA, txHash: body.data.txHash });

    const proposal = await readProposal(proposalId);
    expect(proposal.terminal).toBe(true);
    expect(proposal.executionEvidence.status).toBe("executed");
    expect(proposal.executionEvidence.evidence).toMatchObject({
      txHash: body.data.txHash,
      chainId: BASE_SEPOLIA,
      transaction: { to: TOKEN, value: "0", data: MINT_DATA },
    });
  });

  it("repeated and concurrent executes never sign twice", async () => {
    signCalls.length = 0;
    const proposalId = await propose();
    const results = await Promise.all([
      execute(proposalId),
      execute(proposalId),
      execute(proposalId),
    ]);
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 200).length).toBeGreaterThanOrEqual(1);
    const again = await execute(proposalId);
    expect(again.status).toBe(200);
    expect(((await again.json()) as { data: any }).data.replay).toBe(true);
    expect(signCalls).toHaveLength(1);
  });

  it("refuses any chain other than Base Sepolia 84532 before reservation or signing", async () => {
    signCalls.length = 0;
    const proposalId = await propose(8453);
    const res = await execute(proposalId);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { data: { code: string } }).data.code).toBe("chain_not_admitted");
    expect(signCalls).toHaveLength(0);
    const rows = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.executionRef, `application-proposal:${proposalId}`));
    expect(rows).toHaveLength(0);
    expect((await readProposal(proposalId)).executionEvidence.status).toBe("unknown");
  });

  it("application credentials cannot reach the executor", async () => {
    signCalls.length = 0;
    const proposalId = await propose();
    const res = await execute(proposalId, appHeaders());
    expect(res.status).toBe(403);
    expect(signCalls).toHaveLength(0);
  });

  it("unknown or malformed proposal ids are refused without signing", async () => {
    signCalls.length = 0;
    expect((await execute(`atp_${"0".repeat(40)}`)).status).toBe(404);
    expect((await execute("not-a-proposal")).status).toBe(400);
    expect(signCalls).toHaveLength(0);
  });

  it("manual-approval policy queues for a human approver, then execute reconciles the txHash", async () => {
    signCalls.length = 0;
    const proposalId = await propose(BASE_SEPOLIA, "5");
    const executions = await getDb().select().from(applicationProposalExecutions);
    const [wallet] = await getDb()
      .select({ agentId: transactions.agentId })
      .from(transactions)
      .where(eq(transactions.id, executions[0]!.transactionId));
    await getDb()
      .insert(policies)
      .values({
        id: `pol_exec_gap_a_${counter}`,
        agentId: wallet!.agentId,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "1" },
      });
    const queued = await execute(proposalId);
    expect(queued.status).toBe(202);
    const queuedBody = (await queued.json()) as { data: any };
    expect(queuedBody.data.kind).toBe("pending_approval");
    expect(signCalls).toHaveLength(0);
    expect((await readProposal(proposalId)).executionEvidence.status).toBe("unknown");

    // Simulate the human approver path having broadcast (existing approve route).
    const fakeHash = `0x${"e1".repeat(32)}`;
    await getDb()
      .update(transactions)
      .set({ status: "signed", txHash: fakeHash, signedAt: new Date() })
      .where(eq(transactions.id, queuedBody.data.transactionId));
    const reconciled = await execute(proposalId);
    expect(reconciled.status).toBe(200);
    expect(((await reconciled.json()) as { data: any }).data).toMatchObject({
      kind: "executed",
      txHash: fakeHash,
      replay: true,
    });
    expect(signCalls).toHaveLength(0);
    expect((await readProposal(proposalId)).executionEvidence.evidence.txHash).toBe(fakeHash);
  });
});
