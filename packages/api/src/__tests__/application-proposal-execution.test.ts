/**
 * STRATA-1515 exec gap (option A): an approved application proposal is signed
 * and broadcast by Steward through the policy engine and the application
 * boundary, exactly once.
 *
 * In-memory PGLite. The vault's `broadcastEvm` seam is stubbed, so the REAL
 * signTransaction path runs (agent lookup, protected posture, RPC preflight,
 * key decrypt, row upsert) and no RPC is ever contacted.
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import {
  agents,
  applicationExecutorSigners,
  applicationProposalExecutions,
  applicationWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "exec-gap-a";
const OTHER_TENANT = "exec-gap-a-other";
const SIGNER = "exec-gap-a-minter";
const TOKEN = "0x7045ee8bcd2f2bd5f04622829334faeb6129971b";
const OTHER_TOKEN = "0x00000000000000000000000000000000000000c0";
const CHAIN = 84532;
const ADMIN_USER = crypto.randomUUID();
const SECOND_ADMIN_USER = crypto.randomUUID();
const OWNER_USER = crypto.randomUUID();
const MEMBER_USER = crypto.randomUUID();
const OTHER_ADMIN_USER = crypto.randomUUID();
const FAR = "2030-01-01T00:00:00.000Z";
const CRED_FAR = "2029-01-01T00:00:00.000Z";
const MINT_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let tenantKey: string;
let otherTenantKey: string;
let adminToken: string;
let secondAdminToken: string;
let ownerToken: string;
let memberToken: string;
let otherAdminToken: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let policyEngine: Awaited<typeof import("../services/context")>["policyEngine"];
let executionsModule: typeof import("../services/application-executions");
const sent: Array<{ to: string; data?: string; chainId: number; value: bigint }> = [];
let broadcastImpl: () => Promise<`0x${string}`>;

type Issued = { principal: { id: string }; credential: { keyId: string; secret: string } };

const tenantHeaders = (tenant = TENANT, key = tenantKey) => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": tenant,
  "X-Steward-Key": key,
});
const bearer = (token: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${token}`,
});
const appHeaders = (issued: Issued, idem?: string) => ({
  "Content-Type": "application/json",
  "X-Steward-Application-Key-Id": issued.credential.keyId,
  "X-Steward-Application-Secret": issued.credential.secret,
  ...(idem ? { "Idempotency-Key": idem } : {}),
});

let counter = 0;
const next = () => `${Date.now()}-${++counter}`;

async function issuePrincipal(
  owner: string,
  expiresAt = FAR,
  credentialExpiresAt = CRED_FAR,
): Promise<Issued> {
  const r = await app.request("/application-principals", {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      name: `exec ${owner}`,
      capabilities: [
        "wallet:ensure",
        "wallet:address:read",
        "transaction:prepare",
        "transaction:propose",
        "transaction:proposal:read",
      ],
      resources: [{ kind: "wallet_owner", id: owner }],
      expiresAt,
      credentialExpiresAt,
    }),
  });
  expect(r.status).toBe(201);
  return ((await r.json()) as { data: Issued }).data;
}

async function ensureWallet(issued: Issued, owner: string) {
  const r = await app.request("/application/wallets/ensure", {
    method: "POST",
    headers: appHeaders(issued, `ensure:${next()}`),
    body: JSON.stringify({ resourceId: owner }),
  });
  expect(r.status).toBe(201);
  return ((await r.json()) as { data: { wallet: { id: string; addresses: { evm: string } } } }).data
    .wallet;
}

async function propose(
  issued: Issued,
  walletId: string,
  opts: {
    to?: string;
    recipient: string;
    amount?: bigint;
    value?: string;
    data?: string;
    chainId?: number;
  },
) {
  const data =
    opts.data ??
    encodeFunctionData({
      abi: MINT_ABI,
      functionName: "mint",
      args: [opts.recipient as `0x${string}`, opts.amount ?? 10n ** 18n],
    });
  const prepared = await app.request("/application/transactions/prepare", {
    method: "POST",
    headers: appHeaders(issued, `prepare:${next()}`),
    body: JSON.stringify({
      walletId,
      network: { type: "evm", chainId: opts.chainId ?? CHAIN },
      transaction: { to: opts.to ?? TOKEN, value: opts.value ?? "0", data },
    }),
  });
  expect(prepared.status).toBe(201);
  const preparedId = ((await prepared.json()) as { data: { preparedTransaction: { id: string } } })
    .data.preparedTransaction.id;
  const proposed = await app.request("/application/transactions/propose", {
    method: "POST",
    headers: appHeaders(issued, `propose:${next()}`),
    body: JSON.stringify({ preparedTransactionId: preparedId }),
  });
  expect(proposed.status).toBe(202);
  return ((await proposed.json()) as { data: { proposal: { id: string } } }).data.proposal.id;
}

async function bind(
  principalId: string,
  targets = [TOKEN],
  signer = SIGNER,
  token = adminToken,
  chainId: number = CHAIN,
) {
  return app.request(`/application-principals/${principalId}/executor-signers`, {
    method: "POST",
    headers: bearer(token),
    body: JSON.stringify({ chainId, signerAgentId: signer, allowedTargets: targets }),
  });
}

async function executionRows(proposalId: string) {
  return getDb()
    .select()
    .from(applicationProposalExecutions)
    .where(eq(applicationProposalExecutions.proposalId, proposalId));
}

async function reservationRows(proposalId: string) {
  return getDb()
    .select()
    .from(transactions)
    .where(eq(transactions.executionRef, `application-proposal:${proposalId}`));
}

async function createAgent(id: string, tenant = TENANT, key = tenantKey) {
  const r = await app.request("/agents", {
    method: "POST",
    headers: tenantHeaders(tenant, key),
    body: JSON.stringify({ id, name: id }),
  });
  expect(r.status).toBe(200);
}

function execute(principalId: string, proposalId: string, headers: Record<string, string>) {
  return app.request(`/application-principals/${principalId}/proposals/${proposalId}/execute`, {
    method: "POST",
    headers,
  });
}

async function readProposal(issued: Issued, proposalId: string) {
  const r = await app.request(`/application/transactions/proposals/${proposalId}`, {
    headers: appHeaders(issued),
  });
  expect(r.status).toBe(200);
  return ((await r.json()) as { data: { proposal: any } }).data.proposal;
}

/** One fully wired principal: wallet, binding, open mint proposal to its own wallet. */
async function scenario(owner: string, targets = [TOKEN]) {
  const issued = await issuePrincipal(owner);
  const wallet = await ensureWallet(issued, owner);
  expect((await bind(issued.principal.id, targets)).status).toBe(201);
  const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
  return { issued, wallet, proposalId };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "exec-gap-a-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "exec-gap-a-audit-key-32-bytes-minimum-aaaaaaa";
  process.env.STEWARD_JWT_SECRET = "exec-gap-a-jwt-secret-with-enough-bytes-aaaaaa";
  process.env.RPC_URL_84532 = "https://exec-gap-a-sepolia.invalid/v2/UNUSED";
  process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = String(CHAIN);

  const created = await createPGLiteDb("memory://");
  setPGLiteOverride(created.db, async () => created.client.close());
  const k = generateApiKey();
  const k2 = generateApiKey();
  tenantKey = k.key;
  otherTenantKey = k2.key;
  await created.db.insert(tenants).values([
    { id: TENANT, name: "Exec gap A", apiKeyHash: k.hash },
    { id: OTHER_TENANT, name: "Other", apiKeyHash: k2.hash },
  ]);
  await created.db.insert(users).values(
    [ADMIN_USER, SECOND_ADMIN_USER, OWNER_USER, MEMBER_USER, OTHER_ADMIN_USER].map((id) => ({
      id,
      email: `${id}@x.test`,
    })),
  );
  await created.db.insert(userTenants).values([
    { userId: ADMIN_USER, tenantId: TENANT, role: "admin" },
    { userId: SECOND_ADMIN_USER, tenantId: TENANT, role: "admin" },
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: MEMBER_USER, tenantId: TENANT, role: "member" },
    { userId: OTHER_ADMIN_USER, tenantId: OTHER_TENANT, role: "admin" },
  ]);

  ({ app } = await import("../app"));
  ({ vault, policyEngine } = await import("../services/context"));
  executionsModule = await import("../services/application-executions");
  adminToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: ADMIN_USER } as never,
    "1h",
  );
  memberToken = await signAccessToken(
    { address: `0x${"2".repeat(40)}`, tenantId: TENANT, userId: MEMBER_USER } as never,
    "1h",
  );
  secondAdminToken = await signAccessToken(
    { address: `0x${"3".repeat(40)}`, tenantId: TENANT, userId: SECOND_ADMIN_USER } as never,
    "1h",
  );
  ownerToken = await signAccessToken(
    { address: `0x${"4".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  otherAdminToken = await signAccessToken(
    { address: `0x${"5".repeat(40)}`, tenantId: OTHER_TENANT, userId: OTHER_ADMIN_USER } as never,
    "1h",
  );

  const r = await app.request("/agents", {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({ id: SIGNER, name: SIGNER }),
  });
  expect(r.status).toBe(200);

  broadcastImpl = async () => `0x${(sent.length + 0xabc).toString(16).padStart(64, "0")}`;
  spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _client: unknown,
    tx: { to: string; data?: string; chainId: number; value: bigint },
  ) => {
    sent.push(tx);
    return broadcastImpl();
  }) as never);
}, 120_000);

afterAll(async () => {
  await closeDb();
  for (const key of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL_84532",
    "STEWARD_APPLICATION_EXECUTION_CHAIN_IDS",
  ])
    delete process.env[key];
});

describe.serial("application proposal execution (STRATA-1515 exec gap A)", () => {
  it("signs and broadcasts the exact stored mint once, through policy, and exposes canonical evidence", async () => {
    const { issued, wallet, proposalId } = await scenario("party_inv_happy");
    const before = await readProposal(issued, proposalId);
    expect(before.executionEvidence).toEqual({
      status: "unknown",
      evidence: null,
      reason: "no_canonical_execution_linkage",
    });

    const sentBefore = sent.length;
    const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(r.status).toBe(201);
    const body = (await r.json()) as { data: { execution: any; replay: boolean } };
    expect(body.data.replay).toBe(false);
    expect(body.data.execution.status).toBe("broadcast");
    expect(body.data.execution.txHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(body.data.execution.approvedBy).toBe(`user:${ADMIN_USER}`);
    expect(sent.length).toBe(sentBefore + 1);
    const tx = sent.at(-1)!;
    expect(tx.to.toLowerCase()).toBe(TOKEN);
    expect(tx.value).toBe(0n);
    expect(tx.chainId).toBe(CHAIN);
    expect(tx.data).toBe(
      encodeFunctionData({
        abi: MINT_ABI,
        functionName: "mint",
        args: [wallet.addresses.evm as `0x${string}`, 10n ** 18n],
      }).toLowerCase(),
    );

    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.execution.transactionId));
    expect(row).toMatchObject({
      agentId: SIGNER,
      tenantId: TENANT,
      status: "broadcast",
      executionRef: `application-proposal:${proposalId}`,
      txHash: body.data.execution.txHash,
    });

    const after = await readProposal(issued, proposalId);
    expect(after.status).toBe("proposed");
    expect(after.terminal).toBe(false);
    expect(after.executionEvidence).toEqual({
      status: "broadcast",
      reason: null,
      evidence: {
        executionId: body.data.execution.id,
        network: { namespace: "eip155", chainId: CHAIN },
        txHash: body.data.execution.txHash,
        to: TOKEN,
        call: {
          function: "mint(address,uint256)",
          recipient: wallet.addresses.evm.toLowerCase(),
          amount: (10n ** 18n).toString(),
        },
      },
    });

    // Replay never signs again.
    const replay = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(replay.status).toBe(200);
    const replayBody = (await replay.json()) as { data: { execution: any; replay: boolean } };
    expect(replayBody.data.replay).toBe(true);
    expect(replayBody.data.execution.txHash).toBe(body.data.execution.txHash);
    expect(sent.length).toBe(sentBefore + 1);

    const audits = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT), eq(auditEvents.resourceId, proposalId)));
    expect(audits.map((a) => a.action)).toContain("application.transaction_proposal.execute");
  });

  it("concurrent executes of one proposal broadcast exactly once", async () => {
    const { issued, proposalId } = await scenario("party_inv_race");
    const sentBefore = sent.length;
    const results = await Promise.all(
      Array.from({ length: 5 }, () => execute(issued.principal.id, proposalId, bearer(adminToken))),
    );
    // Exactly one request performs the broadcast (201). The rest are replays:
    // 200 if they read the finished row, 202 if they read it still executing.
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    for (const s of statuses) expect([200, 201, 202]).toContain(s);
    const bodies = (await Promise.all(results.map((r) => r.json()))) as Array<{
      data: { replay: boolean; execution: { status: string } };
    }>;
    expect(bodies.filter((b) => !b.data.replay)).toHaveLength(1);
    for (const b of bodies) expect(["executing", "broadcast"]).toContain(b.data.execution.status);
    expect(sent.length).toBe(sentBefore + 1);
    const rows = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.proposalId, proposalId));
    expect(rows).toHaveLength(1);
  });

  it("only a human owner/admin session may bind or execute; application and tenant keys cannot", async () => {
    const issued = await issuePrincipal("party_inv_authz");
    const wallet = await ensureWallet(issued, "party_inv_authz");
    for (const headers of [tenantHeaders(), bearer(memberToken)]) {
      const r = await app.request(
        `/application-principals/${issued.principal.id}/executor-signers`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({ chainId: CHAIN, signerAgentId: SIGNER, allowedTargets: [TOKEN] }),
        },
      );
      expect(r.status).toBe(403);
    }
    expect((await bind(issued.principal.id)).status).toBe(201);
    // The binding is immutable.
    expect((await bind(issued.principal.id, [OTHER_TOKEN])).status).toBe(409);
    const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
    const sentBefore = sent.length;
    for (const headers of [
      tenantHeaders(),
      bearer(memberToken),
      appHeaders(issued),
      tenantHeaders(OTHER_TENANT, otherTenantKey),
    ]) {
      const r = await execute(issued.principal.id, proposalId, headers);
      expect([403, 404]).toContain(r.status);
    }
    expect(sent.length).toBe(sentBefore);
    // There is no execute route on the application namespace at all.
    const viaApp = await app.request(`/application/transactions/proposals/${proposalId}/execute`, {
      method: "POST",
      headers: appHeaders(issued),
    });
    expect(viaApp.status).toBe(404);
    expect(sent.length).toBe(sentBefore);
  });

  it("refuses a revoked principal with no reservation and no broadcast", async () => {
    const { issued, proposalId } = await scenario("party_inv_revoked");
    const revoke = await app.request(`/application-principals/${issued.principal.id}/revoke`, {
      method: "POST",
      headers: tenantHeaders(),
    });
    expect(revoke.status).toBe(200);
    const sentBefore = sent.length;
    const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(r.status).toBe(409);
    expect(((await r.json()) as any).data.code).toBe("principal_revoked");
    expect(sent.length).toBe(sentBefore);
    const rows = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.proposalId, proposalId));
    expect(rows).toHaveLength(0);
  });

  it("refuses an expired principal (and therefore expired intent)", async () => {
    const soon = new Date(Date.now() + 2_500).toISOString();
    const issued = await issuePrincipal("party_inv_expired", soon, soon);
    const wallet = await ensureWallet(issued, "party_inv_expired");
    expect((await bind(issued.principal.id)).status).toBe(201);
    const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
    await Bun.sleep(3_000);
    const sentBefore = sent.length;
    const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(r.status).toBe(409);
    expect(((await r.json()) as any).data.code).toBe("principal_expired");
    expect(sent.length).toBe(sentBefore);
  });

  it("refuses shapes outside the exact mint-to-own-wallet contract", async () => {
    const issued = await issuePrincipal("party_inv_shape");
    const wallet = await ensureWallet(issued, "party_inv_shape");
    expect((await bind(issued.principal.id)).status).toBe(201);
    const cases: Array<[string, Parameters<typeof propose>[2]]> = [
      ["recipient_mismatch", { recipient: `0x${"de".repeat(20)}` }],
      ["target_not_allowed", { to: OTHER_TOKEN, recipient: wallet.addresses.evm }],
      ["intent_shape_refused", { value: "1", recipient: wallet.addresses.evm }],
      ["intent_call_refused", { data: "0xdeadbeef", recipient: wallet.addresses.evm }],
      ["amount_refused", { amount: 0n, recipient: wallet.addresses.evm }],
    ];
    const sentBefore = sent.length;
    for (const [code, opts] of cases) {
      const proposalId = await propose(issued, wallet.id, opts);
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect([403, 409]).toContain(r.status);
      expect(((await r.json()) as any).data.code, code).toBe(code);
    }
    expect(sent.length).toBe(sentBefore);
  });

  it("refuses chains the deployment has not enabled", async () => {
    const { issued, proposalId } = await scenario("party_inv_chain_off");
    process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = "";
    try {
      const sentBefore = sent.length;
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(r.status).toBe(403);
      expect(((await r.json()) as any).data.code).toBe("chain_not_enabled");
      expect(sent.length).toBe(sentBefore);
    } finally {
      process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = String(CHAIN);
    }
  });

  it("goes through the policy engine: a hard policy failure refuses before any reservation", async () => {
    const agent = "exec-gap-a-policy-signer";
    expect(
      (
        await app.request("/agents", {
          method: "POST",
          headers: tenantHeaders(),
          body: JSON.stringify({ id: agent, name: agent }),
        })
      ).status,
    ).toBe(200);
    const put = await app.request(`/agents/${agent}/policies`, {
      method: "PUT",
      headers: tenantHeaders(),
      body: JSON.stringify([
        {
          id: "allow-only-other",
          type: "approved-addresses",
          enabled: true,
          config: { mode: "whitelist", addresses: [OTHER_TOKEN] },
        },
      ]),
    });
    expect(put.status).toBe(200);
    const issued = await issuePrincipal("party_inv_policy");
    const wallet = await ensureWallet(issued, "party_inv_policy");
    expect((await bind(issued.principal.id, [TOKEN], agent)).status).toBe(201);
    const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
    const sentBefore = sent.length;
    const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(r.status).toBe(403);
    const body = (await r.json()) as any;
    expect(body.data.code).toBe("policy_rejected");
    expect(body.data.policyResults[0]).toMatchObject({ type: "approved-addresses", passed: false });
    expect(sent.length).toBe(sentBefore);
    const rows = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.proposalId, proposalId));
    expect(rows).toHaveLength(0);
  });

  it("refuses to bind an application wallet's own agent as the executor", async () => {
    const issued = await issuePrincipal("party_inv_selfsign");
    await ensureWallet(issued, "party_inv_selfsign");
    const [walletRow] = await getDb()
      .select({ agentId: applicationWallets.stewardAgentId })
      .from(applicationWallets)
      .where(eq(applicationWallets.resourceId, "party_inv_selfsign"));
    const agentId = walletRow!.agentId;
    const r = await bind(issued.principal.id, [TOKEN], agentId);
    expect(r.status).toBe(409);
    expect(((await r.json()) as any).data.code).toBe("signer_is_application_wallet");
  });

  it("an RPC failure after the vault is invoked is terminal indeterminate and never re-signed", async () => {
    const { issued, proposalId } = await scenario("party_inv_rpc_fail");
    broadcastImpl = async () => {
      throw new Error("upstream reset at https://exec-gap-a-sepolia.invalid/v2/UNUSED");
    };
    try {
      const sentBefore = sent.length;
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(r.status).toBe(202);
      const body = (await r.json()) as any;
      expect(body.data.execution.status).toBe("indeterminate");
      expect(body.data.execution.txHash).toBeNull();
      expect(body.data.execution.failureReason).not.toContain("exec-gap-a-sepolia.invalid");
      expect(sent.length).toBe(sentBefore + 1);
      const evidence = (await readProposal(issued, proposalId)).executionEvidence;
      expect(evidence).toEqual({
        status: "indeterminate",
        evidence: null,
        reason: "execution_outcome_indeterminate",
      });
      broadcastImpl = async () => `0x${"f".repeat(64)}`;
      const again = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(again.status).toBe(202);
      expect(((await again.json()) as any).data.replay).toBe(true);
      expect(sent.length).toBe(sentBefore + 1);
    } finally {
      broadcastImpl = async () => `0x${(sent.length + 0xabc).toString(16).padStart(64, "0")}`;
    }
  });

  it("the execution row is forward-only in the database", async () => {
    const [row] = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.status, "broadcast"));
    expect(row).toBeDefined();
    const refused = async (op: PromiseLike<unknown>) => {
      try {
        await op;
        return false;
      } catch {
        return true;
      }
    };
    expect(
      await refused(
        getDb()
          .update(applicationProposalExecutions)
          .set({ txHash: `0x${"0".repeat(64)}` })
          .where(eq(applicationProposalExecutions.id, row!.id)),
      ),
    ).toBe(true);
    expect(
      await refused(
        getDb()
          .update(applicationProposalExecutions)
          .set({ amount: "1" })
          .where(eq(applicationProposalExecutions.id, row!.id)),
      ),
    ).toBe(true);
    expect(
      await refused(
        getDb()
          .delete(applicationProposalExecutions)
          .where(eq(applicationProposalExecutions.id, row!.id)),
      ),
    ).toBe(true);
    const [still] = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.id, row!.id));
    expect(still).toEqual(row);
  });
  // ─── 84532 hard pin (prod-executor-38-finish) ────────────────────────────

  it("env allowlist can only narrow the 84532 pin, never widen it", () => {
    const ids = executionsModule.applicationExecutionChainIds;
    const env = (v: string | undefined) => ({ STEWARD_APPLICATION_EXECUTION_CHAIN_IDS: v });
    expect([...ids(env(undefined))]).toEqual([]);
    expect([...ids(env(""))]).toEqual([]);
    expect([...ids(env("8453"))]).toEqual([]);
    expect([...ids(env("1,10,137,11155111,8453"))]).toEqual([]);
    expect([...ids(env("8453, 84532 ,1"))]).toEqual([84532]);
    expect([...ids(env("84532"))]).toEqual([84532]);
    expect(() => ids(env("84532,base"))).toThrow();
    expect(executionsModule.APPLICATION_EXECUTION_CHAIN_ID).toBe(84532);
  });

  it("8453 and arbitrary chains are refused before any vault/key/RPC use, even when configured", async () => {
    const issued = await issuePrincipal("party_inv_pin");
    const wallet = await ensureWallet(issued, "party_inv_pin");
    expect((await bind(issued.principal.id)).status).toBe(201);
    const previousEnv = process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS;
    process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = `${CHAIN},8453,1,11155111,2147483647`;
    process.env.RPC_URL_8453 = "https://exec-gap-a-mainnet.invalid/v2/UNUSED";
    const rpcReady = spyOn(vault, "assertChainRpcReady");
    const sign = spyOn(vault, "signTransaction");
    const evaluate = spyOn(policyEngine, "evaluate");
    try {
      for (const chainId of [8453, 1, 11155111, 2147483647]) {
        const proposalId = await propose(issued, wallet.id, {
          recipient: wallet.addresses.evm,
          chainId,
        });
        const sentBefore = sent.length;
        const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
        expect(r.status, `chain ${chainId}`).toBe(403);
        expect(((await r.json()) as any).data.code).toBe("chain_not_permitted");
        expect(sent.length).toBe(sentBefore);
        expect(await executionRows(proposalId)).toHaveLength(0);
        expect(await reservationRows(proposalId)).toHaveLength(0);
        const evidence = (await readProposal(issued, proposalId)).executionEvidence;
        expect(evidence.status).toBe("unknown");
      }
      expect(rpcReady).not.toHaveBeenCalled();
      expect(sign).not.toHaveBeenCalled();
      expect(evaluate).not.toHaveBeenCalled();
    } finally {
      rpcReady.mockRestore();
      sign.mockRestore();
      evaluate.mockRestore();
      delete process.env.RPC_URL_8453;
      process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = previousEnv;
    }
  });

  it("a non-84532 executor-signer binding is refused at creation and writes nothing", async () => {
    const issued = await issuePrincipal("party_inv_pin_bind");
    process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = `${CHAIN},8453`;
    try {
      for (const chainId of [8453, 1, 10, 11155111]) {
        const r = await bind(issued.principal.id, [TOKEN], SIGNER, adminToken, chainId);
        expect(r.status, `chain ${chainId}`).toBe(403);
        expect(((await r.json()) as any).data.code).toBe("chain_not_permitted");
      }
      const rows = await getDb()
        .select()
        .from(applicationExecutorSigners)
        .where(eq(applicationExecutorSigners.principalId, issued.principal.id));
      expect(rows).toHaveLength(0);
      const denied = await getDb()
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT),
            eq(auditEvents.action, "application_principal.executor_signer.bind"),
            eq(auditEvents.resourceId, issued.principal.id),
          ),
        );
      expect(denied).toHaveLength(0);
      // The pinned chain still binds normally afterwards.
      expect((await bind(issued.principal.id)).status).toBe(201);
    } finally {
      process.env.STEWARD_APPLICATION_EXECUTION_CHAIN_IDS = String(CHAIN);
    }
  });

  it("the database refuses non-84532 binding and execution rows directly", async () => {
    const refused = async (op: PromiseLike<unknown>) => {
      try {
        await op;
        return false;
      } catch {
        return true;
      }
    };
    const issued = await issuePrincipal("party_inv_pin_db");
    for (const chainId of [8453, 1, 0, -1]) {
      expect(
        await refused(
          getDb()
            .insert(applicationExecutorSigners)
            .values({
              tenantId: TENANT,
              principalId: issued.principal.id,
              chainId,
              signerAgentId: SIGNER,
              allowedTargets: [TOKEN],
              createdBy: "test:direct-db",
            }),
        ),
        `binding chain ${chainId}`,
      ).toBe(true);
    }
    expect(
      await refused(
        getDb()
          .insert(applicationExecutorSigners)
          .values({
            tenantId: TENANT,
            principalId: issued.principal.id,
            chainId: CHAIN,
            signerAgentId: SIGNER,
            allowedTargets: [TOKEN],
            createdBy: "test:direct-db",
          }),
      ),
    ).toBe(false);
    // An existing 84532 binding cannot be re-pointed to 8453 (immutable).
    expect(
      await refused(
        getDb()
          .update(applicationExecutorSigners)
          .set({ chainId: 8453 })
          .where(eq(applicationExecutorSigners.principalId, issued.principal.id)),
      ),
    ).toBe(true);

    // Execution rows: copy a real broadcast row's identity onto 8453.
    const [row] = await getDb()
      .select()
      .from(applicationProposalExecutions)
      .where(eq(applicationProposalExecutions.status, "broadcast"));
    expect(row).toBeDefined();
    const wallet = await ensureWallet(issued, "party_inv_pin_db");
    const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
    const txId = crypto.randomUUID();
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: SIGNER,
        tenantId: TENANT,
        executionRef: `direct-db:${proposalId}`,
        status: "approved",
        toAddress: TOKEN,
        value: "0",
        chainId: 8453,
      });
    const base = {
      id: `ape_${"d".repeat(40)}`,
      tenantId: TENANT,
      principalId: issued.principal.id,
      proposalId,
      signerAgentId: SIGNER,
      transactionId: txId,
      executionRef: `direct-db:${proposalId}`,
      toAddress: TOKEN,
      recipientAddress: wallet.addresses.evm.toLowerCase(),
      amount: "1",
      approvedBy: "test:direct-db",
    };
    for (const chainId of [8453, 1]) {
      expect(
        await refused(
          getDb()
            .insert(applicationProposalExecutions)
            .values({ ...base, chainId }),
        ),
        `execution chain ${chainId}`,
      ).toBe(true);
    }
    expect(await executionRows(proposalId)).toHaveLength(0);
    // And an existing 84532 execution row can never be moved to 8453.
    expect(
      await refused(
        getDb()
          .update(applicationProposalExecutions)
          .set({ chainId: 8453 })
          .where(eq(applicationProposalExecutions.id, row!.id)),
      ),
    ).toBe(true);
  });

  // ─── identity, authority and separation ──────────────────────────────────

  it("agent tokens and other-tenant admins cannot bind or execute; owner sessions can", async () => {
    const { issued, proposalId } = await scenario("party_inv_authz2");
    const agentToken = await signAgentToken({ agentId: SIGNER, tenantId: TENANT });
    const sentBefore = sent.length;
    for (const token of [agentToken, otherAdminToken]) {
      const b = await bind(issued.principal.id, [OTHER_TOKEN], SIGNER, token);
      expect([401, 403, 404]).toContain(b.status);
      const r = await execute(issued.principal.id, proposalId, bearer(token));
      expect([401, 403, 404]).toContain(r.status);
    }
    expect(sent.length).toBe(sentBefore);
    expect(await executionRows(proposalId)).toHaveLength(0);
    const r = await execute(issued.principal.id, proposalId, bearer(ownerToken));
    expect(r.status).toBe(201);
    const body = (await r.json()) as any;
    expect(body.data.execution.approvedBy).toBe(`user:${OWNER_USER}`);
    expect(sent.length).toBe(sentBefore + 1);
  });

  it("requester and approver are separate identities; a later approver never re-signs or re-attributes", async () => {
    const { issued, proposalId } = await scenario("party_inv_separation");
    // The requester (application principal) has no route to approve/execute.
    for (const path of [
      `/application/transactions/proposals/${proposalId}/execute`,
      `/application/transactions/proposals/${proposalId}/approve`,
      `/application-principals/${issued.principal.id}/proposals/${proposalId}/execute`,
    ]) {
      const r = await app.request(path, { method: "POST", headers: appHeaders(issued) });
      expect([401, 403, 404]).toContain(r.status);
    }
    expect(await executionRows(proposalId)).toHaveLength(0);
    const sentBefore = sent.length;
    const first = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(first.status).toBe(201);
    const second = await execute(issued.principal.id, proposalId, bearer(secondAdminToken));
    expect(second.status).toBe(200);
    const secondBody = (await second.json()) as any;
    expect(secondBody.data.replay).toBe(true);
    expect(secondBody.data.execution.approvedBy).toBe(`user:${ADMIN_USER}`);
    expect(sent.length).toBe(sentBefore + 1);
    const [row] = await executionRows(proposalId);
    expect(row!.approvedBy).toBe(`user:${ADMIN_USER}`);
    expect(row!.approvedBy).not.toContain(issued.principal.id);
    // The prepared intent records the requester credential, distinct from the approver.
    const audits = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT), eq(auditEvents.resourceId, proposalId)));
    const actions = audits.map((a) => `${a.actorType}:${a.action}`);
    expect(actions).toContain("user:application.transaction_proposal.execute");
    expect(actions).toContain("user:application.transaction_proposal.execute.replay");
  });

  it("refuses cross-tenant, protected and application-wallet signers", async () => {
    // Cross-tenant signer: an agent that exists only in the other tenant.
    await createAgent("exec-gap-a-foreign-signer", OTHER_TENANT, otherTenantKey);
    const crossIssued = await issuePrincipal("party_inv_cross_signer");
    const cross = await bind(crossIssued.principal.id, [TOKEN], "exec-gap-a-foreign-signer");
    expect(cross.status).toBe(404);
    expect(((await cross.json()) as any).data.code).toBe("signer_not_found");

    // Protected (persisted marker) signer is refused at binding.
    await createAgent("exec-gap-a-protected-signer");
    await getDb()
      .update(agents)
      .set({ protected: true })
      .where(and(eq(agents.tenantId, TENANT), eq(agents.id, "exec-gap-a-protected-signer")));
    const protIssued = await issuePrincipal("party_inv_protected_signer");
    const prot = await bind(protIssued.principal.id, [TOKEN], "exec-gap-a-protected-signer");
    expect(prot.status).toBe(403);
    expect(((await prot.json()) as any).data.code).toBe("protected_signer_refused");

    // A signer that becomes protected after binding is refused at execution,
    // before any reservation or key use.
    await createAgent("exec-gap-a-later-protected");
    const lateIssued = await issuePrincipal("party_inv_later_protected");
    const lateWallet = await ensureWallet(lateIssued, "party_inv_later_protected");
    expect(
      (await bind(lateIssued.principal.id, [TOKEN], "exec-gap-a-later-protected")).status,
    ).toBe(201);
    const lateProposal = await propose(lateIssued, lateWallet.id, {
      recipient: lateWallet.addresses.evm,
    });
    await getDb()
      .update(agents)
      .set({ protected: true })
      .where(and(eq(agents.tenantId, TENANT), eq(agents.id, "exec-gap-a-later-protected")));
    const sentBefore = sent.length;
    const r = await execute(lateIssued.principal.id, lateProposal, bearer(adminToken));
    expect(r.status).toBe(403);
    expect(((await r.json()) as any).data.code).toBe("protected_signer_refused");
    expect(sent.length).toBe(sentBefore);
    expect(await executionRows(lateProposal)).toHaveLength(0);
    expect(await reservationRows(lateProposal)).toHaveLength(0);

    // Another principal's application wallet is also not a valid signer.
    const otherIssued = await issuePrincipal("party_inv_other_app_wallet");
    await ensureWallet(otherIssued, "party_inv_other_app_wallet");
    const [otherWallet] = await getDb()
      .select({ agentId: applicationWallets.stewardAgentId })
      .from(applicationWallets)
      .where(eq(applicationWallets.resourceId, "party_inv_other_app_wallet"));
    const victim = await issuePrincipal("party_inv_app_wallet_signer");
    const appWalletBind = await bind(victim.principal.id, [TOKEN], otherWallet!.agentId);
    expect(appWalletBind.status).toBe(409);
    expect(((await appWalletBind.json()) as any).data.code).toBe("signer_is_application_wallet");
  });

  it("cross-tenant execute of another tenant's proposal is indistinguishable from not found", async () => {
    const { issued, proposalId } = await scenario("party_inv_cross_exec");
    const sentBefore = sent.length;
    const r = await execute(issued.principal.id, proposalId, bearer(otherAdminToken));
    expect([403, 404]).toContain(r.status);
    const viaKey = await execute(
      issued.principal.id,
      proposalId,
      tenantHeaders(OTHER_TENANT, otherTenantKey),
    );
    expect([403, 404]).toContain(viaKey.status);
    expect(sent.length).toBe(sentBefore);
    expect(await executionRows(proposalId)).toHaveLength(0);
  });

  // ─── pre-sign refusal, rejection and failure contracts ──────────────────

  it("a pre-sign failure leaves no reservation, so a later approval can still execute exactly once", async () => {
    const { issued, proposalId } = await scenario("party_inv_presign");
    const sentBefore = sent.length;

    const rpc = spyOn(vault, "assertChainRpcReady").mockImplementation(() => {
      throw new Error("RPC endpoint not configured for chainId 84532");
    });
    try {
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(r.status).toBe(500);
      expect(((await r.json()) as any).data.code).toBe("rpc_not_ready");
    } finally {
      rpc.mockRestore();
    }
    expect(await executionRows(proposalId)).toHaveLength(0);
    expect(await reservationRows(proposalId)).toHaveLength(0);

    const evaluate = spyOn(policyEngine, "evaluate").mockImplementationOnce(async () => {
      throw new Error("transient policy evaluation failure");
    });
    try {
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(r.status).toBe(500);
    } finally {
      evaluate.mockRestore();
    }
    expect(await executionRows(proposalId)).toHaveLength(0);
    expect(await reservationRows(proposalId)).toHaveLength(0);
    expect(sent.length).toBe(sentBefore);
    expect((await readProposal(issued, proposalId)).executionEvidence.status).toBe("unknown");

    const ok = await execute(issued.principal.id, proposalId, bearer(adminToken));
    expect(ok.status).toBe(201);
    expect(sent.length).toBe(sentBefore + 1);
    expect(await executionRows(proposalId)).toHaveLength(1);
    expect(await reservationRows(proposalId)).toHaveLength(1);
  });

  it("a policy rejection is a recorded denial with no execution state and unknown evidence", async () => {
    const agent = "exec-gap-a-policy-reject-2";
    await createAgent(agent);
    expect(
      (
        await app.request(`/agents/${agent}/policies`, {
          method: "PUT",
          headers: tenantHeaders(),
          body: JSON.stringify([
            {
              id: "allow-only-other-reject-contract",
              type: "approved-addresses",
              enabled: true,
              config: { mode: "whitelist", addresses: [OTHER_TOKEN] },
            },
          ]),
        })
      ).status,
    ).toBe(200);
    const issued = await issuePrincipal("party_inv_reject_contract");
    const wallet = await ensureWallet(issued, "party_inv_reject_contract");
    expect((await bind(issued.principal.id, [TOKEN], agent)).status).toBe(201);
    const proposalId = await propose(issued, wallet.id, { recipient: wallet.addresses.evm });
    for (let i = 0; i < 2; i++) {
      const r = await execute(issued.principal.id, proposalId, bearer(adminToken));
      expect(r.status).toBe(403);
      expect(((await r.json()) as any).data.code).toBe("policy_rejected");
    }
    expect(await executionRows(proposalId)).toHaveLength(0);
    expect(await reservationRows(proposalId)).toHaveLength(0);
    const read = await readProposal(issued, proposalId);
    expect(read.status).toBe("proposed");
    expect(read.terminal).toBe(false);
    expect(read.executionEvidence).toEqual({
      status: "unknown",
      evidence: null,
      reason: "no_canonical_execution_linkage",
    });
    const status = await app.request(
      `/application-principals/${issued.principal.id}/proposals/${proposalId}/execution`,
      { headers: tenantHeaders() },
    );
    expect(status.status).toBe(404);
    const denied = await getDb()
      .select()
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT),
          eq(auditEvents.resourceId, proposalId),
          eq(auditEvents.action, "application.transaction_proposal.execute.denied"),
        ),
      );
    expect(denied).toHaveLength(2);
    expect(denied.every((a) => a.actorType === "user" && a.actorId === ADMIN_USER)).toBe(true);
  });

  it("an ambiguous broadcast is a durable failure contract: indeterminate, failed reservation, zero retry", async () => {
    const { issued, proposalId } = await scenario("party_inv_ambiguous");
    broadcastImpl = async () => {
      throw new Error("socket hang up after send");
    };
    const sentBefore = sent.length;
    try {
      const results = await Promise.all(
        Array.from({ length: 3 }, () =>
          execute(issued.principal.id, proposalId, bearer(adminToken)),
        ),
      );
      for (const r of results) expect([202]).toContain(r.status);
    } finally {
      broadcastImpl = async () => `0x${(sent.length + 0xabc).toString(16).padStart(64, "0")}`;
    }
    expect(sent.length).toBe(sentBefore + 1);
    for (const token of [adminToken, secondAdminToken, ownerToken]) {
      const r = await execute(issued.principal.id, proposalId, bearer(token));
      expect(r.status).toBe(202);
      expect(((await r.json()) as any).data.replay).toBe(true);
    }
    expect(sent.length).toBe(sentBefore + 1);
    const [row] = await executionRows(proposalId);
    expect(row!.status).toBe("indeterminate");
    expect(row!.txHash).toBeNull();
    const [reservation] = await reservationRows(proposalId);
    expect(reservation!.status).toBe("failed");
    const status = await app.request(
      `/application-principals/${issued.principal.id}/proposals/${proposalId}/execution`,
      { headers: tenantHeaders() },
    );
    expect(status.status).toBe(200);
    expect(((await status.json()) as any).data.execution.status).toBe("indeterminate");
    // The DB forbids re-arming it into executing or claiming a hash later.
    let rearmed = false;
    try {
      await getDb()
        .update(applicationProposalExecutions)
        .set({ status: "broadcast", txHash: `0x${"a".repeat(64)}` })
        .where(eq(applicationProposalExecutions.id, row!.id));
      rearmed = true;
    } catch {}
    expect(rearmed).toBe(false);
  });
});
