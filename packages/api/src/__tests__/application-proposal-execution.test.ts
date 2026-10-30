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
import { generateApiKey, signAccessToken } from "@stwd/auth";
import {
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
const MEMBER_USER = crypto.randomUUID();
const FAR = "2030-01-01T00:00:00.000Z";
const CRED_FAR = "2029-01-01T00:00:00.000Z";
const MINT_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let tenantKey: string;
let otherTenantKey: string;
let adminToken: string;
let memberToken: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
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
  opts: { to?: string; recipient: string; amount?: bigint; value?: string; data?: string },
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
      network: { type: "evm", chainId: CHAIN },
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

async function bind(principalId: string, targets = [TOKEN], signer = SIGNER, token = adminToken) {
  return app.request(`/application-principals/${principalId}/executor-signers`, {
    method: "POST",
    headers: bearer(token),
    body: JSON.stringify({ chainId: CHAIN, signerAgentId: signer, allowedTargets: targets }),
  });
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
  await created.db
    .insert(users)
    .values([ADMIN_USER, MEMBER_USER].map((id) => ({ id, email: `${id}@x.test` })));
  await created.db.insert(userTenants).values([
    { userId: ADMIN_USER, tenantId: TENANT, role: "admin" },
    { userId: MEMBER_USER, tenantId: TENANT, role: "member" },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  adminToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: ADMIN_USER } as never,
    "1h",
  );
  memberToken = await signAccessToken(
    { address: `0x${"2".repeat(40)}`, tenantId: TENANT, userId: MEMBER_USER } as never,
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
    for (const r of results) expect([200, 201]).toContain(r.status);
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
});
