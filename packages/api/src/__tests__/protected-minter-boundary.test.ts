/**
 * STRATA-1499 (SF-1) — protected production-minter boundary, adversarial tests.
 *
 * Every test here is expected to FAIL on origin/develop (cacb3035) and pass
 * on feat/strata-1499-protected-minter. Runs on in-memory PGLite; the
 * vault's final EVM send is replaced by a fake that records exactly the bytes
 * it was asked to sign, so "one signature" is observable and no RPC is hit.
 *
 * Requirement map (brief items 1-10) is in the test names: `[R<n>]`.
 */

import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import {
  approvalQueue,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const AGENT = "prod-minter-canary";
const OTHER_AGENT = "ordinary-agent";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const UNVERIFIED_TOKEN = "0x0000000000000000000000000000000000700002";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const OWNER_USER = crypto.randomUUID();
const ADMIN_USER = crypto.randomUUID();
const MEMBER_USER = crypto.randomUUID();

const FACTORY_ABI = parseAbi([
  "function createDealToken(string name, string symbol, address admin, address minter, bytes32 salt) returns (address)",
]);
const OLD_FACTORY_ABI = parseAbi([
  "function createDealToken(string name, string symbol, address admin, bytes32 salt) returns (address)",
]);
const TOKEN_ABI = parseAbi([
  "function mint(address to, uint256 amount)",
  "function grantRole(bytes32 role, address account)",
  "function transfer(address to, uint256 amount)",
]);
const SALT = `0x${"11".repeat(32)}` as `0x${string}`;

let app: Hono;
let rootKey: string;
let signerAddress: string;
let ownerToken: string;
let adminToken: string;
let memberToken: string;
let agentJwt: string;
let otherAgentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let sendSpy: Mock<(...args: unknown[]) => Promise<unknown>>;
let signedBytes: Array<{ to: string; value: bigint; data?: string; chainId: number }> = [];
let refCounter = 0;

function ref() {
  refCounter += 1;
  return `strata:test:${refCounter}`;
}

const rootHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": TENANT,
  "X-Steward-Key": rootKey,
});
const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

function createCalldata(opts: { admin?: string; minter?: string; name?: string } = {}) {
  return encodeFunctionData({
    abi: FACTORY_ABI,
    functionName: "createDealToken",
    args: [
      opts.name ?? "Deal One",
      "DL1",
      (opts.admin ?? SAFE) as `0x${string}`,
      (opts.minter ?? signerAddress) as `0x${string}`,
      SALT,
    ],
  });
}
function mintCalldata(to = RECIPIENT, amount = 1000n * 10n ** 18n) {
  return encodeFunctionData({
    abi: TOKEN_ABI,
    functionName: "mint",
    args: [to as `0x${string}`, amount],
  });
}

async function sign(body: Record<string, unknown>, headers: Record<string, string>, agent = AGENT) {
  return app.request(`/vault/${agent}/sign`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}
async function approve(
  txId: string,
  headers: Record<string, string>,
  body: Record<string, unknown> = {},
  agent = AGENT,
) {
  return app.request(`/vault/${agent}/approve/${txId}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}
async function json<T = any>(r: Response): Promise<T> {
  return (await r.json()) as T;
}

/** Queue a valid proposal and return txId + reviewDigest. */
async function queueValid(data = mintCalldata(), to = TOKEN, executionRef = ref()) {
  const r = await sign({ to, value: "0", data, chainId: 8453, executionRef }, bearer(agentJwt));
  expect(r.status).toBe(202);
  const b = await json(r);
  expect(b.data.status).toBe("pending_approval");
  expect(b.data.reviewDigest).toStartWith("0x");
  return {
    txId: b.data.txId as string,
    reviewDigest: b.data.reviewDigest as string,
    executionRef,
    body: b,
  };
}

async function queueRow(txId: string) {
  const [q] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
  return q;
}
async function txRow(txId: string) {
  const [t] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
  return t;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "protected-minter-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "protected-minter-audit-key-32-bytes-minimum-aa";
  process.env.STEWARD_JWT_SECRET = "protected-minter-jwt-secret-with-enough-bytes-aaaa";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  rootKey = k.key;
  await db.insert(tenants).values({ id: TENANT, name: "Strata", apiKeyHash: k.hash });
  await db.insert(users).values([
    { id: OWNER_USER, email: `owner-${OWNER_USER}@example.test` },
    { id: ADMIN_USER, email: `admin-${ADMIN_USER}@example.test` },
    { id: MEMBER_USER, email: `member-${MEMBER_USER}@example.test` },
  ]);
  await db.insert(userTenants).values([
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: ADMIN_USER, tenantId: TENANT, role: "admin" },
    { userId: MEMBER_USER, tenantId: TENANT, role: "member" },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");

  // Create both agents with the root key BEFORE the manifest is installed
  // (mirrors "create reserved signer while posture is closed, then pin").
  for (const id of [AGENT, OTHER_AGENT]) {
    const r = await app.request("/agents", {
      method: "POST",
      headers: rootHeaders(),
      body: JSON.stringify({ id, name: id }),
    });
    if (r.status !== 200) throw new Error(`POST /agents ${id} → ${r.status}: ${await r.text()}`);
    if (id === AGENT) signerAddress = (await json(r)).data.walletAddress;
  }

  boundary.installProtectedMinterManifest({
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress,
    chainId: 8453,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:receipt:verified-by-human" }],
  });

  const mk = (userId: string) =>
    signAccessToken({ address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId } as never, "1h");
  ownerToken = await mk(OWNER_USER);
  adminToken = await mk(ADMIN_USER);
  memberToken = await mk(MEMBER_USER);
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");
  otherAgentJwt = await signAgentToken({ agentId: OTHER_AGENT, tenantId: TENANT }, "1h");

  // Fake the network send inside vault.signTransaction: the vault's final
  // `broadcastEvm` seam records exactly the bytes it was handed. Everything
  // before it (guards, key decryption, address pin) is real.
  sendSpy = spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _client: unknown,
    tx: { to: string; value: bigint; data?: string; chainId: number },
  ) => {
    signedBytes.push(tx);
    return `0x${signedBytes.length.toString(16).padStart(64, "0")}`;
  }) as never) as never;
});

afterAll(async () => {
  sendSpy?.mockRestore();
  boundary?.installProtectedMinterManifest(null);
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
  ])
    delete process.env[k];
});

describe.serial("STRATA-1499 protected production minter", () => {
  // ── R1: credential boundary ────────────────────────────────────────────────
  it("[R1] agent JWT cannot export/import/policy-PUT/delete/approve", async () => {
    const h = bearer(agentJwt);
    expect(
      (await app.request(`/vault/${AGENT}/export`, { method: "POST", headers: h })).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/vault/${AGENT}/import`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ privateKey: "0x" + "22".repeat(32), chain: "evm" }),
        })
      ).status,
    ).toBe(403);
    expect(
      (await app.request(`/agents/${AGENT}/policies`, { method: "PUT", headers: h, body: "[]" }))
        .status,
    ).toBe(403);
    expect((await app.request(`/agents/${AGENT}`, { method: "DELETE", headers: h })).status).toBe(
      403,
    );
    const { txId, reviewDigest } = await queueValid();
    expect((await approve(txId, h, { reviewDigest })).status).toBe(403);
    expect(
      (await app.request(`/approvals/${txId}/approve`, { method: "POST", headers: h, body: "{}" }))
        .status,
    ).toBe(403);
    expect((await queueRow(txId))?.status).toBe("pending");
    expect(signedBytes).toHaveLength(0);
  });

  it("[R1] tenant root API key cannot export/import/policy/delete/sign/approve for the protected signer", async () => {
    const h = rootHeaders();
    const exportRes = await app.request(`/vault/${AGENT}/export`, { method: "POST", headers: h });
    expect(exportRes.status).toBe(403);
    expect(
      (
        await app.request(`/vault/${AGENT}/import`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ privateKey: "0x" + "22".repeat(32), chain: "evm" }),
        })
      ).status,
    ).toBe(403);
    expect(
      (await app.request(`/agents/${AGENT}/policies`, { method: "PUT", headers: h, body: "[]" }))
        .status,
    ).toBe(403);
    expect((await app.request(`/agents/${AGENT}`, { method: "DELETE", headers: h })).status).toBe(
      403,
    );
    const signRes = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef: ref() },
      h,
    );
    expect(signRes.status).toBe(403);
    const { txId, reviewDigest } = await queueValid();
    expect((await approve(txId, h, { reviewDigest })).status).toBe(403);
    expect(
      (await app.request(`/approvals/${txId}/approve`, { method: "POST", headers: h, body: "{}" }))
        .status,
    ).toBe(403);
    expect(
      (
        await app.request(`/approvals/${txId}/deny`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ reason: "x" }),
        })
      ).status,
    ).toBe(403);
    expect((await queueRow(txId))?.status).toBe("pending");
    expect((await txRow(txId))?.status).toBe("pending");
    expect(signedBytes).toHaveLength(0);
    // Unrelated agent keeps legacy root-key behaviour (regression guard).
    expect(
      (await app.request(`/vault/${OTHER_AGENT}/export`, { method: "POST", headers: h })).status,
    ).toBe(200);
  });

  it("[R1] human owner session also cannot export/import/delete/edit policy of the protected signer", async () => {
    const h = bearer(ownerToken);
    expect(
      (await app.request(`/vault/${AGENT}/export`, { method: "POST", headers: h })).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/vault/${AGENT}/import`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ privateKey: "0x" + "22".repeat(32), chain: "evm" }),
        })
      ).status,
    ).toBe(403);
    expect(
      (await app.request(`/agents/${AGENT}/policies`, { method: "PUT", headers: h, body: "[]" }))
        .status,
    ).toBe(403);
    expect((await app.request(`/agents/${AGENT}`, { method: "DELETE", headers: h })).status).toBe(
      403,
    );
  });

  // ── R2: manifest fixed outside the API ────────────────────────────────────
  it("[R2] no route changes the protected scope: policy PUT, template assign/apply, batch are refused and the manifest digest is unchanged", async () => {
    const before = boundary.getProtectedMinterManifestDigest();
    const h = bearer(ownerToken);
    const put = await app.request(`/agents/${AGENT}/policies`, {
      method: "PUT",
      headers: h,
      body: JSON.stringify([
        { type: "approved-addresses", enabled: true, config: { addresses: [UNVERIFIED_TOKEN] } },
      ]),
    });
    expect(put.status).toBe(403);
    const tpl = await app.request(`/policies`, {
      method: "POST",
      headers: h,
      body: JSON.stringify({
        name: "x",
        description: "x",
        rules: [
          { type: "approved-addresses", enabled: true, config: { addresses: [UNVERIFIED_TOKEN] } },
        ],
      }),
    });
    if (tpl.status === 200 || tpl.status === 201) {
      const id = (await json(tpl)).data.id;
      expect(
        (
          await app.request(`/policies/${id}/assign`, {
            method: "POST",
            headers: h,
            body: JSON.stringify({ agentIds: [AGENT] }),
          })
        ).status,
      ).toBe(403);
    }
    expect(
      (
        await app.request(`/tenants/${TENANT}/config/templates/conservative/apply`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ agentId: AGENT }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/agents/batch`, {
          method: "POST",
          headers: h,
          body: JSON.stringify({ agents: [{ id: AGENT, name: AGENT }] }),
        })
      ).status,
    ).toBe(403);
    const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT));
    expect(rows).toHaveLength(0);
    expect(boundary.getProtectedMinterManifestDigest()).toBe(before);
    const m = boundary.getProtectedMinterManifest()!;
    expect(m.safeAdmin).toBe(SAFE);
    expect(m.chainId).toBe(8453);
    expect(m.verifiedTokens[0]?.provenance).toContain("verified");
    // Unverified token with no provenance cannot be installed.
    expect(() =>
      boundary.validateManifest({
        ...m,
        verifiedTokens: [{ address: UNVERIFIED_TOKEN, provenance: "" }],
      }),
    ).toThrow();
    expect(() => boundary.validateManifest({ ...m, safeAdmin: RECIPIENT })).toThrow();
  });

  // ── R3: chain + value ─────────────────────────────────────────────────────
  it("[R3] chainId != 8453 or value != 0 refused at proposal", async () => {
    for (const body of [
      { chainId: 84532 },
      { chainId: 1 },
      { chainId: undefined },
      { chainId: "8453" },
      { value: "1" },
      { value: "-0" },
      { value: "0x0" },
      { value: "" },
    ]) {
      const r = await sign(
        {
          to: TOKEN,
          value: "0",
          data: mintCalldata(),
          chainId: 8453,
          executionRef: ref(),
          ...body,
        },
        bearer(agentJwt),
      );
      expect(r.status).toBe(403);
    }
    const q = await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT));
    expect(q.filter((x) => x.status === "pending").length).toBeGreaterThan(0);
    expect(signedBytes).toHaveLength(0);
  });

  it("[R3] chainId/value substituted in storage after queueing are refused at signing", async () => {
    const { txId, reviewDigest } = await queueValid();
    await getDb().update(transactions).set({ chainId: 84532 }).where(eq(transactions.id, txId));
    const r1 = await approve(txId, bearer(ownerToken), { reviewDigest });
    expect(r1.status).toBe(403);
    await getDb()
      .update(transactions)
      .set({ chainId: 8453, value: "1" })
      .where(eq(transactions.id, txId));
    const r2 = await approve(txId, bearer(ownerToken), { reviewDigest });
    expect(r2.status).toBe(403);
    expect((await queueRow(txId))?.status).toBe("pending");
    expect(signedBytes).toHaveLength(0);
  });

  // ── R4: createDealToken ───────────────────────────────────────────────────
  it("[R4] createDealToken: factory + Safe admin + own minter queues; every substitution/malformation is refused", async () => {
    const ok = await sign(
      { to: FACTORY, value: "0", data: createCalldata(), chainId: 8453, executionRef: ref() },
      bearer(agentJwt),
    );
    expect(ok.status).toBe(202);
    const okBody = await json(ok);
    expect(okBody.data.review.kind).toBe("createDealToken");
    expect(okBody.data.review.adminSafe).toBe(SAFE);
    expect(okBody.data.review.minter.toLowerCase()).toBe(signerAddress.toLowerCase());

    const bad: Array<[string, Record<string, unknown>]> = [
      ["admin != Safe", { data: createCalldata({ admin: RECIPIENT }) }],
      ["minter != signer", { data: createCalldata({ minter: RECIPIENT }) }],
      ["admin == minter == signer", { data: createCalldata({ admin: signerAddress }) }],
      [
        "old 4-arg ABI",
        {
          data: encodeFunctionData({
            abi: OLD_FACTORY_ABI,
            functionName: "createDealToken",
            args: ["Deal", "DL", SAFE, SALT],
          }),
        },
      ],
      ["trailing bytes", { data: `${createCalldata()}00` }],
      ["trailing word", { data: `${createCalldata()}${"00".repeat(32)}` }],
      ["truncated", { data: createCalldata().slice(0, -64) }],
      [
        "dirty admin padding",
        {
          data: (() => {
            const d = createCalldata();
            const i = 10 + 2 * 64;
            return d.slice(0, i) + "ff" + d.slice(i + 2);
          })(),
        },
      ],
      ["unapproved factory", { to: UNVERIFIED_TOKEN }],
      ["mint selector at factory", { data: mintCalldata() }],
      ["createDealToken selector at token", { to: TOKEN }],
      ["empty name", { data: createCalldata({ name: "" }) }],
    ];
    for (const [label, over] of bad) {
      const r = await sign(
        {
          to: FACTORY,
          value: "0",
          data: createCalldata(),
          chainId: 8453,
          executionRef: ref(),
          ...over,
        },
        bearer(agentJwt),
      );
      expect(r.status, label).toBe(403);
    }
    expect(signedBytes).toHaveLength(0);
  });

  // ── R5: mint ──────────────────────────────────────────────────────────────
  it("[R5] mint: verified token + canonical 68-byte calldata queues; any other selector/target refused", async () => {
    const ok = await queueValid();
    expect(ok.body.data.review.kind).toBe("mint");
    const bad: Array<[string, Record<string, unknown>]> = [
      ["unverified token", { to: UNVERIFIED_TOKEN }],
      [
        "grantRole",
        {
          data: encodeFunctionData({
            abi: TOKEN_ABI,
            functionName: "grantRole",
            args: [`0x${"00".repeat(32)}`, RECIPIENT],
          }),
        },
      ],
      [
        "transfer",
        {
          data: encodeFunctionData({
            abi: TOKEN_ABI,
            functionName: "transfer",
            args: [RECIPIENT, 1n],
          }),
        },
      ],
      ["native transfer (no data)", { data: undefined }],
      ["0x data", { data: "0x" }],
      ["selector only", { data: "0x40c10f19" }],
      ["trailing bytes", { data: `${mintCalldata()}00` }],
      [
        "dirty recipient padding",
        { data: `0x40c10f19${"ff"}${"00".repeat(11)}${RECIPIENT.slice(2)}${"00".repeat(31)}01` },
      ],
      ["zero recipient", { data: mintCalldata(`0x${"00".repeat(20)}`) }],
      ["zero amount", { data: mintCalldata(RECIPIENT, 0n) }],
      ["odd hex", { data: `${mintCalldata()}0` }],
      ["non-hex", { data: "0xzz" }],
      ["EOA / random target", { to: RECIPIENT }],
    ];
    for (const [label, over] of bad) {
      const r = await sign(
        {
          to: TOKEN,
          value: "0",
          data: mintCalldata(),
          chainId: 8453,
          executionRef: ref(),
          ...over,
        },
        bearer(agentJwt),
      );
      expect(r.status, label).toBe(403);
    }
    expect(signedBytes).toHaveLength(0);
  });

  // ── R6: queue + human CAS + digest + substitution ─────────────────────────
  it("[R6] every valid proposal queues (202), never auto-signs, regardless of policy rows", async () => {
    await getDb()
      .insert(policies)
      .values({
        id: crypto.randomUUID(),
        agentId: AGENT,
        type: "auto-approve-threshold",
        enabled: true,
        config: { maxValue: "1000000000000000000000" },
      });
    const { txId } = await queueValid();
    expect((await txRow(txId))?.status).toBe("pending");
    expect(signedBytes).toHaveLength(0);
    await getDb().delete(policies).where(eq(policies.agentId, AGENT));
  });

  it("[R6] member session, agent JWT, dashboard-less root key cannot approve; owner/admin can, exactly once, signing the exact bytes", async () => {
    const { txId, reviewDigest } = await queueValid();
    expect((await approve(txId, bearer(memberToken), { reviewDigest })).status).toBe(403);
    expect((await approve(txId, bearer(agentJwt), { reviewDigest })).status).toBe(403);
    expect((await approve(txId, rootHeaders(), { reviewDigest })).status).toBe(403);
    // no digest echoed → refused
    expect((await approve(txId, bearer(ownerToken), {})).status).toBe(400);
    // wrong digest echoed → refused
    expect(
      (await approve(txId, bearer(ownerToken), { reviewDigest: `0x${"ab".repeat(32)}` })).status,
    ).toBe(403);
    expect(signedBytes).toHaveLength(0);

    const before = await txRow(txId);
    const ok = await approve(txId, bearer(adminToken), { reviewDigest });
    expect(ok.status).toBe(200);
    expect(signedBytes).toHaveLength(1);
    expect(signedBytes[0]!.to.toLowerCase()).toBe(before!.toAddress.toLowerCase());
    expect(signedBytes[0]!.data?.toLowerCase()).toBe(before!.data!.toLowerCase());
    expect(signedBytes[0]!.value).toBe(0n);
    expect(signedBytes[0]!.chainId).toBe(8453);
    const q = await queueRow(txId);
    expect(q?.status).toBe("approved");
    expect(q?.approvedByUserId).toBe(ADMIN_USER);
    // second approval: consumed
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(409);
    expect(signedBytes).toHaveLength(1);
    signedBytes = [];
  });

  it("[R6] substitution after approval: payload swapped in storage is refused, nothing signed, digest rechecked", async () => {
    const { txId, reviewDigest } = await queueValid();
    // Attacker with DB write swaps the stored target/data to an unverified token.
    await getDb()
      .update(transactions)
      .set({ toAddress: UNVERIFIED_TOKEN })
      .where(eq(transactions.id, txId));
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(403);
    await getDb()
      .update(transactions)
      .set({ toAddress: TOKEN, data: mintCalldata(RECIPIENT, 999999n * 10n ** 18n) })
      .where(eq(transactions.id, txId));
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(403);
    // executionRef swap
    await getDb()
      .update(transactions)
      .set({ data: mintCalldata(), executionRef: "strata:swapped" })
      .where(eq(transactions.id, txId));
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(403);
    expect(signedBytes).toHaveLength(0);
    expect((await queueRow(txId))?.status).toBe("pending");
  });

  it("[R6] vault-level: signTransaction without a permit, or with a reused permit, never signs the protected agent", async () => {
    const { txId, reviewDigest } = await queueValid();
    const row = await txRow(txId);
    const req: SignRequest = {
      agentId: AGENT,
      tenantId: TENANT,
      to: row!.toAddress,
      value: row!.value,
      data: row!.data!,
      chainId: 8453,
      executionRef: row!.executionRef!,
      broadcast: true,
    };
    await expect(vault.signTransaction(req, { txId })).rejects.toThrow(/Protected signer/);
    await expect(
      vault.signTransaction(req, { txId, protectedReviewDigest: reviewDigest }),
    ).rejects.toThrow(/permit/);
    const { issueProtectedSigningPermit } = await import("@stwd/vault");
    // REVIEW-STEWARD-28: issuance itself verifies a consumed approval; a
    // pending queue row cannot yield a permit.
    await expect(
      issueProtectedSigningPermit({ tenantId: TENANT, agentId: AGENT, txId, reviewDigest }),
    ).rejects.toThrow(/no consumed approval/);
    // Simulate the CAS continuation having claimed the row, then issue.
    await getDb()
      .update(approvalQueue)
      .set({ status: "approved", resolvedAt: new Date(), resolvedBy: "test" })
      .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.status, "pending")));
    const permit = await issueProtectedSigningPermit({
      tenantId: TENANT,
      agentId: AGENT,
      txId,
      reviewDigest,
    });
    // Permit bound to digest A cannot sign different bytes B.
    await expect(
      vault.signTransaction(
        { ...req, data: mintCalldata(RECIPIENT, 5n) },
        { txId, protectedPermit: permit, protectedReviewDigest: reviewDigest },
      ),
    ).rejects.toThrow(/Protected signer/);
    // ...and is consumed by that failed attempt.
    await expect(
      vault.signTransaction(req, {
        txId,
        protectedPermit: permit,
        protectedReviewDigest: reviewDigest,
      }),
    ).rejects.toThrow(/permit/);
    expect(signedBytes).toHaveLength(0);
  });

  it("[R6] parallel approvals: at most one signature", async () => {
    signedBytes = [];
    const { txId, reviewDigest } = await queueValid();
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        approve(txId, bearer(i % 2 ? ownerToken : adminToken), { reviewDigest }),
      ),
    );
    const codes = results.map((r) => r.status).sort();
    expect(codes.filter((c) => c === 200)).toHaveLength(1);
    expect(codes.filter((c) => c === 409)).toHaveLength(5);
    expect(signedBytes).toHaveLength(1);
    signedBytes = [];
  });

  it("[R6] human-originated proposal cannot be approved by its own requester", async () => {
    const executionRef = ref();
    const r = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef },
      bearer(ownerToken),
    );
    expect(r.status).toBe(202);
    const { txId, reviewDigest } = (await json(r)).data;
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(403);
    expect((await approve(txId, bearer(adminToken), { reviewDigest })).status).toBe(200);
    signedBytes = [];
  });

  it("[R6] stale membership: owner removed from tenant cannot approve", async () => {
    const tmpUser = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({ id: tmpUser, email: `tmp-${tmpUser}@example.test` });
    await getDb().insert(userTenants).values({ userId: tmpUser, tenantId: TENANT, role: "owner" });
    const tok = await signAccessToken(
      { address: `0x${"2".repeat(40)}`, tenantId: TENANT, userId: tmpUser } as never,
      "1h",
    );
    const { txId, reviewDigest } = await queueValid();
    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.userId, tmpUser), eq(userTenants.tenantId, TENANT)));
    expect((await approve(txId, bearer(tok), { reviewDigest })).status).toBe(403);
    expect(signedBytes).toHaveLength(0);
  });

  it("[R6] manifest change invalidates pending reviews", async () => {
    const { txId, reviewDigest } = await queueValid();
    const m = boundary.getProtectedMinterManifest()!;
    boundary.installProtectedMinterManifest({
      ...m,
      verifiedTokens: [...m.verifiedTokens, { address: UNVERIFIED_TOKEN, provenance: "0xnew" }],
    });
    expect((await approve(txId, bearer(ownerToken), { reviewDigest })).status).toBe(403);
    boundary.installProtectedMinterManifest(m);
    expect(signedBytes).toHaveLength(0);
  });

  // ── R7: evidence ──────────────────────────────────────────────────────────
  it("[R7] pending GET exposes decoded fields to humans only; audit record carries review projection", async () => {
    const amount = 1234n * 10n ** 18n;
    const { txId, executionRef } = await queueValid(mintCalldata(RECIPIENT, amount));
    const create = await sign(
      { to: FACTORY, value: "0", data: createCalldata(), chainId: 8453, executionRef: ref() },
      bearer(agentJwt),
    );
    const createTx = (await json(create)).data.txId;

    expect(
      (await app.request(`/vault/${AGENT}/pending`, { headers: bearer(agentJwt) })).status,
    ).toBe(403);
    expect((await app.request(`/vault/${AGENT}/pending`, { headers: rootHeaders() })).status).toBe(
      403,
    );
    expect(
      (await app.request(`/vault/${AGENT}/pending`, { headers: bearer(memberToken) })).status,
    ).toBe(403);
    const r = await app.request(`/vault/${AGENT}/pending`, { headers: bearer(ownerToken) });
    expect(r.status).toBe(200);
    const list = (await json(r)).data as Array<any>;
    const mint = list.find((e) => e.transaction.id === txId);
    expect(mint.protected).toBe(true);
    expect(mint.reviewDigest).toStartWith("0x");
    expect(mint.manifestDigest).toBe(boundary.getProtectedMinterManifestDigest());
    expect(mint.review).toMatchObject({
      kind: "mint",
      chainId: 8453,
      token: TOKEN,
      recipient: RECIPIENT,
      amount: amount.toString(),
      executionRef,
    });
    expect(mint.review.tokenProvenance).toContain("verified");
    expect(mint.originalCalldata).toBe(mintCalldata(RECIPIENT, amount));
    const dep = list.find((e) => e.transaction.id === createTx);
    expect(dep.review).toMatchObject({
      kind: "createDealToken",
      chainId: 8453,
      factory: FACTORY,
      adminSafe: SAFE,
      name: "Deal One",
      symbol: "DL1",
      salt: SALT,
    });
    expect(dep.review.minter.toLowerCase()).toBe(signerAddress.toLowerCase());
    expect(dep.review).toHaveProperty("predictedTokenAddress");
    expect(dep.review.predictedTokenAddressNote).toContain("CREATE");

    const audit = await getDb().execute(
      `select action, metadata from audit_events where tenant_id = '${TENANT}' and resource_id = '${txId}' and action = 'vault.sign.protected_queued'`,
    );
    const rows = (audit as any).rows ?? audit;
    expect(rows.length).toBe(1);
    expect(rows[0].metadata.review.amount).toBe(amount.toString());
    expect(rows[0].metadata.reviewDigest).toBe(mint.reviewDigest);
  });

  // ── R8: executionRef semantics ────────────────────────────────────────────
  it("[R8] re-propose / re-approve of the same executionRef never yields a second signature; failed stays failed", async () => {
    const executionRef = ref();
    const first = await queueValid(mintCalldata(), TOKEN, executionRef);
    const replay = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef },
      bearer(agentJwt),
    );
    expect(replay.status).toBe(202);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect((await json(replay)).data.txId).toBe(first.txId);
    const diff = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(RECIPIENT, 7n), chainId: 8453, executionRef },
      bearer(agentJwt),
    );
    expect(diff.status).toBe(409);

    expect(
      (await approve(first.txId, bearer(ownerToken), { reviewDigest: first.reviewDigest })).status,
    ).toBe(200);
    expect(signedBytes).toHaveLength(1);
    const again = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef },
      bearer(agentJwt),
    );
    expect(again.status).toBe(200);
    expect((await json(again)).data.txHash).toBeDefined();
    expect(
      (await approve(first.txId, bearer(ownerToken), { reviewDigest: first.reviewDigest })).status,
    ).toBe(409);
    expect(signedBytes).toHaveLength(1);
    const byRef = await app.request(`/vault/${AGENT}/actions/by-ref/${executionRef}`, {
      headers: bearer(agentJwt),
    });
    expect((await json(byRef)).data.status).toBe("signed");
    signedBytes = [];

    // Lost response: broadcaster throws after send → failed, consumed, no reset.
    const second = await queueValid();
    sendSpy.mockImplementationOnce((async () => {
      throw new Error("socket hang up after send");
    }) as never);
    const failed = await approve(second.txId, bearer(ownerToken), {
      reviewDigest: second.reviewDigest,
    });
    expect([500, 502]).toContain(failed.status);
    expect((await txRow(second.txId))?.status).toBe("failed");
    expect((await queueRow(second.txId))?.status).toBe("approved");
    expect(
      (await approve(second.txId, bearer(ownerToken), { reviewDigest: second.reviewDigest }))
        .status,
    ).toBe(409);
    const replayFailed = await sign(
      {
        to: TOKEN,
        value: "0",
        data: mintCalldata(),
        chainId: 8453,
        executionRef: second.executionRef,
      },
      bearer(agentJwt),
    );
    expect(replayFailed.status).toBe(500);
    expect(signedBytes).toHaveLength(0);
  });

  it("[R8] retention never sweeps protected executionRef tombstones", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    const { txId } = await queueValid();
    await getDb()
      .update(transactions)
      .set({ status: "failed", createdAt: new Date(Date.now() - 400 * 86400_000) })
      .where(eq(transactions.id, txId));
    await getDb()
      .update(approvalQueue)
      .set({ status: "approved" })
      .where(eq(approvalQueue.txId, txId));
    const other = crypto.randomUUID();
    await getDb()
      .insert(transactions)
      .values({
        id: other,
        agentId: OTHER_AGENT,
        tenantId: TENANT,
        status: "failed",
        toAddress: RECIPIENT,
        value: "0",
        chainId: 8453,
        policyResults: [],
        createdAt: new Date(Date.now() - 400 * 86400_000),
      });
    await runRetentionSweep();
    expect(await txRow(txId)).toBeDefined();
    expect(await txRow(other)).toBeUndefined();
  });

  // ── R10: alternate signing paths ──────────────────────────────────────────
  it("[R10] every alternate signing/approval route refuses the protected signer for every credential", async () => {
    const typed = {
      domain: { name: "x", chainId: 8453 },
      types: { M: [{ name: "a", type: "uint256" }] },
      primaryType: "M",
      message: { a: "1" },
    };
    for (const h of [bearer(agentJwt), bearer(ownerToken), rootHeaders()]) {
      expect(
        (
          await app.request(`/vault/${AGENT}/sign-message`, {
            method: "POST",
            headers: h,
            body: JSON.stringify({ message: "hi" }),
          })
        ).status,
      ).toBe(403);
      expect(
        (
          await app.request(`/vault/${AGENT}/sign-typed-data`, {
            method: "POST",
            headers: h,
            body: JSON.stringify(typed),
          })
        ).status,
      ).toBe(403);
      expect(
        (
          await app.request(`/vault/${AGENT}/sign-solana`, {
            method: "POST",
            headers: h,
            body: JSON.stringify({ transaction: "AAAA", chainId: 101 }),
          })
        ).status,
      ).toBe(403);
      expect(
        (
          await sign(
            {
              to: TOKEN,
              value: "0",
              data: mintCalldata(),
              chainId: 8453,
              executionRef: ref(),
              broadcast: false,
            },
            h,
          )
        ).status,
      ).toBe(403);
      // Smuggled fields / missing ref are refused as client errors (400) by
      // the protected proposer; a root key is refused outright (403).
      const isRoot = "X-Steward-Key" in h;
      expect([400, 403]).toContain(
        (
          await sign(
            {
              to: TOKEN,
              value: "0",
              data: mintCalldata(),
              chainId: 8453,
              executionRef: ref(),
              nonce: 1,
            },
            h,
          )
        ).status,
      );
      expect([400, 403]).toContain(
        (
          await sign(
            {
              to: TOKEN,
              value: "0",
              data: mintCalldata(),
              chainId: 8453,
              executionRef: ref(),
              gasLimit: "1",
            },
            h,
          )
        ).status,
      );
      expect(
        (await sign({ to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453 }, h)).status,
      ).toBe(isRoot ? 403 : 400);
    }
    // sibling agent JWT cannot touch the protected signer at all
    expect(
      (
        await sign(
          { to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef: ref() },
          bearer(otherAgentJwt),
        )
      ).status,
    ).toBe(403);
    // Token issuance: only human; never api:proxy
    expect(
      (
        await app.request(`/agents/${AGENT}/token`, {
          method: "POST",
          headers: rootHeaders(),
          body: "{}",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/agents/${AGENT}/token`, {
          method: "POST",
          headers: bearer(agentJwt),
          body: "{}",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/agents/${AGENT}/token`, {
          method: "POST",
          headers: bearer(ownerToken),
          body: JSON.stringify({ scopes: ["api:proxy"] }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request(`/agents/${AGENT}/token`, {
          method: "POST",
          headers: bearer(ownerToken),
          body: "{}",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await app.request(`/agents/${AGENT}/wallets`, {
          method: "POST",
          headers: bearer(ownerToken),
          body: JSON.stringify({ chain: "solana" }),
        })
      ).status,
    ).toBe(403);

    // Direct vault calls (any internal module) are refused before key use.
    await expect(vault.signMessage(TENANT, AGENT, "hi")).rejects.toThrow(/Protected signer/);
    await expect(
      vault.signTypedData({ agentId: AGENT, tenantId: TENANT, ...typed } as never),
    ).rejects.toThrow(/Protected signer/);
    await expect(
      vault.signAuthorization(TENANT, AGENT, {
        contractAddress: RECIPIENT as `0x${string}`,
        chainId: 8453,
        nonce: 0,
      }),
    ).rejects.toThrow(/Protected signer/);
    await expect(
      vault.signSolanaTransaction({
        agentId: AGENT,
        tenantId: TENANT,
        transaction: "AAAA",
        chainId: 101,
      } as never),
    ).rejects.toThrow(/Protected signer/);
    await expect(vault.exportPrivateKey(TENANT, AGENT)).rejects.toThrow(/Protected signer/);
    await expect(vault.importKey(TENANT, AGENT, `0x${"22".repeat(32)}`, "evm")).rejects.toThrow(
      /Protected signer/,
    );
    expect(signedBytes).toHaveLength(0);
  });
});
