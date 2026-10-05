/**
 * STRATA-1499 SF-1 — REVIEW-STEWARD-28-R5 N1: `issueProtectedSigningPermit`
 * enforces the pinned approver allowlist itself (defense in depth behind the
 * HTTP route). Ported from the independent review5 'direct permit' probe.
 *
 * An approval_queue row that is `approved` with a non-allowlisted
 * `approved_by_user_id` (seeded with internal DB authority; not an HTTP
 * capability) must be refused at issuance: the claim stays NULL, no permit
 * exists and nothing is broadcast. An allowlisted approver still yields
 * exactly one permit. No guard => refuse.
 *
 * In-memory PGLite; broadcast seam stubbed; no RPC (no-network preload).
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { approvalQueue, closeDb, tenants, transactions, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const AGENT = "prod-minter-permit-review5";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const PLACEHOLDER = "0x00000000000000000000000000000000000000ff";
const OWNER_USER = crypto.randomUUID(); // creates the agent; NOT an approver
const APPROVER_A = crypto.randomUUID(); // admin, allowlisted

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
let signerAddress: string;
let ownerToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let lib: typeof import("@stwd/vault");
let refCounter = 0;
const ref = () => `strata:permit-review5:${++refCounter}`;
const sent: unknown[] = [];

const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

function manifest(addr: string, approvers: string[] = [APPROVER_A]) {
  return {
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress: addr,
    chainId: 8453 as const,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:verified" }],
    approvers,
  };
}
const proposal = () => ({
  to: TOKEN,
  value: "0",
  data: encodeFunctionData({ abi: TOKEN_ABI, functionName: "mint", args: [RECIPIENT, 10n ** 18n] }),
  chainId: 8453,
  executionRef: ref(),
});

async function queue() {
  const r = await app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: bearer(agentJwt),
    body: JSON.stringify(proposal()),
  });
  const b = (await r.json()) as { data?: { txId: string; reviewDigest: string } };
  return { txId: b.data?.txId ?? "", reviewDigest: b.data?.reviewDigest ?? "", status: r.status };
}
async function fullRow(txId: string) {
  const [row] = await db.select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
  return row;
}
/** Emulates an internal already-approved row. Explicitly NOT an HTTP capability. */
async function seedApproved(txId: string, approvedBy: string | null) {
  await db
    .update(approvalQueue)
    .set({
      status: "approved",
      approvedByUserId: approvedBy,
      resolvedBy: approvedBy ? `user:${approvedBy}` : null,
    })
    .where(eq(approvalQueue.txId, txId));
}
const issue = (q: { txId: string; reviewDigest: string }) =>
  lib.issueProtectedSigningPermit({
    tenantId: TENANT,
    agentId: AGENT,
    txId: q.txId,
    reviewDigest: q.reviewDigest,
  });
const humanToken = (userId: string) =>
  signAccessToken({ address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId } as never, "1h");

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "permit-review5-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "permit-review5-audit-key-32-bytes-minimum-aaaa";
  process.env.STEWARD_JWT_SECRET = "permit-review5-jwt-secret-with-enough-bytes-aaa";
  process.env.RPC_URL_8453 = "https://protected-tests-mainnet.invalid/v2/UNUSED";

  const created = await createPGLiteDb("memory://");
  db = created.db;
  setPGLiteOverride(db, async () => created.client.close());
  const k = generateApiKey();
  await db.insert(tenants).values([{ id: TENANT, name: "Strata", apiKeyHash: k.hash }]);
  await db
    .insert(users)
    .values([OWNER_USER, APPROVER_A].map((id) => ({ id, email: `${id}@x.test` })));
  await db.insert(userTenants).values([
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: APPROVER_A, tenantId: TENANT, role: "admin" },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  lib = await import("@stwd/vault");

  ownerToken = await humanToken(OWNER_USER);
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

  boundary.installProtectedMinterManifest(manifest(PLACEHOLDER));
  const r = await app.request("/agents", {
    method: "POST",
    headers: bearer(ownerToken),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`protected create ${r.status}: ${await r.text()}`);
  signerAddress = ((await r.json()) as { data: { walletAddress: string } }).data.walletAddress;
  boundary.installProtectedMinterManifest(manifest(signerAddress));

  spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _client: unknown,
    tx: unknown,
  ) => {
    sent.push(tx);
    return `0x${sent.length.toString(16).padStart(64, "0")}`;
  }) as never);
}, 120000);

afterAll(async () => {
  boundary?.installProtectedMinterManifest(null);
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL_8453",
  ])
    delete process.env[k];
}, 120000);

describe.serial("SF-1 permit issuance enforces the approver allowlist (R5-N1)", () => {
  it("[N1] guard exposes isApprover from the installed manifest", () => {
    const guard = lib.getProtectedSignerGuard();
    expect(guard).not.toBeNull();
    expect(guard!.isApprover(APPROVER_A)).toBe(true);
    expect(guard!.isApprover(APPROVER_A.toUpperCase())).toBe(true);
    expect(guard!.isApprover(OWNER_USER)).toBe(false);
    expect(guard!.isApprover(null)).toBe(false);
    expect(guard!.isApprover(undefined)).toBe(false);
    expect(guard!.isApprover("")).toBe(false);
  });

  it("[N1] seeded approved row with a non-allowlisted approver is refused; claim stays NULL; 0 broadcasts", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    expect(boundary.isProtectedMinterApprover(OWNER_USER)).toBe(false);
    const before = sent.length;
    const permits = lib.outstandingProtectedPermits();

    // Pending row: refused (unchanged behaviour).
    await expect(issue(q)).rejects.toThrow(/no consumed approval/);

    // Internal authority seeds an approved row owned by a non-approver.
    await seedApproved(q.txId, OWNER_USER);
    await expect(issue(q)).rejects.toThrow(/not in the pinned manifest allowlist/);
    expect((await fullRow(q.txId))?.issuanceClaimedAt).toBeNull();
    expect(await lib.isProtectedIssuanceClaimed(q.txId)).toBe(false);
    expect(lib.outstandingProtectedPermits()).toBe(permits);

    // Signing without a permit is refused too; nothing reaches the broadcast seam.
    const [tx] = await db.select().from(transactions).where(eq(transactions.id, q.txId));
    expect(tx).toBeDefined();
    await expect(
      vault.signTransaction(
        {
          tenantId: TENANT,
          agentId: AGENT,
          to: tx!.toAddress,
          value: tx!.value,
          data: tx!.data ?? undefined,
          chainId: tx!.chainId,
          executionRef: tx!.executionRef!,
          broadcast: true,
        },
        { txId: q.txId, protectedReviewDigest: q.reviewDigest },
      ),
    ).rejects.toThrow();
    expect(sent.length).toBe(before);
  });

  it("[N1] approved row with NO recorded approver is refused; claim stays NULL", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await seedApproved(q.txId, null);
    await expect(issue(q)).rejects.toThrow(/no recorded approver/);
    expect((await fullRow(q.txId))?.issuanceClaimedAt).toBeNull();
  });

  it("[N1] approver removed from the allowlist after approval is refused (manifest is authoritative)", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await seedApproved(q.txId, APPROVER_A);
    try {
      boundary.installProtectedMinterManifest(manifest(signerAddress, []));
      await expect(issue(q)).rejects.toThrow(/not in the pinned manifest allowlist/);
      expect((await fullRow(q.txId))?.issuanceClaimedAt).toBeNull();
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
  });

  it("[N1] no guard registered => refused; claim stays NULL", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await seedApproved(q.txId, APPROVER_A);
    try {
      boundary.installProtectedMinterManifest(null);
      await expect(issue(q)).rejects.toThrow(/no valid manifest/);
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
    expect((await fullRow(q.txId))?.issuanceClaimedAt).toBeNull();
    // The same row with the manifest restored is still claimable once: the
    // refusal above did not spend it.
    const permit = await issue(q);
    expect(typeof permit).toBe("string");
    expect((await fullRow(q.txId))?.issuanceClaimedAt).not.toBeNull();
    await expect(issue(q)).rejects.toThrow(/already issued/);
  });

  it("[N1] allowlisted approver gets exactly one permit and exactly one broadcast", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await seedApproved(q.txId, APPROVER_A);
    const before = sent.length;
    const permits = lib.outstandingProtectedPermits();

    const permit = await issue(q);
    expect(typeof permit).toBe("string");
    expect(lib.outstandingProtectedPermits()).toBe(permits + 1);
    expect((await fullRow(q.txId))?.issuanceClaimedAt).not.toBeNull();
    await expect(issue(q)).rejects.toThrow(/already issued/);
    expect(lib.outstandingProtectedPermits()).toBe(permits + 1);

    const [tx] = await db.select().from(transactions).where(eq(transactions.id, q.txId));
    await vault.signTransaction(
      {
        tenantId: TENANT,
        agentId: AGENT,
        to: tx!.toAddress,
        value: tx!.value,
        data: tx!.data ?? undefined,
        chainId: tx!.chainId,
        executionRef: tx!.executionRef!,
        broadcast: true,
      },
      { txId: q.txId, protectedPermit: permit, protectedReviewDigest: q.reviewDigest },
    );
    expect(sent.length).toBe(before + 1);
    expect(lib.outstandingProtectedPermits()).toBe(permits);
  });
});
