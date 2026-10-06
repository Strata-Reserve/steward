/**
 * STRATA-1499 SF-1 — pinned approver allowlist (REVIEW-STEWARD-28-R3
 * platform-promotion finding; JJ decision 2026-10-05 22:26Z).
 *
 * The protected-signer manifest carries `approvers`: the stable user IDs of
 * the only humans who may approve. Owner/admin membership alone is NOT enough,
 * so platform membership administration (which can promote anyone) cannot
 * manufacture an approver. Empty allowlist => nobody can approve (fail-closed).
 * The allowlist is part of the manifest digest, so changing it invalidates
 * pending reviews and no API credential can touch it.
 *
 * In-memory PGLite; broadcast seam stubbed; no RPC (no-network preload).
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { approvalQueue, closeDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const AGENT = "prod-minter-allowlist";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const PLACEHOLDER = "0x00000000000000000000000000000000000000ff";
const OWNER_USER = crypto.randomUUID(); // creates the agent; NOT an approver
const APPROVER_A = crypto.randomUUID(); // admin, allowlisted
const APPROVER_B = crypto.randomUUID(); // admin, allowlisted
const PLATFORM_KEY = "allowlist-platform-key-for-tests";

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
let rootKey: string;
let signerAddress: string;
let ownerToken: string;
let approverAToken: string;
let approverBToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let refCounter = 0;
const ref = () => `strata:allowlist:${++refCounter}`;
const sent: unknown[] = [];

const rootHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": TENANT,
  "X-Steward-Key": rootKey,
});
const platformHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Platform-Key": PLATFORM_KEY,
});
const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

function manifest(addr: string, approvers: string[] = [APPROVER_A, APPROVER_B]) {
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

async function call(method: string, path: string, h: Record<string, string>, body?: unknown) {
  return app.request(path, {
    method,
    headers: h,
    body:
      ["GET", "HEAD", "DELETE"].includes(method) && body === undefined
        ? undefined
        : JSON.stringify(body ?? {}),
  });
}
async function queue() {
  const r = await call("POST", `/vault/${AGENT}/sign`, bearer(agentJwt), proposal());
  const b = (await r.json()) as { data?: { txId: string; reviewDigest: string } };
  return { txId: b.data?.txId ?? "", reviewDigest: b.data?.reviewDigest ?? "", status: r.status };
}
async function approve(q: { txId: string; reviewDigest: string }, h: Record<string, string>) {
  return call("POST", `/vault/${AGENT}/approve/${q.txId}`, h, { reviewDigest: q.reviewDigest });
}
async function queueStatus(txId: string) {
  const [row] = await db
    .select({ status: approvalQueue.status, approvedBy: approvalQueue.approvedByUserId })
    .from(approvalQueue)
    .where(eq(approvalQueue.txId, txId));
  return row;
}
const humanToken = (userId: string) =>
  signAccessToken({ address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId } as never, "1h");

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "allowlist-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "allowlist-audit-key-32-bytes-minimum-aaaaaa";
  process.env.STEWARD_JWT_SECRET = "allowlist-jwt-secret-with-enough-bytes-aaaaa";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.RPC_URL_8453 = "https://protected-tests-mainnet.invalid/v2/UNUSED";

  const created = await createPGLiteDb("memory://");
  db = created.db;
  setPGLiteOverride(db, async () => created.client.close());
  const k = generateApiKey();
  rootKey = k.key;
  await db.insert(tenants).values([{ id: TENANT, name: "Strata", apiKeyHash: k.hash }]);
  await db
    .insert(users)
    .values([OWNER_USER, APPROVER_A, APPROVER_B].map((id) => ({ id, email: `${id}@x.test` })));
  await db.insert(userTenants).values([
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: APPROVER_A, tenantId: TENANT, role: "admin" },
    { userId: APPROVER_B, tenantId: TENANT, role: "admin" },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");

  ownerToken = await humanToken(OWNER_USER);
  approverAToken = await humanToken(APPROVER_A);
  approverBToken = await humanToken(APPROVER_B);
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
    "STEWARD_PLATFORM_KEYS",
    "RPC_URL_8453",
  ])
    delete process.env[k];
}, 120000);

describe.serial("SF-1 approver allowlist", () => {
  it("[AL-1] platform key promotes a new owner/admin; that human's real session gets 403 and the approval stays pending", async () => {
    // Platform membership administration: create a user and make them admin,
    // then promote to owner. Both succeed (trusted admin authority retained).
    const email = `promoted-${crypto.randomUUID()}@x.test`;
    const add = await call("POST", `/platform/tenants/${TENANT}/members`, platformHeaders(), {
      email,
      role: "admin",
    });
    expect(add.status).toBe(201);
    const promotedId = ((await add.json()) as { data: { userId: string } }).data.userId;
    const promote = await call(
      "PATCH",
      `/platform/tenants/${TENANT}/members/${promotedId}`,
      platformHeaders(),
      { role: "owner" },
    );
    expect(promote.status).toBe(200);

    // The promoted human's genuine session is owner/admin but not allowlisted.
    const promotedToken = await humanToken(promotedId);
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    const r = await approve(q, bearer(promotedToken));
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toMatch(/allowlist/);
    const row = await queueStatus(q.txId);
    expect(row?.status).toBe("pending");
    expect(row?.approvedBy ?? null).toBeNull();
    expect(sent.length - before).toBe(0);

    // The tenant's original owner (who created the agent) is likewise refused.
    expect((await approve(q, bearer(ownerToken))).status).toBe(403);
    expect((await queueStatus(q.txId))?.status).toBe("pending");

    // An allowlisted admin can still take that same pending approval.
    expect((await approve(q, bearer(approverAToken))).status).toBe(200);
    expect(sent.length - before).toBe(1);
  });

  it("[AL-2] an allowlisted human approves exactly once", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    const first = await approve(q, bearer(approverBToken));
    expect(first.status).toBe(200);
    expect((await queueStatus(q.txId))?.approvedBy).toBe(APPROVER_B);
    // Second attempt by the same approver, and by the other approver: not pending.
    expect((await approve(q, bearer(approverBToken))).status).toBe(409);
    expect((await approve(q, bearer(approverAToken))).status).toBe(409);
    expect(sent.length - before).toBe(1);
  });

  it("[AL-3] removing an approver from the allowlist (new manifest digest) refuses their next approval", async () => {
    const digestBefore = boundary.getProtectedMinterManifestDigest();
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    try {
      boundary.installProtectedMinterManifest(manifest(signerAddress, [APPROVER_A]));
      expect(boundary.getProtectedMinterManifestDigest()).not.toBe(digestBefore);
      // Removed approver: 403 (not in allowlist).
      const removed = await approve(q, bearer(approverBToken));
      expect(removed.status).toBe(403);
      // Still-listed approver: also refused for this row, because the manifest
      // digest changed since the proposal was reviewed (re-propose required).
      const stale = await approve(q, bearer(approverAToken));
      expect(stale.status).toBe(403);
      expect(((await stale.json()) as { error: string }).error).toMatch(/manifest changed/);
      expect((await queueStatus(q.txId))?.status).toBe("pending");
      // A fresh proposal under the new manifest: B refused, A approves.
      const q2 = await queue();
      expect(q2.status).toBe(202);
      expect((await approve(q2, bearer(approverBToken))).status).toBe(403);
      expect((await approve(q2, bearer(approverAToken))).status).toBe(200);
      expect(sent.length - before).toBe(1);
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
    expect(boundary.getProtectedMinterManifestDigest()).toBe(digestBefore);
  });

  it("[AL-4] empty or missing allowlist => no approver at all; malformed allowlist is a malformed manifest", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    try {
      boundary.installProtectedMinterManifest(manifest(signerAddress, []));
      const q2 = await queue(); // proposals still queue under the new digest
      expect(q2.status).toBe(202);
      for (const t of [approverAToken, approverBToken, ownerToken]) {
        expect((await approve(q2, bearer(t))).status).toBe(403);
      }
      expect((await queueStatus(q2.txId))?.status).toBe("pending");
      expect(boundary.isProtectedMinterApprover(APPROVER_A)).toBe(false);
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
    expect(sent.length - before).toBe(0);

    // Env: unset => [] (no approver, but a valid manifest); malformed => throws.
    const base = {
      STEWARD_PROTECTED_MINTER_TENANT: TENANT,
      STEWARD_PROTECTED_MINTER_AGENT: AGENT,
      STEWARD_PROTECTED_MINTER_ADDRESS: signerAddress,
      STEWARD_PROTECTED_MINTER_FACTORIES: FACTORY,
      STEWARD_PROTECTED_MINTER_TOKENS: `${TOKEN}@0xdeploytx:verified`,
    };
    const unset = boundary.manifestFromEnv(base as NodeJS.ProcessEnv);
    expect(unset?.approvers).toEqual([]);
    const listed = boundary.manifestFromEnv({
      ...base,
      STEWARD_PROTECTED_MINTER_APPROVERS: `${APPROVER_A}, ${APPROVER_B}`,
    } as NodeJS.ProcessEnv);
    expect(listed?.approvers).toEqual([APPROVER_A, APPROVER_B]);
    for (const bad of [
      "approver@example.test", // email is not an identity
      "not-a-uuid",
      `${APPROVER_A},${APPROVER_A}`, // duplicate
    ]) {
      expect(() =>
        boundary.manifestFromEnv({
          ...base,
          STEWARD_PROTECTED_MINTER_APPROVERS: bad,
        } as NodeJS.ProcessEnv),
      ).toThrow(/approver/);
    }
    // The digest binds the allowlist exactly like the signer address.
    const m = boundary.getProtectedMinterManifest()!;
    expect(boundary.computeManifestDigest({ ...m, approvers: [APPROVER_A] })).not.toBe(
      boundary.computeManifestDigest(m),
    );
    expect(boundary.computeManifestDigest({ ...m, approvers: [APPROVER_B, APPROVER_A] })).toBe(
      boundary.computeManifestDigest(m),
    );
  });

  it("[AL-5] neither a tenant/root key, the platform key, nor an agent JWT can change the allowlist", async () => {
    const digest = boundary.getProtectedMinterManifestDigest();
    const approvers = [...boundary.getProtectedMinterManifest()!.approvers];
    const intruder = crypto.randomUUID();
    const bodies = [
      { approvers: [intruder] },
      { manifest: { approvers: [intruder] } },
      { protected: { approvers: [intruder] } },
      { policies: [{ type: "approvers", approvers: [intruder] }] },
      { config: { approvers: [intruder] } },
    ];
    const attempts: Array<[string, string, Record<string, string>]> = [];
    for (const h of [rootHeaders(), platformHeaders(), bearer(agentJwt)]) {
      attempts.push(
        ["PUT", `/agents/${AGENT}/policies`, h],
        ["PATCH", `/agents/${AGENT}`, h],
        ["PUT", `/agents/${AGENT}`, h],
        ["POST", `/agents/${AGENT}/approvers`, h],
        ["PUT", `/agents/${AGENT}/approvers`, h],
        ["PUT", `/tenants/${TENANT}/config`, h],
        ["PUT", `/platform/tenants/${TENANT}/policies`, h],
        ["PATCH", `/platform/tenants/${TENANT}`, h],
        ["POST", `/platform/tenants/${TENANT}/agents/${AGENT}/approvers`, h],
      );
    }
    const successes: unknown[] = [];
    for (const [method, path, h] of attempts) {
      for (const body of bodies) {
        const r = await call(method, path, h, body);
        if (r.status >= 200 && r.status < 300 && method !== "GET") {
          // Any 2xx must not have touched the manifest.
          if (
            boundary.getProtectedMinterManifestDigest() !== digest ||
            boundary.isProtectedMinterApprover(intruder)
          ) {
            successes.push({ method, path, status: r.status, body });
          }
        }
      }
    }
    expect(successes).toEqual([]);
    expect(boundary.getProtectedMinterManifestDigest()).toBe(digest);
    expect(boundary.getProtectedMinterManifest()!.approvers).toEqual(approvers);
    expect(boundary.isProtectedMinterApprover(intruder)).toBe(false);
    // The installed manifest is frozen: direct mutation is also impossible.
    expect(() => {
      (boundary.getProtectedMinterManifest()!.approvers as string[]).push(intruder);
    }).toThrow();
    // Intruder's genuine session (if one were ever minted) still 403s.
    await db.insert(users).values({ id: intruder, email: `${intruder}@x.test` });
    await db.insert(userTenants).values({ userId: intruder, tenantId: TENANT, role: "owner" });
    const q = await queue();
    expect(q.status).toBe(202);
    expect((await approve(q, bearer(await humanToken(intruder)))).status).toBe(403);
    expect((await queueStatus(q.txId))?.status).toBe("pending");
  });
});
