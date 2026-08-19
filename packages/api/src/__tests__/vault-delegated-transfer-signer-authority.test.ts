/**
 * STRATA-1098 — the delegated transfer signer authority boundary.
 *
 * ============================================================================
 * THE GAP THIS CLOSES
 * ============================================================================
 * `vault-delegated-action-signer.test.ts` already proves the NEGATIVE half of
 * this boundary, but every case in it sends `x-steward-signer-id` WITHOUT
 * `x-steward-signer-secret`. `requireSignerPermission` returns the same opaque
 * 403 the moment either header is absent, so those tests all terminate at the
 * first gate. Nothing in the suite has ever proven that a CORRECTLY SCOPED
 * signer can actually create a pending action.
 *
 * That asymmetry is dangerous in exactly one direction: a change that broke
 * delegated signing entirely would keep the whole existing suite green, and the
 * failure would first appear as a 403 in Strata's treasury adapter at the
 * moment a human authorized a real payment.
 *
 * So this file drives the full credential pair and asserts BOTH halves:
 *   - the correctly scoped signer is PERMITTED to request the transfer;
 *   - every mis-scoped variant is REFUSED;
 *   - the signer that may request can never approve.
 *
 * ============================================================================
 * WHY THE SEPARATION-OF-POWERS ASSERTIONS LIVE HERE
 * ============================================================================
 * Strata's adapter (STRATA-1098) holds this credential server-side. The whole
 * security argument for handing an autonomous runtime a signing credential is
 * that the credential can only ever REQUEST — a human with a browser session,
 * recent MFA, and a DIFFERENT principal must approve before anything is signed.
 * If that ever stopped being true, the delegated signer would silently become a
 * self-approving money-mover. It is asserted here, against the real routes.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  agents,
  agentSigners,
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
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { createSignerCredentialHash } from "../services/signer-credentials";
import type { AppVariables } from "../services/context";

const TENANT_ID = `d1098-tenant-${Date.now()}`;
const FOREIGN_TENANT_ID = `d1098-foreign-tenant-${Date.now()}`;
const AGENT_ID = `d1098-agent-${Date.now()}`;
const OTHER_AGENT_ID = `d1098-other-agent-${Date.now()}`;
const FOREIGN_AGENT_ID = `d1098-foreign-agent-${Date.now()}`;

const APPROVER_USER_ID = crypto.randomUUID();
const OUTSIDER_USER_ID = crypto.randomUUID();

/** Base Sepolia USDC-shaped fixture. Mirrors the proposed staging policy. */
const TOKEN = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ALLOWED = "0x2613000000000000000000000000000000000730";
const CHAIN_ID = 84532;

/** The one credential that is supposed to work. */
const TRANSFER_SECRET = "d1098-correctly-scoped-transfer-secret";
/** Same tenant/agent, but holds a non-signing permission. */
const READ_ONLY_SECRET = "d1098-read-only-secret";
/** Correct permission, but bound to a DIFFERENT agent in the same tenant. */
const OTHER_AGENT_SECRET = "d1098-other-agent-secret";
/** Correct permission, but bound to a different TENANT entirely. */
const FOREIGN_TENANT_SECRET = "d1098-foreign-tenant-secret";
/** Correct permission and scope, but the signer row is revoked. */
const REVOKED_SECRET = "d1098-revoked-secret";

const signerIds: Record<string, string> = {};

/**
 * The adapter's posture: an API-key principal with NO browser session, NO
 * tenant role, and NO MFA. This is exactly what Strata's server-to-server
 * treasury adapter presents, and it must never be enough on its own.
 */
function makeAdapterApp(tenantId = TENANT_ID) {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "api-key");
    await next();
  });
  return app;
}

/** A human owner/admin: browser session, tenant role, fresh MFA. */
function makeHumanApp(userId: string, role: "admin" | "owner" = "admin") {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", role);
    c.set("userId", userId);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  return app;
}

async function mountVault(app: Hono<{ Variables: AppVariables }>) {
  const { vaultRoutes } = await import("../routes/vault");
  app.route("/vault", vaultRoutes);
  return app;
}

function signerHeaders(id: string, secret: string): Record<string, string> {
  return {
    "content-type": "application/json",
    "x-steward-signer-id": id,
    "x-steward-signer-secret": secret,
  };
}

function transferBody(referenceId: string) {
  return JSON.stringify({
    to: ALLOWED,
    token: TOKEN,
    value: "1000000",
    chainId: CHAIN_ID,
    broadcast: false,
    referenceId,
  });
}

describe("STRATA-1098 delegated transfer signer authority", () => {
  let adapter: Hono<{ Variables: AppVariables }>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "d1098-master-password";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    // The STRATA-1097 deployment guard is ACTIVE for this whole file. Every
    // assertion below therefore runs in the exact posture staging will run in:
    // an explicit manual-approval rule is mandatory, so nothing here can pass
    // by way of an implicit auto-sign path.
    process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS = "wallet_action_transfer";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "1098 Tenant", apiKeyHash: `hash-${TENANT_ID}` },
        {
          id: FOREIGN_TENANT_ID,
          name: "1098 Foreign Tenant",
          apiKeyHash: `hash-${FOREIGN_TENANT_ID}`,
        },
      ]);

    await getDb()
      .insert(agents)
      .values([
        {
          id: AGENT_ID,
          tenantId: TENANT_ID,
          name: "1098 Treasury Agent",
          walletAddress: "0x0000000000000000000000000000000000000a01",
        },
        {
          id: OTHER_AGENT_ID,
          tenantId: TENANT_ID,
          name: "1098 Unrelated Agent",
          walletAddress: "0x0000000000000000000000000000000000000a02",
        },
        {
          id: FOREIGN_AGENT_ID,
          tenantId: FOREIGN_TENANT_ID,
          name: "1098 Foreign Agent",
          walletAddress: "0x0000000000000000000000000000000000000a03",
        },
      ]);

    await getDb()
      .insert(users)
      .values([
        {
          id: APPROVER_USER_ID,
          email: `d1098-approver-${Date.now()}@example.com`,
          walletAddress: "0x0000000000000000000000000000000000000b01",
        },
        {
          id: OUTSIDER_USER_ID,
          email: `d1098-outsider-${Date.now()}@example.com`,
          walletAddress: "0x0000000000000000000000000000000000000b02",
        },
      ]);
    // Only the approver holds an active admin membership. The outsider is a
    // real, authenticated user with NO membership in this tenant.
    await getDb()
      .insert(userTenants)
      .values([{ userId: APPROVER_USER_ID, tenantId: TENANT_ID, role: "admin" }]);

    // Hard rules + the STRATA-1097 manual rule, for both agents that can be
    // reached in-tenant. Policy is not what this file tests; it is the
    // environment the authority boundary has to hold inside.
    for (const agentId of [AGENT_ID, OTHER_AGENT_ID]) {
      await getDb()
        .insert(policies)
        .values([
          {
            id: `${agentId}-chains`,
            agentId,
            type: "allowed-chains",
            enabled: true,
            config: { chains: [`eip155:${CHAIN_ID}`] },
          },
          {
            id: `${agentId}-addresses`,
            agentId,
            type: "approved-addresses",
            enabled: true,
            config: { addresses: [TOKEN], mode: "whitelist" },
          },
          {
            id: `${agentId}-contract`,
            agentId,
            type: "contract-allowlist",
            enabled: true,
            config: {
              contracts: [
                {
                  address: TOKEN,
                  selectors: ["0xa9059cbb"],
                  constraints: {
                    "0xa9059cbb": {
                      recipientAllowlist: [ALLOWED],
                      maxNativeValueWei: "0",
                      maxAmount: "1000000",
                    },
                  },
                },
              ],
            },
          },
          {
            id: `${agentId}-manual`,
            agentId,
            type: "manual-approval",
            enabled: true,
            config: { actions: ["wallet_action_transfer"] },
          },
        ]);
    }

    const rows: Array<[string, string, string, string, string[], string?]> = [
      ["transfer", TENANT_ID, AGENT_ID, TRANSFER_SECRET, ["wallet_action_transfer"]],
      ["readOnly", TENANT_ID, AGENT_ID, READ_ONLY_SECRET, ["read_account"]],
      ["otherAgent", TENANT_ID, OTHER_AGENT_ID, OTHER_AGENT_SECRET, ["wallet_action_transfer"]],
      [
        "foreignTenant",
        FOREIGN_TENANT_ID,
        FOREIGN_AGENT_ID,
        FOREIGN_TENANT_SECRET,
        ["wallet_action_transfer"],
      ],
      ["revoked", TENANT_ID, AGENT_ID, REVOKED_SECRET, ["wallet_action_transfer"], "revoked"],
    ];
    for (const [name, tenantId, agentId, secret, permissions, status] of rows) {
      const [signer] = await getDb()
        .insert(agentSigners)
        .values({
          tenantId,
          agentId,
          signerType: "delegated",
          subjectType: "api_key",
          subjectId: `api-key:${name}`,
          permissions,
          metadata: { credentialHash: await createSignerCredentialHash(secret) },
          ...(status === undefined ? {} : { status }),
        })
        .returning();
      signerIds[name] = signer.id;
    }

    adapter = await mountVault(makeAdapterApp());
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS;
  });

  describe("bearer-only is not signing authority", () => {
    it("refuses a transfer carrying no signer credential at all", async () => {
      // The exact 403 that blocked the merged Strata adapter and produced this
      // ticket. It must stay a refusal.
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: transferBody("d1098-bearer-only"),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Signing requires owner/admin MFA");
    });

    it("refuses a signer id presented without its secret", async () => {
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-steward-signer-id": signerIds.transfer,
        },
        body: transferBody("d1098-id-without-secret"),
      });
      expect(res.status).toBe(403);
    });

    it("refuses a correct signer id with a WRONG secret", async () => {
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.transfer, `${TRANSFER_SECRET}-wrong`),
        body: transferBody("d1098-wrong-secret"),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("scope is enforced on every axis", () => {
    it("refuses a signer that lacks wallet_action_transfer", async () => {
      // Correct tenant, correct agent, valid credential — but the permission
      // array does not contain the action. Authentication is not authorization.
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.readOnly, READ_ONLY_SECRET),
        body: transferBody("d1098-no-permission"),
      });
      expect(res.status).toBe(403);
    });

    it("refuses a signer scoped to a DIFFERENT agent in the same tenant", async () => {
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.otherAgent, OTHER_AGENT_SECRET),
        body: transferBody("d1098-wrong-agent"),
      });
      expect(res.status).toBe(403);
    });

    it("refuses a signer belonging to a DIFFERENT tenant", async () => {
      // The lookup is `(id, tenantId, agentId)`, so a foreign signer resolves
      // to nothing here — indistinguishable, correctly, from an invented id.
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.foreignTenant, FOREIGN_TENANT_SECRET),
        body: transferBody("d1098-wrong-tenant"),
      });
      expect(res.status).toBe(403);
    });

    it("refuses a REVOKED signer — revocation is immediate and needs no redeploy", async () => {
      // The operational kill switch for the Strata adapter. Flipping `status`
      // away from `active` must stop action creation on the very next request.
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.revoked, REVOKED_SECRET),
        body: transferBody("d1098-revoked"),
      });
      expect(res.status).toBe(403);
    });

    it("every refusal is the SAME opaque error — no scope oracle", async () => {
      // A caller must not be able to distinguish "no such signer" from "wrong
      // secret" from "insufficient permission" from "revoked". Distinguishable
      // errors would let an attacker enumerate the signer graph.
      const attempts: Array<[string, string]> = [
        [signerIds.readOnly, READ_ONLY_SECRET],
        [signerIds.otherAgent, OTHER_AGENT_SECRET],
        [signerIds.foreignTenant, FOREIGN_TENANT_SECRET],
        [signerIds.revoked, REVOKED_SECRET],
        [crypto.randomUUID(), TRANSFER_SECRET],
      ];
      const errors = new Set<string>();
      for (const [id, secret] of attempts) {
        const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
          method: "POST",
          headers: signerHeaders(id, secret),
          body: transferBody(`d1098-oracle-${id}`),
        });
        expect(res.status).toBe(403);
        errors.add(((await res.json()) as { error?: string }).error ?? "");
      }
      expect(errors.size).toBe(1);
    });
  });

  describe("the correctly scoped signer MAY request, and ONLY request", () => {
    let pendingTxId: string;

    it("permits the correctly scoped signer to create a PENDING action", async () => {
      // The positive path no existing test covered. Without this, a regression
      // that broke delegated signing entirely would leave every other test in
      // the repository green.
      const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: signerHeaders(signerIds.transfer, TRANSFER_SECRET),
        body: transferBody("d1098-happy-path"),
      });

      expect(res.status).toBe(202);
      const body = (await res.json()) as {
        ok: boolean;
        data: { status: string; id: string };
      };
      // PENDING, not signed. The credential bought a queue slot, nothing more.
      expect(body.data.status).toBe("pending_approval");
      pendingTxId = body.data.id;

      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, pendingTxId));
      expect(row.status).toBe("pending");
      expect(row.txHash).toBeNull();
    });

    it("attributes the request to the SIGNER principal, not to a user", async () => {
      // Attribution is what makes separation of duties enforceable later. If
      // the request were recorded as a user, a human could approve their own
      // machine-initiated payment without tripping the same-principal check.
      const [approval] = await getDb()
        .select()
        .from(approvalQueue)
        .where(
          and(eq(approvalQueue.txId, pendingTxId), eq(approvalQueue.agentId, AGENT_ID)),
        );
      expect(approval.status).toBe("pending");
      expect(approval.requestedByType).toBe("signer");
      expect(approval.requestedById).toBe(signerIds.transfer);
    });

    it("the delegated signer CANNOT approve its own request", async () => {
      // The central claim of the whole design. The approve route requires a
      // tenant admin SESSION; an api-key/signer principal fails before the
      // same-principal check is even reached.
      const res = await adapter.request(`/vault/${AGENT_ID}/approve/${pendingTxId}`, {
        method: "POST",
        headers: signerHeaders(signerIds.transfer, TRANSFER_SECRET),
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error?: string };
      expect(body.error).toContain("owner or admin session");

      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, pendingTxId));
      expect(row.status).toBe("pending");
    });

    it("an authenticated user with NO active admin membership cannot approve", async () => {
      // Session alone is not authority either. Membership is re-checked at
      // review time, so a removed admin loses approval power immediately.
      const outsider = await mountVault(makeHumanApp(OUTSIDER_USER_ID));
      const res = await outsider.request(`/vault/${AGENT_ID}/approve/${pendingTxId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "active owner or admin tenant membership",
      );

      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, pendingTxId));
      expect(row.status).toBe("pending");
    });


    it("a human owner/admin with recent MFA and a different principal CAN approve", async () => {
      // The other half of the boundary. The design must not be so strict that
      // nobody can ever release a payment: a real admin, with a real session,
      // fresh MFA, and a principal different from the requesting signer, IS
      // able to act — and only then does the action leave `pending`.
      //
      // The hardened approve path REALLY SIGNS, so the signer is stubbed (the
      // same technique `wallet-actions.test.ts` uses). Stubbing the signer is
      // what lets this assert the AUTHORITY decision rather than key custody —
      // and `signCalls` proves the distinction that matters: the signer is
      // reached exactly once, and only AFTER the human decided.
      const context = await import("../services/context");
      const originalSign = context.vault.signTransaction.bind(context.vault);
      let signCalls = 0;
      context.vault.signTransaction = async (request) => {
        signCalls += 1;
        // The approved payload is the one the delegated signer requested:
        // an ERC20 transfer to the token contract, zero native value.
        expect(request.agentId).toBe(AGENT_ID);
        expect(request.chainId).toBe(CHAIN_ID);
        expect(request.to).toBe(TOKEN);
        expect(request.value).toBe("0");
        return "0xd1098approvedtx";
      };

      let res: Response;
      try {
        const human = await mountVault(makeHumanApp(APPROVER_USER_ID));
        res = await human.request(`/vault/${AGENT_ID}/approve/${pendingTxId}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        });
      } finally {
        context.vault.signTransaction = originalSign;
      }

      expect(res.status).toBe(200);
      // Nothing was signed by the machine's own request; exactly one signature
      // happened, and it happened downstream of the human approval.
      expect(signCalls).toBe(1);

      const [approval] = await getDb()
        .select()
        .from(approvalQueue)
        .where(
          and(eq(approvalQueue.txId, pendingTxId), eq(approvalQueue.agentId, AGENT_ID)),
        );
      expect(approval.status).toBe("approved");
      // Attribution survives: requester is still the machine, approver is the
      // human. That pairing is the audit record the whole control depends on.
      expect(approval.requestedByType).toBe("signer");
      expect(approval.requestedById).toBe(signerIds.transfer);
      expect(approval.resolvedByType).toBe("user");
      expect(approval.resolvedById).toBe(APPROVER_USER_ID);
    });
  });

  describe("the credential is never disclosed", () => {
    it("no response body echoes the signer secret", async () => {
      // Sweeps the permitted path and the refused paths together. A credential
      // reflected in ANY response would be readable from Strata's own logs.
      const probes: Array<[string, string, string]> = [
        [signerIds.transfer, TRANSFER_SECRET, "d1098-echo-permitted"],
        [signerIds.readOnly, READ_ONLY_SECRET, "d1098-echo-nopermission"],
        [signerIds.revoked, REVOKED_SECRET, "d1098-echo-revoked"],
        [signerIds.foreignTenant, FOREIGN_TENANT_SECRET, "d1098-echo-foreign"],
      ];
      for (const [id, secret, ref] of probes) {
        const res = await adapter.request(`/vault/${AGENT_ID}/actions/transfer`, {
          method: "POST",
          headers: signerHeaders(id, secret),
          body: transferBody(ref),
        });
        expect(await res.text()).not.toContain(secret);
      }
    });

    it("the persisted transaction row never stores the signer secret", async () => {
      const rows = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.agentId, AGENT_ID));
      const encoded = JSON.stringify(rows);
      for (const secret of [TRANSFER_SECRET, READ_ONLY_SECRET, REVOKED_SECRET]) {
        expect(encoded).not.toContain(secret);
      }
    });

    it("the signer row stores only a hash, never the secret itself", async () => {
      const [signer] = await getDb()
        .select()
        .from(agentSigners)
        .where(eq(agentSigners.id, signerIds.transfer));
      const encoded = JSON.stringify(signer);
      expect(encoded).not.toContain(TRANSFER_SECRET);
      expect(typeof signer.metadata.credentialHash).toBe("string");
    });
  });
});
