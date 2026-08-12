import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { readFileSync } from "node:fs";
import { generateApiKey } from "@stwd/auth";
import {
  agents,
  agentWallets,
  applicationIdempotencyRecords,
  applicationPrincipalCredentials,
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  auditEvents,
  closeDb,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import type { Hono } from "hono";
import { deterministicId } from "../services/application-boundary";

const TENANT_ID = "application-boundary-test";
const FAR_FUTURE = "2030-01-01T00:00:00.000Z";
const CREDENTIAL_FUTURE = "2029-01-01T00:00:00.000Z";

let app: Hono;
let tenantKey: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let proposalCredential: IssuedPrincipal;

type IssuedPrincipal = {
  principal: { id: string };
  credential: { keyId: string; secret: string };
};

function tenantHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT_ID,
    "X-Steward-Key": tenantKey,
  };
}

function applicationHeaders(issued: IssuedPrincipal, idempotencyKey?: string) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Application-Key-Id": issued.credential.keyId,
    "X-Steward-Application-Secret": issued.credential.secret,
    ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
  };
}

async function issuePrincipal(
  name: string,
  capabilities: string[],
  ownerReferences: string[],
  expiresAt = FAR_FUTURE,
  credentialExpiresAt = CREDENTIAL_FUTURE,
): Promise<IssuedPrincipal> {
  const response = await app.request("/application-principals", {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      name,
      capabilities,
      resources: ownerReferences.map((id) => ({ kind: "wallet_owner", id })),
      expiresAt,
      credentialExpiresAt,
    }),
  });
  expect(response.status).toBe(201);
  const payload = (await response.json()) as { data: IssuedPrincipal };
  return payload.data;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "application-boundary-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "application-boundary-audit-key-32-bytes-minimum";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const key = generateApiKey();
  tenantKey = key.key;
  await db
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Application Boundary", apiKeyHash: key.hash });
  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe.serial("application principal custody boundary", () => {
  it("executes only the deterministic proposal command contract and never signs or broadcasts", async () => {
    const issued = await issuePrincipal(
      "Strata API",
      [
        "wallet:ensure",
        "wallet:address:read",
        "transaction:prepare",
        "transaction:propose",
        "transaction:proposal:read",
      ],
      ["investor:001"],
    );
    proposalCredential = issued;
    expect(issued.principal.id).toStartWith("app_");
    expect(issued.credential.secret).toStartWith("aps_");

    const ensureResponse = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "ensure:001"),
      body: JSON.stringify({ resourceId: "investor:001" }),
    });
    expect(ensureResponse.status).toBe(201);
    const ensure = (await ensureResponse.json()) as {
      data: { wallet: { id: string; addresses: { evm: string } }; replay: boolean };
    };
    expect(ensure.data.wallet.id).toStartWith("aw_");
    expect(ensure.data.wallet.addresses.evm).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(ensure.data.replay).toBe(false);

    const replayEnsure = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "ensure:001"),
      body: JSON.stringify({ resourceId: "investor:001" }),
    });
    expect(replayEnsure.status).toBe(200);
    const replayWallet = (await replayEnsure.json()) as {
      data: { wallet: { id: string }; replay: boolean };
    };
    expect(replayWallet.data.wallet.id).toBe(ensure.data.wallet.id);
    expect(replayWallet.data.replay).toBe(true);

    const addressResponse = await app.request(
      `/application/wallets/${ensure.data.wallet.id}/address`,
      {
        headers: applicationHeaders(issued),
      },
    );
    expect(addressResponse.status).toBe(200);

    const prepareBody = {
      walletId: ensure.data.wallet.id,
      network: { type: "evm", chainId: 8453 },
      transaction: {
        to: `0x${"ab".repeat(20)}`,
        value: "0001000",
        data: "0x",
      },
    };
    const prepareResponse = await app.request("/application/transactions/prepare", {
      method: "POST",
      headers: applicationHeaders(issued, "prepare:001"),
      body: JSON.stringify(prepareBody),
    });
    expect(prepareResponse.status).toBe(201);
    const prepared = (await prepareResponse.json()) as {
      data: {
        preparedTransaction: { id: string; requestHash: string; intent: any };
        replay: boolean;
      };
    };
    expect(prepared.data.preparedTransaction.id).toStartWith("ati_");
    expect(prepared.data.preparedTransaction.intent.transaction.value).toBe("1000");
    expect(prepared.data.preparedTransaction.requestHash).toHaveLength(64);

    const prepareReplay = await app.request("/application/transactions/prepare", {
      method: "POST",
      headers: applicationHeaders(issued, "prepare:001"),
      body: JSON.stringify(prepareBody),
    });
    expect(prepareReplay.status).toBe(200);
    expect(((await prepareReplay.json()) as any).data.preparedTransaction.id).toBe(
      prepared.data.preparedTransaction.id,
    );

    const conflict = await app.request("/application/transactions/prepare", {
      method: "POST",
      headers: applicationHeaders(issued, "prepare:001"),
      body: JSON.stringify({
        ...prepareBody,
        transaction: { ...prepareBody.transaction, value: "1001" },
      }),
    });
    expect(conflict.status).toBe(409);

    const proposeBody = {
      preparedTransactionId: prepared.data.preparedTransaction.id,
    };
    const proposalResponse = await app.request("/application/transactions/propose", {
      method: "POST",
      headers: applicationHeaders(issued, "proposal:001"),
      body: JSON.stringify(proposeBody),
    });
    expect(proposalResponse.status).toBe(202);
    const proposed = (await proposalResponse.json()) as {
      data: { proposal: { id: string; status: string } };
    };
    expect(proposed.data.proposal.id).toStartWith("atp_");
    expect(proposed.data.proposal.status).toBe("proposed");

    const proposalReplay = await app.request("/application/transactions/propose", {
      method: "POST",
      headers: applicationHeaders(issued, "proposal:001"),
      body: JSON.stringify(proposeBody),
    });
    expect(proposalReplay.status).toBe(200);

    const [walletRow] = await getDb()
      .select({ agentId: applicationWallets.stewardAgentId })
      .from(applicationWallets)
      .where(eq(applicationWallets.id, ensure.data.wallet.id));
    const signedRows = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.agentId, walletRow.agentId));
    expect(signedRows).toHaveLength(0);
    expect(await getDb().select().from(applicationTransactionProposals)).toHaveLength(1);

    const appAudits = await getDb()
      .select()
      .from(auditEvents)
      .where(
        and(eq(auditEvents.actorType, "application"), eq(auditEvents.actorId, issued.principal.id)),
      );
    expect(appAudits.map((event) => event.action)).toContain("application.wallet.ensure");
    expect(appAudits.map((event) => event.action)).toContain("application.transaction.prepare");
    expect(appAudits.map((event) => event.action)).toContain("application.transaction.propose");
    expect(appAudits.every((event) => event.actorId === issued.principal.id)).toBe(true);
  });

  it("reads proposal acceptance without inventing execution evidence", async () => {
    const [proposalBefore] = await getDb().select().from(applicationTransactionProposals);
    expect(proposalBefore).toBeDefined();

    const read = await app.request(`/application/transactions/proposals/${proposalBefore!.id}`, {
      headers: applicationHeaders(proposalCredential),
    });
    expect(read.status).toBe(200);
    expect(read.headers.get("Cache-Control")).toBe("no-store");
    const body = (await read.json()) as {
      data: {
        proposal: {
          id: string;
          intentId: string;
          status: string;
          terminal: boolean;
          resource: { kind: string; id: string; walletId: string };
          executionEvidence: { status: string; evidence: unknown; reason: string };
        };
      };
    };
    expect(body.data.proposal).toMatchObject({
      id: proposalBefore!.id,
      intentId: proposalBefore!.intentId,
      status: "proposed",
      terminal: false,
      executionEvidence: {
        status: "unknown",
        evidence: null,
        reason: "no_canonical_execution_linkage",
      },
    });
    expect(body.data.proposal.resource.kind).toBe("wallet_owner");
    expect(body.data.proposal.resource.id).toBe("investor:001");

    const replay = await app.request(`/application/transactions/proposals/${proposalBefore!.id}`, {
      headers: applicationHeaders(proposalCredential),
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(body);
    expect(await getDb().select().from(transactions)).toHaveLength(0);
    const [proposalAfter] = await getDb()
      .select()
      .from(applicationTransactionProposals)
      .where(eq(applicationTransactionProposals.id, proposalBefore!.id));
    expect(proposalAfter).toEqual(proposalBefore);

    const readAudits = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, "application.transaction_proposal.read"));
    expect(readAudits).toHaveLength(2);
    expect(readAudits.every((event) => event.actorId === proposalCredential.principal.id)).toBe(
      true,
    );
    expect(
      readAudits.every(
        (event) =>
          event.resourceId === proposalBefore!.id &&
          event.metadata?.executionEvidenceStatus === "unknown",
      ),
    ).toBe(true);
  });

  it("fails closed for proposal read capability, identity, tenant, credential, and identifiers", async () => {
    const [ownedProposal] = await getDb().select().from(applicationTransactionProposals);
    expect(ownedProposal).toBeDefined();

    const noRead = await issuePrincipal(
      "No proposal read",
      ["wallet:ensure", "transaction:propose"],
      ["owner:no-read"],
    );
    const capabilityDenied = await app.request(
      `/application/transactions/proposals/${ownedProposal!.id}`,
      { headers: applicationHeaders(noRead) },
    );
    expect(capabilityDenied.status).toBe(403);

    const otherPrincipal = await issuePrincipal(
      "Other proposal reader",
      ["transaction:proposal:read"],
      ["owner:other-reader"],
    );
    const crossPrincipal = await app.request(
      `/application/transactions/proposals/${ownedProposal!.id}`,
      { headers: applicationHeaders(otherPrincipal) },
    );
    const unknown = await app.request(`/application/transactions/proposals/atp_${"f".repeat(40)}`, {
      headers: applicationHeaders(otherPrincipal),
    });
    expect(crossPrincipal.status).toBe(404);
    expect(unknown.status).toBe(404);
    const enumerationResistantBody = await unknown.text();
    expect(await crossPrincipal.text()).toBe(enumerationResistantBody);

    const tenantBKey = generateApiKey();
    const tenantB = `${TENANT_ID}-b`;
    await getDb()
      .insert(tenants)
      .values({ id: tenantB, name: "Application Boundary B", apiKeyHash: tenantBKey.hash });
    const tenantBResponse = await app.request("/application-principals", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Tenant": tenantB,
        "X-Steward-Key": tenantBKey.key,
      },
      body: JSON.stringify({
        name: "Cross tenant proposal reader",
        capabilities: ["transaction:proposal:read"],
        resources: [{ kind: "wallet_owner", id: "owner:tenant-b" }],
        expiresAt: FAR_FUTURE,
        credentialExpiresAt: CREDENTIAL_FUTURE,
      }),
    });
    expect(tenantBResponse.status).toBe(201);
    const tenantBPrincipal = ((await tenantBResponse.json()) as { data: IssuedPrincipal }).data;
    const crossTenant = await app.request(
      `/application/transactions/proposals/${ownedProposal!.id}`,
      { headers: applicationHeaders(tenantBPrincipal) },
    );
    expect(crossTenant.status).toBe(404);
    expect(await crossTenant.text()).toBe(enumerationResistantBody);

    for (const malformed of [
      "atp_",
      `atp_${"g".repeat(40)}`,
      `atp_${"a".repeat(39)}`,
      `atp_${"a".repeat(41)}`,
      "../atp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]) {
      const response = await app.request(
        `/application/transactions/proposals/${encodeURIComponent(malformed)}`,
        { headers: applicationHeaders(proposalCredential) },
      );
      expect(response.status, malformed).toBe(400);
    }

    const wrongSecret = await app.request(
      `/application/transactions/proposals/${ownedProposal!.id}`,
      {
        headers: {
          ...applicationHeaders(proposalCredential),
          "X-Steward-Application-Secret": `aps_${"f".repeat(64)}`,
        },
      },
    );
    expect(wrongSecret.status).toBe(401);

    const lifecycle = await issuePrincipal(
      "Credential lifecycle reader",
      ["transaction:proposal:read"],
      ["owner:lifecycle-reader"],
    );
    const rotate = await app.request(`/application-principals/${lifecycle.principal.id}/rotate`, {
      method: "POST",
      headers: tenantHeaders(),
      body: JSON.stringify({
        credentialExpiresAt: new Date(Date.now() + 250).toISOString(),
      }),
    });
    expect(rotate.status).toBe(200);
    const rotatedCredential = (await rotate.json()) as {
      data: { keyId: string; secret: string };
    };
    const revoked = await app.request(`/application/transactions/proposals/${ownedProposal!.id}`, {
      headers: applicationHeaders(lifecycle),
    });
    expect(revoked.status).toBe(401);
    const rotated: IssuedPrincipal = {
      principal: lifecycle.principal,
      credential: rotatedCredential.data,
    };
    const activeButUnowned = await app.request(
      `/application/transactions/proposals/${ownedProposal!.id}`,
      { headers: applicationHeaders(rotated) },
    );
    expect(activeButUnowned.status).toBe(404);
    await Bun.sleep(300);
    const expired = await app.request(`/application/transactions/proposals/${ownedProposal!.id}`, {
      headers: applicationHeaders(rotated),
    });
    expect(expired.status).toBe(401);
  });

  it("enforces capability and assigned-resource ownership on every command", async () => {
    const ensureOnly = await issuePrincipal("Ensure only", ["wallet:ensure"], ["investor:cap"]);
    const deniedUnassigned = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(ensureOnly, "cap:other"),
      body: JSON.stringify({ resourceId: "investor:other" }),
    });
    expect(deniedUnassigned.status).toBe(403);

    const ensured = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(ensureOnly, "cap:ensure"),
      body: JSON.stringify({ resourceId: "investor:cap" }),
    });
    const wallet = ((await ensured.json()) as any).data.wallet;

    expect(
      (
        await app.request(`/application/wallets/${wallet.id}/address`, {
          headers: applicationHeaders(ensureOnly),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request("/application/transactions/prepare", {
          method: "POST",
          headers: applicationHeaders(ensureOnly),
          body: "{}",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await app.request("/application/transactions/propose", {
          method: "POST",
          headers: applicationHeaders(ensureOnly),
          body: "{}",
        })
      ).status,
    ).toBe(403);

    const readOnly = await issuePrincipal("Read only", ["wallet:address:read"], ["investor:read"]);
    expect(
      (
        await app.request("/application/wallets/ensure", {
          method: "POST",
          headers: applicationHeaders(readOnly),
          body: "{}",
        })
      ).status,
    ).toBe(403);
  });

  it("prevents cross-principal and arbitrary resource access", async () => {
    const a = await issuePrincipal("A", ["wallet:ensure", "wallet:address:read"], ["owner:a"]);
    const b = await issuePrincipal("B", ["wallet:ensure", "wallet:address:read"], ["owner:b"]);
    const bEnsure = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(b, "cross:b"),
      body: JSON.stringify({ resourceId: "owner:b" }),
    });
    const bWallet = ((await bEnsure.json()) as any).data.wallet;
    expect(
      (
        await app.request(`/application/wallets/${bWallet.id}/address`, {
          headers: applicationHeaders(a),
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await app.request("/application/agents", {
          method: "POST",
          headers: applicationHeaders(a),
          body: JSON.stringify({ id: "arbitrary", name: "Arbitrary" }),
        })
      ).status,
    ).toBe(404);
  });

  it("uses uniform credential failures and enforces expiry at the next request", async () => {
    const expiresAt = new Date(Date.now() + 200).toISOString();
    const issued = await issuePrincipal(
      "Auth checks",
      ["wallet:ensure"],
      ["owner:auth"],
      FAR_FUTURE,
      expiresAt,
    );
    const wrongSecret = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: {
        ...applicationHeaders(issued, "auth:wrong"),
        "X-Steward-Application-Secret": "wrong",
      },
      body: "{}",
    });
    const unknownKey = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: {
        ...applicationHeaders(issued, "auth:unknown"),
        "X-Steward-Application-Key-Id": "apk_ffffffffffffffffffffffff",
        "X-Steward-Application-Secret": `aps_${"f".repeat(64)}`,
      },
      body: "{}",
    });
    expect(wrongSecret.status).toBe(401);
    expect(unknownKey.status).toBe(401);
    expect(await wrongSecret.text()).toBe(await unknownKey.text());
    const mixedApplicationAuth = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: {
        ...applicationHeaders(issued, "auth:mixed"),
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": tenantKey,
      },
      body: JSON.stringify({ resourceId: "owner:auth" }),
    });
    expect(mixedApplicationAuth.status).toBe(401);
    await Bun.sleep(250);
    const expired = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "auth:expired"),
      body: JSON.stringify({ resourceId: "owner:auth" }),
    });
    expect(expired.status).toBe(401);
  });

  it("rotates credentials and independently revokes the principal", async () => {
    const issued = await issuePrincipal("Lifecycle", ["wallet:ensure"], ["owner:lifecycle"]);
    const rotate = await app.request(`/application-principals/${issued.principal.id}/rotate`, {
      method: "POST",
      headers: tenantHeaders(),
      body: JSON.stringify({ credentialExpiresAt: CREDENTIAL_FUTURE }),
    });
    expect(rotate.status).toBe(200);
    const rotated = (await rotate.json()) as { data: { keyId: string; secret: string } };

    expect(
      (
        await app.request("/application/wallets/ensure", {
          method: "POST",
          headers: applicationHeaders(issued),
          body: "{}",
        })
      ).status,
    ).toBe(401);

    const rotatedIssued: IssuedPrincipal = {
      principal: issued.principal,
      credential: rotated.data,
    };
    const active = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(rotatedIssued, "lifecycle:new"),
      body: JSON.stringify({ resourceId: "owner:lifecycle" }),
    });
    expect(active.status).toBe(201);

    const revoke = await app.request(`/application-principals/${issued.principal.id}/revoke`, {
      method: "POST",
      headers: tenantHeaders(),
    });
    expect(revoke.status).toBe(200);
    expect(
      (
        await app.request("/application/wallets/ensure", {
          method: "POST",
          headers: applicationHeaders(rotatedIssued),
          body: "{}",
        })
      ).status,
    ).toBe(401);
  });

  it("rolls back agent, keys, addresses, binding, and idempotency together", async () => {
    const issued = await issuePrincipal("Atomic", ["wallet:ensure"], ["owner:atomic"]);
    const agentId = deterministicId(
      "appw",
      "application-wallet-agent",
      TENANT_ID,
      issued.principal.id,
      "wallet_owner",
      "owner:atomic",
    ).slice(0, 64);

    await getDb().execute(sql`
      CREATE FUNCTION fail_atomic_application_wallet() RETURNS trigger AS $$
      BEGIN
        IF NEW.resource_id = 'owner:atomic' THEN
          RAISE EXCEPTION 'injected binding failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);
    await getDb().execute(sql`
      CREATE TRIGGER fail_atomic_application_wallet_trigger
      BEFORE INSERT ON application_wallets
      FOR EACH ROW EXECUTE FUNCTION fail_atomic_application_wallet();
    `);

    const failed = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "atomic:failure"),
      body: JSON.stringify({ resourceId: "owner:atomic" }),
    });
    expect(failed.status).toBe(500);
    expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(0);
    expect(
      await getDb().select().from(encryptedKeys).where(eq(encryptedKeys.agentId, agentId)),
    ).toHaveLength(0);
    expect(
      await getDb()
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, agentId)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, agentId)),
    ).toHaveLength(0);
    expect(
      await getDb()
        .select()
        .from(applicationIdempotencyRecords)
        .where(
          and(
            eq(applicationIdempotencyRecords.tenantId, TENANT_ID),
            eq(applicationIdempotencyRecords.principalId, issued.principal.id),
            eq(applicationIdempotencyRecords.idempotencyKey, "atomic:failure"),
          ),
        ),
    ).toHaveLength(0);

    await getDb().execute(
      sql`DROP TRIGGER fail_atomic_application_wallet_trigger ON application_wallets`,
    );
    await getDb().execute(sql`DROP FUNCTION fail_atomic_application_wallet()`);

    const [first, second] = await Promise.all([
      app.request("/application/wallets/ensure", {
        method: "POST",
        headers: applicationHeaders(issued, "atomic:success"),
        body: JSON.stringify({ resourceId: "owner:atomic" }),
      }),
      app.request("/application/wallets/ensure", {
        method: "POST",
        headers: applicationHeaders(issued, "atomic:success"),
        body: JSON.stringify({ resourceId: "owner:atomic" }),
      }),
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 201]);
    expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(1);
    expect(
      await getDb()
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, agentId)),
    ).toHaveLength(2);
  });

  it("rejects unknown capabilities, execution-field smuggling, and ownership mutation", async () => {
    const unknown = await app.request("/application-principals", {
      method: "POST",
      headers: tenantHeaders(),
      body: JSON.stringify({
        name: "Unknown capability",
        capabilities: ["wallet:*"],
        resources: [{ kind: "wallet_owner", id: "owner:unknown" }],
        expiresAt: FAR_FUTURE,
        credentialExpiresAt: CREDENTIAL_FUTURE,
      }),
    });
    expect(unknown.status).toBe(400);

    const issued = await issuePrincipal(
      "Strict",
      ["wallet:ensure", "transaction:prepare", "transaction:propose"],
      ["owner:strict"],
    );
    const smuggledEnsure = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "strict:ensure"),
      body: JSON.stringify({ resourceId: "owner:strict", agentId: "caller-controlled" }),
    });
    expect(smuggledEnsure.status).toBe(400);

    for (const field of [
      "broadcast",
      "approve",
      "signature",
      "signedTx",
      "status",
      "actorId",
      "tenantId",
      "principalId",
    ]) {
      const response = await app.request("/application/transactions/propose", {
        method: "POST",
        headers: applicationHeaders(issued, `strict:${field}`),
        body: JSON.stringify({ preparedTransactionId: "ati_missing", [field]: true }),
      });
      expect(response.status, field).toBe(400);
    }

    const ensured = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued, "strict:valid"),
      body: JSON.stringify({ resourceId: "owner:strict" }),
    });
    const walletId = ((await ensured.json()) as any).data.wallet.id as string;
    let immutableError: unknown;
    try {
      await getDb()
        .update(applicationWallets)
        .set({ resourceId: "owner:laundered" })
        .where(
          and(
            eq(applicationWallets.tenantId, TENANT_ID),
            eq(applicationWallets.principalId, issued.principal.id),
            eq(applicationWallets.id, walletId),
          ),
        );
    } catch (error) {
      immutableError = error;
    }
    expect(immutableError).toBeDefined();
    const [unchangedWallet] = await getDb()
      .select()
      .from(applicationWallets)
      .where(
        and(
          eq(applicationWallets.tenantId, TENANT_ID),
          eq(applicationWallets.principalId, issued.principal.id),
          eq(applicationWallets.id, walletId),
        ),
      );
    expect(unchangedWallet!.resourceId).toBe("owner:strict");
  });

  it("enforces tenant+principal composition in database foreign keys", async () => {
    const a = await issuePrincipal(
      "Composition A",
      ["wallet:ensure", "transaction:prepare", "transaction:propose"],
      ["owner:composition-a"],
    );
    const b = await issuePrincipal(
      "Composition B",
      ["wallet:ensure", "transaction:prepare", "transaction:propose"],
      ["owner:composition-b"],
    );
    const walletResponse = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(a, "composition:wallet"),
      body: JSON.stringify({ resourceId: "owner:composition-a" }),
    });
    const walletId = ((await walletResponse.json()) as any).data.wallet.id as string;
    const [credentialB] = await getDb()
      .select()
      .from(applicationPrincipalCredentials)
      .where(
        and(
          eq(applicationPrincipalCredentials.tenantId, TENANT_ID),
          eq(applicationPrincipalCredentials.principalId, b.principal.id),
        ),
      );
    let intentCompositionError: unknown;
    try {
      await getDb()
        .insert(applicationTransactionIntents)
        .values({
          id: "ati_cross_principal",
          tenantId: TENANT_ID,
          principalId: b.principal.id,
          credentialKeyId: credentialB!.keyId,
          walletId,
          requestHash: "a".repeat(64),
          intent: {},
          expiresAt: new Date(FAR_FUTURE),
        });
    } catch (error) {
      intentCompositionError = error;
    }
    expect(intentCompositionError).toBeDefined();

    const [intentA] = await getDb()
      .select()
      .from(applicationTransactionIntents)
      .where(eq(applicationTransactionIntents.principalId, a.principal.id));
    if (intentA) {
      expect(
        getDb()
          .insert(applicationTransactionProposals)
          .values({
            id: "atp_cross_principal",
            tenantId: TENANT_ID,
            principalId: b.principal.id,
            credentialKeyId: credentialB!.keyId,
            intentId: intentA.id,
            requestHash: "b".repeat(64),
            status: "proposed",
          }),
      ).rejects.toThrow();
    }
  });

  it("keeps exact proposal IDs outside every legacy sign/approve/reject state machine", async () => {
    const [proposal] = await getDb().select().from(applicationTransactionProposals);
    const [wallet] = await getDb().select().from(applicationWallets);
    expect(proposal).toBeDefined();
    expect(wallet).toBeDefined();
    const proposalBefore = JSON.stringify(proposal);
    const signSpies = [
      spyOn(vault, "signTransaction"),
      spyOn(vault, "signMessage"),
      spyOn(vault, "signTypedData"),
      spyOn(vault, "signSolanaTransaction"),
      spyOn(vault, "rpcPassthrough"),
    ];

    const routes: Array<[string, string]> = [
      ["POST", `/vault/${wallet!.stewardAgentId}/approve/${proposal!.id}`],
      ["POST", `/vault/${wallet!.stewardAgentId}/reject/${proposal!.id}`],
      ["POST", `/approvals/${proposal!.id}/approve`],
      ["POST", `/approvals/${proposal!.id}/deny`],
    ];
    for (const [method, path] of routes) {
      const applicationResponse = await app.request(path, {
        method,
        headers: applicationHeaders(proposalCredential),
        body: "{}",
      });
      expect(applicationResponse.status).toBe(403);
      const legacyResponse = await app.request(path, {
        method,
        headers: tenantHeaders(),
        body: "{}",
      });
      expect([400, 404, 409]).toContain(legacyResponse.status);
    }
    const applicationSignAttempt = await app.request(`/vault/${wallet!.stewardAgentId}/sign`, {
      method: "POST",
      headers: applicationHeaders(proposalCredential),
      body: JSON.stringify({ txId: proposal!.id }),
    });
    expect(applicationSignAttempt.status).toBe(403);
    const legacySignAttempt = await app.request(`/vault/${wallet!.stewardAgentId}/sign`, {
      method: "POST",
      headers: tenantHeaders(),
      body: JSON.stringify({ txId: proposal!.id }),
    });
    expect(legacySignAttempt.status).toBe(400);
    expect(signSpies.every((spy) => spy.mock.calls.length === 0)).toBe(true);
    for (const spy of signSpies) spy.mockRestore();
    expect(await getDb().select().from(transactions)).toHaveLength(0);
    const [proposalAfter] = await getDb()
      .select()
      .from(applicationTransactionProposals)
      .where(
        and(
          eq(applicationTransactionProposals.tenantId, proposal!.tenantId),
          eq(applicationTransactionProposals.principalId, proposal!.principalId),
          eq(applicationTransactionProposals.id, proposal!.id),
        ),
      );
    expect(JSON.stringify(proposalAfter)).toBe(proposalBefore);
  });

  it("keeps proposal persistence statically disconnected from Vault and execution modules", () => {
    const source = readFileSync(
      new URL("../services/application-proposals.ts", import.meta.url),
      "utf8",
    );
    const imports = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]);
    expect(
      imports.some((path) =>
        /vault|context|approval|rpc|broadcast|transaction-execution/i.test(path),
      ),
    ).toBe(false);
  });

  it("denies application credentials across every mounted non-application route and method", async () => {
    const issued = await issuePrincipal("Dynamic matrix", ["wallet:ensure"], ["owner:dynamic"]);
    const methods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
    const routes = [
      ...new Map(
        app.routes
          .filter(
            (route) =>
              methods.has(route.method) &&
              !route.path.startsWith("/application/") &&
              route.path !== "/application",
          )
          .map((route) => [`${route.method} ${route.path}`, route] as const),
      ).values(),
    ];
    expect(routes.length).toBeGreaterThan(50);
    for (const route of routes) {
      const path = route.path.replace(/:([A-Za-z0-9_]+)/g, "matrix").replace(/\*/g, "matrix");
      const response = await app.request(path, {
        method: route.method,
        headers: applicationHeaders(issued),
        body: route.method === "GET" || route.method === "DELETE" ? undefined : "{}",
      });
      expect(response.status, `${route.method} ${route.path}`).toBe(403);
    }
  });

  it("denies application credentials across the complete legacy custody/admin route matrix", async () => {
    const issued = await issuePrincipal(
      "Matrix",
      ["wallet:ensure", "wallet:address:read", "transaction:prepare", "transaction:propose"],
      ["owner:matrix"],
    );
    const routes: Array<[string, string]> = [
      ["POST", "/vault/x/sign"],
      ["POST", "/vault/x/sign-message"],
      ["POST", "/vault/x/sign-typed-data"],
      ["POST", "/vault/x/sign-solana"],
      ["POST", "/vault/x/import"],
      ["POST", "/vault/x/export"],
      ["POST", "/vault/x/rpc"],
      ["POST", "/vault/x/approve/y"],
      ["POST", "/vault/x/reject/y"],
      ["GET", "/vault/x/pending"],
      ["GET", "/vault/x/history"],
      ["GET", "/vault/x/addresses"],
      ["POST", "/agents/x/token"],
      ["POST", "/agents/x/wallets"],
      ["DELETE", "/agents/x"],
      ["POST", "/agents/batch"],
      ["GET", "/agents/x/policies"],
      ["PUT", "/agents/x/policies"],
      ["POST", "/tenants"],
      ["GET", `/tenants/${TENANT_ID}`],
      ["PUT", `/tenants/${TENANT_ID}/webhook`],
      ["GET", "/policies"],
      ["POST", "/policies"],
      ["GET", "/policies/x"],
      ["PUT", "/policies/x"],
      ["DELETE", "/policies/x"],
      ["POST", "/policies/x/assign"],
      ["POST", "/policies/simulate"],
      ["POST", "/webhooks"],
      ["GET", "/webhooks"],
      ["PUT", "/webhooks/x"],
      ["DELETE", "/webhooks/x"],
      ["GET", "/webhooks/x/deliveries"],
      ["POST", "/webhooks/deliveries/x/retry"],
      ["POST", "/secrets"],
      ["GET", "/secrets"],
      ["POST", "/secrets/routes"],
      ["GET", "/secrets/routes"],
      ["PUT", "/secrets/routes/x"],
      ["DELETE", "/secrets/routes/x"],
      ["GET", "/secrets/x"],
      ["PUT", "/secrets/x"],
      ["DELETE", "/secrets/x"],
      ["POST", "/secrets/x/rotate"],
      ["POST", "/application-principals"],
      ["POST", `/application-principals/${issued.principal.id}/rotate`],
      ["POST", `/application-principals/${issued.principal.id}/revoke`],
    ];

    for (const [method, path] of routes) {
      const response = await app.request(path, {
        method,
        headers: applicationHeaders(issued),
        body: method === "GET" || method === "DELETE" ? undefined : "{}",
      });
      expect(response.status, `${method} ${path}`).toBe(403);
      expect(await response.text()).toContain("Application credentials are not accepted");
    }

    const mixedCredentialAttempt = await app.request("/vault/x/sign", {
      method: "POST",
      headers: { ...tenantHeaders(), ...applicationHeaders(issued) },
      body: "{}",
    });
    expect(mixedCredentialAttempt.status).toBe(403);
    expect(await mixedCredentialAttempt.text()).toContain(
      "Application credentials are not accepted",
    );
  });

  /**
   * The independent security review probed these by hand and they all held, but
   * a probe that lives only in a review document is not a control — it protects
   * the commit it was run against and nothing after it. Encoding them here makes
   * the negative authorization matrix a STANDING artifact.
   *
   * Note the sibling test above already enumerates `app.routes` dynamically, so
   * newly mounted routes are covered automatically. What that cannot cover is
   * paths that never appear in the route table: normalization tricks aimed at
   * reaching a custody route while dodging the `/application/*` prefix guard.
   */
  it("denies application credentials on path-normalization attempts against custody routes", async () => {
    const issued = await issuePrincipal("Normalization", ["wallet:ensure"], ["owner:norm"]);
    const attempts = [
      "/application/../vault/x/sign",
      "/application/..%2fvault/x/sign",
      "//application/wallets/ensure",
      "/Application/wallets/ensure",
      "/APPLICATION/wallets/ensure",
      "/application//../vault/x/sign",
      "/./application/../vault/x/sign",
    ];
    let sawGuardDenial = false;
    for (const path of attempts) {
      const response = await app.request(path, {
        method: "POST",
        headers: applicationHeaders(issued),
        body: "{}",
      });
      // 401 = committed to application auth and rejected. 403 = the prefix
      // guard denied it. 404 = the encoded path matched no route at all
      // (`%2f` is not decoded into a separator, which is itself the safe
      // behaviour). All three mean the request never reached a custody handler.
      //
      // A blanket `>= 400` would let this pass even if EVERY path merely
      // 404'd — a guard proven to work by never being invoked. The
      // `sawGuardDenial` assertion below forecloses that: at least one path
      // must reach the guard and be actively denied 403.
      expect([401, 403, 404], `POST ${path} -> ${response.status}`).toContain(response.status);
      if (response.status === 403) sawGuardDenial = true;
    }
    // Proves the loop above is not vacuous: the guard was genuinely exercised.
    expect(sawGuardDenial).toBe(true);
  });

  it("rejects every application-credential header combination on a custody route", async () => {
    const issued = await issuePrincipal("Header mixes", ["wallet:ensure"], ["owner:mix"]);
    const base = { "Content-Type": "application/json" };
    const keyId = { "X-Steward-Application-Key-Id": issued.credential.keyId };
    const secret = { "X-Steward-Application-Secret": issued.credential.secret };
    const mixes: Array<[string, Record<string, string>]> = [
      ["key-id only", { ...base, ...keyId }],
      ["secret only", { ...base, ...secret }],
      ["both", { ...base, ...keyId, ...secret }],
      ["empty key-id", { ...base, "X-Steward-Application-Key-Id": "" }],
      ["whitespace key-id", { ...base, "X-Steward-Application-Key-Id": "   " }],
      ["empty secret", { ...base, ...keyId, "X-Steward-Application-Secret": "" }],
    ];
    for (const [label, headers] of mixes) {
      const response = await app.request("/vault/x/sign", { method: "POST", headers, body: "{}" });
      expect(response.status, `custody sign with ${label}`).toBe(403);
    }
  });
});
