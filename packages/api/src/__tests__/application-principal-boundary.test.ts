import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  applicationPrincipalCredentials,
  applicationPrincipals,
  applicationTransactionProposals,
  applicationWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT_ID = "application-boundary-test";
const FAR_FUTURE = "2030-01-01T00:00:00.000Z";
const CREDENTIAL_FUTURE = "2029-01-01T00:00:00.000Z";

let app: Hono;
let tenantKey: string;

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

function applicationHeaders(issued: IssuedPrincipal) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Application-Key-Id": issued.credential.keyId,
    "X-Steward-Application-Secret": issued.credential.secret,
  };
}

async function issuePrincipal(
  name: string,
  capabilities: string[],
  ownerReferences: string[],
): Promise<IssuedPrincipal> {
  const response = await app.request("/application-principals", {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      name,
      capabilities,
      ownerReferences,
      expiresAt: FAR_FUTURE,
      credentialExpiresAt: CREDENTIAL_FUTURE,
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
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe.serial("application principal custody boundary", () => {
  it("executes only the deterministic four-command contract and never signs or broadcasts", async () => {
    const issued = await issuePrincipal(
      "Strata API",
      ["ensure_wallet", "read_wallet_address", "prepare_transaction", "propose_transaction"],
      ["investor:001"],
    );
    expect(issued.principal.id).toStartWith("app_");
    expect(issued.credential.secret).toStartWith("aps_");

    const ensureResponse = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued),
      body: JSON.stringify({ ownerReference: "investor:001", chainFamily: "evm" }),
    });
    expect(ensureResponse.status).toBe(201);
    const ensure = (await ensureResponse.json()) as {
      data: { wallet: { id: string; address: string }; replay: boolean };
    };
    expect(ensure.data.wallet.id).toStartWith("aw_");
    expect(ensure.data.wallet.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(ensure.data.replay).toBe(false);

    const replayEnsure = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued),
      body: JSON.stringify({ ownerReference: "investor:001", chainFamily: "evm" }),
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
      idempotencyKey: "prepare:001",
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
      headers: applicationHeaders(issued),
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
      headers: applicationHeaders(issued),
      body: JSON.stringify(prepareBody),
    });
    expect(prepareReplay.status).toBe(200);
    expect(((await prepareReplay.json()) as any).data.preparedTransaction.id).toBe(
      prepared.data.preparedTransaction.id,
    );

    const conflict = await app.request("/application/transactions/prepare", {
      method: "POST",
      headers: applicationHeaders(issued),
      body: JSON.stringify({
        ...prepareBody,
        transaction: { ...prepareBody.transaction, value: "1001" },
      }),
    });
    expect(conflict.status).toBe(409);

    const proposeBody = {
      idempotencyKey: "proposal:001",
      preparedTransactionId: prepared.data.preparedTransaction.id,
    };
    const proposalResponse = await app.request("/application/transactions/propose", {
      method: "POST",
      headers: applicationHeaders(issued),
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
      headers: applicationHeaders(issued),
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

  it("enforces capability and assigned-resource ownership on every command", async () => {
    const ensureOnly = await issuePrincipal("Ensure only", ["ensure_wallet"], ["investor:cap"]);
    const deniedUnassigned = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(ensureOnly),
      body: JSON.stringify({ ownerReference: "investor:other", chainFamily: "evm" }),
    });
    expect(deniedUnassigned.status).toBe(403);

    const ensured = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(ensureOnly),
      body: JSON.stringify({ ownerReference: "investor:cap", chainFamily: "evm" }),
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

    const readOnly = await issuePrincipal("Read only", ["read_wallet_address"], ["investor:read"]);
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
    const a = await issuePrincipal("A", ["ensure_wallet", "read_wallet_address"], ["owner:a"]);
    const b = await issuePrincipal("B", ["ensure_wallet", "read_wallet_address"], ["owner:b"]);
    const bEnsure = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(b),
      body: JSON.stringify({ ownerReference: "owner:b", chainFamily: "evm" }),
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

  it("uses generic, constant-time credential validation behavior and enforces expiry", async () => {
    const issued = await issuePrincipal("Auth checks", ["ensure_wallet"], ["owner:auth"]);
    const wrongSecret = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: { ...applicationHeaders(issued), "X-Steward-Application-Secret": "wrong" },
      body: "{}",
    });
    const unknownKey = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: { ...applicationHeaders(issued), "X-Steward-Application-Key-Id": "apk_unknown" },
      body: "{}",
    });
    expect(wrongSecret.status).toBe(401);
    expect(unknownKey.status).toBe(401);
    expect(await wrongSecret.text()).toBe(await unknownKey.text());

    await getDb()
      .update(applicationPrincipalCredentials)
      .set({ expiresAt: new Date("2000-01-01T00:00:00Z") })
      .where(eq(applicationPrincipalCredentials.keyId, issued.credential.keyId));
    const expired = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued),
      body: "{}",
    });
    expect(expired.status).toBe(401);

    await getDb()
      .update(applicationPrincipalCredentials)
      .set({ expiresAt: new Date(CREDENTIAL_FUTURE) })
      .where(eq(applicationPrincipalCredentials.keyId, issued.credential.keyId));
    await getDb()
      .update(applicationPrincipals)
      .set({ expiresAt: new Date("2000-01-01T00:00:00Z") })
      .where(eq(applicationPrincipals.id, issued.principal.id));
    const principalExpired = await app.request("/application/wallets/ensure", {
      method: "POST",
      headers: applicationHeaders(issued),
      body: "{}",
    });
    expect(principalExpired.status).toBe(401);
  });

  it("rotates credentials and independently revokes the principal", async () => {
    const issued = await issuePrincipal("Lifecycle", ["ensure_wallet"], ["owner:lifecycle"]);
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
      headers: applicationHeaders(rotatedIssued),
      body: JSON.stringify({ ownerReference: "owner:lifecycle", chainFamily: "evm" }),
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

  it("denies application credentials across the complete legacy custody/admin route matrix", async () => {
    const issued = await issuePrincipal(
      "Matrix",
      ["ensure_wallet", "read_wallet_address", "prepare_transaction", "propose_transaction"],
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
});
