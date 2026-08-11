import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  agents,
  applicationIdempotencyRecords,
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  getDb,
  tenants,
  transactions,
} from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";
import { deterministicId } from "../services/application-boundary";

const SKIP = !process.env.DATABASE_URL;
const BASE_URL = `http://127.0.0.1:${process.env.PORT ?? "3299"}`;
const runId = crypto.randomUUID().replaceAll("-", "");
const tenantIds = [`app-pg-a-${runId}`, `app-pg-b-${runId}`];
const tenantKeys = [generateApiKey(), generateApiKey()];

type Issued = {
  principal: { id: string };
  credential: { keyId: string; secret: string };
};

function tenantHeaders(index: number) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": tenantIds[index]!,
    "X-Steward-Key": tenantKeys[index]!.key,
  };
}

function appHeaders(issued: Issued, idempotencyKey: string) {
  return {
    "Content-Type": "application/json",
    "X-Steward-Application-Key-Id": issued.credential.keyId,
    "X-Steward-Application-Secret": issued.credential.secret,
    "Idempotency-Key": idempotencyKey,
  };
}

async function issue(index: number, resourceId: string): Promise<Issued> {
  const response = await fetch(`${BASE_URL}/application-principals`, {
    method: "POST",
    headers: tenantHeaders(index),
    body: JSON.stringify({
      name: `Postgres application ${index}`,
      capabilities: [
        "wallet:ensure",
        "wallet:address:read",
        "transaction:prepare",
        "transaction:propose",
      ],
      resources: [{ kind: "wallet_owner", id: resourceId }],
      expiresAt: "2030-01-01T00:00:00.000Z",
      credentialExpiresAt: "2029-01-01T00:00:00.000Z",
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { data: Issued }).data;
}

beforeAll(async () => {
  if (SKIP) return;
  await getDb()
    .insert(tenants)
    .values([
      { id: tenantIds[0]!, name: "Application PG A", apiKeyHash: tenantKeys[0]!.hash },
      { id: tenantIds[1]!, name: "Application PG B", apiKeyHash: tenantKeys[1]!.hash },
    ]);
});

afterAll(async () => {
  if (SKIP) return;
  await getDb().delete(tenants).where(eq(tenants.id, tenantIds[0]!));
  await getDb().delete(tenants).where(eq(tenants.id, tenantIds[1]!));
});

describe.skipIf(SKIP)("application principal real Postgres concurrency", () => {
  it("serializes concurrent replays durably and isolates equal keys across tenant/principal scopes", async () => {
    const resourceId = `postgres:concurrency:${runId}`;
    const [a, b] = await Promise.all([issue(0, resourceId), issue(1, resourceId)]);

    const ensure = (issued: Issued) =>
      fetch(`${BASE_URL}/application/wallets/ensure`, {
        method: "POST",
        headers: appHeaders(issued, "same-idempotency-key"),
        body: JSON.stringify({ resourceId }),
      });
    const responses = await Promise.all(Array.from({ length: 20 }, () => ensure(a)));
    expect(responses.filter((response) => response.status === 201)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 200)).toHaveLength(19);
    const payloads = await Promise.all(
      responses.map((response) => response.json() as Promise<any>),
    );
    const walletIds = new Set(payloads.map((payload) => payload.data.wallet.id));
    expect(walletIds.size).toBe(1);
    const walletId = [...walletIds][0] as string;

    const bWalletResponse = await ensure(b);
    expect(bWalletResponse.status).toBe(201);
    const bWalletId = ((await bWalletResponse.json()) as any).data.wallet.id as string;
    expect(bWalletId).not.toBe(walletId);

    const prepareBody = {
      walletId,
      network: { type: "evm", chainId: 8453 },
      transaction: { to: `0x${"ab".repeat(20)}`, value: "1000", data: "0x" },
    };
    const prepare = () =>
      fetch(`${BASE_URL}/application/transactions/prepare`, {
        method: "POST",
        headers: appHeaders(a, "prepare-concurrent"),
        body: JSON.stringify(prepareBody),
      });
    const preparedResponses = await Promise.all(Array.from({ length: 20 }, prepare));
    expect(preparedResponses.filter((response) => response.status === 201)).toHaveLength(1);
    expect(preparedResponses.filter((response) => response.status === 200)).toHaveLength(19);
    const preparedPayloads = await Promise.all(
      preparedResponses.map((response) => response.json() as Promise<any>),
    );
    const intentIds = new Set(
      preparedPayloads.map((payload) => payload.data.preparedTransaction.id),
    );
    expect(intentIds.size).toBe(1);
    const intentId = [...intentIds][0] as string;

    const proposalResponses = await Promise.all(
      Array.from({ length: 20 }, () =>
        fetch(`${BASE_URL}/application/transactions/propose`, {
          method: "POST",
          headers: appHeaders(a, "proposal-concurrent"),
          body: JSON.stringify({ preparedTransactionId: intentId }),
        }),
      ),
    );
    expect(proposalResponses.filter((response) => response.status === 202)).toHaveLength(1);
    expect(proposalResponses.filter((response) => response.status === 200)).toHaveLength(19);

    const conflict = await fetch(`${BASE_URL}/application/transactions/prepare`, {
      method: "POST",
      headers: appHeaders(a, "prepare-concurrent"),
      body: JSON.stringify({
        ...prepareBody,
        transaction: { ...prepareBody.transaction, value: "1001" },
      }),
    });
    expect(conflict.status).toBe(409);

    expect(
      await getDb()
        .select()
        .from(applicationWallets)
        .where(eq(applicationWallets.resourceId, resourceId)),
    ).toHaveLength(2);
    expect(
      await getDb()
        .select()
        .from(applicationTransactionIntents)
        .where(
          and(
            eq(applicationTransactionIntents.tenantId, tenantIds[0]!),
            eq(applicationTransactionIntents.principalId, a.principal.id),
          ),
        ),
    ).toHaveLength(1);
    expect(
      await getDb()
        .select()
        .from(applicationTransactionProposals)
        .where(
          and(
            eq(applicationTransactionProposals.tenantId, tenantIds[0]!),
            eq(applicationTransactionProposals.principalId, a.principal.id),
          ),
        ),
    ).toHaveLength(1);
    expect(
      await getDb()
        .select()
        .from(applicationIdempotencyRecords)
        .where(eq(applicationIdempotencyRecords.idempotencyKey, "same-idempotency-key")),
    ).toHaveLength(2);
    expect(await getDb().select().from(transactions)).toHaveLength(0);
  });

  it("rolls back a real Postgres failure injected after key/address writes", async () => {
    const resourceId = `postgres:rollback:${runId}`;
    const issued = await issue(0, resourceId);
    const agentId = deterministicId(
      "appw",
      "application-wallet-agent",
      tenantIds[0]!,
      issued.principal.id,
      "wallet_owner",
      resourceId,
    ).slice(0, 64);

    await getDb().execute(
      sql.raw(`
      CREATE FUNCTION fail_application_wallet_${runId}() RETURNS trigger AS $$
      BEGIN
        IF NEW.resource_id = '${resourceId}' THEN
          RAISE EXCEPTION 'injected binding failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
      CREATE TRIGGER fail_application_wallet_${runId}
      BEFORE INSERT ON application_wallets
      FOR EACH ROW EXECUTE FUNCTION fail_application_wallet_${runId}();
    `),
    );
    const failed = await fetch(`${BASE_URL}/application/wallets/ensure`, {
      method: "POST",
      headers: appHeaders(issued, "rollback-key"),
      body: JSON.stringify({ resourceId }),
    });
    expect(failed.status).toBe(500);
    expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(0);
    expect(
      await getDb()
        .select()
        .from(applicationIdempotencyRecords)
        .where(
          and(
            eq(applicationIdempotencyRecords.tenantId, tenantIds[0]!),
            eq(applicationIdempotencyRecords.principalId, issued.principal.id),
            eq(applicationIdempotencyRecords.idempotencyKey, "rollback-key"),
          ),
        ),
    ).toHaveLength(0);
    await getDb().execute(
      sql.raw(`
      DROP TRIGGER fail_application_wallet_${runId} ON application_wallets;
      DROP FUNCTION fail_application_wallet_${runId}();
    `),
    );
  });
});
