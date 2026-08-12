import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { hashApiKey } from "@stwd/auth";
import { createPostgresClient } from "@stwd/db";

const SKIP = !process.env.DATABASE_URL;
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const databaseName = `steward_strata987_${runId}`;
const port = 40_000 + Math.floor(Math.random() * 8_000);
const baseUrl = `http://127.0.0.1:${port}`;
const sourceUrl = process.env.DATABASE_URL ?? "";
const databaseUrl = sourceUrl
  ? (() => {
      const url = new URL(sourceUrl);
      url.pathname = `/${databaseName}`;
      return url.toString();
    })()
  : "";

const tenantId = `strata987-${runId}`;
const otherTenantId = `${tenantId}-other`;
const principals = {
  legacy: `app_${"1".repeat(40)}`,
  nonProposer: `app_${"2".repeat(40)}`,
  legacyNoResource: `app_${"8".repeat(40)}`,
  replacement: `app_${"3".repeat(40)}`,
  explicit: `app_${"4".repeat(40)}`,
  otherTenant: `app_${"5".repeat(40)}`,
};
const credentials = {
  legacyRevoked: { keyId: `apk_${"1".repeat(24)}`, secret: `aps_${"1".repeat(64)}` },
  legacyRotated: { keyId: `apk_${"2".repeat(24)}`, secret: `aps_${"2".repeat(64)}` },
  nonProposer: { keyId: `apk_${"3".repeat(24)}`, secret: `aps_${"3".repeat(64)}` },
  legacyNoResource: { keyId: `apk_${"8".repeat(24)}`, secret: `aps_${"8".repeat(64)}` },
  replacement: { keyId: `apk_${"4".repeat(24)}`, secret: `aps_${"4".repeat(64)}` },
  explicit: { keyId: `apk_${"5".repeat(24)}`, secret: `aps_${"5".repeat(64)}` },
  otherTenant: { keyId: `apk_${"6".repeat(24)}`, secret: `aps_${"6".repeat(64)}` },
  expired: { keyId: `apk_${"7".repeat(24)}`, secret: `aps_${"7".repeat(64)}` },
};
const proposals = {
  legacy: `atp_${"1".repeat(40)}`,
  nonProposer: `atp_${"2".repeat(40)}`,
  siblingAfterMigration: `atp_${"3".repeat(40)}`,
  wrongResourceAfterMigration: `atp_${"4".repeat(40)}`,
  replacementAfterMigration: `atp_${"5".repeat(40)}`,
  explicitAfterMigration: `atp_${"6".repeat(40)}`,
};

let admin: ReturnType<typeof createPostgresClient> | undefined;
let sql: ReturnType<typeof createPostgresClient> | undefined;
let server: ReturnType<typeof Bun.spawn> | undefined;

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function applyMigration(file: string) {
  const source = await readFile(`${migrationsDir}/${file}`, "utf8");
  for (const statement of source.split("--> statement-breakpoint")) {
    const trimmed = statement.trim();
    if (trimmed && trimmed !== "--") await sql!.unsafe(trimmed);
  }
}

function headers(credential: { keyId: string; secret: string }) {
  return {
    "X-Steward-Application-Key-Id": credential.keyId,
    "X-Steward-Application-Secret": credential.secret,
  };
}

async function readProposal(credential: { keyId: string; secret: string }, proposalId: string) {
  return fetch(`${baseUrl}/application/transactions/proposals/${proposalId}`, {
    headers: headers(credential),
  });
}

async function insertCredential(
  keyId: string,
  secret: string,
  principalId: string,
  targetTenantId = tenantId,
  expiresAt = "2035-01-01T00:00:00Z",
  revokedAt: string | null = null,
) {
  await sql!.unsafe(
    `INSERT INTO application_principal_credentials
       (key_id, tenant_id, principal_id, secret_hash, expires_at, revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [keyId, targetTenantId, principalId, hashApiKey(secret), expiresAt, revokedAt],
  );
}

async function insertProposal(
  proposalId: string,
  suffix: string,
  principalId: string,
  keyId: string,
  walletId: string,
  targetTenantId = tenantId,
) {
  const intentId = `ati_${suffix.repeat(40)}`;
  await sql!.unsafe(
    `INSERT INTO application_transaction_intents
       (id, tenant_id, principal_id, credential_key_id, wallet_id, request_hash, intent, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, '{}', '2035-01-01T00:00:00Z')`,
    [intentId, targetTenantId, principalId, keyId, walletId, suffix.repeat(64)],
  );
  await sql!.unsafe(
    `INSERT INTO application_transaction_proposals
       (id, tenant_id, principal_id, credential_key_id, intent_id, request_hash)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [proposalId, targetTenantId, principalId, keyId, intentId, suffix.repeat(64)],
  );
}

beforeAll(async () => {
  if (SKIP) return;
  admin = createPostgresClient(sourceUrl);
  await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
  sql = createPostgresClient(databaseUrl);

  const migrationFiles = (await Array.fromAsync(new Bun.Glob("*.sql").scan(migrationsDir)))
    .filter((file) => /^\d{4}.*\.sql$/.test(file) && file <= "0025_application_principals.sql")
    .sort();
  for (const file of migrationFiles) await applyMigration(file);

  await sql.unsafe(
    `INSERT INTO tenants (id, name, api_key_hash) VALUES
       ($1, 'STRATA-987', $2), ($3, 'STRATA-987 other', $4)`,
    [tenantId, "a".repeat(64), otherTenantId, "b".repeat(64)],
  );
  await sql.unsafe(
    `INSERT INTO application_principals (id, tenant_id, name, capabilities, expires_at) VALUES
       ($1, $2, 'legacy', ARRAY['transaction:propose']::application_capability[], '2035-01-01T00:00:00Z'),
       ($3, $2, 'non proposer', ARRAY['wallet:ensure']::application_capability[], '2035-01-01T00:00:00Z'),
       ($4, $2, 'legacy no resource', ARRAY['transaction:propose']::application_capability[], '2035-01-01T00:00:00Z')`,
    [principals.legacy, tenantId, principals.nonProposer, principals.legacyNoResource],
  );
  await insertCredential(
    credentials.legacyRevoked.keyId,
    credentials.legacyRevoked.secret,
    principals.legacy,
  );
  await insertCredential(
    credentials.legacyRotated.keyId,
    credentials.legacyRotated.secret,
    principals.legacy,
  );
  await insertCredential(
    credentials.nonProposer.keyId,
    credentials.nonProposer.secret,
    principals.nonProposer,
  );
  await insertCredential(
    credentials.legacyNoResource.keyId,
    credentials.legacyNoResource.secret,
    principals.legacyNoResource,
  );
  await insertCredential(
    credentials.expired.keyId,
    credentials.expired.secret,
    principals.legacy,
    tenantId,
    new Date(Date.now() + 250).toISOString(),
  );

  await sql.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES
       ('agent_legacy', $1, 'legacy', $2), ('agent_nonproposer', $1, 'nonproposer', $3)`,
    [tenantId, `0x${"11".repeat(20)}`, `0x${"22".repeat(20)}`],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_resources
       (tenant_id, principal_id, resource_kind, resource_id) VALUES
       ($1, $2, 'wallet_owner', 'resource:legacy'),
       ($1, $2, 'wallet_owner', 'resource:legacy-other'),
       ($1, $3, 'wallet_owner', 'resource:nonproposer')`,
    [tenantId, principals.legacy, principals.nonProposer],
  );
  await sql
    .unsafe(
      `INSERT INTO application_wallets
       (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses) VALUES
       ('aw_legacy', $1, $2, 'wallet_owner', 'resource:legacy', 'agent_legacy', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb),
       ('aw_legacy_other', $1, $2, 'wallet_owner', 'resource:legacy-other', 'agent_legacy_other', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb),
       ('aw_nonproposer', $1, $3, 'wallet_owner', 'resource:nonproposer', 'agent_nonproposer', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb)`,
      [tenantId, principals.legacy, principals.nonProposer],
    )
    .catch(async () => {
      await sql!.unsafe(
        `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES
         ('agent_legacy_other', $1, 'legacy other', $2)`,
        [tenantId, `0x${"44".repeat(20)}`],
      );
      await sql!.unsafe(
        `INSERT INTO application_wallets
         (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses) VALUES
         ('aw_legacy', $1, $2, 'wallet_owner', 'resource:legacy', 'agent_legacy', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb),
         ('aw_legacy_other', $1, $2, 'wallet_owner', 'resource:legacy-other', 'agent_legacy_other', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb),
         ('aw_nonproposer', $1, $3, 'wallet_owner', 'resource:nonproposer', 'agent_nonproposer', '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb)`,
        [tenantId, principals.legacy, principals.nonProposer],
      );
    });
  await insertProposal(
    proposals.legacy,
    "1",
    principals.legacy,
    credentials.legacyRevoked.keyId,
    "aw_legacy",
  );
  await insertProposal(
    proposals.nonProposer,
    "2",
    principals.nonProposer,
    credentials.nonProposer.keyId,
    "aw_nonproposer",
  );

  await applyMigration("0026_application_proposal_read.sql");

  await sql.unsafe(
    `UPDATE application_principal_credentials SET revoked_at = now() WHERE key_id = $1`,
    [credentials.legacyRevoked.keyId],
  );
  await sql.unsafe(
    `INSERT INTO application_principals (id, tenant_id, name, capabilities, expires_at) VALUES
       ($1, $2, 'replacement', ARRAY['transaction:propose']::application_capability[], '2035-01-01T00:00:00Z'),
       ($3, $2, 'explicit', ARRAY['transaction:proposal:read']::application_capability[], '2035-01-01T00:00:00Z'),
       ($4, $5, 'other tenant', ARRAY['transaction:proposal:read']::application_capability[], '2035-01-01T00:00:00Z')`,
    [principals.replacement, tenantId, principals.explicit, principals.otherTenant, otherTenantId],
  );
  await insertCredential(
    credentials.replacement.keyId,
    credentials.replacement.secret,
    principals.replacement,
  );
  await insertCredential(
    credentials.explicit.keyId,
    credentials.explicit.secret,
    principals.explicit,
  );
  await insertCredential(
    credentials.otherTenant.keyId,
    credentials.otherTenant.secret,
    principals.otherTenant,
    otherTenantId,
  );
  await sql.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES
       ('agent_replacement', $1, 'replacement', $2),
       ('agent_explicit', $1, 'explicit', $3),
       ('agent_other_tenant', $4, 'other tenant', $5)`,
    [
      tenantId,
      `0x${"55".repeat(20)}`,
      `0x${"66".repeat(20)}`,
      otherTenantId,
      `0x${"77".repeat(20)}`,
    ],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_resources
       (tenant_id, principal_id, resource_kind, resource_id) VALUES
       ($1, $2, 'wallet_owner', 'resource:replacement'),
       ($1, $3, 'wallet_owner', 'resource:explicit'),
       ($4, $5, 'wallet_owner', 'resource:other-tenant')`,
    [tenantId, principals.replacement, principals.explicit, otherTenantId, principals.otherTenant],
  );
  await sql.unsafe(
    `INSERT INTO application_wallets
       (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses) VALUES
       ('aw_replacement', $1, $2, 'wallet_owner', 'resource:replacement', 'agent_replacement', '{"evm":"0x8888888888888888888888888888888888888888","solana":"22222222222222222222222222222222"}'::jsonb),
       ('aw_explicit', $1, $3, 'wallet_owner', 'resource:explicit', 'agent_explicit', '{"evm":"0x8888888888888888888888888888888888888888","solana":"22222222222222222222222222222222"}'::jsonb),
       ('aw_other_tenant', $4, $5, 'wallet_owner', 'resource:other-tenant', 'agent_other_tenant', '{"evm":"0x8888888888888888888888888888888888888888","solana":"22222222222222222222222222222222"}'::jsonb)`,
    [tenantId, principals.replacement, principals.explicit, otherTenantId, principals.otherTenant],
  );
  await insertProposal(
    proposals.siblingAfterMigration,
    "3",
    principals.legacy,
    credentials.legacyRotated.keyId,
    "aw_legacy",
  );
  await insertProposal(
    proposals.wrongResourceAfterMigration,
    "4",
    principals.legacy,
    credentials.legacyRotated.keyId,
    "aw_legacy_other",
  );
  await insertProposal(
    proposals.replacementAfterMigration,
    "5",
    principals.replacement,
    credentials.replacement.keyId,
    "aw_replacement",
  );
  await insertProposal(
    proposals.explicitAfterMigration,
    "6",
    principals.explicit,
    credentials.explicit.keyId,
    "aw_explicit",
  );

  // Replay after later proposals exist must not expand the one-time snapshot.
  await applyMigration("0026_application_proposal_read.sql");

  await Bun.sleep(300);

  server = Bun.spawn(["bun", "run", "packages/api/src/index.ts"], {
    cwd: fileURLToPath(new URL("../../../..", import.meta.url)),
    env: {
      ...process.env,
      DATABASE_URL: databaseUrl,
      PORT: String(port),
      SKIP_MIGRATIONS: "1",
      STEWARD_BIND_HOST: "127.0.0.1",
      STEWARD_MASTER_PASSWORD: "strata987-real-pg-master-password",
      STEWARD_PLATFORM_KEY: "strata987-platform-key",
      STEWARD_PLATFORM_KEYS: "strata987-platform-key",
      STEWARD_JWT_SECRET: "strata987-jwt-secret-must-be-at-least-32-chars",
      STEWARD_AUDIT_HMAC_KEY: "strata987-audit-key-32-bytes-minimum-value",
      SIWE_ALLOWED_DOMAINS: "localhost",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (
      await fetch(`${baseUrl}/health`)
        .then((response) => response.ok)
        .catch(() => false)
    )
      return;
    await Bun.sleep(100);
  }
  throw new Error(
    `STRATA-987 API did not become healthy: ${await new Response(server.stderr).text()}`,
  );
}, 120_000);

afterAll(async () => {
  if (SKIP) return;
  server?.kill();
  await server?.exited;
  await sql?.end();
  await admin?.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(databaseName)} WITH (FORCE)`);
  await admin?.end();
});

describe.skipIf(SKIP)("STRATA-987 real Postgres 0025 upgrade and endpoint boundary", () => {
  it("snapshots only exact pre-0026 proposal/resource authority and is replay-safe", async () => {
    const rows = await sql!.unsafe(
      `SELECT tenant_id, principal_id, proposal_id, resource_kind, resource_id, source
       FROM application_proposal_read_compatibility ORDER BY proposal_id`,
    );
    expect(rows).toEqual([
      {
        tenant_id: tenantId,
        principal_id: principals.legacy,
        proposal_id: proposals.legacy,
        resource_kind: "wallet_owner",
        resource_id: "resource:legacy",
        source: "pre_0026_transaction_proposal",
      },
    ]);
    const principalCapabilities = await sql!.unsafe(
      `SELECT capabilities::text[] AS capabilities FROM application_principals WHERE id = $1`,
      [principals.legacy],
    );
    expect(principalCapabilities[0]!.capabilities).toEqual(["transaction:propose"]);
  });

  it("allows the legacy proposer only for its exact historical proposal", async () => {
    const allowed = await readProposal(credentials.legacyRotated, proposals.legacy);
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toMatchObject({
      data: { proposal: { id: proposals.legacy, status: "proposed", terminal: false } },
    });
    for (const deniedId of [
      proposals.siblingAfterMigration,
      proposals.wrongResourceAfterMigration,
      proposals.nonProposer,
      proposals.replacementAfterMigration,
      `atp_${"f".repeat(40)}`,
    ]) {
      expect((await readProposal(credentials.legacyRotated, deniedId)).status, deniedId).toBe(404);
    }
  });

  it("keeps concurrent historical reads proposal-bounded and audit-complete", async () => {
    const before = await sql!.unsafe(
      `SELECT count(*)::int AS count FROM audit_events
       WHERE action = 'application.transaction_proposal.read'
         AND actor_id = $1 AND resource_id = $2`,
      [principals.legacy, proposals.legacy],
    );
    const responses = await Promise.all(
      Array.from({ length: 20 }, () => readProposal(credentials.legacyRotated, proposals.legacy)),
    );
    expect(responses.every((response) => response.status === 200)).toBe(true);
    const bodies = await Promise.all(responses.map((response) => response.json()));
    expect(new Set(bodies.map((body) => JSON.stringify(body))).size).toBe(1);
    const after = await sql!.unsafe(
      `SELECT count(*)::int AS count FROM audit_events
       WHERE action = 'application.transaction_proposal.read'
         AND actor_id = $1 AND resource_id = $2`,
      [principals.legacy, proposals.legacy],
    );
    expect(after[0]!.count - before[0]!.count).toBe(20);
  });

  it("denies non-proposer, replacement, cross-principal, cross-tenant, revoked, expired, and wrong credentials", async () => {
    expect((await readProposal(credentials.nonProposer, proposals.nonProposer)).status).toBe(404);
    expect((await readProposal(credentials.legacyNoResource, proposals.legacy)).status).toBe(404);
    expect(
      (await readProposal(credentials.replacement, proposals.replacementAfterMigration)).status,
    ).toBe(404);
    expect((await readProposal(credentials.explicit, proposals.legacy)).status).toBe(404);
    expect((await readProposal(credentials.otherTenant, proposals.legacy)).status).toBe(404);
    expect((await readProposal(credentials.legacyRevoked, proposals.legacy)).status).toBe(401);
    expect((await readProposal(credentials.expired, proposals.legacy)).status).toBe(401);
    expect(
      (
        await readProposal(
          { ...credentials.legacyRotated, secret: `aps_${"f".repeat(64)}` },
          proposals.legacy,
        )
      ).status,
    ).toBe(401);
  });

  it("requires explicit capability for post-0026 proposals", async () => {
    const explicit = await readProposal(credentials.explicit, proposals.explicitAfterMigration);
    expect(explicit.status).toBe(200);
    expect(await explicit.json()).toMatchObject({
      data: {
        proposal: {
          id: proposals.explicitAfterMigration,
          status: "proposed",
          terminal: false,
          executionEvidence: { status: "unknown", evidence: null },
        },
      },
    });
  });

  it("rejects insert, update, and delete mutations of compatibility authority", async () => {
    await sql!.unsafe("SET statement_timeout = '5s'");
    for (const statement of [
      `INSERT INTO application_proposal_read_compatibility
        (tenant_id, principal_id, proposal_id, resource_kind, resource_id, source)
       VALUES ('${tenantId}', '${principals.legacy}', '${proposals.siblingAfterMigration}',
        'wallet_owner', 'resource:legacy', 'pre_0026_transaction_proposal')`,
      `UPDATE application_proposal_read_compatibility SET resource_id = 'resource:legacy-other'`,
      `DELETE FROM application_proposal_read_compatibility`,
    ]) {
      let mutationError: unknown;
      try {
        await sql!.unsafe(statement);
      } catch (error) {
        mutationError = error;
      }
      expect(String(mutationError)).toContain(
        "application proposal read compatibility assignments are immutable",
      );
    }
  }, 20_000);

  it("preserves the durable principal audit identity across credential rotation", async () => {
    const audits = await sql!.unsafe(
      `SELECT actor_type, actor_id, action, resource_id, metadata
       FROM audit_events
       WHERE action = 'application.transaction_proposal.read'
       ORDER BY created_at`,
    );
    const legacyAudit = audits.find((row) => row.resource_id === proposals.legacy);
    const explicitAudit = audits.find(
      (row) => row.resource_id === proposals.explicitAfterMigration,
    );
    expect(legacyAudit).toMatchObject({
      actor_type: "application",
      actor_id: principals.legacy,
      action: "application.transaction_proposal.read",
      resource_id: proposals.legacy,
      metadata: {
        credentialKeyId: credentials.legacyRotated.keyId,
        authorizationBasis: "pre_0026_proposal_compatibility",
      },
    });
    expect(explicitAudit).toMatchObject({
      actor_type: "application",
      actor_id: principals.explicit,
      metadata: { authorizationBasis: "explicit_capability" },
    });
  });
});
