// User-wallet rate-limit policy: env parsing, provisioning, and re-apply.
// Uses PGLite (in-process Postgres via WASM) against the real schema.

import { afterAll, afterEach, beforeEach, describe, expect, test } from "bun:test";

import { agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

import { applyUserWalletDefaults, buildUserWalletDefaultPolicies } from "../user-wallet";
import {
  DEFAULT_USER_WALLET_MAX_TX_PER_DAY,
  DEFAULT_USER_WALLET_MAX_TX_PER_HOUR,
  getUserWalletRateLimitConfig,
} from "../user-wallet-config";
import { reapplyUserWalletRateLimit } from "../user-wallet-reapply";

const HOUR = "USER_WALLET_MAX_TX_PER_HOUR";
const DAY = "USER_WALLET_MAX_TX_PER_DAY";

function collectWarn(): { warn: (m: string) => void; messages: string[] } {
  const messages: string[] = [];
  return { warn: (m) => messages.push(m), messages };
}

describe("getUserWalletRateLimitConfig", () => {
  test("unset -> defaults, no warning", () => {
    const w = collectWarn();
    expect(getUserWalletRateLimitConfig({}, w.warn)).toEqual({
      maxTxPerHour: DEFAULT_USER_WALLET_MAX_TX_PER_HOUR,
      maxTxPerDay: DEFAULT_USER_WALLET_MAX_TX_PER_DAY,
    });
    expect(DEFAULT_USER_WALLET_MAX_TX_PER_HOUR).toBe(10);
    expect(DEFAULT_USER_WALLET_MAX_TX_PER_DAY).toBe(50);
    expect(w.messages).toHaveLength(0);
  });

  test("empty string -> defaults, no warning", () => {
    const w = collectWarn();
    expect(getUserWalletRateLimitConfig({ [HOUR]: "", [DAY]: "  " }, w.warn)).toEqual({
      maxTxPerHour: 10,
      maxTxPerDay: 50,
    });
    expect(w.messages).toHaveLength(0);
  });

  test("valid values are used", () => {
    const w = collectWarn();
    expect(getUserWalletRateLimitConfig({ [HOUR]: "30", [DAY]: " 200 " }, w.warn)).toEqual({
      maxTxPerHour: 30,
      maxTxPerDay: 200,
    });
    expect(w.messages).toHaveLength(0);
  });

  test("zero -> default + warn", () => {
    const w = collectWarn();
    expect(getUserWalletRateLimitConfig({ [HOUR]: "0", [DAY]: "0" }, w.warn)).toEqual({
      maxTxPerHour: 10,
      maxTxPerDay: 50,
    });
    expect(w.messages).toHaveLength(2);
    expect(w.messages[0]).toContain(HOUR);
    expect(w.messages[1]).toContain(DAY);
  });

  test("negative -> default + warn", () => {
    const w = collectWarn();
    expect(getUserWalletRateLimitConfig({ [HOUR]: "-5", [DAY]: "-1" }, w.warn)).toEqual({
      maxTxPerHour: 10,
      maxTxPerDay: 50,
    });
    expect(w.messages).toHaveLength(2);
  });

  test("non-integer -> default + warn", () => {
    for (const bad of ["1.5", "abc", "10tx", "1e3", "0x10", "99999999999999999999"]) {
      const w = collectWarn();
      expect(getUserWalletRateLimitConfig({ [HOUR]: bad }, w.warn).maxTxPerHour).toBe(10);
      expect(w.messages).toHaveLength(1);
    }
  });

  test("warning never echoes the raw value", () => {
    const w = collectWarn();
    getUserWalletRateLimitConfig({ [HOUR]: "secret-looking-value" }, w.warn);
    expect(w.messages[0]).not.toContain("secret-looking-value");
  });
});

describe("buildUserWalletDefaultPolicies", () => {
  test("rate-limit rule reflects env; spending limit untouched", () => {
    const rules = buildUserWalletDefaultPolicies({ [HOUR]: "40", [DAY]: "120" });
    const rate = rules.find((r) => r.type === "rate-limit");
    expect(rate?.id).toBe("user-rate-limit");
    expect(rate?.config).toEqual({ maxTxPerHour: 40, maxTxPerDay: 120 });
    const spend = rules.find((r) => r.type === "spending-limit");
    expect(spend?.config.maxPerTx).toBe("500000000000000000");
  });
});

// ─── DB-backed tests ─────────────────────────────────────────────────────────

const TENANT_A = "tenant-a";
const TENANT_B = "tenant-b";
const savedEnv = { hour: process.env[HOUR], day: process.env[DAY] };

async function freshDb(): Promise<void> {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });
  await getDb()
    .insert(tenants)
    .values([
      { id: TENANT_A, name: "A", apiKeyHash: "h" },
      { id: TENANT_B, name: "B", apiKeyHash: "h" },
    ]);
}

async function seedAgent(id: string, tenantId: string): Promise<void> {
  await getDb()
    .insert(agents)
    .values({ id, tenantId, name: id, walletAddress: `0x${"0".repeat(40)}` });
}

async function rateRow(userId: string) {
  const [row] = await getDb()
    .select()
    .from(policies)
    .where(eq(policies.id, `user-rate-limit-${userId}`));
  return row;
}

async function policySnapshot() {
  const rows = await getDb().select().from(policies);
  return rows
    .map((r) => ({ id: r.id, enabled: r.enabled, config: r.config }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

function setEnv(hour?: string, day?: string): void {
  if (hour === undefined) delete process.env[HOUR];
  else process.env[HOUR] = hour;
  if (day === undefined) delete process.env[DAY];
  else process.env[DAY] = day;
}

describe("user-wallet rate-limit (PGLite)", () => {
  beforeEach(async () => {
    await freshDb();
  });

  afterEach(async () => {
    await closeDb();
    setEnv(savedEnv.hour, savedEnv.day);
  });

  afterAll(() => {
    setEnv(savedEnv.hour, savedEnv.day);
  });

  test("provisioning (applyUserWalletDefaults) uses env values", async () => {
    await seedAgent("user-wallet-u1", TENANT_A);
    setEnv("25", "100");
    await applyUserWalletDefaults("u1");
    expect((await rateRow("u1"))?.config).toEqual({ maxTxPerHour: 25, maxTxPerDay: 100 });
  });

  test("provisioning falls back to 10/50 when env unset", async () => {
    await seedAgent("user-wallet-u1", TENANT_A);
    setEnv(undefined, undefined);
    await applyUserWalletDefaults("u1");
    expect((await rateRow("u1"))?.config).toEqual({ maxTxPerHour: 10, maxTxPerDay: 50 });
  });

  test("re-apply: dry-run writes nothing, apply updates, second apply is a no-op", async () => {
    await seedAgent("user-wallet-u1", TENANT_A);
    await seedAgent("user-wallet-u2", TENANT_A);
    await seedAgent("user-wallet-u3", TENANT_B); // outside tenant set
    await seedAgent("ops-agent", TENANT_A); // not a user wallet
    setEnv(undefined, undefined);
    await applyUserWalletDefaults("u1");
    await applyUserWalletDefaults("u3");
    // u2 has no policies yet -> insert path
    // ops-agent gets a rate-limit policy that must not be touched
    await getDb()
      .insert(policies)
      .values({
        id: "ops-rate",
        agentId: "ops-agent",
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerHour: 1, maxTxPerDay: 2 },
      });

    const before = await policySnapshot();
    const env = { [HOUR]: "30", [DAY]: "200" };

    const dry = await reapplyUserWalletRateLimit({ tenantIds: [TENANT_A], env });
    expect(dry).toEqual({
      mode: "dry-run",
      maxTxPerHour: 30,
      maxTxPerDay: 200,
      scanned: 2,
      inserted: 1,
      updated: 1,
      unchanged: 0,
    });
    expect(await policySnapshot()).toEqual(before);

    const first = await reapplyUserWalletRateLimit({ tenantIds: [TENANT_A], env, apply: true });
    expect(first).toMatchObject({
      mode: "apply",
      scanned: 2,
      inserted: 1,
      updated: 1,
      unchanged: 0,
    });
    expect((await rateRow("u1"))?.config).toEqual({ maxTxPerHour: 30, maxTxPerDay: 200 });
    expect((await rateRow("u2"))?.config).toEqual({ maxTxPerHour: 30, maxTxPerDay: 200 });
    expect((await rateRow("u3"))?.config).toEqual({ maxTxPerHour: 10, maxTxPerDay: 50 });
    const [ops] = await getDb().select().from(policies).where(eq(policies.id, "ops-rate"));
    expect(ops?.config).toEqual({ maxTxPerHour: 1, maxTxPerDay: 2 });
    // spending-limit row for u1 untouched
    const [spend] = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.id, "user-spend-limit-u1"));
    expect(spend?.type).toBe("spending-limit");

    const afterFirst = await policySnapshot();
    const second = await reapplyUserWalletRateLimit({ tenantIds: [TENANT_A], env, apply: true });
    expect(second).toMatchObject({ scanned: 2, inserted: 0, updated: 0, unchanged: 2 });
    expect(await policySnapshot()).toEqual(afterFirst);
  });

  test("re-apply requires at least one tenant", async () => {
    await expect(reapplyUserWalletRateLimit({ tenantIds: [" "] })).rejects.toThrow("tenant");
  });
});
