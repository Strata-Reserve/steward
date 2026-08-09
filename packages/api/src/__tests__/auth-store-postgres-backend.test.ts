/**
 * Regression test for the auth-store Postgres backend.
 *
 * Bug (2026-06-24): PostgresBackend used the raw postgres-js tagged-template
 * client via getSql(). On the prod runtime the first parameterised write threw
 * "The string argument must be of type string", so token/challenge/siwe-nonce
 * stores all silently fell back to in-memory — wiping auth state on every
 * restart. The fix routes PostgresBackend through the shared Drizzle client
 * (getDb().execute(sql`...`)), the same path migrations and /ready use.
 *
 * This test exercises the backend end-to-end against a real (PGLite) database:
 * set → get → overwrite → ttl-expiry → delete. It would FAIL to even run on the
 * old getSql() path, because getSql() throws in PGLite mode — which is exactly
 * the brittleness the fix removes.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PostgresBackend } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

describe("PostgresBackend (auth_kv_store via Drizzle)", () => {
  test("set then get round-trips a value", async () => {
    const store = new PostgresBackend("token");
    await store.set("k1", "v1", 60_000);
    expect(await store.get("k1")).toBe("v1");
  });

  test("namespaces are isolated (same key, different store)", async () => {
    const tokenStore = new PostgresBackend("token");
    const challengeStore = new PostgresBackend("challenge");
    await tokenStore.set("shared", "from-token", 60_000);
    await challengeStore.set("shared", "from-challenge", 60_000);
    expect(await tokenStore.get("shared")).toBe("from-token");
    expect(await challengeStore.get("shared")).toBe("from-challenge");
  });

  test("set overwrites an existing key (ON CONFLICT upsert)", async () => {
    const store = new PostgresBackend("token");
    await store.set("dup", "first", 60_000);
    await store.set("dup", "second", 60_000);
    expect(await store.get("dup")).toBe("second");
  });

  test("an expired entry reads as null", async () => {
    const store = new PostgresBackend("token");
    await store.set("ttl", "soon-gone", -1_000); // already expired
    expect(await store.get("ttl")).toBeNull();
  });

  test("get of an unknown key is null", async () => {
    const store = new PostgresBackend("token");
    expect(await store.get("never-set")).toBeNull();
  });

  test("delete removes a key", async () => {
    const store = new PostgresBackend("token");
    await store.set("del", "bye", 60_000);
    expect(await store.get("del")).toBe("bye");
    await store.delete("del");
    expect(await store.get("del")).toBeNull();
  });
});
