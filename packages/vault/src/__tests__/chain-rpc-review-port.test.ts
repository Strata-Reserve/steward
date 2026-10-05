/**
 * STRATA-1499 — Vault-level port of the REVIEW-STEWARD-27 independent tests,
 * inverted to assert the FIXED behaviour:
 *
 * - F1: a missing / non-https Base endpoint rejects BEFORE the key is
 *   decrypted (decrypt spy = 0 calls), before any network and any row write.
 * - F2: a configured endpoint that then fails (RPC revert / transport error)
 *   is redacted from the thrown error (no host, path or key).
 * - Explicit endpoints are the ONLY URLs used for Base sign/broadcast/nonce/
 *   balance/receipt; non-Base and Solana paths work with both Base keys unset.
 *
 * `globalThis.fetch` is replaced BEFORE the vault module is imported (the
 * Solana SDK captures fetch at load). Nothing falls back to real fetch.
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { parseTransaction } from "viem";
import type { Vault as VaultType } from "../vault";

let Vault: typeof import("../vault").Vault;
let chainRpcUrlsFromEnv: typeof import("../vault").chainRpcUrlsFromEnv;
let redactRpcEndpoints: typeof import("../vault").redactRpcEndpoints;
let assertChainRpcReady: typeof import("../vault").assertChainRpcReady;

const T = "review-port-tenant";
const A = "review-port-agent";
const TO = "0x000000000000000000000000000000000000dEaD";
const HASH = `0x${"a".repeat(64)}`;
const KEY = "SYNTHETIC_REVIEW_KEY";
const urls: Record<number, string> = {
  8453: `https://explicit-mainnet.invalid/v2/${KEY}`,
  84532: `https://explicit-sepolia.invalid/v2/${KEY}`,
};
let client: { close(): Promise<void> };
let vault: VaultType;
const calls: Array<{ url: string; method: string }> = [];
const realFetch = globalThis.fetch;
let rpcMode: "ok" | "revert" | "transport" = "ok";

const fakeFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const b = JSON.parse(String(init?.body ?? "{}")) as { id: number; method: string };
  calls.push({ url, method: b.method });
  if (rpcMode === "transport") throw new Error(`mock transport cannot connect to ${url}`);
  if (rpcMode === "revert") {
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: b.id,
        error: { code: -32000, message: `execution reverted (via ${url})` },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  }
  let result: unknown;
  switch (b.method) {
    case "eth_chainId":
      result = url === urls[84532] ? "0x14a34" : "0x2105";
      break;
    case "eth_getTransactionCount":
      result = "0x0";
      break;
    case "eth_gasPrice":
    case "eth_maxPriorityFeePerGas":
      result = "0x3b9aca00";
      break;
    case "eth_getBlockByNumber":
      result = { number: "0x1", baseFeePerGas: "0x3b9aca00", hash: HASH, transactions: [] };
      break;
    case "eth_estimateGas":
      result = "0x5208";
      break;
    case "eth_sendRawTransaction":
      result = HASH;
      break;
    case "eth_getBalance":
      result = "0x7b";
      break;
    case "eth_getTransactionReceipt":
      result = { transactionHash: HASH, status: "0x1" };
      break;
    case "getBalance":
      result = { context: { slot: 1 }, value: 123 };
      break;
    default:
      throw new Error(`Unexpected mocked method ${b.method}`);
  }
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: b.id, result }), {
    headers: { "Content-Type": "application/json" },
  });
};

beforeAll(async () => {
  const created = await createPGLiteDb("memory://");
  client = created.client;
  setPGLiteOverride(created.db as never, async () => client.close());
  globalThis.fetch = fakeFetch as typeof fetch;
  ({ Vault, chainRpcUrlsFromEnv, redactRpcEndpoints, assertChainRpcReady } = await import(
    "../vault"
  ));
  await getDb().insert(tenants).values({ id: T, name: T, apiKeyHash: "review" });
  vault = new Vault({
    masterPassword: "review-password",
    rpcUrl: "https://generic.invalid/forbidden",
    chainRpcUrls: urls,
  });
  await vault.createAgent(T, A, A);
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  await client.close();
});

const leakFree = (s: string, url: string) => {
  const parsed = new URL(url);
  expect(s).not.toContain(url);
  expect(s).not.toContain(parsed.host);
  expect(s).not.toContain(parsed.pathname);
  expect(s).not.toContain(KEY);
};

describe("explicit Base endpoints (STRATA-1499)", () => {
  for (const chainId of [8453, 84532]) {
    it(`real viem sign/broadcast/nonce/balance/receipt use only the explicit endpoint ${chainId}`, async () => {
      calls.length = 0;
      rpcMode = "ok";
      const signed = await vault.signTransaction({
        agentId: A,
        tenantId: T,
        to: TO,
        value: "1",
        chainId,
        broadcast: false,
      });
      expect(parseTransaction(signed as `0x${string}`).chainId).toBe(chainId);
      expect(calls.some((c) => c.method === "eth_getTransactionCount")).toBe(true);
      expect(
        await vault.signTransaction({
          agentId: A,
          tenantId: T,
          to: TO,
          value: "1",
          chainId,
          gasLimit: "21000",
        }),
      ).toBe(HASH);
      expect(calls.some((c) => c.method === "eth_sendRawTransaction")).toBe(true);
      expect((await vault.getBalance(T, A, chainId)).native).toBe(123n);
      expect(
        (
          await vault.rpcPassthrough({
            chainId,
            method: "eth_getTransactionReceipt",
            params: [HASH],
          })
        ).result,
      ).toEqual({ transactionHash: HASH, status: "0x1" });
      expect(calls.length).toBeGreaterThan(4);
      expect(calls.every((c) => c.url === urls[chainId])).toBe(true);
    });

    for (const bad of [undefined, `http://unsafe.invalid/${KEY}`]) {
      const label = bad ? "non-https" : "missing";
      it(`F1: ${label} ${chainId} rejects before decrypt, network, signing and DB write`, async () => {
        const v = new Vault({
          masterPassword: "review-password",
          rpcUrl: "https://generic.invalid/forbidden",
          chainRpcUrls: { [chainId]: bad },
        });
        const decrypt = spyOn(
          (v as unknown as { keyStore: { decrypt: (k: unknown) => string } }).keyStore,
          "decrypt",
        );
        const before = await getDb().select().from(transactions).where(eq(transactions.agentId, A));
        calls.length = 0;

        expect(() => assertChainRpcReady(chainId, { chainRpcUrls: { [chainId]: bad } })).toThrow(
          `RPC_URL_${chainId}`,
        );
        expect(() => v.assertChainRpcReady(chainId)).toThrow(`RPC_URL_${chainId}`);
        for (const broadcast of [false, true]) {
          await expect(
            v.signTransaction({ agentId: A, tenantId: T, to: TO, value: "1", chainId, broadcast }),
          ).rejects.toThrow(`RPC_URL_${chainId}`);
        }
        // Readiness is checked BEFORE any key material is touched.
        expect(decrypt).toHaveBeenCalledTimes(0);
        decrypt.mockRestore();

        await expect(v.getBalance(T, A, chainId)).rejects.toThrow(`RPC_URL_${chainId}`);
        await expect(v.getTokenBalances(T, A, chainId, [TO])).rejects.toThrow(`RPC_URL_${chainId}`);
        for (const method of [
          "eth_getTransactionCount",
          "eth_getTransactionReceipt",
          "eth_getBalance",
        ]) {
          await expect(v.rpcPassthrough({ chainId, method, params: [HASH] })).rejects.toThrow(
            `RPC_URL_${chainId}`,
          );
        }
        expect(calls).toHaveLength(0);
        const after = await getDb().select().from(transactions).where(eq(transactions.agentId, A));
        expect(after).toHaveLength(before.length);
        if (bad) {
          try {
            await v.signTransaction({ agentId: A, tenantId: T, to: TO, value: "1", chainId });
          } catch (e) {
            expect((e as Error).message).not.toContain("unsafe.invalid");
            expect((e as Error).message).not.toContain(KEY);
          }
        }
      });
    }
  }

  it("Solana and legacy chains are not gated by assertChainRpcReady", () => {
    const cfg = { chainRpcUrls: chainRpcUrlsFromEnv({}) };
    for (const chainId of [1, 137, 42161, 101, 102]) {
      expect(() => assertChainRpcReady(chainId, cfg)).not.toThrow();
    }
  });
});

describe("non-Base compatibility with both Base keys unset", () => {
  for (const [chainId, url] of [
    [1, "https://eth.llamarpc.com"],
    [137, "https://polygon-rpc.com"],
    [42161, "https://arb1.arbitrum.io/rpc"],
  ] as const) {
    it(`non-Base ${chainId} sign-without-broadcast and balance`, async () => {
      calls.length = 0;
      rpcMode = "ok";
      const v = new Vault({
        masterPassword: "review-password",
        chainRpcUrls: chainRpcUrlsFromEnv({}),
      });
      const signed = await v.signTransaction({
        agentId: A,
        tenantId: T,
        to: TO,
        value: "1",
        chainId,
        broadcast: false,
      });
      expect(parseTransaction(signed as `0x${string}`).chainId).toBe(chainId);
      expect((await v.getBalance(T, A, chainId)).native).toBe(123n);
      expect([...new Set(calls.map((c) => c.url.replace(/\/$/, "")))]).toEqual([
        url.replace(/\/$/, ""),
      ]);
    });
  }

  it("Solana balance and passthrough work without Base keys (mocked endpoints)", async () => {
    calls.length = 0;
    rpcMode = "ok";
    const v = new Vault({
      masterPassword: "review-password",
      chainRpcUrls: chainRpcUrlsFromEnv({}),
    });
    expect((await v.getBalance(T, A, 101)).native).toBe(123n);
    expect(
      (
        await v.rpcPassthrough({
          chainId: 102,
          method: "getBalance",
          params: ["11111111111111111111111111111111"],
        })
      ).result,
    ).toEqual({ context: { slot: 1 }, value: 123 });
    expect(calls.map((c) => c.url)).toEqual([
      "https://api.mainnet-beta.solana.com",
      "https://api.devnet.solana.com",
    ]);
  });
});

describe("F2: the configured endpoint never leaks from a thrown error", () => {
  for (const mode of ["revert", "transport"] as const) {
    it(`${mode}: signTransaction error carries no host, path or key`, async () => {
      rpcMode = mode;
      let error: unknown;
      try {
        await vault.signTransaction({
          agentId: A,
          tenantId: T,
          to: TO,
          value: "1",
          chainId: 8453,
          broadcast: false,
        });
      } catch (e) {
        error = e;
      } finally {
        rpcMode = "ok";
      }
      expect(error).toBeInstanceOf(Error);
      const err = error as Error;
      leakFree(err.message, urls[8453]);
      leakFree(String(err), urls[8453]);
      leakFree(JSON.stringify(err, Object.getOwnPropertyNames(err)), urls[8453]);
      expect(err.cause).toBeUndefined();
      if (mode === "revert") expect(err.message).toContain("execution reverted");
    });

    it(`${mode}: getBalance / getTokenBalances / rpcPassthrough errors carry no host, path or key`, async () => {
      rpcMode = mode;
      try {
        for (const op of [
          () => vault.getBalance(T, A, 8453),
          () => vault.getTokenBalances(T, A, 8453, [TO]),
          () => vault.rpcPassthrough({ chainId: 8453, method: "eth_getBalance", params: [TO] }),
        ]) {
          let error: unknown;
          try {
            await op();
          } catch (e) {
            error = e;
          }
          if (error === undefined) continue; // revert mode: passthrough returns the JSON-RPC error body
          leakFree((error as Error).message, urls[8453]);
          leakFree(String(error), urls[8453]);
        }
      } finally {
        rpcMode = "ok";
      }
    });
  }

  it("redactRpcEndpoints: exact match (url/host/path/query/key) and URL-pattern stripping", () => {
    const configured = ["https://rpc.example.invalid/v2/abcdefghij?apikey=zyxwvutsrq", "http://x"];
    const input = [
      "full https://rpc.example.invalid/v2/abcdefghij?apikey=zyxwvutsrq here",
      "host rpc.example.invalid alone",
      "path /v2/abcdefghij alone",
      "key abcdefghij alone",
      "query zyxwvutsrq alone",
      "encoded https%3A%2F%2Frpc.example.invalid%2Fv2%2Fabcdefghij",
      "unrelated https://other.invalid/secret and wss://ws.invalid/x",
    ].join("\n");
    const out = redactRpcEndpoints(input, configured);
    for (const needle of [
      "rpc.example.invalid",
      "abcdefghij",
      "zyxwvutsrq",
      "other.invalid",
      "ws.invalid",
      "/v2/",
    ]) {
      expect(out).not.toContain(needle);
    }
    expect(out).toContain("[redacted-rpc-endpoint]");
    expect(redactRpcEndpoints(out, configured)).toBe(out); // idempotent
    expect(redactRpcEndpoints("plain text", [undefined, ""])).toBe("plain text");
  });
});
