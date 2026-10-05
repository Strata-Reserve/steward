/**
 * STRATA-1499 — explicit per-chain RPC for Base, no silent fallback.
 *
 * Covers the pure resolver and the vault entry points that must fail closed
 * BEFORE any key is decrypted, any client is built, or any row is written
 * when RPC_URL_8453 / RPC_URL_84532 is missing or invalid.
 *
 * Runs against in-memory PGLite; no network is touched. A missing endpoint
 * throws before viem's `http()` transport is ever constructed, so there is
 * nothing to mock.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

import {
  chainRpcEnvKey,
  chainRpcUrlsFromEnv,
  EXPLICIT_RPC_CHAINS,
  resolveEvmRpcUrl,
  Vault,
} from "../vault";

const MASTER_PASSWORD = "test-vault-chain-rpc";
const TENANT_ID = "chain-rpc-tenant";
const AGENT_ID = "chain-rpc-agent";
const TO = "0x000000000000000000000000000000000000dEaD";
const SECRET_HOST = "base-mainnet.g.example-provider.com";
const SECRET_KEY = "provider-key-DO-NOT-LOG-9f8e7d6c";
const SECRET_URL = `https://${SECRET_HOST}/v2/${SECRET_KEY}`;

// ─── Pure resolver ────────────────────────────────────────────────────────

describe("resolveEvmRpcUrl (STRATA-1499)", () => {
  it("marks exactly Base mainnet and Base Sepolia as explicit chains", () => {
    expect([...EXPLICIT_RPC_CHAINS].sort()).toEqual([8453, 84532]);
    expect(chainRpcEnvKey(8453)).toBe("RPC_URL_8453");
    expect(chainRpcEnvKey(84532)).toBe("RPC_URL_84532");
  });

  for (const chainId of [8453, 84532]) {
    describe(`chainId ${chainId}`, () => {
      it("returns the configured https endpoint", () => {
        expect(resolveEvmRpcUrl(chainId, { chainRpcUrls: { [chainId]: SECRET_URL } })).toBe(
          SECRET_URL,
        );
      });

      it("fails closed when unset — never falls back to RPC_URL or a public URL", () => {
        const generic = "https://generic.example.com/rpc";
        const cases: Array<Record<number, string | undefined> | undefined> = [
          undefined,
          {},
          { [chainId]: undefined },
          { [chainId]: "" },
          { [chainId]: "   " },
        ];
        for (const chainRpcUrls of cases) {
          let err: unknown;
          try {
            resolveEvmRpcUrl(chainId, { rpcUrl: generic, chainRpcUrls });
          } catch (e) {
            err = e;
          }
          expect(err).toBeInstanceOf(Error);
          const msg = (err as Error).message;
          expect(msg).toContain(`chainId ${chainId}`);
          expect(msg).toContain(`RPC_URL_${chainId}`);
          expect(msg).not.toContain(generic);
          expect(msg).not.toContain("base.org");
        }
      });

      it("rejects non-https / malformed values without echoing them", () => {
        const bad = [
          "http://insecure.example.com/rpc",
          "ws://insecure.example.com",
          "wss://insecure.example.com",
          "ftp://x",
          "not a url",
          "mainnet.base.org",
          "https://",
        ];
        for (const value of bad) {
          let err: unknown;
          try {
            resolveEvmRpcUrl(chainId, { chainRpcUrls: { [chainId]: value } });
          } catch (e) {
            err = e;
          }
          expect(err).toBeInstanceOf(Error);
          const msg = (err as Error).message;
          expect(msg).toContain(`RPC_URL_${chainId}`);
          // The configured value may carry a key: it must never appear.
          expect(msg).not.toContain(value);
        }
      });

      it("never leaks the endpoint (host or key) in the error for a sibling chain", () => {
        // Config has a key for 8453 only; resolving 84532 must not mention it.
        const other = chainId === 8453 ? 84532 : 8453;
        let err: unknown;
        try {
          resolveEvmRpcUrl(other, { chainRpcUrls: { [chainId]: SECRET_URL } });
        } catch (e) {
          err = e;
        }
        const msg = (err as Error).message;
        expect(msg).not.toContain(SECRET_HOST);
        expect(msg).not.toContain(SECRET_KEY);
      });
    });
  }

  it("leaves non-explicit chains on the legacy path (CHAIN_RPCS ?? rpcUrl)", () => {
    // Known legacy chain: public default, config.rpcUrl ignored.
    expect(resolveEvmRpcUrl(1, { rpcUrl: "https://generic.example.com" })).toBe(
      "https://eth.llamarpc.com",
    );
    expect(resolveEvmRpcUrl(42161, {})).toBe("https://arb1.arbitrum.io/rpc");
    // Unknown legacy chain: falls back to config.rpcUrl, may be undefined.
    expect(resolveEvmRpcUrl(999999, { rpcUrl: "https://generic.example.com" })).toBe(
      "https://generic.example.com",
    );
    expect(resolveEvmRpcUrl(999999, {})).toBeUndefined();
    // chainRpcUrls has no effect on legacy chains (explicit scope only).
    expect(resolveEvmRpcUrl(1, { chainRpcUrls: { 1: "https://override.example.com" } })).toBe(
      "https://eth.llamarpc.com",
    );
  });

  it("chainRpcUrlsFromEnv reads only RPC_URL_8453 / RPC_URL_84532", () => {
    const env = {
      RPC_URL: "https://generic.example.com",
      RPC_URL_8453: SECRET_URL,
      RPC_URL_1: "https://eth.example.com",
    };
    const urls = chainRpcUrlsFromEnv(env);
    expect(urls[8453]).toBe(SECRET_URL);
    expect(urls[84532]).toBeUndefined();
    expect(Object.keys(urls).sort()).toEqual(["8453", "84532"]);
  });
});

// ─── Vault entry points fail closed before any mutation ───────────────────

describe("Vault fails closed on Base without an explicit endpoint (STRATA-1499)", () => {
  let client: { close: () => Promise<void> };
  let vaultNoRpc: Vault;
  let vaultBadRpc: Vault;
  let walletAddress: string;

  beforeAll(async () => {
    const created = await createPGLiteDb("memory://");
    client = created.client;
    setPGLiteOverride(created.db as never, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Chain RPC Tenant",
      apiKeyHash: "test-hash",
    });

    // Generic RPC_URL is set on purpose: it must be ignored for Base.
    vaultNoRpc = new Vault({
      masterPassword: MASTER_PASSWORD,
      rpcUrl: "https://generic.example.com/rpc",
      chainId: 84532,
    });
    vaultBadRpc = new Vault({
      masterPassword: MASTER_PASSWORD,
      rpcUrl: "https://generic.example.com/rpc",
      chainId: 84532,
      chainRpcUrls: { 8453: "http://insecure.example.com", 84532: "not-a-url" },
    });

    const identity = await vaultNoRpc.createAgent(TENANT_ID, AGENT_ID, "Chain RPC Agent");
    walletAddress = identity.walletAddress;
  });

  afterAll(async () => {
    await client.close().catch(() => {});
  });

  async function txRowsForAgent() {
    return getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID));
  }

  for (const [label, getVault] of [
    ["unset", () => vaultNoRpc],
    ["invalid", () => vaultBadRpc],
  ] as const) {
    for (const chainId of [8453, 84532]) {
      it(`signTransaction(broadcast) on ${chainId} with ${label} endpoint throws and writes no row`, async () => {
        const before = (await txRowsForAgent()).length;
        const txId = crypto.randomUUID();
        await expect(
          getVault().signTransaction(
            { agentId: AGENT_ID, tenantId: TENANT_ID, to: TO, value: "1", chainId },
            { txId, status: "signed" },
          ),
        ).rejects.toThrow(`RPC endpoint not configured for chainId ${chainId}`);
        const after = await txRowsForAgent();
        expect(after.length).toBe(before);
        expect(after.find((r) => r.id === txId)).toBeUndefined();
      });

      it(`signTransaction(broadcast:false) on ${chainId} with ${label} endpoint throws (nonce path)`, async () => {
        const before = (await txRowsForAgent()).length;
        await expect(
          getVault().signTransaction({
            agentId: AGENT_ID,
            tenantId: TENANT_ID,
            to: TO,
            value: "1",
            chainId,
            broadcast: false,
          }),
        ).rejects.toThrow(`RPC_URL_${chainId}`);
        expect((await txRowsForAgent()).length).toBe(before);
      });

      it(`getBalance on ${chainId} with ${label} endpoint throws`, async () => {
        await expect(getVault().getBalance(TENANT_ID, AGENT_ID, chainId)).rejects.toThrow(
          `RPC endpoint not configured for chainId ${chainId}`,
        );
      });

      it(`getTokenBalances on ${chainId} with ${label} endpoint throws`, async () => {
        await expect(
          getVault().getTokenBalances(TENANT_ID, AGENT_ID, chainId, [TO]),
        ).rejects.toThrow(`RPC endpoint not configured for chainId ${chainId}`);
      });

      it(`rpcPassthrough on ${chainId} with ${label} endpoint throws`, async () => {
        await expect(
          getVault().rpcPassthrough({ chainId, method: "eth_blockNumber", params: [] }),
        ).rejects.toThrow(`RPC endpoint not configured for chainId ${chainId}`);
      });
    }
  }

  it("the default chain (config.chainId=84532) is also fail-closed when chainId is omitted", async () => {
    await expect(
      vaultNoRpc.signTransaction({ agentId: AGENT_ID, tenantId: TENANT_ID, to: TO, value: "1" }),
    ).rejects.toThrow("RPC endpoint not configured for chainId 84532");
  });

  it("error messages never contain the configured endpoint or the generic RPC_URL", async () => {
    const vaultWithSecret = new Vault({
      masterPassword: MASTER_PASSWORD,
      rpcUrl: "https://generic.example.com/rpc",
      chainRpcUrls: { 8453: SECRET_URL }, // 84532 intentionally missing
    });
    let err: unknown;
    try {
      await vaultWithSecret.signTransaction({
        agentId: AGENT_ID,
        tenantId: TENANT_ID,
        to: TO,
        value: "1",
        chainId: 84532,
      });
    } catch (e) {
      err = e;
    }
    const msg = (err as Error).message;
    expect(msg).toContain("RPC_URL_84532");
    expect(msg).not.toContain(SECRET_HOST);
    expect(msg).not.toContain(SECRET_KEY);
    expect(msg).not.toContain("generic.example.com");
    expect(msg).not.toContain("base.org");
  });

  it("agent row is untouched by the failed attempts", async () => {
    const [row] = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    expect(row?.walletAddress).toBe(walletAddress);
  });
});
