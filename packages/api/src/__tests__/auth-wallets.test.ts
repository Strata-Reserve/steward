import { afterAll, beforeEach, describe, expect, it } from "bun:test";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { getDb, refreshTokens, tenants, users, userTenants } from "@stwd/db";
import bs58 from "bs58";
import { eq } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const SKIP = !process.env.DATABASE_URL;
const describeWithDatabase = SKIP ? describe.skip : describe;
const TEST_PORT = 3299;
const BASE_URL = `http://localhost:${TEST_PORT}`;

const SOLANA_TEST_KEYPAIR = {
  d: "_AcsmFehfd3TZ-8I5f7TgoiFLcjrclBONqMMnX2Zeew",
  x: "DtNuOw6T7fPESIGzt_Qp6V0Q5d2a1-mUks5zrxPIoeE",
  publicKey: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
};
const createdEvmAddresses = new Set<string>();

type VerifyResponse = {
  ok: boolean;
  token: string;
  refreshToken: string;
  expiresIn: number;
  address: string;
  tenant: { id: string; name: string; apiKey?: string };
};

function decodeJwtPayload(token: string): Record<string, unknown> {
  const [, payload] = token.split(".");
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

function buildSiweMessage(address: string, nonce: string, chainId = 1): string {
  const issuedAt = new Date().toISOString();
  return [
    "steward.fi wants you to sign in with your Ethereum account:",
    address,
    "",
    "Sign in to Steward",
    "",
    "URI: https://steward.fi",
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

function buildSiwsMessage(publicKey: string, nonce: string): string {
  const issuedAt = new Date().toISOString();
  return [
    "steward.fi wants you to sign in with your Solana account:",
    publicKey,
    "",
    "Sign in to Steward",
    "",
    "URI: https://steward.fi",
    "Version: 1",
    "Chain ID: mainnet",
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

function signSolanaMessage(message: string): string {
  const keyObject = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: SOLANA_TEST_KEYPAIR.d,
      x: SOLANA_TEST_KEYPAIR.x,
    },
    format: "jwk",
  });

  return bs58.encode(cryptoSign(null, Buffer.from(message, "utf8"), keyObject));
}

async function fetchNonce(): Promise<string> {
  const res = await fetch(`${BASE_URL}/auth/nonce`);
  const json = (await res.json()) as { nonce: string };
  return json.nonce;
}

async function cleanupCreatedRows(): Promise<void> {
  const db = getDb();

  for (const address of createdEvmAddresses) {
    const tenantId = `t-${address.slice(2, 10)}`;
    await db.delete(refreshTokens).where(eq(refreshTokens.tenantId, tenantId));
    await db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await db.delete(tenants).where(eq(tenants.id, tenantId));
    await db.delete(users).where(eq(users.walletAddress, address));
  }

  await db
    .delete(refreshTokens)
    .where(eq(refreshTokens.tenantId, `solana:${SOLANA_TEST_KEYPAIR.publicKey}`));
  await db
    .delete(userTenants)
    .where(eq(userTenants.tenantId, `solana:${SOLANA_TEST_KEYPAIR.publicKey}`));
  await db.delete(tenants).where(eq(tenants.id, `solana:${SOLANA_TEST_KEYPAIR.publicKey}`));
  await db.delete(users).where(eq(users.walletAddress, SOLANA_TEST_KEYPAIR.publicKey));
}

describeWithDatabase("wallet auth flows", () => {
  beforeEach(async () => {
    await cleanupCreatedRows();
    createdEvmAddresses.clear();
  });

  afterAll(async () => {
    if (SKIP) return;
    await cleanupCreatedRows();
  });

  it("lowercases SIWE addresses, upserts a user, and mints JWTs with userId", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const nonce = await fetchNonce();
    const message = buildSiweMessage(account.address, nonce);
    const signature = await account.signMessage({ message });

    const res = await fetch(`${BASE_URL}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, signature }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as VerifyResponse;
    createdEvmAddresses.add(account.address.toLowerCase());
    expect(json.address).toBe(account.address.toLowerCase());
    const db = getDb();
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.walletAddress, account.address.toLowerCase()));
    expect(user).toBeDefined();
    expect(user?.walletChain).toBe("ethereum");

    const [tenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.ownerAddress, account.address.toLowerCase()));
    expect(tenant?.id).toBe(json.tenant.id);

    const payload = decodeJwtPayload(json.token);
    // Token SUBJECT is now the canonical personal wallet (stable per user.id),
    // NOT the raw third-party credential. The raw address still appears in the
    // response body (json.address) and remains the user-row lookup key.
    expect(payload.userId).toBe(user?.id);
    expect(typeof payload.address).toBe("string");
    expect((payload.address as string).length).toBeGreaterThan(0);
    expect(payload.address).not.toBe(account.address.toLowerCase());
    // Wallet-only user: no verified email → no email claim (fail-closed).
    expect(payload.email).toBeUndefined();
    expect(payload.emailVerified).toBeUndefined();
    // Personal wallet was provisioned (stewardWalletId recorded) but the
    // lookup key (walletAddress) was NOT overwritten.
    expect(user?.stewardWalletId).toBeTruthy();
    expect(user?.walletAddress).toBe(account.address.toLowerCase());

    // Stability regression: a SECOND login by the same wallet yields the SAME
    // subject (the rotation bug fix).
    const nonce2 = await fetchNonce();
    const message2 = buildSiweMessage(account.address, nonce2);
    const signature2 = await account.signMessage({ message: message2 });
    const res2 = await fetch(`${BASE_URL}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message2, signature: signature2 }),
    });
    expect(res2.status).toBe(200);
    const json2 = (await res2.json()) as VerifyResponse;
    const payload2 = decodeJwtPayload(json2.token);
    expect(payload2.userId).toBe(payload.userId);
    expect(payload2.address).toBe(payload.address);
  });

  it("rejects SIWS messages whose signed domain is not on the allowlist", async () => {
    const previousAllowedDomains = process.env.SIWE_ALLOWED_DOMAINS;
    process.env.SIWE_ALLOWED_DOMAINS = "steward.fi";

    try {
      const nonce = await fetchNonce();
      // Construct a signed message whose domain AND uri both claim evil.com,
      // so the URI-vs-domain consistency check passes and only the domain
      // allowlist check can reject.
      const message = buildSiwsMessage(SOLANA_TEST_KEYPAIR.publicKey, nonce)
        .replace(
          "steward.fi wants you to sign in with your Solana account:",
          "evil.com wants you to sign in with your Solana account:",
        )
        .replace("URI: https://steward.fi", "URI: https://evil.com");
      const signature = signSolanaMessage(message);

      const res = await fetch(`${BASE_URL}/auth/verify/solana`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          signature,
          publicKey: SOLANA_TEST_KEYPAIR.publicKey,
        }),
      });

      expect(res.status).toBe(401);
      await expect(res.json()).resolves.toMatchObject({
        ok: false,
        error: "SIWS domain not allowed",
      });
    } finally {
      if (previousAllowedDomains === undefined) {
        delete process.env.SIWE_ALLOWED_DOMAINS;
      } else {
        process.env.SIWE_ALLOWED_DOMAINS = previousAllowedDomains;
      }
    }
  });

  // Parameterised SIWE auth across multiple EVM chains (Gnosis, Polygon).
  // Confirms the auth flow is chain-agnostic and auto-detects regardless of
  // which EVM chain the signer is currently on.
  for (const { name, chainId } of [
    { name: "Polygon", chainId: 137 },
    { name: "Gnosis", chainId: 100 },
  ]) {
    it(`accepts SIWE auth signed on ${name} (chainId ${chainId})`, async () => {
      const account = privateKeyToAccount(generatePrivateKey());
      const nonce = await fetchNonce();
      const message = buildSiweMessage(account.address, nonce, chainId);
      const signature = await account.signMessage({ message });

      const res = await fetch(`${BASE_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, signature }),
      });

      expect(res.status).toBe(200);
      const json = (await res.json()) as VerifyResponse;
      createdEvmAddresses.add(account.address.toLowerCase());
      expect(json.address).toBe(account.address.toLowerCase());

      const payload = decodeJwtPayload(json.token);
      // Subject is the canonical personal wallet, not the raw signer address.
      expect(typeof payload.address).toBe("string");
      expect(payload.address).not.toBe(account.address.toLowerCase());
    });
  }

  it("verifies a known-good Solana signature and provisions a solana user/tenant", async () => {
    const nonce = await fetchNonce();
    const message = buildSiwsMessage(SOLANA_TEST_KEYPAIR.publicKey, nonce);
    const signature = signSolanaMessage(message);

    const res = await fetch(`${BASE_URL}/auth/verify/solana`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        signature,
        publicKey: SOLANA_TEST_KEYPAIR.publicKey,
      }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as VerifyResponse;
    expect(json.address).toBe(SOLANA_TEST_KEYPAIR.publicKey);
    expect(json.tenant.id).toBe(`solana:${SOLANA_TEST_KEYPAIR.publicKey}`);

    const db = getDb();
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.walletAddress, SOLANA_TEST_KEYPAIR.publicKey));
    expect(user).toBeDefined();
    expect(user?.walletChain).toBe("solana");

    const [tenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.ownerAddress, `solana:${SOLANA_TEST_KEYPAIR.publicKey}`));
    expect(tenant?.id).toBe(`solana:${SOLANA_TEST_KEYPAIR.publicKey}`);

    const payload = decodeJwtPayload(json.token);
    // Subject is the canonical personal wallet (stable per user.id), not the
    // raw Solana public key (which still appears in json.address/publicKey).
    expect(payload.userId).toBe(user?.id);
    expect(typeof payload.address).toBe("string");
    expect(payload.address).not.toBe(SOLANA_TEST_KEYPAIR.publicKey);
    expect(payload.email).toBeUndefined();
    expect(user?.stewardWalletId).toBeTruthy();
    // Lookup key preserved.
    expect(user?.walletAddress).toBe(SOLANA_TEST_KEYPAIR.publicKey);
  });
});
