import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  agents,
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
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `wallet-actions-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `wallet-actions-other-tenant-${Date.now()}`;
const AGENT_ID = `wallet-actions-agent-${Date.now()}`;
const AGENT_WITHOUT_ALLOWLIST_ID = `wallet-actions-no-allowlist-${Date.now()}`;
const MANUAL_AGENT_ID = `wallet-actions-manual-${Date.now()}`;
const REQUESTER_USER_ID = crypto.randomUUID();
const APPROVER_USER_ID = crypto.randomUUID();
const SOLANA_AGENT_ID = `wallet-actions-solana-agent-${Date.now()}`;
const SOLANA_AGENT_WITHOUT_MINT_ID = `wallet-actions-solana-no-mint-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN = "0x4200000000000000000000000000000000000006";
const ALLOWED_SOLANA = "7J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg";
const BLOCKED_SOLANA = "8J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg";
const SOLANA_MINT = "So11111111111111111111111111111111111111112";

function expectedErc20TransferCalldata(recipient: string, amount: string) {
  return `0xa9059cbb${recipient.toLowerCase().replace(/^0x/, "").padStart(64, "0")}${BigInt(amount).toString(16).padStart(64, "0")}`;
}

async function makeApp(tenantId = TENANT_ID, userId = REQUESTER_USER_ID) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", userId);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

async function makeAgentCredentialApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "agent-jwt");
    c.set("agentId", MANUAL_AGENT_ID);
    c.set("tenantRole", undefined);
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("wallet transfer actions", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-actions-master-password";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Wallet Actions Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb()
      .insert(tenants)
      .values({
        id: OTHER_TENANT_ID,
        name: "Other Wallet Actions Tenant",
        apiKeyHash: `hash-${OTHER_TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agents).values({
      id: AGENT_WITHOUT_ALLOWLIST_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent Without Allowlist",
      walletAddress: "0x0000000000000000000000000000000000000002",
    });
    await getDb().insert(agents).values({
      id: MANUAL_AGENT_ID,
      tenantId: TENANT_ID,
      name: "Manual Approval Wallet Actions Agent",
      walletAddress: "0x0000000000000000000000000000000000000003",
    });
    await getDb()
      .insert(users)
      .values([
        {
          id: REQUESTER_USER_ID,
          email: `requester-${Date.now()}@example.com`,
          walletAddress: "0x0000000000000000000000000000000000000011",
        },
        {
          id: APPROVER_USER_ID,
          email: `approver-${Date.now()}@example.com`,
          walletAddress: "0x0000000000000000000000000000000000000012",
        },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId: REQUESTER_USER_ID, tenantId: TENANT_ID, role: "admin" },
        { userId: APPROVER_USER_ID, tenantId: TENANT_ID, role: "admin" },
      ]);
    await getDb().insert(agents).values({
      id: SOLANA_AGENT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Solana Agent",
      walletAddress: "9J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
    });
    await getDb().insert(agents).values({
      id: SOLANA_AGENT_WITHOUT_MINT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Solana Agent Without Mint Allowlist",
      walletAddress: "Aj9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
    });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED, TOKEN], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-token-transfer-selector",
        agentId: AGENT_ID,
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
                  maxAmount: "99",
                },
              },
            },
          ],
        },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "manual-approval-threshold",
        agentId: AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    await getDb()
      .insert(policies)
      .values([
        {
          id: "manual-agent-chain",
          agentId: MANUAL_AGENT_ID,
          type: "allowed-chains",
          enabled: true,
          config: { chains: ["eip155:84532"] },
        },
        {
          id: "manual-agent-addresses",
          agentId: MANUAL_AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [TOKEN], mode: "whitelist" },
        },
        {
          id: "manual-agent-contract",
          agentId: MANUAL_AGENT_ID,
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
          id: "manual-agent-rate",
          agentId: MANUAL_AGENT_ID,
          type: "rate-limit",
          enabled: true,
          config: { maxTxPerHour: 100, maxTxPerDay: 100 },
        },
        {
          id: "manual-agent-review",
          agentId: MANUAL_AGENT_ID,
          type: "manual-approval",
          enabled: true,
          config: { actions: ["wallet_action_transfer"] },
        },
      ]);
    await getDb()
      .insert(policies)
      .values({
        id: "approved-solana-recipient",
        agentId: SOLANA_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED_SOLANA, SOLANA_MINT], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "solana-auto-approve-threshold",
        agentId: SOLANA_AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-solana-recipient-without-mint",
        agentId: SOLANA_AGENT_WITHOUT_MINT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED_SOLANA], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "solana-without-mint-auto-approve-threshold",
        agentId: SOLANA_AGENT_WITHOUT_MINT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  });

  it("quotes native transfers and records rejected transfer actions for status polling", async () => {
    const quoteResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer/quote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(quoteResponse.status).toBe(200);
    const quoteBody = (await quoteResponse.json()) as {
      ok: boolean;
      data: { type: string; token: string; request: { broadcast: boolean } };
    };
    expect(quoteBody.ok).toBe(true);
    expect(quoteBody.data.type).toBe("transfer");
    expect(quoteBody.data.token).toBe("native");
    expect(quoteBody.data.request.broadcast).toBe(false);

    const createResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: BLOCKED, amountWei: "1000", chainId: 8453, broadcast: false }),
    });
    expect(createResponse.status).toBe(403);
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; type: string; status: string; to: string };
    };
    expect(createBody.ok).toBe(false);
    expect(createBody.data.type).toBe("transfer");
    expect(createBody.data.status).toBe("rejected");
    expect(createBody.data.to).toBe(BLOCKED);

    const [tx] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, createBody.data.id));
    expect(tx.id).toBe(createBody.data.id);
    expect(tx.status).toBe("rejected");
    expect(tx.actionType).toBe("transfer");

    const statusResponse = await app.request(`/vault/${AGENT_ID}/actions/${createBody.data.id}`);
    expect(statusResponse.status).toBe(200);
    const statusBody = (await statusResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(statusBody.ok).toBe(true);
    expect(statusBody.data.id).toBe(createBody.data.id);
    expect(statusBody.data.status).toBe("rejected");

    const otherTenantApp = await makeApp(OTHER_TENANT_ID);
    const otherTenantStatusResponse = await otherTenantApp.request(
      `/vault/${AGENT_ID}/actions/${createBody.data.id}`,
    );
    expect(otherTenantStatusResponse.status).toBe(404);

    await getDb().insert(transactions).values({
      id: "legacy-sign-tx",
      agentId: AGENT_ID,
      status: "signed",
      toAddress: ALLOWED,
      value: "1000",
      chainId: 8453,
    });
    const legacyStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/legacy-sign-tx`);
    expect(legacyStatusResponse.status).toBe(404);

    const pendingResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(pendingResponse.status).toBe(202);
    const pendingBody = (await pendingResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(pendingBody.ok).toBe(true);
    expect(pendingBody.data.status).toBe("pending_approval");

    const pendingStatusResponse = await app.request(
      `/vault/${AGENT_ID}/actions/${pendingBody.data.id}`,
    );
    expect(pendingStatusResponse.status).toBe(200);
    const pendingStatusBody = (await pendingStatusResponse.json()) as {
      ok: boolean;
      data: { status: string };
    };
    expect(pendingStatusBody.data.status).toBe("pending_approval");

    const signedActionId = "legacy-signed-transfer-action";
    await getDb()
      .insert(transactions)
      .values({
        id: signedActionId,
        agentId: AGENT_ID,
        status: "signed",
        toAddress: ALLOWED,
        value: "1000",
        chainId: 8453,
        actionType: "transfer",
        actionPayload: {
          type: "transfer",
          token: "native",
          broadcast: false,
          signedTx: "0xsigned-bearer-transaction",
        },
      });
    const signedStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/${signedActionId}`);
    expect(signedStatusResponse.status).toBe(200);
    const signedStatusBody = (await signedStatusResponse.json()) as {
      ok: boolean;
      data: { status: string; signedTx?: string };
    };
    expect(signedStatusBody.ok).toBe(true);
    expect(signedStatusBody.data.status).toBe("signed");
    expect(signedStatusBody.data.signedTx).toBeUndefined();

    const confirmedActionId = "legacy-confirmed-transfer-action";
    const confirmedAt = new Date();
    await getDb()
      .insert(transactions)
      .values({
        id: confirmedActionId,
        agentId: AGENT_ID,
        status: "confirmed",
        toAddress: ALLOWED,
        value: "1000",
        chainId: 8453,
        actionType: "transfer",
        txHash: "0xconfirmed-transfer",
        confirmedAt,
        actionPayload: {
          type: "transfer",
          token: "native",
          recipient: ALLOWED,
          amount: "1000",
          broadcast: true,
        },
      });
    const confirmedStatusResponse = await app.request(
      `/vault/${AGENT_ID}/actions/${confirmedActionId}`,
    );
    expect(confirmedStatusResponse.status).toBe(200);
    const confirmedStatusBody = (await confirmedStatusResponse.json()) as {
      ok: boolean;
      data: { status: string; txHash?: string; confirmedAt?: string };
    };
    expect(confirmedStatusBody.ok).toBe(true);
    expect(confirmedStatusBody.data.status).toBe("confirmed");
    expect(confirmedStatusBody.data.txHash).toBe("0xconfirmed-transfer");
    expect(confirmedStatusBody.data.confirmedAt).toBe(confirmedAt.toISOString());
  });

  it("signs ERC20 transfer actions through selector-gated token contracts", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    const calldata = expectedErc20TransferCalldata(ALLOWED, "42");

    context.vault.signTransaction = async (request, metadata) => {
      expect(request.agentId).toBe(AGENT_ID);
      expect(request.to).toBe(TOKEN);
      expect(request.value).toBe("0");
      expect(request.data).toBe(calldata);
      expect(request.chainId).toBe(8453);
      expect(request.gasLimit).toBe("65000");
      expect(request.broadcast).toBe(false);
      expect(metadata.status).toBe("signed");
      await getDb().insert(transactions).values({
        id: metadata.txId,
        agentId: request.agentId,
        status: "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId: request.chainId,
      });
      return "0xsigned-erc20";
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED,
          token: TOKEN,
          value: "42",
          chainId: 8453,
          broadcast: false,
          referenceId: "erc20-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.token).toBe(TOKEN);
      expect(body.data.to).toBe(ALLOWED);
      expect(body.data.value).toBe("42");
      expect(body.data.signedTx).toBe("0xsigned-erc20");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(TOKEN);
      expect(tx.value).toBe("0");
      expect(tx.data).toBe(calldata);
      const actionPayload = tx.actionPayload as {
        type: string;
        token: string;
        recipient: string;
        amount: string;
        broadcast: boolean;
        referenceId?: string;
      };
      expect(actionPayload).toEqual({
        type: "transfer",
        token: TOKEN,
        recipient: ALLOWED,
        amount: "42",
        broadcast: false,
        referenceId: "erc20-transfer-success",
      });

      const statusResponse = await app.request(`/vault/${AGENT_ID}/actions/${body.data.id}`);
      expect(statusResponse.status).toBe(200);
      const statusBody = (await statusResponse.json()) as {
        ok: boolean;
        data: { status: string; token: string; to: string; value: string; signedTx?: string };
      };
      expect(statusBody.ok).toBe(true);
      expect(statusBody.data.status).toBe("signed");
      expect(statusBody.data.token).toBe(TOKEN);
      expect(statusBody.data.to).toBe(ALLOWED);
      expect(statusBody.data.value).toBe("42");
      expect(statusBody.data.signedTx).toBeUndefined();
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("rejects ERC20 transfer actions without a constrained selector allowlist", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    context.vault.signTransaction = async () => {
      throw new Error("ERC20 rejection should not reach signing");
    };

    const response = await app.request(`/vault/${AGENT_WITHOUT_ALLOWLIST_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1",
        chainId: 8453,
        broadcast: false,
      }),
    });
    try {
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { id: string; status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe(TOKEN);
      expect(body.data?.policyResults).toEqual([
        expect.objectContaining({
          policyId: "erc20-transfer-contract-allowlist-required",
          passed: false,
        }),
      ]);

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data?.id ?? ""));
      expect(tx.status).toBe("rejected");
      expect(tx.toAddress).toBe(TOKEN);
      expect(tx.value).toBe("0");
      expect(tx.data).toBe(expectedErc20TransferCalldata(ALLOWED, "1"));
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("rejects ERC20 transfer actions above selector maxAmount", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1000",
        chainId: 8453,
        broadcast: false,
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { status: string; token: string; policyResults?: Array<unknown> };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Transfer rejected by policy");
    expect(body.data?.status).toBe("rejected");
    expect(body.data?.token).toBe(TOKEN);
    expect(body.data?.policyResults).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "contract-allowlist",
          passed: false,
          reason: "Token amount 1000 exceeds selector maxAmount 99",
        }),
      ]),
    );
  });

  it("signs native Solana transfer actions through the existing Solana signing primitive", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);

    context.vault.signTransaction = async (request, metadata) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.to).toBe(ALLOWED_SOLANA);
      expect(request.value).toBe("123");
      expect(request.data).toBeUndefined();
      expect(request.chainId).toBe(101);
      expect(request.broadcast).toBe(false);
      expect(metadata.status).toBe("signed");
      await getDb().insert(transactions).values({
        id: metadata.txId,
        agentId: request.agentId,
        status: "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId: request.chainId,
      });
      return "base64-signed-solana-transaction";
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          value: "123",
          chainId: 101,
          broadcast: false,
          referenceId: "native-solana-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          chainId: number;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.chainId).toBe(101);
      expect(body.data.token).toBe("native");
      expect(body.data.to).toBe(ALLOWED_SOLANA);
      expect(body.data.value).toBe("123");
      expect(body.data.signedTx).toBe("base64-signed-solana-transaction");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(ALLOWED_SOLANA);
      expect(tx.value).toBe("123");
      expect(tx.data).toBeNull();
      expect(tx.chainId).toBe(101);
      expect(tx.actionPayload).toEqual({
        type: "transfer",
        token: "native",
        recipient: ALLOWED_SOLANA,
        amount: "123",
        broadcast: false,
        referenceId: "native-solana-transfer-success",
      });
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("rejects Solana transfer actions outside the recipient allowlist", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    context.vault.signTransaction = async () => {
      throw new Error("Solana rejection should not reach signing");
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: BLOCKED_SOLANA,
          value: "123",
          chainId: 101,
          broadcast: false,
        }),
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe("native");
      expect(body.data?.policyResults).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policyId: "approved-solana-recipient",
            passed: false,
          }),
        ]),
      );
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("signs SPL token transfer actions with recipient and mint allowlisted", async () => {
    const context = await import("../services/context");
    const originalBuildSplTransfer = context.vault.buildSolanaSplTransferTransaction.bind(
      context.vault,
    );
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);

    context.vault.buildSolanaSplTransferTransaction = async (request) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.tenantId).toBe(TENANT_ID);
      expect(request.to).toBe(ALLOWED_SOLANA);
      expect(request.token).toBe(SOLANA_MINT);
      expect(request.value).toBe("123");
      expect(request.chainId).toBe(101);
      return {
        transaction: "base64-spl-transfer-transaction",
        sourceTokenAccount: "source-token-account",
        destinationTokenAccount: "destination-token-account",
        mint: SOLANA_MINT,
        tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        decimals: 9,
      };
    };
    context.vault.signSolanaTransaction = async (request) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.tenantId).toBe(TENANT_ID);
      expect(request.transaction).toBe("base64-spl-transfer-transaction");
      expect(request.chainId).toBe(101);
      expect(request.broadcast).toBe(false);
      expect(request.expectedTo).toBeUndefined();
      expect(request.expectedValue).toBeUndefined();
      return {
        signature: "base64-signed-spl-transfer-transaction",
        broadcast: false,
        chainId: request.chainId,
      };
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          token: SOLANA_MINT,
          value: "123",
          chainId: 101,
          broadcast: false,
          referenceId: "spl-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          chainId: number;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.chainId).toBe(101);
      expect(body.data.token).toBe(SOLANA_MINT);
      expect(body.data.to).toBe(ALLOWED_SOLANA);
      expect(body.data.value).toBe("123");
      expect(body.data.signedTx).toBe("base64-signed-spl-transfer-transaction");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(ALLOWED_SOLANA);
      expect(tx.value).toBe("123");
      expect(tx.data).toBe("base64-spl-transfer-transaction");
      expect(tx.chainId).toBe(101);
      expect(tx.actionPayload).toEqual({
        type: "transfer",
        token: SOLANA_MINT,
        recipient: ALLOWED_SOLANA,
        amount: "123",
        broadcast: false,
        referenceId: "spl-transfer-success",
      });
    } finally {
      context.vault.buildSolanaSplTransferTransaction = originalBuildSplTransfer;
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });

  it("rejects SPL token transfer actions when the mint is not allowlisted", async () => {
    const context = await import("../services/context");
    const originalBuildSplTransfer = context.vault.buildSolanaSplTransferTransaction.bind(
      context.vault,
    );
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);

    context.vault.buildSolanaSplTransferTransaction = async () => ({
      transaction: "base64-spl-transfer-transaction-without-mint-policy",
      sourceTokenAccount: "source-token-account",
      destinationTokenAccount: "destination-token-account",
      mint: SOLANA_MINT,
      tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      decimals: 9,
    });
    context.vault.signSolanaTransaction = async () => {
      throw new Error("SPL mint policy rejection should not reach signing");
    };

    try {
      const response = await app.request(
        `/vault/${SOLANA_AGENT_WITHOUT_MINT_ID}/actions/transfer`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            to: ALLOWED_SOLANA,
            token: SOLANA_MINT,
            value: "123",
            chainId: 101,
            broadcast: false,
          }),
        },
      );
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe(SOLANA_MINT);
      expect(body.data?.policyResults).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policyId: "spl-transfer-mint-recipient-allowlist-required",
            passed: false,
          }),
        ]),
      );
    } finally {
      context.vault.buildSolanaSplTransferTransaction = originalBuildSplTransfer;
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });

  it("STRATA-1097: permitted ERC20 transfer stays pending until a different tenant human explicitly approves", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    const previousRequiredActions = process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS;
    process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS = "wallet_action_transfer";
    let signCalls = 0;
    context.vault.signTransaction = async (request) => {
      signCalls += 1;
      expect(request.agentId).toBe(MANUAL_AGENT_ID);
      expect(request.chainId).toBe(84532);
      expect(request.to).toBe(TOKEN);
      expect(request.value).toBe("0");
      expect(request.data).toBe(expectedErc20TransferCalldata(ALLOWED, "1"));
      expect(request.broadcast).toBe(true);
      return "0xmanualapprovaltx";
    };

    try {
      const requesterApp = await makeApp(TENANT_ID, REQUESTER_USER_ID);
      const pending = await requesterApp.request(`/vault/${MANUAL_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": "manual-pending-1" },
        body: JSON.stringify({
          to: ALLOWED,
          token: TOKEN,
          value: "1",
          chainId: 84532,
          broadcast: true,
          referenceId: "manual-pending-1",
        }),
      });
      expect(pending.status).toBe(202);
      const pendingBody = (await pending.json()) as {
        ok: boolean;
        data: { id: string; status: string };
      };
      expect(pendingBody.ok).toBe(true);
      expect(pendingBody.data.status).toBe("pending_approval");
      expect(signCalls).toBe(0); // no sign/broadcast before approval

      const [queued] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, pendingBody.data.id));
      expect(queued.status).toBe("pending");
      expect(queued.requestedByType).toBe("user");
      expect(queued.requestedById).toBe(REQUESTER_USER_ID);
      await new Promise((resolve) => setTimeout(resolve, 5));
      const [stillPending] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, pendingBody.data.id));
      expect(stillPending.status).toBe("pending");
      expect(stillPending.resolvedAt).toBeNull();

      // An agent/API credential cannot self-approve.
      const agentApp = await makeAgentCredentialApp();
      const agentApprove = await agentApp.request(
        `/vault/${MANUAL_AGENT_ID}/approve/${pendingBody.data.id}`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": "agent-self-approve" },
        },
      );
      expect(agentApprove.status).toBe(403);
      expect(signCalls).toBe(0);

      const approverApp = await makeApp(TENANT_ID, APPROVER_USER_ID);
      const approved = await approverApp.request(
        `/vault/${MANUAL_AGENT_ID}/approve/${pendingBody.data.id}`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": "human-approve-1" },
        },
      );
      expect(approved.status).toBe(200);
      expect(signCalls).toBe(1);

      const [evidence] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, pendingBody.data.id));
      expect(evidence.status).toBe("approved");
      expect(evidence.resolvedByType).toBe("user");
      expect(evidence.resolvedById).toBe(APPROVER_USER_ID);
      expect(evidence.resolvedAt).not.toBeNull();
      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, pendingBody.data.id));
      expect(tx.status).toBe("broadcast");
      expect(tx.txHash).toBe("0xmanualapprovaltx");
      expect(tx.policyResults).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policyId: "manual-agent-review",
            passed: false,
            requiresManualApproval: true,
          }),
        ]),
      );
    } finally {
      context.vault.signTransaction = originalSign;
      if (previousRequiredActions === undefined) {
        delete process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS;
      } else {
        process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS = previousRequiredActions;
      }
    }
  });

  it("STRATA-1097: explicit human deny is terminal and never reaches signing", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      return "0xshould-not-sign";
    };
    try {
      const requesterApp = await makeApp(TENANT_ID, REQUESTER_USER_ID);
      const pending = await requesterApp.request(`/vault/${MANUAL_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": "manual-deny-1" },
        body: JSON.stringify({
          to: ALLOWED,
          token: TOKEN,
          value: "1",
          chainId: 84532,
          broadcast: true,
          referenceId: "manual-deny-1",
        }),
      });
      expect(pending.status).toBe(202);
      const id = ((await pending.json()) as { data: { id: string } }).data.id;

      const approverApp = await makeApp(TENANT_ID, APPROVER_USER_ID);
      const denied = await approverApp.request(`/vault/${MANUAL_AGENT_ID}/reject/${id}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reason: "Rehearsal cancelled" }),
      });
      expect(denied.status).toBe(200);
      expect(signCalls).toBe(0);
      const [tx] = await getDb().select().from(transactions).where(eq(transactions.id, id));
      expect(tx.status).toBe("rejected");
      const [evidence] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, id));
      expect(evidence.status).toBe("rejected");
      expect(evidence.resolvedByType).toBe("user");
      expect(evidence.resolvedById).toBe(APPROVER_USER_ID);
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });

  it("STRATA-1097: hard chain/token/recipient/amount failures are terminal and create no approval row", async () => {
    const cases = [
      {
        key: "wrong-chain",
        body: { to: ALLOWED, token: TOKEN, value: "1", chainId: 1, broadcast: false },
      },
      {
        key: "wrong-token",
        body: { to: ALLOWED, token: BLOCKED, value: "1", chainId: 84532, broadcast: false },
      },
      {
        key: "wrong-recipient",
        body: { to: BLOCKED, token: TOKEN, value: "1", chainId: 84532, broadcast: false },
      },
      {
        key: "over-amount",
        body: { to: ALLOWED, token: TOKEN, value: "1000001", chainId: 84532, broadcast: false },
      },
    ];
    const requesterApp = await makeApp(TENANT_ID, REQUESTER_USER_ID);
    for (const item of cases) {
      const response = await requesterApp.request(`/vault/${MANUAL_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...item.body, referenceId: `manual-${item.key}` }),
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as { data?: { id?: string; status?: string } };
      expect(body.data?.status).toBe("rejected");
      if (body.data?.id) {
        const approvals = await getDb()
          .select()
          .from(approvalQueue)
          .where(eq(approvalQueue.txId, body.data.id));
        expect(approvals).toHaveLength(0);
      }
    }
  });

  it("STRATA-1097 activation guard refuses required action when explicit manual policy is absent", async () => {
    const previous = process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS;
    process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS = "wallet_action_transfer";
    try {
      const response = await app.request(`/vault/${AGENT_WITHOUT_ALLOWLIST_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED,
          value: "1",
          chainId: 84532,
          broadcast: false,
          referenceId: "manual-rule-required",
        }),
      });
      expect(response.status).toBe(503);
      expect((await response.json()).error).toContain("requires an enabled manual-approval policy");
      const rows = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.agentId, AGENT_WITHOUT_ALLOWLIST_ID));
      expect(
        rows.some(
          (row) =>
            (row.actionPayload as { referenceId?: string } | null)?.referenceId ===
            "manual-rule-required",
        ),
      ).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS;
      else process.env.STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS = previous;
    }
  });
});
