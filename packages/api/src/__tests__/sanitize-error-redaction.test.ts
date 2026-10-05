/**
 * STRATA-1499 SF-1 (REVIEW-STEWARD-28-R4 N1 follow-up): sanitizeErrorMessage
 * runs even its allowlisted pass-through messages through redactRpcMessage,
 * so a configured RPC endpoint interpolated into a "safe" message never
 * reaches an HTTP body. No DB access, no network.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

const HOST = "sanitize-redaction.invalid";
const KEY = "SECRETKEY1234567890";
const URL_8453 = `https://${HOST}/v2/${KEY}`;

let sanitizeErrorMessage: typeof import("../services/context").sanitizeErrorMessage;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "sanitize-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "sanitize-audit-key-32-bytes-minimum-aaaaaaa";
  process.env.STEWARD_JWT_SECRET = "sanitize-jwt-secret-with-enough-bytes-aaaaaa";
  process.env.RPC_URL_8453 = URL_8453;
  ({ sanitizeErrorMessage } = await import("../services/context"));
}, 60000);

afterAll(() => {
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL_8453",
  ])
    delete process.env[k];
});

describe("sanitizeErrorMessage redacts allowlisted pass-through messages", () => {
  it("strips a configured endpoint (host, path, key) from a 'safe' message", () => {
    const out = sanitizeErrorMessage(
      new Error(`RPC endpoint not configured for chain 8453 (tried ${URL_8453})`),
    );
    expect(out).toContain("RPC endpoint not configured");
    expect(out).not.toContain(HOST);
    expect(out).not.toContain(KEY);
    expect(out).not.toContain(URL_8453);
  });

  it("strips an unconfigured URL's scheme+host by pattern from a 'not found' message", () => {
    // Pattern sweep lives in @stwd/vault redactRpcEndpoints (not this lane);
    // this only asserts the pass-through goes through it at all.
    const out = sanitizeErrorMessage(
      new Error("Agent not found at https://other-endpoint.invalid/rpc/abcdefghijkl"),
    );
    expect(out).toContain("not found");
    expect(out).not.toContain("other-endpoint.invalid");
    expect(out).not.toContain("https://");
  });

  it("keeps the generic fallback and plain safe messages unchanged", () => {
    expect(sanitizeErrorMessage(new Error(`boom ${URL_8453}`))).toBe("Internal server error");
    expect(sanitizeErrorMessage(new Error("Agent already exists"))).toBe("Agent already exists");
    expect(sanitizeErrorMessage("string")).toBe("Internal server error");
  });
});
