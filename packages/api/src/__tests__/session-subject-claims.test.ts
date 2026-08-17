import { describe, expect, it } from "bun:test";
import type { users } from "@stwd/db";
import { buildSessionIdentityClaims } from "../routes/auth";

// Pure-unit tests for the identity-claim builder used by every human session
// token. These run without a database or vault — they exercise the fail-closed
// email-claim policy that prevents one human's verified email from being
// embedded (and therefore impersonable) on a token it doesn't belong to.

type UserRow = typeof users.$inferSelect;

function makeUser(overrides: Partial<UserRow>): UserRow {
  return {
    id: "user-1",
    email: null,
    emailVerified: false,
    name: null,
    image: null,
    walletAddress: null,
    walletChain: "ethereum",
    stewardWalletId: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as UserRow;
}

describe("buildSessionIdentityClaims (verified-email-only, fail-closed)", () => {
  it("always embeds userId", () => {
    const claims = buildSessionIdentityClaims(makeUser({ id: "abc" }));
    expect(claims.userId).toBe("abc");
  });

  it("embeds email + emailVerified:true when the email is verified", () => {
    const claims = buildSessionIdentityClaims(
      makeUser({ id: "u1", email: "a@example.com", emailVerified: true }),
    );
    expect(claims.email).toBe("a@example.com");
    expect(claims.emailVerified).toBe(true);
  });

  it("OMITS email when the email is present but NOT verified", () => {
    const claims = buildSessionIdentityClaims(
      makeUser({ id: "u2", email: "unverified@example.com", emailVerified: false }),
    );
    expect(claims.email).toBeUndefined();
    expect(claims.emailVerified).toBeUndefined();
    expect(claims.userId).toBe("u2");
  });

  it("OMITS email when emailVerified is null (default)", () => {
    const claims = buildSessionIdentityClaims(
      makeUser({ id: "u3", email: "x@example.com", emailVerified: null as unknown as boolean }),
    );
    expect(claims.email).toBeUndefined();
    expect(claims.emailVerified).toBeUndefined();
  });

  it("OMITS email for a wallet-only user (email null)", () => {
    const claims = buildSessionIdentityClaims(
      makeUser({ id: "wallet-user", email: null, walletAddress: "0xabc" }),
    );
    expect(claims.email).toBeUndefined();
    expect(claims.emailVerified).toBeUndefined();
    expect(claims.userId).toBe("wallet-user");
  });

  it("never invents an email when none is set", () => {
    const claims = buildSessionIdentityClaims(
      makeUser({ id: "u4", email: null, emailVerified: true }),
    );
    expect(claims.email).toBeUndefined();
  });
});
