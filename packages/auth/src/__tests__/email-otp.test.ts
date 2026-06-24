import { describe, expect, it } from "bun:test";

import { EmailAuth, generateOtpCode } from "../email";
import type { EmailProvider } from "../email-provider";

function makeAuth(): { auth: EmailAuth; sent: { to: string; subject: string; text: string }[] } {
  const sent: { to: string; subject: string; text: string }[] = [];
  const provider: EmailProvider = {
    async send(to, subject, text) {
      sent.push({ to, subject, text });
    },
  };
  const auth = new EmailAuth({
    from: "login@steward.fi",
    baseUrl: "https://steward.fi",
    provider,
    tokenTtlMs: 10 * 60 * 1000,
  });
  return { auth, sent };
}

/** Pull the 6-digit code out of the email text body the provider received. */
function extractCode(text: string): string {
  const m = text.match(/\b(\d{6})\b/);
  if (!m) throw new Error("no 6-digit code in email body");
  return m[1]!;
}

describe("generateOtpCode", () => {
  it("always returns exactly 6 ASCII digits", () => {
    for (let i = 0; i < 5000; i++) {
      const code = generateOtpCode();
      expect(code).toMatch(/^\d{6}$/);
      expect(code.length).toBe(6);
    }
  });

  it("has no gross modulo bias across the digit space (smoke)", () => {
    // 60k draws over 10 buckets keyed on the leading digit. Uniform expectation
    // is 6000/bucket; a biased generator (e.g. naive % without rejection) would
    // skew the low buckets. Allow a generous ±35% band to keep this a smoke
    // test, not a flaky statistical assertion.
    const buckets = new Array<number>(10).fill(0);
    const draws = 60_000;
    for (let i = 0; i < draws; i++) {
      const code = generateOtpCode();
      buckets[Number(code[0])]!++;
    }
    const expected = draws / 10;
    for (const count of buckets) {
      expect(count).toBeGreaterThan(expected * 0.65);
      expect(count).toBeLessThan(expected * 1.35);
    }
  });

  it("produces a wide spread of distinct values (not a constant)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) seen.add(generateOtpCode());
    // With 10^6 space and 2000 draws, collisions are vanishingly unlikely.
    expect(seen.size).toBeGreaterThan(1990);
  });
});

describe("EmailAuth.sendOtp / verifyOtp", () => {
  it("round-trips: a correct code verifies once", async () => {
    const { auth, sent } = makeAuth();
    const res = await auth.sendOtp("user@example.com", { tenantId: "t1" });
    expect(res.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("user@example.com");

    const code = extractCode(sent[0]!.text);
    expect(await auth.verifyOtp("user@example.com", code, "t1")).toBe(true);
    auth.destroy();
  });

  it("rejects a wrong code", async () => {
    const { auth, sent } = makeAuth();
    await auth.sendOtp("user@example.com", { tenantId: "t1" });
    const code = extractCode(sent[0]!.text);
    const wrong = code === "000000" ? "111111" : "000000";
    expect(await auth.verifyOtp("user@example.com", wrong, "t1")).toBe(false);
    // The real code still works after a failed wrong-code attempt.
    expect(await auth.verifyOtp("user@example.com", code, "t1")).toBe(true);
    auth.destroy();
  });

  it("is single-use: the same code cannot verify twice", async () => {
    const { auth, sent } = makeAuth();
    await auth.sendOtp("user@example.com", { tenantId: "t1" });
    const code = extractCode(sent[0]!.text);
    expect(await auth.verifyOtp("user@example.com", code, "t1")).toBe(true);
    expect(await auth.verifyOtp("user@example.com", code, "t1")).toBe(false);
    auth.destroy();
  });

  it("rejects a code bound to a different tenant", async () => {
    const { auth, sent } = makeAuth();
    await auth.sendOtp("user@example.com", { tenantId: "t1" });
    const code = extractCode(sent[0]!.text);
    expect(await auth.verifyOtp("user@example.com", code, "t2")).toBe(false);
    auth.destroy();
  });

  it("rejects a code bound to a different email", async () => {
    const { auth, sent } = makeAuth();
    await auth.sendOtp("user@example.com", { tenantId: "t1" });
    const code = extractCode(sent[0]!.text);
    expect(await auth.verifyOtp("attacker@example.com", code, "t1")).toBe(false);
    auth.destroy();
  });

  it("rejects malformed (non-6-digit) input without touching the store", async () => {
    const { auth } = makeAuth();
    expect(await auth.verifyOtp("user@example.com", "12345", "t1")).toBe(false);
    expect(await auth.verifyOtp("user@example.com", "abcdef", "t1")).toBe(false);
    expect(await auth.verifyOtp("user@example.com", "1234567", "t1")).toBe(false);
    auth.destroy();
  });

  it("expires: a code past its TTL no longer verifies", async () => {
    const sent: { text: string }[] = [];
    const provider: EmailProvider = {
      async send(_to, _subject, text) {
        sent.push({ text });
      },
    };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
      tokenTtlMs: 10, // 10ms TTL
    });
    await auth.sendOtp("user@example.com", { tenantId: "t1" });
    const code = extractCode(sent[0]!.text);
    await new Promise((r) => setTimeout(r, 25));
    expect(await auth.verifyOtp("user@example.com", code, "t1")).toBe(false);
    auth.destroy();
  });

  it("includes the code in the email subject and body", async () => {
    const { auth, sent } = makeAuth();
    await auth.sendOtp("user@example.com", { tenantId: "t1", tenantName: "Acme" });
    const code = extractCode(sent[0]!.text);
    expect(sent[0]!.subject).toContain(code);
    expect(sent[0]!.subject).toContain("Acme");
    expect(sent[0]!.text).toContain(code);
    auth.destroy();
  });
});
