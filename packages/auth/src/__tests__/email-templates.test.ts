import { describe, expect, it } from "bun:test";

import { renderDefaultTemplate } from "../email-templates/default";
import { renderTemplate } from "../email-templates/index";
import { renderStrataTemplate } from "../email-templates/strata";

describe("renderTemplate", () => {
  const data = {
    email: "user@example.com",
    magicLink: "https://steward.fi/auth/callback/email?token=test",
    expiresInMinutes: 10,
  };

  it("falls back to the default template for unknown template ids", () => {
    expect(renderTemplate("unknown-template", data)).toEqual(renderDefaultTemplate(data));
  });

  it("selects the Strata template for templateId 'strata'", () => {
    expect(renderTemplate("strata", data)).toEqual(renderStrataTemplate(data));
  });
});

describe("renderStrataTemplate", () => {
  const data = {
    email: "user@example.com",
    magicLink: "https://app.stratareserve.co/auth/callback?token=abc123",
    expiresInMinutes: 10,
  };

  it("is Strata-branded (subject + wordmark) and not the Steward default", () => {
    const out = renderStrataTemplate(data);
    expect(out.subject).toBe("Sign in to Strata Reserve");
    expect(out.html).toContain("Strata Reserve");
    expect(out.text).toContain("Strata Reserve");
    expect(out.html).not.toContain("Sign in to Steward");
  });

  it("embeds the magic link in both the button and the plaintext fallback", () => {
    const out = renderStrataTemplate(data);
    expect(out.html).toContain(data.magicLink);
    expect(out.text).toContain(data.magicLink);
  });

  it("surfaces the expiry window", () => {
    const out = renderStrataTemplate(data);
    expect(out.html).toContain("10");
    expect(out.text).toContain("10 minutes");
  });
});
