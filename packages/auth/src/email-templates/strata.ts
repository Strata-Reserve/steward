import type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";

/**
 * Strata Reserve email templates.
 *
 * Brand: institutional capital-markets. Light editorial canvas, deep navy
 * ink (#15192e), gold accent (#c99a3b), Source-Serif wordmark/headings with
 * a DM-Sans body. Mirrors the app's design tokens
 * (packages/app/src/styles/tokens.css). Designed for tenants using
 * templateId: "strata".
 *
 * Two surfaces share one visual system:
 *   - renderStrataMagicLinkTemplate(...)  → magic sign-in link
 *   - renderStrataOtpTemplate(...)        → 6-digit verification code
 */

// Email clients are inconsistent about web fonts; we lead with the brand
// faces and fall back to robust system stacks so the layout never breaks.
const SERIF = "'Source Serif 4', Georgia, 'Times New Roman', serif";
const SANS =
  "'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const MONO = "'JetBrains Mono', 'SF Mono', ui-monospace, Menlo, Consolas, monospace";

// Brand palette (resolved from the app's HSL tokens to hex for email safety).
const NAVY = "#15192e"; // --color-ink (light theme)
const NAVY_SOFT = "#3c4257"; // secondary ink
const MUTE = "#6b7280"; // tertiary ink / captions
const GOLD = "#c99a3b"; // --color-accent
const GOLD_INK = "#15192e"; // text on gold
const CANVAS = "#f4f5f7"; // --color-canvas (outer)
const CARD = "#ffffff"; // --color-card
const HAIRLINE = "#e5e7eb"; // hairline borders

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Shared wordmark row: gold tick + "Strata Reserve" in the serif face. */
function wordmark(): string {
  return `
    <tr>
      <td style="padding:0 0 28px 0;">
        <span style="font-family:${SERIF};font-size:19px;font-weight:600;letter-spacing:-0.01em;color:${NAVY};">
          <span style="color:${GOLD};">&#9670;</span>&nbsp;&nbsp;Strata Reserve
        </span>
      </td>
    </tr>`;
}

/** Shared outer shell. `inner` is the card body markup. */
function shell(previewText: string, inner: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="light" />
  <meta name="supported-color-schemes" content="light" />
  <title>Strata Reserve</title>
</head>
<body style="margin:0;padding:0;background-color:${CANVAS};color:${NAVY};font-family:${SANS};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${CANVAS};font-size:1px;line-height:1px;">
    ${escapeHtml(previewText)}
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:${CANVAS};">
    <tr>
      <td align="center" style="padding:48px 16px;">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;">
          <tr>
            <td style="background-color:${CARD};border:1px solid ${HAIRLINE};border-radius:10px;border-top:3px solid ${GOLD};padding:40px 40px 36px 40px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                ${wordmark()}
                ${inner}
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 8px 0 8px;font-family:${SANS};font-size:11px;line-height:1.6;color:${MUTE};text-align:center;">
              Strata Reserve &middot; capital markets infrastructure for real-world assets<br />
              If you didn&rsquo;t request this email, you can safely ignore it.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Magic sign-in link in the Strata brand.
 */
export function renderStrataMagicLinkTemplate({
  magicLink,
  expiresInMinutes,
}: MagicLinkTemplateData): RenderedMagicLinkTemplate {
  const link = magicLink; // injected into href + text; not user-controlled

  const inner = `
    <tr>
      <td style="font-family:${SERIF};font-size:26px;line-height:1.25;font-weight:600;color:${NAVY};letter-spacing:-0.01em;padding:0 0 10px 0;">
        Sign in to Strata Reserve
      </td>
    </tr>
    <tr>
      <td style="font-family:${SANS};font-size:15px;line-height:1.6;color:${NAVY_SOFT};padding:0 0 28px 0;">
        Use the button below to securely sign in. This link expires in ${expiresInMinutes} minutes and can be used once.
      </td>
    </tr>
    <tr>
      <td style="padding:0 0 28px 0;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td align="center" bgcolor="${GOLD}" style="border-radius:6px;background-color:${GOLD};">
              <a href="${link}" target="_blank"
                 style="display:inline-block;padding:14px 34px;font-family:${SANS};font-size:14px;font-weight:600;letter-spacing:0.01em;color:${GOLD_INK};text-decoration:none;border-radius:6px;">
                Sign in &rarr;
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="border-top:1px solid ${HAIRLINE};padding:22px 0 0 0;font-family:${SANS};font-size:12px;line-height:1.6;color:${MUTE};">
        Or paste this link into your browser:<br />
        <a href="${link}" style="color:${GOLD};text-decoration:none;font-family:${MONO};font-size:12px;word-break:break-all;">${link}</a>
      </td>
    </tr>`;

  return {
    subject: "Sign in to Strata Reserve",
    text: [
      "Strata Reserve",
      "",
      "Use the link below to securely sign in:",
      "",
      link,
      "",
      `This link expires in ${expiresInMinutes} minutes and can be used once.`,
      "",
      "If you didn't request this email, you can safely ignore it.",
      "",
      "— Strata Reserve",
    ].join("\n"),
    html: shell(
      `Sign in to Strata Reserve. Link expires in ${expiresInMinutes} minutes.`,
      inner,
    ),
  };
}

export interface StrataOtpTemplateData {
  code: string;
  expiresInMinutes: number;
}

/**
 * 6-digit email verification code in the Strata brand. Used by the
 * passkey-registration email-OTP gate.
 */
export function renderStrataOtpTemplate({
  code,
  expiresInMinutes,
}: StrataOtpTemplateData): RenderedMagicLinkTemplate {
  const safeCode = escapeHtml(code);

  const inner = `
    <tr>
      <td style="font-family:${SERIF};font-size:26px;line-height:1.25;font-weight:600;color:${NAVY};letter-spacing:-0.01em;padding:0 0 10px 0;">
        Verify your email
      </td>
    </tr>
    <tr>
      <td style="font-family:${SANS};font-size:15px;line-height:1.6;color:${NAVY_SOFT};padding:0 0 26px 0;">
        Enter this code to verify your email and continue. It expires in ${expiresInMinutes} minutes.
      </td>
    </tr>
    <tr>
      <td align="center" style="padding:0 0 26px 0;">
        <span style="display:inline-block;background-color:${CANVAS};border:1px solid ${HAIRLINE};border-radius:8px;color:${NAVY};font-family:${MONO};font-size:34px;font-weight:600;letter-spacing:0.32em;padding:18px 24px 18px 32px;">
          ${safeCode}
        </span>
      </td>
    </tr>
    <tr>
      <td style="border-top:1px solid ${HAIRLINE};padding:22px 0 0 0;font-family:${SANS};font-size:12px;line-height:1.6;color:${MUTE};">
        If you didn&rsquo;t request this code, you can safely ignore this email &mdash; no changes are made until it&rsquo;s entered.
      </td>
    </tr>`;

  return {
    subject: `Your Strata Reserve verification code is ${code}`,
    text: [
      "Strata Reserve",
      "",
      `Your verification code is: ${code}`,
      "",
      `It expires in ${expiresInMinutes} minutes. If you didn't request this, ignore this email.`,
      "",
      "— Strata Reserve",
    ].join("\n"),
    html: shell(
      `Your Strata Reserve verification code is ${code}. Expires in ${expiresInMinutes} minutes.`,
      inner,
    ),
  };
}
