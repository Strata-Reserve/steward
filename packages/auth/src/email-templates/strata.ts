import type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";

/**
 * Strata Reserve magic link template.
 *
 * Brand: institutional navy (#16325a) with a gold accent (#cc8b19), light
 * "cream" canvas, serious sans wordmark. Designed for the Strata tenant using
 * templateId: "strata". Mirrors the Strata console's design tokens
 * (--primary 215 60% 22% navy, --accent gold) so the sign-in email reads as a
 * first-class extension of app.stratareserve.co rather than a generic Steward
 * default.
 */
export function renderStrataTemplate({
  magicLink,
  expiresInMinutes,
}: MagicLinkTemplateData): RenderedMagicLinkTemplate {
  const sans =
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";

  // Brand tokens (hex-materialized from the console's HSL design tokens).
  const navy = "#16325a"; // --primary
  const navyDeep = "#0f2540"; // darker header/footer wash
  const gold = "#cc8b19"; // --accent (gold), AA on navy
  const goldBright = "#eead2b";
  const ink = "#151c28"; // --foreground
  const canvas = "#f6f7f9"; // --background (cream)
  const card = "#ffffff";
  const muted = "#5b6472"; // --muted-foreground
  const border = "#dfe3ea"; // --border

  return {
    subject: "Sign in to Strata Reserve",
    text: [
      "Strata Reserve",
      "──────────────",
      "",
      "You requested a secure sign-in link. Click below to continue:",
      "",
      magicLink,
      "",
      `This link expires in ${expiresInMinutes} minutes and can be used once.`,
      "",
      "If you didn't request this, you can safely ignore this email — nothing happens until you click.",
      "",
      "— Strata Reserve",
    ].join("\n"),
    html: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="light" />
  <meta name="supported-color-schemes" content="light" />
  <title>Sign in to Strata Reserve</title>
</head>
<body style="margin:0;padding:0;background-color:${canvas};color:${ink};font-family:${sans};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${canvas};font-size:1px;line-height:1px;">
    Your secure sign-in link for Strata Reserve. Expires in ${expiresInMinutes} minutes.
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:${canvas};">
    <tr>
      <td align="center" style="padding:48px 16px;">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;width:100%;">

          <!-- Brand header band -->
          <tr>
            <td style="background-color:${navy};padding:28px 32px;border-radius:8px 8px 0 0;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${sans};font-size:18px;font-weight:700;letter-spacing:0.02em;color:#ffffff;">
                    <span style="color:${goldBright};">&#9670;</span>&nbsp;&nbsp;Strata Reserve
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Card body -->
          <tr>
            <td style="background-color:${card};border:1px solid ${border};border-top:none;padding:40px 32px 32px 32px;border-radius:0 0 8px 8px;">

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${sans};font-size:22px;line-height:1.3;color:${ink};font-weight:700;letter-spacing:-0.01em;padding-bottom:10px;">
                    Sign in to Strata Reserve
                  </td>
                </tr>
                <tr>
                  <td style="font-family:${sans};font-size:14px;line-height:1.6;color:${muted};padding-bottom:32px;">
                    Click the button below to securely sign in to your account. This link expires in ${expiresInMinutes}&nbsp;minutes and can be used once.
                  </td>
                </tr>
              </table>

              <!-- CTA -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center" style="padding-bottom:28px;">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td align="center" bgcolor="${navy}" style="border-radius:6px;background-color:${navy};">
                          <a href="${magicLink}"
                             style="display:inline-block;padding:14px 40px;font-family:${sans};font-size:15px;font-weight:600;letter-spacing:0.01em;color:#ffffff;text-decoration:none;border-radius:6px;border-top:3px solid ${gold};">
                            Sign in
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Fallback link -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${sans};font-size:13px;line-height:1.6;color:${muted};padding-bottom:28px;">
                    Or paste this link into your browser:<br />
                    <a href="${magicLink}" style="color:${navy};text-decoration:underline;font-size:12px;word-break:break-all;">${magicLink}</a>
                  </td>
                </tr>
              </table>

              <!-- Divider -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="height:1px;background-color:${border};line-height:1px;font-size:1px;">&nbsp;</td>
                </tr>
              </table>

              <!-- Security footnote -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${sans};font-size:12px;line-height:1.6;color:${muted};padding-top:24px;">
                    If you didn't request this, you can safely ignore this email — nothing happens until you click the link.
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer wordmark -->
          <tr>
            <td style="padding:24px 32px 0 32px;font-family:${sans};font-size:11px;line-height:1.6;color:${muted};letter-spacing:0.02em;">
              <span style="color:${navyDeep};font-weight:600;">Strata Reserve</span>&nbsp;&middot;&nbsp;Capital markets infrastructure for real-world assets
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`,
  };
}
