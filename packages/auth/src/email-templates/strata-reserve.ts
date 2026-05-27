import type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";

/**
 * Strata Reserve magic-link template.
 *
 * Brand: institutional capital-markets — deep ink on cream paper, gold
 * rule, structured grid. Designed for tenants using
 * templateId: "strata-reserve".
 *
 * Inlined styles, table layout, double-rendered (HTML + plaintext) for
 * compatibility with Gmail / Outlook / Apple Mail / mobile clients.
 */
export function renderStrataReserveTemplate({
  email,
  magicLink,
  expiresInMinutes,
}: MagicLinkTemplateData): RenderedMagicLinkTemplate {
  const sans =
    "-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Helvetica, Arial, sans-serif";
  const mono = "'JetBrains Mono', 'SF Mono', 'Menlo', 'Consolas', monospace";

  // Brand colors (mirrors packages/app design tokens)
  const paper = "#f7f4ee"; // background
  const card = "#ffffff";
  const ink = "#1a1815"; // primary text
  const muted = "#6e665b"; // secondary text
  const rule = "#d8d2c4"; // 1px borders
  const gold = "#b08e3c"; // accent

  return {
    subject: "Sign in to Strata Reserve",
    text: [
      "Strata Reserve",
      "—————————————",
      "",
      `Hello ${email},`,
      "",
      "Use the link below to sign in. This link is single-use and",
      `expires in ${expiresInMinutes} minutes.`,
      "",
      magicLink,
      "",
      "If you didn't request this, you can safely ignore this email —",
      "nothing happens until the link is clicked.",
      "",
      "— Strata Reserve",
      "Capital markets infrastructure for real-world assets",
    ].join("\n"),
    html: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="color-scheme" content="light only" />
  <meta name="supported-color-schemes" content="light" />
  <title>Sign in to Strata Reserve</title>
</head>
<body style="margin:0;padding:0;background-color:${paper};font-family:${sans};color:${ink};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${paper};font-size:1px;line-height:1px;">
    Sign in to Strata Reserve. Link expires in ${expiresInMinutes} minutes.
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:${paper};">
    <tr>
      <td align="center" style="padding:56px 16px 48px;">
        <table role="presentation" width="520" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;width:100%;">

          <!-- Wordmark -->
          <tr>
            <td align="left" style="padding:0 0 28px 0;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${sans};font-size:18px;font-weight:600;letter-spacing:-0.01em;color:${ink};line-height:1;">
                    Strata Reserve
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;font-family:${mono};font-size:10.5px;letter-spacing:0.18em;text-transform:uppercase;color:${muted};">
                    Capital Markets Infrastructure
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Card -->
          <tr>
            <td style="background-color:${card};border:1px solid ${rule};border-radius:2px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">

                <!-- Gold rule -->
                <tr>
                  <td style="height:3px;background-color:${gold};line-height:3px;font-size:0;">&nbsp;</td>
                </tr>

                <tr>
                  <td style="padding:40px 40px 8px;">
                    <p style="margin:0;font-family:${mono};font-size:10.5px;letter-spacing:0.18em;text-transform:uppercase;color:${muted};">
                      Secure sign-in
                    </p>
                  </td>
                </tr>

                <tr>
                  <td style="padding:8px 40px 4px;">
                    <h1 style="margin:0;font-family:${sans};font-size:24px;font-weight:600;letter-spacing:-0.01em;line-height:1.25;color:${ink};">
                      Sign in to Strata Reserve
                    </h1>
                  </td>
                </tr>

                <tr>
                  <td style="padding:12px 40px 28px;">
                    <p style="margin:0;font-family:${sans};font-size:14px;line-height:1.6;color:${muted};">
                      Hello <span style="color:${ink};">${email}</span> — confirm your sign-in by clicking the button below. This link is single-use and expires in <strong style="color:${ink};font-weight:600;">${expiresInMinutes} minutes</strong>.
                    </p>
                  </td>
                </tr>

                <!-- CTA -->
                <tr>
                  <td align="left" style="padding:0 40px 32px;">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td align="center" bgcolor="${ink}" style="border-radius:2px;background-color:${ink};">
                          <a href="${magicLink}"
                             target="_blank"
                             rel="noopener"
                             style="display:inline-block;padding:13px 28px;font-family:${sans};font-size:13.5px;font-weight:600;letter-spacing:0.02em;color:${paper};text-decoration:none;border-radius:2px;">
                            Sign in &rarr;
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- Fallback link -->
                <tr>
                  <td style="padding:0 40px 36px;">
                    <p style="margin:0 0 6px;font-family:${mono};font-size:10.5px;letter-spacing:0.14em;text-transform:uppercase;color:${muted};">
                      Or paste this URL into your browser
                    </p>
                    <p style="margin:0;font-family:${mono};font-size:11.5px;line-height:1.55;word-break:break-all;color:${ink};">
                      <a href="${magicLink}" style="color:${ink};text-decoration:underline;">${magicLink}</a>
                    </p>
                  </td>
                </tr>

                <!-- Footer rule + helper -->
                <tr>
                  <td style="padding:0 40px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="border-top:1px solid ${rule};padding:20px 0 24px;">
                          <p style="margin:0;font-family:${sans};font-size:12px;line-height:1.55;color:${muted};">
                            Didn't request this? You can safely ignore this email — nothing happens until you click the link.
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Outer footer -->
          <tr>
            <td style="padding:24px 4px 0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:${mono};font-size:10px;letter-spacing:0.14em;text-transform:uppercase;color:${muted};line-height:1.5;">
                    Strata Reserve · stratareserve.co
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:4px;font-family:${sans};font-size:11.5px;line-height:1.5;color:${muted};">
                    Capital markets infrastructure for real-world assets.
                  </td>
                </tr>
              </table>
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
