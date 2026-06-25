import {
  type MagicLinkTemplateData,
  type RenderedMagicLinkTemplate,
  renderDefaultTemplate,
} from "./default";
import { renderElizaCloudTemplate } from "./elizacloud";
import {
  renderStrataMagicLinkTemplate,
  renderStrataOtpTemplate,
  type StrataOtpTemplateData,
} from "./strata";

export type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";
export { renderStrataOtpTemplate, type StrataOtpTemplateData } from "./strata";

export function renderTemplate(
  templateId: string | undefined,
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "elizacloud") {
    return renderElizaCloudTemplate(data);
  }

  if (templateId === "strata" || templateId === "strata-reserve") {
    return renderStrataMagicLinkTemplate(data);
  }

  return renderDefaultTemplate(data);
}

/** Template ids that resolve to the Strata Reserve brand. */
function isStrataTemplate(templateId: string | undefined): boolean {
  return templateId === "strata" || templateId === "strata-reserve";
}

/**
 * Render a branded one-time-code email by templateId. Falls back to a generic
 * dark code card when no branded template matches. The OTP path lives outside
 * the magic-link renderer because its payload is a `code`, not a `magicLink`.
 */
export function renderOtpTemplate(
  templateId: string | undefined,
  data: StrataOtpTemplateData & { brand: string },
): RenderedMagicLinkTemplate {
  if (isStrataTemplate(templateId)) {
    return renderStrataOtpTemplate(data);
  }

  return renderDefaultOtpTemplate(data);
}

/** Generic fallback code email (brand-neutral dark card). */
function renderDefaultOtpTemplate({
  code,
  expiresInMinutes,
  brand,
}: StrataOtpTemplateData & { brand: string }): RenderedMagicLinkTemplate {
  const escapeHtml = (v: string): string =>
    v
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  const escapedBrand = escapeHtml(brand);
  const escapedCode = escapeHtml(code);
  return {
    subject: `Your ${brand} verification code is ${code}`,
    text: [
      `Your ${brand} verification code is: ${code}`,
      "",
      `It expires in ${expiresInMinutes} minutes. If you didn't request this, ignore this email.`,
    ].join("\n"),
    html: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#0b0a09;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0b0a09;">
    <tr><td align="center" style="padding:60px 24px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:420px;">
        <tr><td style="background-color:#141210;border:1px solid #2a2722;padding:40px 32px;">
          <div style="font-size:18px;font-weight:700;color:#e8e5e0;padding-bottom:8px;">${escapedBrand} verification code</div>
          <div style="font-size:13px;color:#9c9788;line-height:1.5;padding-bottom:24px;">Enter this code to verify your email. It expires in ${expiresInMinutes} minutes.</div>
          <div style="text-align:center;padding-bottom:24px;">
            <span style="display:inline-block;background-color:#0b0a09;border:1px solid #2a2722;color:#e8e5e0;font-size:32px;font-weight:700;letter-spacing:0.35em;padding:16px 24px 16px 32px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;">${escapedCode}</span>
          </div>
          <div style="border-top:1px solid #2a2722;padding-top:20px;font-size:11px;color:#9c9788;line-height:1.5;">If you didn't request this code, you can safely ignore this email.</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  };
}
