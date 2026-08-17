import {
  type MagicLinkTemplateData,
  type OtpTemplateData,
  type RenderedMagicLinkTemplate,
  renderDefaultOtpTemplate,
  renderDefaultTemplate,
} from "./default";
import { renderStrataReserveTemplate } from "./strata-reserve";

export type { CustomEmailTemplate, TenantEmailTemplates } from "./custom";
export { magicLinkTemplateValues, otpTemplateValues, renderCustomTemplate } from "./custom";
export type {
  MagicLinkTemplateData,
  OtpTemplateData,
  RenderedMagicLinkTemplate,
} from "./default";

export function renderTemplate(
  templateId: string | undefined,
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "strata-reserve") {
    return renderStrataReserveTemplate(data);
  }
  return renderDefaultTemplate(data);
}

/**
 * Per-tenant OTP (sign-in code) template resolution. Unknown/absent
 * templateIds fall back to the Steward-branded default so existing tenants
 * are unaffected.
 *
 * NOTE: the `strata-reserve` template pack currently ships a magic-link
 * renderer only, so Strata tenants intentionally fall through to the
 * Steward-branded default OTP mail here.
 */
export function renderOtpTemplate(
  templateId: string | undefined,
  data: OtpTemplateData,
): RenderedMagicLinkTemplate {
  return renderDefaultOtpTemplate(data);
}
