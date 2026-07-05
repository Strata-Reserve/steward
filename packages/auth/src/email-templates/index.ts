import {
  type MagicLinkTemplateData,
  type RenderedMagicLinkTemplate,
  renderDefaultTemplate,
} from "./default";
import { renderElizaCloudTemplate } from "./elizacloud";
import { renderStrataTemplate } from "./strata";

export type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";

export function renderTemplate(
  templateId: string | undefined,
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "elizacloud") {
    return renderElizaCloudTemplate(data);
  }

  if (templateId === "strata") {
    return renderStrataTemplate(data);
  }

  return renderDefaultTemplate(data);
}
