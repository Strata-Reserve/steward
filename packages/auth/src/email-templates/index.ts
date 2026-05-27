import {
  type MagicLinkTemplateData,
  type RenderedMagicLinkTemplate,
  renderDefaultTemplate,
} from "./default";
import { renderElizaCloudTemplate } from "./elizacloud";
import { renderStrataReserveTemplate } from "./strata-reserve";

export type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";

export function renderTemplate(
  templateId: string | undefined,
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "elizacloud") {
    return renderElizaCloudTemplate(data);
  }
  if (templateId === "strata-reserve") {
    return renderStrataReserveTemplate(data);
  }

  return renderDefaultTemplate(data);
}
