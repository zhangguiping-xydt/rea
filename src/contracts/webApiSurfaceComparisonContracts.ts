import { z } from "zod";
import { analysisViewSourceSchema } from "../domain/analysisView/analysisView.js";
import {
  COMPARE_WEB_API_SURFACES,
  webApiSurfaceComparisonSchema,
} from "../domain/analysisView/webApiSurfaceComparison.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "./toolEffects.js";
import type { ToolContract } from "./toolContractTypes.js";

export const compareWebApiSurfacesInputSchema = z.strictObject({
  left: analysisViewSourceSchema,
  right: analysisViewSourceSchema,
  offset: z.number().int().nonnegative().default(0),
  limit: z.number().int().positive().default(50),
});
export const COMPARE_WEB_API_SURFACES_CONTRACT = {
  name: COMPARE_WEB_API_SURFACES,
  ...toolContractMetadata(COMPARE_WEB_API_SURFACES),
  kind: "application",
  description:
    "Compare API surfaces from two complete inspect_web_network_capture Evidence sources, each inline or retained in this session. Reuses admitted api-surface formats and grouping rules (HAR on this release). Reports endpoint groups observed on either or both sides and recorded status/MIME sets, preserving capture identities, original record ordinals, exclusions and source limitations. Pages after complete grouping; defaults offset 0, limit 50. One-sided observations do not prove server additions/removals; missing response facts remain unknown. No target execution, archive reopening, decoder invocation, request replay or network access.",
  inputSchema: compareWebApiSurfacesInputSchema,
  outputSchema: evidenceResultOf(webApiSurfaceComparisonSchema),
  examples: [],
} as const satisfies ToolContract;
