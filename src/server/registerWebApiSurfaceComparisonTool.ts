import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { compareWebApiSurfaces } from "../application/analysisView/WebApiSurfaceComparisonService.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import {
  toolRegistrationOptions,
  applicationValidatedInputSchema,
} from "./toolRegistrationOptions.js";

/** Reuse the shared capture-view authentication and session Evidence owner. */
export const registerWebApiSurfaceComparisonTool = (
  server: EvidenceMcpServer,
  logger: Logger,
  evidenceById?: EvidenceLookup,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("compare_web_api_surfaces");
  const registration = toolRegistrationOptions(contract);
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => compareWebApiSurfaces(input, options, evidenceById),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    {
      ...registration,
      inputSchema: applicationValidatedInputSchema(registration.inputSchema),
    },
    handler(contract),
  );
};
