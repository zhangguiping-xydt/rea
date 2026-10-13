import { setImmediate } from "node:timers/promises";
import { compareWebApiSurfacesInputSchema } from "../../contracts/webApiSurfaceComparisonContracts.js";
import {
  compareWebApiSurfaceViews,
  COMPARE_WEB_API_SURFACES,
} from "../../domain/analysisView/webApiSurfaceComparison.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ARTIFACT_COMPARISON_PROVIDER } from "../InvestigationProviders.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { EvidenceLookup } from "../EvidenceInputResolver.js";
import { inspectAnalysisViewValidated } from "./AnalysisViewService.js";

/** Authenticate each source once through the owning view workflow, then compare its facts. */
export const compareWebApiSurfaces = async (
  rawInput: unknown,
  options?: ExecutionOptions,
  lookup?: EvidenceLookup,
): Promise<Result<Evidence, AnalysisError>> => {
  const operation = COMPARE_WEB_API_SURFACES;
  if (options?.signal?.aborted)
    return err(new AnalysisCancelledError(operation));
  try {
    const input = compareWebApiSurfacesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, rawInput),
      );
    await setImmediate();
    options?.signal?.throwIfAborted();
    const view = {
      kind: "api-surface" as const,
      offset: 0,
      limit: Number.MAX_SAFE_INTEGER,
    };
    const left = inspectAnalysisViewValidated(
      { source: input.data.left, view },
      lookup,
    );
    if (!left.ok) return left;
    await setImmediate();
    options?.signal?.throwIfAborted();
    const right = inspectAnalysisViewValidated(
      { source: input.data.right, view },
      lookup,
    );
    if (!right.ok) return right;
    const compared = compareWebApiSurfaceViews(
      left.value.normalized_result,
      right.value.normalized_result,
      input.data.offset,
      input.data.limit,
    );
    if (!compared.ok) return compared;
    await setImmediate();
    options?.signal?.throwIfAborted();
    return ok(
      createEvidence(undefined, ARTIFACT_COMPARISON_PROVIDER, {
        operation,
        predicateType: "rea.web-api-surface-comparison",
        parameters: {
          left_evidence_id: compared.value.left.evidence_id,
          right_evidence_id: compared.value.right.evidence_id,
          offset: input.data.offset,
          limit: input.data.limit,
        },
        result: compared.value,
        confidence:
          left.value.confidence === "inferred" ||
          right.value.confidence === "inferred"
            ? "inferred"
            : "derived",
        authority: "analyst-inference",
        limitations: compared.value.limitations,
        evidenceLinks: [
          compared.value.left.evidence_id,
          compared.value.right.evidence_id,
        ],
      }),
    );
  } catch (cause: unknown) {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(operation));
    if (cause instanceof AnalysisError) return err(cause);
    return err(
      new AnalysisInputError(operation, { cause }, [
        {
          path: [],
          reason: "invalid_value",
          message: cause instanceof Error ? cause.message : String(cause),
        },
      ]),
    );
  }
};
