import { z } from "zod";
import { webNetworkApiSurfaceViewResultSchema } from "./analysisView.js";
import { pageViewCoverage } from "./analysisViewCoverage.js";
import { WebNetworkApiSurfaceAccumulator } from "./WebNetworkApiSurfaceAccumulator.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../webNetworkCapture.js";
import { compareUnicodeCodePoints as compare } from "../unicodeCodePointOrder.js";
import { AnalysisResourceConstraintError } from "../analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../inputIssueProjection.js";
import type { AnalysisError } from "../analysisErrorBase.js";
import { err, ok, type Result } from "../result.js";

export const COMPARE_WEB_API_SURFACES = "compare_web_api_surfaces";
type Surface = z.output<typeof webNetworkApiSurfaceViewResultSchema>;
type Group = Surface["groups"][number];
const groupSchema = webNetworkApiSurfaceViewResultSchema.shape.groups.element;
const sourceSchema = webNetworkApiSurfaceViewResultSchema
  .pick({
    artifact: true,
    records: true,
    limitations: true,
    unknowns: true,
  })
  .extend({ evidence_id: z.string() });
export const webApiSurfaceComparisonSchema = z.strictObject({
  scope: z.literal("retained-records"),
  left: sourceSchema,
  right: sourceSchema,
  summary: z.strictObject({
    both: z.number().int().nonnegative(),
    left_only: z.number().int().nonnegative(),
    right_only: z.number().int().nonnegative(),
    response_differences: z.number().int().nonnegative(),
  }),
  coverage: webNetworkApiSurfaceViewResultSchema.shape.coverage,
  groups: z.array(
    z.strictObject({
      method: z.string(),
      origin: z.string(),
      path_template: z.string(),
      presence: z.enum(["both", "left-only", "right-only"]),
      response_comparison: z.enum([
        "same-observed-values",
        "different-observed-values",
        "unknown",
      ]),
      left: groupSchema.nullable(),
      right: groupSchema.nullable(),
    }),
  ),
  limitations: z.array(z.string()),
});
type Comparison = z.output<typeof webApiSurfaceComparisonSchema>;

/** Match the grouping owner's identity, never template display text alone. */
const identity = (group: Group): string =>
  JSON.stringify([
    group.method,
    group.origin,
    group.path_template,
    group.templated_segments.map((segment) => [
      segment.segment_index,
      segment.rule,
    ]),
  ]);
const same = (left: readonly unknown[], right: readonly unknown[]): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

/** Compare selected observations; no absent route or matching set proves server behavior. */
export const compareWebApiSurfaceViews = (
  leftInput: unknown,
  rightInput: unknown,
  offset: number,
  limit: number,
  maximumBytes = WEB_NETWORK_CAPTURE_LIMITS.outputBytes,
): Result<Comparison, AnalysisError> => {
  // Reuse the view owner's conservative graph/text admission before allocating
  // comparison keys, maps, output rows or the schema's cloned result graph.
  const admission = new WebNetworkApiSurfaceAccumulator(maximumBytes);
  const admitted = admission.admitInlineEvidence([leftInput, rightInput]);
  if (!admitted.ok && admitted.error._tag === "AnalysisResourceConstraintError")
    return err(
      new AnalysisResourceConstraintError(
        COMPARE_WEB_API_SURFACES,
        "memory",
        "Combined API surfaces exceed the comparison representation budget.",
        { output_bytes: maximumBytes },
      ),
    );
  if (!admitted.ok) return admitted;
  const parsed = z
    .tuple([
      webNetworkApiSurfaceViewResultSchema,
      webNetworkApiSurfaceViewResultSchema,
    ])
    .safeParse([leftInput, rightInput]);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(
        COMPARE_WEB_API_SURFACES,
        parsed.error.issues,
        [leftInput, rightInput],
      ),
    );
  const [left, right] = parsed.data;
  const rows = new Map<string, { left: Group | null; right: Group | null }>();
  for (const [side, surface] of [
    ["left", left],
    ["right", right],
  ] as const)
    for (const group of surface.groups) {
      const key = identity(group);
      const pair = rows.get(key) ?? { left: null, right: null };
      pair[side] = group;
      rows.set(key, pair);
    }
  const summary: Comparison["summary"] = {
    both: 0,
    left_only: 0,
    right_only: 0,
    response_differences: 0,
  };
  const groups: Comparison["groups"] = [];
  for (const pair of rows.values()) {
    const group = pair.left ?? pair.right!;
    const presence =
      pair.left === null
        ? "right-only"
        : pair.right === null
          ? "left-only"
          : "both";
    summary[
      presence === "both"
        ? "both"
        : presence === "left-only"
          ? "left_only"
          : "right_only"
    ]++;
    const response_comparison =
      pair.left === null ||
      pair.right === null ||
      left.unknowns.length > 0 ||
      right.unknowns.length > 0
        ? "unknown"
        : same(pair.left.statuses, pair.right.statuses) &&
            same(pair.left.content_types, pair.right.content_types)
          ? "same-observed-values"
          : "different-observed-values";
    if (response_comparison === "different-observed-values")
      summary.response_differences++;
    groups.push({
      method: group.method,
      origin: group.origin,
      path_template: group.path_template,
      presence,
      response_comparison,
      ...pair,
    });
  }
  groups.sort(
    (a, b) =>
      compare(a.origin, b.origin) ||
      compare(a.path_template, b.path_template) ||
      compare(a.method, b.method) ||
      compare(identity(a.left ?? a.right!), identity(b.left ?? b.right!)),
  );
  const selected = groups.slice(offset, offset + limit);
  const source = (surface: Surface): Comparison["left"] => ({
    evidence_id: surface.parent_evidence_id,
    artifact: surface.artifact,
    records: surface.records,
    limitations: surface.limitations,
    unknowns: surface.unknowns,
  });
  return ok({
    scope: "retained-records",
    left: source(left),
    right: source(right),
    summary,
    groups: selected,
    coverage: pageViewCoverage(offset, selected.length, groups.length),
    limitations: [
      "Presence describes retained records only; one-sided observations do not establish endpoint addition, removal or global absence.",
      "Equal observed response sets do not establish runtime equivalence or complete server behavior. Counts reflect recorded samples, not runtime invocation counts.",
      "Only exact method, origin, path template and template-rule identities are paired; no deployment-origin mapping is inferred.",
      "If either surface reports unavailable response facts, response-set comparisons remain unknown for all matched groups; observed values remain visible on each side.",
      ...new Set([...left.limitations, ...right.limitations]),
    ],
  });
};
