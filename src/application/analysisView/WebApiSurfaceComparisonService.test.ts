import { expect, it } from "vitest";
import { analysisViewCaptureFixture } from "../../../tests/fixtures/analysisView.js";
import { createEvidence, parseEvidence } from "../../domain/evidence.js";
import { compareWebApiSurfaces } from "./WebApiSurfaceComparisonService.js";
import { inspectAnalysisView } from "./AnalysisViewService.js";
import { compareWebApiSurfaceViews } from "../../domain/analysisView/webApiSurfaceComparison.js";

const source = (
  paths: string[],
  status: number | null = 200,
  options: { total?: number; sensitive?: number; origin?: string } = {},
) => {
  const capture = analysisViewCaptureFixture();
  const record = capture.records[0]!;
  capture.records = paths.map((path, ordinal) => ({
    ...record,
    ordinal,
    reported: {
      request: {
        method: "GET",
        url: `${options.origin ?? "https://api.test"}${path}`,
      },
      response: { status, content: { mimeType: "application/json" } },
    },
  }));
  capture.total_records = options.total ?? paths.length;
  return createEvidence(
    undefined,
    { id: "fixture", name: "Fixture", version: "1" },
    {
      operation: "inspect_web_network_capture",
      parameters: { sensitive_value_count: options.sensitive ?? 0 },
      result: capture,
      confidence: "observed",
    },
  );
};
const compare = (
  left: ReturnType<typeof source>,
  right: ReturnType<typeof source>,
  page = {},
) =>
  compareWebApiSurfaces({
    left: { kind: "inline", evidence: left },
    right: { kind: "inline", evidence: right },
    ...page,
  });

it("compares observed endpoint presence and response sets with both capture references", async () => {
  const left = source(["/old", "/items/1"]);
  const right = source(["/new", "/items/2"], 201);
  const result = await compare(left, right);
  if (!result.ok) throw result.error;
  expect(parseEvidence(result.value)).toEqual(result.value);
  expect(result.value.evidence_links).toEqual([
    left.evidence_id,
    right.evidence_id,
  ]);
  expect(result.value.confidence).toBe("inferred");
  expect(result.value.normalized_result).toMatchObject({
    scope: "retained-records",
    summary: { both: 1, left_only: 1, right_only: 1, response_differences: 1 },
    groups: [
      {
        path_template: "/items/{numeric}",
        presence: "both",
        response_comparison: "different-observed-values",
        left: { statuses: [200], record_ordinals: [1] },
        right: { statuses: [201], record_ordinals: [1] },
      },
      { path_template: "/new", presence: "right-only", left: null },
      { path_template: "/old", presence: "left-only", right: null },
    ],
  });
});

it("keeps literal placeholders, inferred templates and different origins distinct", async () => {
  const result = await compare(
    source(["/items/{numeric}"]),
    source(["/items/1"]),
  );
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    summary: { both: 0, left_only: 1, right_only: 1 },
  });
  const origins = await compare(
    source(["/same"]),
    source(["/same"], 200, { origin: "https://other.test" }),
  );
  if (!origins.ok) throw origins.error;
  expect(origins.value.normalized_result).toMatchObject({
    summary: { both: 0, left_only: 1, right_only: 1 },
  });
});

it("preserves missing response facts and selected-record coverage as uncertainty", async () => {
  const result = await compare(
    source(["/same"], null, { total: 3 }),
    source(["/same"]),
  );
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    left: {
      records: { examined: 1, total: 3, excluded: 0 },
      unknowns: expect.any(Array),
    },
    groups: [
      {
        presence: "both",
        response_comparison: "unknown",
        left: { statuses: [] },
        right: { statuses: [200] },
      },
    ],
  });
  expect(result.value.limitations.join(" ")).toContain("absence");
});

it("pages after full comparison, preserves the summary and returns identical retained results", async () => {
  const left = source(["/a", "/c"]);
  const right = source(["/a", "/b"]);
  const full = await compare(left, right);
  if (!full.ok) throw full.error;
  const page = await compare(left, right, { offset: 1, limit: 1 });
  if (!page.ok) throw page.error;
  expect(page.value.normalized_result).toMatchObject({
    summary: { both: 1, left_only: 1, right_only: 1, response_differences: 0 },
    groups: [{ path_template: "/b", presence: "right-only" }],
    coverage: { examined: 1, total: 3, next_offset: 2, exhausted: false },
  });
  const retained = await compareWebApiSurfaces(
    {
      left: { kind: "retained-evidence", evidence_id: left.evidence_id },
      right: { kind: "retained-evidence", evidence_id: right.evidence_id },
    },
    undefined,
    (id) =>
      id === left.evidence_id
        ? left
        : id === right.evidence_id
          ? right
          : undefined,
  );
  if (!retained.ok) throw retained.error;
  expect(retained.value).toEqual(full.value);
});

it("rejects stale, missing, sensitive and cancelled sources before comparison", async () => {
  const parent = source(["/same"]);
  expect(
    await compare({ ...parent, evidence_id: `ev_${"0".repeat(64)}` }, parent),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  expect(
    await compare(source(["/same"], 200, { sensitive: 1 }), parent),
  ).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisUnsupportedTargetError" },
  });
  expect(
    await compareWebApiSurfaces({
      left: { kind: "retained-evidence", evidence_id: parent.evidence_id },
      right: { kind: "inline", evidence: parent },
    }),
  ).toMatchObject({
    ok: false,
    error: { _tag: "EvidenceIntegrityError", reason: "missing" },
  });
  expect(
    await compareWebApiSurfaces({}, { signal: AbortSignal.abort() }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
});

it("admits both result graphs together before constructing comparison rows", () => {
  const surface = (paths: string[]) => {
    const result = inspectAnalysisView({
      source: { kind: "inline", evidence: source(paths) },
      view: { kind: "api-surface" },
    });
    if (!result.ok) throw result.error;
    return result.value.normalized_result;
  };
  const left = surface([`/${"a".repeat(8000)}`]);
  const right = surface([`/${"b".repeat(8000)}`]);
  const empty = surface([]);
  const maximum = 200 * 1024;
  const one = compareWebApiSurfaceViews(left, empty, 0, 50, maximum);
  if (!one.ok) throw one.error;
  expect(one.value.summary.left_only).toBe(1);
  expect(compareWebApiSurfaceViews(left, right, 0, 50, maximum)).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisResourceConstraintError",
      operation: "compare_web_api_surfaces",
    },
  });
});

it("keeps empty captures empty and honors cancellation between projection stages", async () => {
  const empty = await compare(source([]), source([]));
  if (!empty.ok) throw empty.error;
  expect(empty.value.normalized_result).toMatchObject({
    groups: [],
    summary: { both: 0, left_only: 0, right_only: 0, response_differences: 0 },
    coverage: { total: 0, exhausted: true },
  });
  const controller = new AbortController();
  const parent = source(["/same"]);
  const pending = compareWebApiSurfaces(
    {
      left: { kind: "inline", evidence: parent },
      right: { kind: "inline", evidence: parent },
    },
    { signal: controller.signal },
  );
  controller.abort();
  expect(await pending).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});
