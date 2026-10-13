import { expect, it } from "vitest";
import {
  analysisViewCaptureEvidence,
  analysisViewCaptureFixture,
} from "../../../tests/fixtures/analysisView.js";
import { inspectAnalysisView } from "./AnalysisViewService.js";

const parentFor = (urls: string[]) => {
  const capture = analysisViewCaptureFixture();
  const sample = capture.records[0]!;
  capture.records = urls.map((url, ordinal) => ({
    ...sample,
    ordinal,
    reported: {
      request: { method: "GET", url },
      response: { status: 200, content: { mimeType: "application/json" } },
    },
  }));
  capture.total_records = urls.length;
  return analysisViewCaptureEvidence(capture);
};

const project = (urls: string[], view: Record<string, unknown> = {}) => {
  const parent = parentFor(urls);
  const result = inspectAnalysisView({
    source: { kind: "inline", evidence: parent },
    view: { kind: "api-surface", include_query_parameter_names: true, ...view },
  });
  if (!result.ok) throw result.error;
  return result.value;
};

it("reports distinct observed query names across grouped records without values or fragments", () => {
  const urls = [
    "https://api.test/items/1?category=books&page=1&page=2#fragment_only=hidden",
    "https://api.test/items/2?category=games&sort=price",
    "https://api.test/health",
  ];
  const result = project(urls);
  expect(result.normalized_result).toMatchObject({
    groups: [
      { path_template: "/health", query_parameter_names: [] },
      {
        path_template: "/items/{numeric}",
        query_parameter_names: ["category", "page", "sort"],
        record_ordinals: [0, 1],
      },
    ],
  });
  for (const value of ["books", "games", "price", "fragment_only", "hidden"])
    expect(JSON.stringify(result)).not.toContain(value);
  expect(project(urls)).toEqual(result);
});

it("uses form query decoding for encoded, duplicate, empty, Unicode and malformed names", () => {
  const result = project([
    "https://api.test/?&&=one&bare&%71=two&q=three&a+b=four&a%2Bb=five&%E9%9B%AA=six&bad%ZZ=seven&%FF=eight&x%26y%3Dz=nine&__proto__=ten&?question=eleven&&",
  ]);
  expect(result.normalized_result).toMatchObject({
    groups: [
      {
        query_parameter_names: [
          "",
          "?question",
          "__proto__",
          "a b",
          "a+b",
          "bad%ZZ",
          "bare",
          "q",
          "x&y=z",
          "雪",
          "�",
        ],
      },
    ],
  });
});

it("keeps query selection opt-in and independent of group paging", () => {
  const urls = [
    "https://api.test/a?first=one",
    "https://api.test/z?second=two",
  ];
  const selected = project(urls, { offset: 1, limit: 1 });
  expect(selected.normalized_result).toMatchObject({
    groups: [{ path_template: "/z", query_parameter_names: ["second"] }],
    coverage: { total: 2, examined: 1, exhausted: true },
  });
  const disabled = project(urls, { include_query_parameter_names: false });
  expect(JSON.stringify(disabled.normalized_result)).not.toContain(
    '"query_parameter_names"',
  );
  const parent = parentFor(urls);
  const omitted = inspectAnalysisView({
    source: { kind: "inline", evidence: parent },
    view: { kind: "api-surface" },
  });
  if (!omitted.ok) throw omitted.error;
  expect(JSON.stringify(omitted.value.normalized_result)).not.toContain(
    '"query_parameter_names"',
  );
});

it("reads the recorded query boundary without interpreting fragment text as a query", () => {
  const result = project([
    "https://api.test#fragment?fake=value",
    "https://api.test?actual=value#ignored?other=value",
    "https://api.test/a/%2e%2e/b?recorded=value",
  ]);
  expect(result.normalized_result).toMatchObject({
    groups: [
      {
        path_template: "/",
        query_parameter_names: ["actual"],
        record_ordinals: [0, 1],
      },
      { path_template: "/a/%2e%2e/b", query_parameter_names: ["recorded"] },
    ],
  });
});
