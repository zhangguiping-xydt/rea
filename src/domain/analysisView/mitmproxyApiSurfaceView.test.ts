import { expect, it } from "vitest";
import {
  analysisViewCaptureFixture,
  analysisViewCaptureEvidence,
} from "../../../tests/fixtures/analysisView.js";
import type { JsonValue } from "../jsonValue.js";
import { projectAnalysisView } from "./analysisView.js";
import { WebNetworkApiSurfaceAccumulator } from "./WebNetworkApiSurfaceAccumulator.js";

const native = (
  path: JsonValue = "/items/1",
  request: Record<string, JsonValue> = {},
  response: JsonValue = {
    status_code: 200,
    headers: [["Content-Type", "Application/JSON; charset=utf-8"]],
  },
): JsonValue => ({
  type: "http",
  request: {
    method: "GET",
    scheme: "https",
    host: "api.test",
    port: 443,
    path,
    ...request,
  },
  response,
});
const captureFor = (reported: JsonValue[]) => {
  const capture = analysisViewCaptureFixture();
  capture.format = "mitmproxy";
  capture.records = reported.map((value, ordinal) => ({
    ...capture.records[0]!,
    ordinal,
    reported: value,
    limitations: [],
  }));
  capture.total_records = reported.length;
  return capture;
};
const project = (
  capture = captureFor([native()]),
  offset = 0,
  limit = 50,
  parameters: unknown = { sensitive_value_count: 0 },
) => {
  const parent = analysisViewCaptureEvidence(capture);
  return projectAnalysisView(
    {
      evidenceId: parent.evidence_id,
      operation: parent.operation,
      normalizedResult: parent.normalized_result,
      limitations: [],
      parameters,
    },
    { kind: "api-surface", offset, limit },
  );
};
const surface = (capture = captureFor([native()]), offset = 0, limit = 50) => {
  const result = project(capture, offset, limit);
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error(JSON.stringify(result));
  return result.value;
};
it("groups native HTTP fields with status_code and header tuples, preserving provenance and paging", () => {
  const capture = captureFor([
    native("/items/1?key=value"),
    native(
      "/items/2",
      {},
      { status_code: 404, headers: [["content-type", "text/plain"]] },
    ),
    native("/health"),
  ]);
  capture.records[1]!.ordinal = 5;
  capture.records[2]!.ordinal = 7;
  capture.total_records = 9;
  const result = surface(capture, 1, 1);
  expect(result.groups).toMatchObject([
    {
      method: "GET",
      origin: "https://api.test",
      path_template: "/items/{numeric}",
      record_ordinals: [0, 5],
      statuses: [200, 404],
      content_types: ["application/json", "text/plain"],
    },
  ]);
  expect(result.records).toEqual({ examined: 3, total: 9, excluded: 0 });
  expect(result.coverage).toMatchObject({
    total: 2,
    examined: 1,
    exhausted: true,
  });
  expect(result.artifact).toEqual({
    path: capture.artifact.path,
    sha256: capture.artifact.sha256,
  });
  expect(result.limitations.join(" ")).toContain("ordinal subset");
  expect(JSON.stringify(result)).not.toContain("key=value");
});
it("preserves encoded and dot paths, IPv6 and non-default ports without using Host or authority", () => {
  const result = surface(
    captureFor([
      native("/a/%2e%2e/admin", {
        host: "::1",
        port: 8443,
        authority: "wrong.test",
        headers: [["Host", "wrong.test"]],
      }),
      native("//double/1"),
      native("https://api.test/a/../b"),
      native("/%31"),
      native("/", { port: 0 }),
    ]),
  );
  expect(result.groups.map((g) => [g.origin, g.path_template])).toEqual(
    expect.arrayContaining([
      ["https://[::1]:8443", "/a/%2e%2e/admin"],
      ["https://api.test", "//double/{numeric}"],
      ["https://api.test", "/a/../b"],
      ["https://api.test", "/%31"],
      ["https://api.test:0", "/"],
    ]),
  );
});
it("excludes non-HTTP, missing/redacted fields, malformed authorities and non-route targets", () => {
  const values = [
    { type: "tcp", request: { url: "https://fake.test/" } },
    native("*"),
    native("api.test:443", { method: "CONNECT" }),
    native(null),
    native("/", { host: "evil.test/user:pass@target" }),
    native("/", { host: "bad\\host" }),
    native("/", { host: "%65vil.test" }),
    native("/", { port: 65536 }),
    native("/", { scheme: "file" }),
    native("https://other.test/a"),
    native("/", { method: null }),
    native("/", { method: "G ET" }),
    native("/", { host: null }),
  ];
  const capture = captureFor(values);
  capture.records[3]!.redactions = [
    { pointer: "/request/path", reason: "transport-credential" },
  ];
  const result = surface(capture);
  expect(result.groups).toEqual([]);
  expect(result.excluded_records).toHaveLength(values.length);
  expect(result.excluded_records[0]).toEqual({
    ordinal: 0,
    reason: "request-unavailable",
  });
  expect(result.excluded_records[3]).toEqual({
    ordinal: 3,
    reason: "url-redacted",
  });
  expect(result.excluded_records[10]).toEqual({
    ordinal: 10,
    reason: "method-unavailable",
  });
  expect(JSON.stringify(result)).not.toContain("user:pass");
});
it("treats duplicate, malformed and unreadable Content-Type headers and invalid statuses as unknown", () => {
  const headers = [
    [
      ["Content-Type", "text/plain"],
      ["content-type", "text/plain"],
    ],
    [
      [null, "unknown"],
      ["Content-Type", "text/plain"],
    ],
    [["Content-Type", null]],
    [["Content-Type", "text /plain"]],
    [["Content-Type", "text/plain", "extra"]],
    [],
    null,
  ];
  for (const value of headers) {
    const result = surface(
      captureFor([native("/", {}, { status_code: 200, headers: value })]),
    );
    expect(result.groups[0]).toMatchObject({
      statuses: [200],
      content_types: [],
    });
    expect(result.unknowns).not.toEqual([]);
  }
  for (const status of [0, -1, 99, 1000, 200.5, null, "200"]) {
    const result = surface(
      captureFor([
        native(
          "/",
          {},
          {
            status_code: status,
            headers: [["Content-Type", "application/json"]],
          },
        ),
      ]),
    );
    expect(result.groups[0]).toMatchObject({
      statuses: [],
      content_types: ["application/json"],
    });
    expect(result.unknowns).not.toEqual([]);
  }
});
it("does not substitute HAR fields for missing native response or request facts", () => {
  const result = surface(
    captureFor([
      native("/", {}, { status: 200, content: { mimeType: "text/plain" } }),
      { type: "http", request: { method: "GET", url: "https://fake.test/" } },
    ]),
  );
  expect(result.groups[0]).toMatchObject({ statuses: [], content_types: [] });
  expect(result.excluded_records).toEqual([
    { ordinal: 1, reason: "url-unparseable" },
  ]);
});
it("retains unknown native response facts and refuses undeclared sensitive policy", () => {
  const capture = captureFor([native("/", {}, null)]);
  expect(surface(capture).unknowns).not.toEqual([]);
  for (const parameters of [{}, { sensitive_value_count: 1 }])
    expect(project(capture, 0, 50, parameters)).toMatchObject({
      ok: false,
      error: { reason: "sensitive_values_unretained" },
    });
});
it("admits native URL construction and MIME normalization before allocation", () => {
  const capture = captureFor([native(`/${"a".repeat(100_000)}`)]);
  const accumulator = new WebNetworkApiSurfaceAccumulator(64 * 1024);
  expect(accumulator.add(capture.records[0]!, "mitmproxy")).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError" },
  });
  expect(accumulator.page(0, 50).groups).toEqual([]);
});

it("keeps undecodable fields distinct from safely redacted text at another coordinate", () => {
  const capture = captureFor([native("https://api.test/", { host: null })]);
  capture.records[0]!.redactions = [
    { pointer: "/request/path", reason: "transport-credential" },
  ];
  expect(surface(capture).excluded_records).toEqual([
    { ordinal: 0, reason: "url-unparseable" },
  ]);
});
