import { z } from "zod";
import { parseRecordedTransportUrl } from "../recordedTransportUrl.js";
import { err, ok, type Result } from "../result.js";
import type { WebNetworkCaptureRecord } from "../webNetworkCapture.js";
import type { UnsignedAnalysisView } from "./analysisView.js";

type ExclusionReason = Extract<
  UnsignedAnalysisView,
  { kind: "api-surface" }
>["excluded_records"][number]["reason"];
/** Only formats whose recorded request representation is interpreted here. */
export type ApiSurfaceCaptureFormat = "har" | "mitmproxy";
type Request = {
  readonly method: unknown;
  readonly textLength: number;
} & (
  | { readonly kind: "har"; readonly url: string }
  | {
      readonly kind: "mitmproxy";
      readonly scheme: string;
      readonly host: string;
      readonly port: number;
      readonly path: string;
    }
);
const harRequestSchema = z.object({
  request: z.object({ url: z.unknown(), method: z.unknown() }),
});
const nativeRequestSchema = z.object({
  type: z.literal("http"),
  request: z.object({
    method: z.unknown().optional(),
    scheme: z.unknown().optional(),
    host: z.unknown().optional(),
    port: z.unknown().optional(),
    path: z.unknown().optional(),
  }),
});
const responseSchema = z.object({
  response: z.object({
    status: z.unknown().optional(),
    content: z.unknown().optional(),
    status_code: z.unknown().optional(),
    headers: z.unknown().optional(),
  }),
});
const contentSchema = z.object({ mimeType: z.unknown().optional() });

/** Borrow the format's identity text; the caller admits scratch before parsing it. */
export const readApiSurfaceRequest = (
  record: WebNetworkCaptureRecord,
  format: ApiSurfaceCaptureFormat,
): Result<Request, ExclusionReason> => {
  if (format === "har") {
    const request = harRequestSchema.safeParse(record.reported);
    if (!request.success) return err("request-unavailable");
    const { url, method } = request.data.request;
    if (url === null) return err("url-redacted");
    if (typeof url !== "string") return err("url-unparseable");
    return ok({ kind: "har", method, url, textLength: url.length });
  }
  const request = nativeRequestSchema.safeParse(record.reported);
  if (!request.success) return err("request-unavailable");
  const { scheme, host, port, path, method } = request.data.request;
  if (
    record.redactions.some(
      ({ pointer }) =>
        (pointer === "/request/scheme" && scheme === null) ||
        (pointer === "/request/host" && host === null) ||
        (pointer === "/request/path" && path === null),
    )
  )
    return err("url-redacted");
  if (
    typeof scheme !== "string" ||
    typeof host !== "string" ||
    typeof path !== "string" ||
    typeof port !== "number"
  )
    return err("url-unparseable");
  // Length only: no normalization, concatenation or header copying before admission.
  return ok({
    kind: "mitmproxy",
    method,
    scheme,
    host,
    port,
    path,
    textLength: scheme.length + host.length + path.length + 16,
  });
};

/** Parse only recorded HTTP route targets; never resolve against Host or a guessed origin. */
export const parseApiSurfaceRequest = (
  request: Request,
): Result<
  { method: string; origin: string; path: string },
  ExclusionReason
> => {
  let url: string;
  let expectedOrigin: string | null = null;
  if (request.kind === "har") url = request.url;
  else {
    const { scheme, host, port, path } = request;
    if (
      !/^https?$/iu.test(scheme) ||
      host.length === 0 ||
      /[\x00-\x20\x7f/\\?#@%]/u.test(host) ||
      !Number.isInteger(port) ||
      port < 0 ||
      port > 65535 ||
      /[\x00-\x20\x7f\\#]/u.test(path)
    )
      return err("url-unparseable");
    // mitmproxy records IPv6 host literals without brackets. URL parsing validates
    // the literal, including already bracketed forms, after expansion is admitted.
    const authority =
      host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    const base = URL.parse(`${scheme}://${authority}:${port}`);
    if (
      base === null ||
      base.username !== "" ||
      base.password !== "" ||
      base.pathname !== "/"
    )
      return err("url-unparseable");
    expectedOrigin = base.origin;
    if (path.startsWith("/")) url = `${expectedOrigin}${path}`;
    else if (/^https?:\/\//iu.test(path)) url = path;
    else return err("url-unparseable"); // CONNECT authority and OPTIONS * are not routes.
  }
  const parsed = parseRecordedTransportUrl(url);
  if (
    parsed.origin === null ||
    (expectedOrigin !== null && parsed.origin !== expectedOrigin)
  )
    return err("url-unparseable");
  if (
    typeof request.method !== "string" ||
    request.method.length === 0 ||
    (request.kind === "mitmproxy" &&
      !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/u.test(request.method))
  )
    return err("method-unavailable");
  if (parsed.path === null) return err("url-unparseable");
  return ok({
    method: request.method,
    origin: parsed.origin,
    path: parsed.path,
  });
};

const nativeContentType = (headers: unknown): string | null => {
  if (!Array.isArray(headers)) return null;
  let value: string | null = null;
  let found = false;
  for (const field of headers) {
    // An unreadable name could conceal another Content-Type. Preserve uncertainty.
    if (
      !Array.isArray(field) ||
      field.length !== 2 ||
      typeof field[0] !== "string" ||
      !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/u.test(field[0])
    )
      return null;
    if (field[0].length !== 12 || !/^content-type$/iu.test(field[0])) continue;
    if (found || typeof field[1] !== "string") return null;
    found = true;
    value = field[1];
  }
  return value;
};

/** Borrow the one unambiguous MIME value; normalization belongs after admission. */
export const readApiSurfaceResponse = (
  record: WebNetworkCaptureRecord,
  format: ApiSurfaceCaptureFormat,
): { status: number | null; mime: string } => {
  const parsed = responseSchema.safeParse(record.reported);
  if (!parsed.success) return { status: null, mime: "" };
  const response = parsed.data.response;
  if (format === "mitmproxy") {
    const status = response.status_code;
    return {
      status:
        typeof status === "number" &&
        Number.isInteger(status) &&
        status >= 100 &&
        status <= 999
          ? status
          : null,
      mime: nativeContentType(response.headers) ?? "",
    };
  }
  const content = contentSchema.safeParse(response.content);
  const mime = content.success ? content.data.mimeType : undefined;
  return {
    status:
      typeof response.status === "number" && response.status !== 0
        ? response.status
        : null,
    mime: typeof mime === "string" ? mime : "",
  };
};

const MEDIA_TYPE_ESSENCE =
  /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+$/u;
export const apiSurfaceMediaTypeEssence = (reported: string): string | null => {
  const separator = reported.indexOf(";");
  let start = 0;
  let end = separator < 0 ? reported.length : separator;
  // HTTP OWS is SP/HTAB; bounded scans avoid trailing-regex backtracking.
  while (start < end && (reported[start] === " " || reported[start] === "\t"))
    start += 1;
  while (
    end > start &&
    (reported[end - 1] === " " || reported[end - 1] === "\t")
  )
    end -= 1;
  const essence = reported.slice(start, end);
  // Validate ASCII tokens before case folding can turn Unicode into ASCII.
  return MEDIA_TYPE_ESSENCE.test(essence) ? essence.toLowerCase() : null;
};
