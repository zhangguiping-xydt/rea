import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect } from "vitest";
import { parseEvidence } from "../../src/domain/evidence.js";
import { composeBinarySession } from "../../src/application/binary/BinarySessionComposition.js";
import { AnalysisProviderRegistry } from "../../src/application/binary/AnalysisProviderRegistry.js";
import { createServer } from "../../src/server/createServer.js";
import {
  analysisViewCaptureFixture,
  analysisViewCaptureEvidence,
} from "../fixtures/analysisView.js";
import { cliTest } from "../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

cliTest(
  "projects native HTTP capture Evidence identically through portable CLI and retained MCP without a decoder",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-mitm-api-surface-");
    const capture = analysisViewCaptureFixture();
    capture.format = "mitmproxy";
    capture.artifact.path = join(root, "missing.mitm");
    capture.records = capture.records.slice(0, 3);
    capture.total_records = 3;
    for (const record of capture.records)
      record.reported = {
        type: "http",
        request: {
          method: "GET",
          scheme: "https",
          host: "api.test",
          port: 443,
          path:
            record.ordinal === 2
              ? "/health"
              : `/items/${record.ordinal + 1}?q=observed`,
        },
        response: {
          status_code: 200,
          headers: [["Content-Type", "application/json"]],
        },
      };
    const parent = analysisViewCaptureEvidence(capture);
    const path = join(root, "view.json");
    await writeFile(
      path,
      JSON.stringify({
        source: { kind: "inline", evidence: parent },
        view: { kind: "api-surface" },
      }),
    );
    const result = await cli.run({
      arguments: ["inspect-analysis-view", path, "--json"],
      environment: { REA_MITMDUMP_COMMAND: join(root, "missing-mitmdump") },
    });
    expect(result.exitCode, result.stdout).toBe(0);
    const evidence = parseEvidence(result.json);
    expect(evidence.evidence_links).toEqual([parent.evidence_id]);
    expect(evidence.normalized_result).toMatchObject({
      records: { examined: 3, total: 3, excluded: 0 },
      groups: [
        { path_template: "/health", record_ordinals: [2] },
        {
          path_template: "/items/{numeric}",
          record_ordinals: [0, 1],
          statuses: [200],
          content_types: ["application/json"],
        },
      ],
    });
    const session = composeBinarySession(new AnalysisProviderRegistry([]));
    const server = createServer({ kind: "session", session });
    const client = new Client({ name: "mitm-api-surface", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
      const recorded = session.recordEvidence(parent);
      if (!recorded.ok) throw recorded.error;
      await server.connect(st);
      await client.connect(ct);
      const tool = (await client.listTools()).tools.find(
        (t) => t.name === "inspect_analysis_view",
      );
      if (tool?.outputSchema === undefined) throw new Error("Missing schema");
      const source = {
        kind: "retained-evidence",
        evidence_id: parent.evidence_id,
      };
      const args = { source, view: { kind: "api-surface" } };
      const ajv = new Ajv2020({ strict: false });
      const inputSchema: Record<string, unknown> = tool.inputSchema;
      const outputSchema: Record<string, unknown> = tool.outputSchema;
      expect(ajv.compile(inputSchema)(args)).toBe(true);
      const response = await client.callTool({
        name: tool.name,
        arguments: args,
      });
      expect(response.isError).not.toBe(true);
      expect(ajv.compile(outputSchema)(response.structuredContent)).toBe(true);
      expect(parseEvidence(response.structuredContent)).toEqual(evidence);
      const page = await client.callTool({
        name: tool.name,
        arguments: {
          source,
          view: { kind: "api-surface", offset: 1, limit: 1 },
        },
      });
      expect(
        parseEvidence(page.structuredContent).normalized_result,
      ).toMatchObject({
        coverage: { examined: 1, total: 2, exhausted: true },
        groups: [{ record_ordinals: [0, 1] }],
      });
    } finally {
      await client.close();
      await server.close();
      await session.close();
    }
  },
);
