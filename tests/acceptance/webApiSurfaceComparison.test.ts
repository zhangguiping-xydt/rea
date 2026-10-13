import { writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect } from "vitest";
import { parseEvidence } from "../../src/domain/evidence.js";
import { webApiSurfaceComparisonSchema } from "../../src/domain/analysisView/webApiSurfaceComparison.js";
import { composeBinarySession } from "../../src/application/binary/BinarySessionComposition.js";
import { AnalysisProviderRegistry } from "../../src/application/binary/AnalysisProviderRegistry.js";
import { createServer } from "../../src/server/createServer.js";
import { apiSurfaceHar } from "../fixtures/historicalHar.js";
import { cliTest } from "../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

cliTest(
  "compares decoded HAR sources identically through compiled CLI and retained MCP after source removal",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-web-api-comparison-");
    const sources = [];
    for (const side of ["left", "right"] as const) {
      const har = apiSurfaceHar();
      har.log.entries = har.log.entries.slice(0, 2);
      if (side === "right") {
        har.log.entries[0]!.response.status = 201;
        har.log.entries[1]!.request.url = "https://api.example.test/new";
      }
      const path = join(root, `${side}.har`);
      await writeFile(path, JSON.stringify(har));
      const captured = await cli.run({
        arguments: ["inspect-web-network-capture", path, "har", "--json"],
      });
      expect(captured.exitCode, captured.stdout).toBe(0);
      sources.push(parseEvidence(captured.json));
      await unlink(path);
    }
    const [left, right] = sources;
    if (left === undefined || right === undefined)
      throw new Error("Missing source");
    const input = join(root, "compare.json");
    await writeFile(
      input,
      JSON.stringify({
        left: { kind: "inline", evidence: left },
        right: { kind: "inline", evidence: right },
      }),
    );
    const result = await cli.run({
      arguments: ["compare-web-api-surfaces", input, "--json"],
    });
    expect(result.exitCode, result.stdout).toBe(0);
    const evidence = parseEvidence(result.json);
    expect(
      webApiSurfaceComparisonSchema.parse(evidence.normalized_result),
    ).toMatchObject({
      summary: {
        both: 1,
        left_only: 0,
        right_only: 1,
        response_differences: 1,
      },
      groups: [
        { path_template: "/new", presence: "right-only" },
        {
          path_template: "/users/{numeric}",
          presence: "both",
          response_comparison: "different-observed-values",
        },
      ],
    });
    expect(evidence.evidence_links).toEqual([
      left.evidence_id,
      right.evidence_id,
    ]);
    const session = composeBinarySession(new AnalysisProviderRegistry([]));
    const server = createServer({ kind: "session", session });
    const client = new Client({ name: "web-api-comparison", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
      for (const source of sources) {
        const recorded = session.recordEvidence(source);
        if (!recorded.ok) throw recorded.error;
      }
      await server.connect(st);
      await client.connect(ct);
      const tool = (await client.listTools()).tools.find(
        (t) => t.name === "compare_web_api_surfaces",
      );
      if (tool?.outputSchema === undefined) throw new Error("Missing schema");
      const args = {
        left: { kind: "retained-evidence", evidence_id: left.evidence_id },
        right: { kind: "retained-evidence", evidence_id: right.evidence_id },
      };
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
        arguments: { ...args, offset: 1, limit: 1 },
      });
      expect(
        parseEvidence(page.structuredContent).normalized_result,
      ).toMatchObject({
        summary: { both: 1, right_only: 1, response_differences: 1 },
        groups: [{ path_template: "/users/{numeric}" }],
        coverage: { examined: 1, total: 2, exhausted: true },
      });
    } finally {
      await client.close();
      await server.close();
      await session.close();
    }
  },
);
