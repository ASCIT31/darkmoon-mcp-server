import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { DarkmoonClient, DarkmoonError } from "./client.js";

export const VERSION = "0.1.0";

type Result = { content: { type: "text"; text: string }[]; isError?: boolean };

async function wrap(fn: () => Promise<unknown>): Promise<Result> {
  try {
    const out = await fn();
    return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
  } catch (e) {
    const msg = e instanceof DarkmoonError ? e.message : `Unexpected error: ${(e as Error).message}`;
    return { content: [{ type: "text", text: msg }], isError: true };
  }
}

export function createServer(client: DarkmoonClient): McpServer {
  const server = new McpServer({ name: "darkmoon", version: VERSION });

  server.registerTool(
    "run_pentest",
    {
      title: "Start a Darkmoon pentest",
      description:
        "Start an autonomous Darkmoon penetration test against one authorized target. The run executes in the background and can take a long time. Returns the run_id; poll it with get_run_status and read results with get_findings once a campaign exists (list_campaigns). Only use against systems the user owns or has explicit written authorization to test. Findings can include false positives and must be reviewed by a qualified human.",
      inputSchema: {
        target: z.string().describe("Host, URL or scope to assess. Only targets you are authorized to test."),
        program: z.string().optional().describe("Optional program name or rules-of-engagement note"),
        focus: z.array(z.string()).optional().describe("Optional focus areas, e.g. ['auth', 'injection']"),
        severity: z.string().optional().describe("Optional minimum severity to report"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    (args) => wrap(() => client.runPentest(args)),
  );

  server.registerTool(
    "get_run_status",
    {
      title: "Get run status",
      description:
        "Report whether a Darkmoon run is 'running', 'completed', 'error' or 'unknown' (run log not found), with the event count and the 5 most recent events.",
      inputSchema: { run_id: z.string().describe("The run_id returned by run_pentest") },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    ({ run_id }) => wrap(() => client.getRunStatus(run_id)),
  );

  server.registerTool(
    "list_campaigns",
    {
      title: "List campaigns",
      description:
        "List the Darkmoon campaigns visible to the dashboard user, with ids and status. Use a campaign id with get_findings.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    () => wrap(() => client.listCampaigns()),
  );

  server.registerTool(
    "get_findings",
    {
      title: "Get campaign findings",
      description:
        "Return the vulnerabilities and aggregated severity statistics for a Darkmoon campaign (read only). Each finding carries title, severity, CVSS score, category, status (exploited, confirmed or unconfirmed), endpoint and remediation guidance. Findings may contain false positives and require human review.",
      inputSchema: { campaign_id: z.string().describe("Darkmoon campaign id, e.g. camp_20260922_abc123") },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    ({ campaign_id }) => wrap(() => client.getFindings(campaign_id)),
  );

  return server;
}
