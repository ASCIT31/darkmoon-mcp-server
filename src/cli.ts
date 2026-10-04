#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DarkmoonClient, configFromEnv } from "./client.js";
import { createServer } from "./server.js";

async function main() {
  const client = new DarkmoonClient(configFromEnv());
  await createServer(client).connect(new StdioServerTransport());
  console.error("darkmoon-mcp-server ready on stdio");
}

main().catch((e) => {
  console.error(`darkmoon-mcp-server: ${(e as Error).message}`);
  process.exit(1);
});
