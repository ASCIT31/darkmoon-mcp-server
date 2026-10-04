import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttp } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { DarkmoonClient, configFromEnv } from "../src/client.js";
import { createServer } from "../src/server.js";

const BASE = "https://darkmoon.test";
const finding = { title: "SQL injection", severity: "high", status: "exploited" };

function mockFetch(routes: Record<string, [number, unknown]>, seen: { url: URL; init?: RequestInit }[] = []) {
  return (async (input: URL | string, init?: RequestInit) => {
    const url = new URL(String(input));
    seen.push({ url, init });
    const key = `${init?.method ?? "GET"} ${url.pathname}`;
    if (key === "POST /api/v1/auth/login") {
      const b = JSON.parse(String(init?.body));
      return b.password === "s3cret"
        ? Response.json({ token: "jwt" })
        : Response.json({ detail: "bad credentials" }, { status: 401 });
    }
    assert.equal((init?.headers as Record<string, string>).Authorization, "Bearer jwt");
    const r = routes[key];
    return r ? Response.json(r[1], { status: r[0] }) : Response.json({ detail: "not found" }, { status: 404 });
  }) as unknown as typeof fetch;
}

async function connect(routes: Record<string, [number, unknown]>, seen: any[] = [], password = "s3cret") {
  const dm = new DarkmoonClient({ baseUrl: BASE + "/", username: "analyst", password, fetchImpl: mockFetch(routes, seen) });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createServer(dm).connect(a);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(b);
  return client;
}
const text = (r: any) => r.content[0].text as string;

test("tools/list exposes the four tools", async () => {
  const c = await connect({});
  const names = (await c.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["get_findings", "get_run_status", "list_campaigns", "run_pentest"]);
});

test("run_pentest sends a trimmed payload and returns run_id", async () => {
  const seen: any[] = [];
  const c = await connect({ "POST /api/v1/run/campaign": [200, { run_id: "run_1" }] }, seen);
  const r = await c.callTool({ name: "run_pentest", arguments: { target: " app.example.com ", program: "acme", focus: ["auth", " "], severity: "high" } });
  assert.deepEqual(JSON.parse(text(r)), { status: "started", run_id: "run_1", target: "app.example.com" });
  assert.deepEqual(JSON.parse(String(seen.at(-1).init.body)), { target: "app.example.com", program: "acme", focus: ["auth"], severity: "high" });
});

test("run_pentest rejects an empty target", async () => {
  const c = await connect({});
  const r: any = await c.callTool({ name: "run_pentest", arguments: { target: "  " } });
  assert.equal(r.isError, true);
  assert.match(text(r), /target is required/);
});

test("get_run_status maps run-log events to states", async () => {
  const p = "GET /api/v1/run/logs/run_1";
  const st = async (routes: any) => JSON.parse(text(await (await connect(routes)).callTool({ name: "get_run_status", arguments: { run_id: "run_1" } })));
  assert.equal((await st({ [p]: [200, { data: [{ type: "run_started" }] }] })).status, "running");
  const done = await st({ [p]: [200, { data: [{ type: "run_started" }, { type: "run_completed" }] }] });
  assert.equal(done.status, "completed");
  assert.equal(done.event_count, 2);
  assert.equal((await st({ [p]: [200, { data: [{ type: "run_error" }] }] })).status, "error");
  assert.equal((await st({})).status, "unknown");
});

test("list_campaigns", async () => {
  const camps = [{ id: "camp_1", status: "completed" }];
  const c = await connect({ "GET /api/v1/campaigns": [200, { data: camps, total: 1 }] });
  assert.deepEqual(JSON.parse(text(await c.callTool({ name: "list_campaigns", arguments: {} }))), { total: 1, campaigns: camps });
});

test("get_findings returns the expected shape and passes campaign_id", async () => {
  const seen: any[] = [];
  const c = await connect({ "GET /api/v1/vulnerabilities": [200, { data: [finding], total: 1, stats: { high: 1 } }] }, seen);
  const r = await c.callTool({ name: "get_findings", arguments: { campaign_id: "camp_1" } });
  assert.deepEqual(JSON.parse(text(r)), { campaign_id: "camp_1", total: 1, stats: { high: 1 }, findings: [finding] });
  assert.equal(seen.at(-1).url.searchParams.get("campaign_id"), "camp_1");
});

test("bad credentials give a clear error without echoing the password", async () => {
  const c = await connect({}, [], "wrong");
  const r: any = await c.callTool({ name: "list_campaigns", arguments: {} });
  assert.equal(r.isError, true);
  assert.match(text(r), /authentication failed/);
  assert.ok(!text(r).includes("wrong"));
});

test("API error detail is reported", async () => {
  const c = await connect({ "GET /api/v1/campaigns": [500, { detail: "db down" }] });
  const r: any = await c.callTool({ name: "list_campaigns", arguments: {} });
  assert.equal(r.isError, true);
  assert.match(text(r), /db down/);
});

test("DARKMOON_TOKEN skips login", async () => {
  const seen: any[] = [];
  const f = (async (u: any, init: any) => { seen.push(new URL(String(u)).pathname); return Response.json({ data: [] }); }) as unknown as typeof fetch;
  await new DarkmoonClient({ baseUrl: BASE, token: "abc", fetchImpl: f }).listCampaigns();
  assert.deepEqual(seen, ["/api/v1/campaigns"]);
});

test("configFromEnv validates", () => {
  assert.throws(() => configFromEnv({}), /DARKMOON_BASE_URL/);
  assert.throws(() => configFromEnv({ DARKMOON_BASE_URL: "x" }), /DARKMOON_TOKEN/);
  assert.equal(configFromEnv({ DARKMOON_BASE_URL: "x", DARKMOON_TOKEN: "t" }).token, "t");
});

test("real stdio process: tools/list and tools/call against a local mock API", async () => {
  const api = createHttp((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/api/v1/auth/login") return res.end(JSON.stringify({ token: "jwt" }));
      if (req.url === "/api/v1/campaigns") return res.end(JSON.stringify({ data: [{ id: "camp_9" }], total: 1 }));
      res.statusCode = 404; res.end("{}");
    });
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const port = (api.address() as AddressInfo).port;
  const t = new StdioClientTransport({
    command: process.execPath,
    args: [new URL("../src/cli.js", import.meta.url).pathname],
    env: { PATH: process.env.PATH ?? "", DARKMOON_BASE_URL: `http://127.0.0.1:${port}`, DARKMOON_USERNAME: "u", DARKMOON_PASSWORD: "p" },
  });
  const c = new Client({ name: "t", version: "0" });
  await c.connect(t);
  assert.equal((await c.listTools()).tools.length, 4);
  const r = await c.callTool({ name: "list_campaigns", arguments: {} });
  assert.deepEqual(JSON.parse(text(r)), { total: 1, campaigns: [{ id: "camp_9" }] });
  await c.close();
  api.close();
});

test("cli exits non-zero with a clear message when unconfigured", async () => {
  const p = spawn(process.execPath, [new URL("../src/cli.js", import.meta.url).pathname], { env: { PATH: process.env.PATH } });
  let err = ""; p.stderr.on("data", (d) => (err += d));
  const [code] = await once(p, "exit");
  assert.equal(code, 1);
  assert.match(err, /DARKMOON_BASE_URL/);
});
