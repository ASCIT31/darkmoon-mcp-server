/**
 * Minimal client for the Darkmoon Dashboard API (self-hosted, part of Darkmoon Pro).
 *
 *   POST /api/v1/auth/login                   -> { token }
 *   POST /api/v1/run/campaign                 -> { run_id }
 *   GET  /api/v1/run/logs/{run_id}            -> { data: events[], total }
 *   GET  /api/v1/campaigns                    -> { data: campaigns[], total }
 *   GET  /api/v1/vulnerabilities?campaign_id  -> { data, total, stats }
 */

export interface DarkmoonConfig {
  baseUrl: string;
  /** Pre-issued JWT. If set, username/password are not needed. */
  token?: string;
  username?: string;
  password?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class DarkmoonError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = "DarkmoonError";
  }
}

const TERMINAL_EVENTS = new Set(["run_completed", "run_error"]);

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): DarkmoonConfig {
  const baseUrl = (env.DARKMOON_BASE_URL ?? "").trim();
  if (!baseUrl) {
    throw new DarkmoonError(
      "DARKMOON_BASE_URL is required: the URL of your self-hosted Darkmoon Pro Dashboard API.",
    );
  }
  const token = env.DARKMOON_TOKEN?.trim() || undefined;
  const username = env.DARKMOON_USERNAME?.trim() || undefined;
  const password = env.DARKMOON_PASSWORD || undefined;
  if (!token && !(username && password)) {
    throw new DarkmoonError(
      "Set DARKMOON_TOKEN, or both DARKMOON_USERNAME and DARKMOON_PASSWORD.",
    );
  }
  const timeoutMs = env.DARKMOON_TIMEOUT_MS ? Number(env.DARKMOON_TIMEOUT_MS) : undefined;
  return { baseUrl, token, username, password, timeoutMs };
}

export class DarkmoonClient {
  private readonly baseUrl: string;
  private readonly f: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly cfg: DarkmoonConfig) {
    this.baseUrl = cfg.baseUrl.replace(/\/+$/, "");
    this.f = cfg.fetchImpl ?? fetch;
    this.timeoutMs = cfg.timeoutMs && cfg.timeoutMs > 0 ? cfg.timeoutMs : 60_000;
  }

  private async raw(path: string, init: RequestInit & { params?: Record<string, string> } = {}) {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(init.params ?? {})) url.searchParams.set(k, v);
    try {
      return await this.f(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (e) {
      throw new DarkmoonError(
        `Could not reach the Darkmoon Dashboard API at ${this.baseUrl}: ${(e as Error).message}`,
      );
    }
  }

  private async detail(res: Response): Promise<string> {
    try {
      const body = (await res.json()) as Record<string, unknown>;
      const d = body?.detail ?? body?.message;
      if (typeof d === "string" && d) return d;
    } catch {
      /* not JSON */
    }
    return "no detail provided";
  }

  private async fail(res: Response, action: string): Promise<never> {
    if (res.status === 401) {
      throw new DarkmoonError(
        "Darkmoon authentication failed. Check DARKMOON_TOKEN or DARKMOON_USERNAME/DARKMOON_PASSWORD.",
        401,
      );
    }
    if (res.status === 403) {
      throw new DarkmoonError(`Permission denied: the Darkmoon user cannot ${action}.`, 403);
    }
    throw new DarkmoonError(
      `Darkmoon API error ${res.status} while trying to ${action}: ${await this.detail(res)}`,
      res.status,
    );
  }

  private async authHeaders(): Promise<Record<string, string>> {
    let token = this.cfg.token;
    if (!token) {
      const res = await this.raw("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username: this.cfg.username, password: this.cfg.password }),
      });
      if (!res.ok) await this.fail(res, "log in");
      const body = (await res.json()) as { token?: string };
      token = body?.token;
      if (!token) throw new DarkmoonError("Darkmoon login did not return a token.", 502);
    }
    return { Authorization: `Bearer ${token}`, Accept: "application/json" };
  }

  private async call(
    method: "GET" | "POST",
    path: string,
    action: string,
    opts: { params?: Record<string, string>; json?: unknown; allow404?: boolean } = {},
  ): Promise<{ status: number; body: any }> {
    const headers = await this.authHeaders();
    if (opts.json !== undefined) headers["Content-Type"] = "application/json";
    const res = await this.raw(path, {
      method,
      headers,
      params: opts.params,
      body: opts.json !== undefined ? JSON.stringify(opts.json) : undefined,
    });
    if (res.status === 404 && opts.allow404) return { status: 404, body: null };
    if (!res.ok) await this.fail(res, action);
    return { status: res.status, body: await res.json() };
  }

  async runPentest(args: {
    target: string;
    program?: string;
    focus?: string[];
    severity?: string;
  }) {
    const target = args.target.trim();
    if (!target) {
      throw new DarkmoonError("A target is required (a host, URL or scope you are authorized to test).");
    }
    const payload: Record<string, unknown> = { target };
    if (args.program?.trim()) payload.program = args.program.trim();
    const focus = (args.focus ?? []).map((f) => f.trim()).filter(Boolean);
    if (focus.length) payload.focus = focus;
    if (args.severity?.trim()) payload.severity = args.severity.trim();
    const { body } = await this.call("POST", "/api/v1/run/campaign", "start the pentest run", {
      json: payload,
    });
    if (!body?.run_id) {
      throw new DarkmoonError("Darkmoon accepted the request but returned no run_id.", 502);
    }
    return { status: "started", run_id: String(body.run_id), target };
  }

  async getRunStatus(runId: string) {
    const id = runId.trim();
    if (!id) throw new DarkmoonError("A run_id is required.");
    const { status, body } = await this.call(
      "GET",
      `/api/v1/run/logs/${encodeURIComponent(id)}`,
      "read the run log",
      { allow404: true },
    );
    if (status === 404) return { run_id: id, status: "unknown", event_count: 0, recent_events: [] };
    const events: any[] = Array.isArray(body?.data) ? body.data : [];
    const terminal = events.find((e) => TERMINAL_EVENTS.has(e?.type));
    const state = !terminal ? "running" : terminal.type === "run_error" ? "error" : "completed";
    return { run_id: id, status: state, event_count: events.length, recent_events: events.slice(-5) };
  }

  async listCampaigns() {
    const { body } = await this.call("GET", "/api/v1/campaigns", "list campaigns");
    const campaigns: unknown[] = Array.isArray(body?.data) ? body.data : [];
    return { total: campaigns.length, campaigns };
  }

  async getFindings(campaignId: string) {
    const id = campaignId.trim();
    if (!id) throw new DarkmoonError("A campaign_id is required.");
    const { body } = await this.call("GET", "/api/v1/vulnerabilities", "fetch findings", {
      params: { campaign_id: id },
    });
    return {
      campaign_id: id,
      total: body?.total ?? 0,
      stats: body?.stats ?? {},
      findings: Array.isArray(body?.data) ? body.data : [],
    };
  }
}
