# Darkmoon

Drive a self-hosted [Darkmoon](https://github.com/ASCIT31/Dark-Moon) instance from Claude Code.
Darkmoon is an open source (GPL-3.0) autonomous AI penetration testing platform: an LLM
orchestrates specialist agents and offensive tools, and proves findings with real exploits.

```
/plugin marketplace add ASCIT31/darkmoon-mcp-server
/plugin install darkmoon@darkmoon
```

## Requires Darkmoon Pro

The Darkmoon engine and CLI are open source. This plugin's MCP server
([`@darkmoon_ai/mcp-server`](https://www.npmjs.com/package/@darkmoon_ai/mcp-server)) talks to the
Dashboard API, which is part of **Darkmoon Pro** and always self-hosted. There is no public hosted
endpoint, and the plugin does not work against the open source CLI alone.

## Setup

Set these in the environment Claude Code starts from, with the base URL of your own instance:

```
export DARKMOON_BASE_URL=https://darkmoon.example.internal
export DARKMOON_USERNAME=your-dashboard-user
export DARKMOON_PASSWORD=your-dashboard-password
```

Or register the server directly:

```
claude mcp add darkmoon -e DARKMOON_BASE_URL=https://darkmoon.example.internal \
  -e DARKMOON_USERNAME=your-dashboard-user -e DARKMOON_PASSWORD=your-dashboard-password \
  -- npx -y @darkmoon_ai/mcp-server
```

A pre-issued JWT can be supplied as `DARKMOON_TOKEN` instead of a username and password.

## Tools

| Tool | Description |
|---|---|
| `run_pentest` | Start an autonomous pentest against one authorized target and return the `run_id` |
| `get_run_status` | Report `running`, `completed`, `error` or `unknown` for a run |
| `list_campaigns` | List campaigns visible to the dashboard user (read only) |
| `get_findings` | Vulnerabilities and severity statistics for a campaign (read only) |

`run_pentest` starts a real assessment and is not read only. Use it only on systems you own or are
explicitly authorized in writing to test. Findings can include false positives and must be
reviewed by a qualified human.

## Links

- Project: <https://github.com/ASCIT31/Dark-Moon>
- MCP server source: <https://github.com/ASCIT31/darkmoon-mcp-server>
- npm: <https://www.npmjs.com/package/@darkmoon_ai/mcp-server>

License: GPL-3.0-only.
