# Gatekeeper

**Your agent can send the email. Gatekeeper decides whether it should.**

Gatekeeper sits between an AI agent and the tools it calls. It's an MCP server
that wraps your real MCP servers. Every tool call passes through a policy you
write in five lines of JSON: let it through, hold it for a human, or block it.
Everything is written to a hash-chained audit log that proves what the agent
did, who approved it, and that nobody edited the record afterwards.

```
  Claude / Cursor / your agent
            │  MCP (stdio)
            ▼
     ┌─────────────┐      ┌──────────────┐
     │  Gatekeeper │─────▶│  Slack alert │
     │   policy    │      └──────────────┘
     │   audit log │◀──── human approves / rejects in the inbox
     └─────────────┘
            │  MCP (stdio)
            ▼
   your real MCP servers (CRM, email, DB, Stripe, filesystem, ...)
```

- **Zero dependencies.** One static Go binary. Nothing to `npm install`, no
  supply chain to audit, no database to run.
- **Works with any MCP server.** If your agent can call it today, Gatekeeper
  can front it. Multiple upstreams behind one gate.
- **Tamper-evident log.** Every entry carries the SHA-256 of the previous one.
  `gatekeeper verify` tells you if a line was edited or removed, and which one.
- **Agent-friendly failures.** A blocked call comes back as a tool result the
  agent can read and explain to its user, not a crash.

## 60-second demo

```sh
go install github.com/gatekeeper-run/gatekeeper/cmd/gatekeeper@latest   # or grab a binary from Releases
gatekeeper demo
```

Then open <http://localhost:8484> (token `demo-token`). A scripted agent will
read a customer (allowed), try to charge a card it pasted into a prompt
(blocked), email the customer (held — go approve it), and delete the customer
record (held — go reject it). Then verify the log:

```sh
gatekeeper verify --log /tmp/gatekeeper-demo-*/audit.jsonl
# OK: 9 entries, chain intact.
```

Edit one character in that file and run it again.

## Install for real

### 1. Write a config

```sh
gatekeeper init > gatekeeper.json
export GATEKEEPER_TOKEN=$(openssl rand -hex 16)
```

A minimal config:

```json
{
  "agent": "support-bot",
  "listen": ":8484",
  "token": "${GATEKEEPER_TOKEN}",
  "log_path": "audit.jsonl",
  "approval_timeout": "10m",
  "default_action": "allow",
  "upstreams": [
    { "name": "crm", "command": "npx", "args": ["-y", "@acme/crm-mcp"] }
  ],
  "rules": [
    { "match": "*",        "action": "deny",             "if_args_match": "\\b\\d{13,19}\\b", "reason": "Looks like a card number" },
    { "match": "send_*",   "action": "require_approval", "reason": "Outbound communication" },
    { "match": "delete_*", "action": "require_approval", "reason": "Destructive" },
    { "match": "pay_*",    "action": "require_approval", "reason": "Moves money" }
  ],
  "redact": ["password", "token", "ssn", "card_number"]
}
```

### 2. Point your agent at Gatekeeper instead of the tool server

Claude Desktop (`claude_desktop_config.json`), Claude Code (`.mcp.json`),
Cursor (`mcp.json`) — same shape:

```json
{
  "mcpServers": {
    "gatekeeper": {
      "command": "/usr/local/bin/gatekeeper",
      "args": ["serve", "--config", "/path/to/gatekeeper.json"],
      "env": { "GATEKEEPER_TOKEN": "..." }
    }
  }
}
```

Remove the direct entries for the servers you listed as upstreams. The agent
sees the same tools with the same names; it just can't reach them without going
through the gate.

### 3. Open the inbox

<http://localhost:8484>, paste the token, type your name. Held calls appear
within two seconds, with the full (redacted) arguments and the rule that caught
them. Approve runs the call and returns the real result to the agent. Reject
returns a readable refusal. Do nothing and it times out, which is also a reject.

Set `slack_webhook` to an incoming-webhook URL and every held call also lands
in Slack with a link straight to it.

## Config reference

| Field | Meaning |
|---|---|
| `agent` | Name shown in logs and alerts. |
| `principal` | Optional. The human the agent acts for (`ops@acme.com`). Recorded on every entry. |
| `listen` | Inbox address, e.g. `:8484`. Required if any rule needs approval. |
| `public_url` | How humans reach the inbox; used in Slack links. Defaults from `listen`. |
| `token` | Inbox password. `${ENV}` expansion supported; falls back to `GATEKEEPER_TOKEN`. |
| `log_path` | Audit log file (JSONL). |
| `approval_timeout` | How long a held call waits. Go duration (`10m`, `1h`). |
| `default_action` | `allow`, `require_approval` or `deny` when no rule matches. |
| `slack_webhook` | Optional incoming-webhook URL. |
| `upstreams[]` | `name`, `command`, `args`, `env`, `cwd`. Gatekeeper launches each one. |
| `rules[]` | Evaluated top to bottom; first match wins. |
| `redact[]` | Argument keys (case-insensitive, nested) masked in logs and the inbox. |

### Rules

```json
{ "match": "send_*", "action": "require_approval", "if_args_match": "(?i)refund", "reason": "..." }
```

- `match` is a glob against the tool name (`send_*`, `*`, `delete_user`). Use
  `upstream/tool` to scope it: `stripe/*`, `db/query`.
- `action` is `allow`, `require_approval` or `deny`.
- `if_args_match` is an optional regex tested against the JSON-encoded
  arguments. The rule only fires if it matches. Combine a deny-on-pattern rule
  with an allow rule for the same tool to get "reads are fine, writes need a
  human".
- `reason` is what approvers see and what goes in the log.

When two upstreams expose a tool with the same name, both are exposed as
`upstream__tool` so nothing is ambiguous.

## The audit log

Each line is one event:

```
gatekeeper.start · call.allowed · call.pending · call.approved · call.rejected
call.denied · call.timeout · call.completed · call.failed
```

with the agent, principal, upstream, tool, redacted arguments, matching rule,
reason, approver, a summary of the upstream's result, the previous entry's hash
and this entry's hash.

```sh
gatekeeper verify --log audit.jsonl          # exit 0 intact, 3 if tampered
gatekeeper export --log audit.jsonl > a.csv  # for the auditor
curl -H "Authorization: Bearer $GATEKEEPER_TOKEN" \
  "http://localhost:8484/export.csv?since=2026-11-01T00:00:00Z"
```

The log is append-only and fsynced on every write. For stronger guarantees,
ship the file to object storage with versioning, or periodically record the
last hash somewhere the agent can't reach (a ticket, a Slack message, a
timestamping service). Anyone holding that hash can later prove the log hasn't
been rewritten up to that point.

## Running it somewhere

```sh
docker build -t gatekeeper .
docker run -p 8484:8484 -e GATEKEEPER_TOKEN=... \
  -v $PWD/gatekeeper.json:/etc/gatekeeper.json \
  -v gk-audit:/var/lib/gatekeeper gatekeeper
```

Gatekeeper launches upstreams as child processes, so the container needs
whatever they need. The default image includes Node and Python.

Put the inbox behind your VPN or a reverse proxy with TLS. The token is a
shared secret, not an identity layer; it's fine for a team, not for the
internet.

## HTTP API

All endpoints take `Authorization: Bearer <token>` (or `?token=`).

| | |
|---|---|
| `GET /api/state` | pending, recent decisions, last 100 log entries, chain status |
| `POST /api/decide` | `{"id","decision":"approve"\|"reject","approver","note"}` |
| `GET /api/log?limit=N` | raw entries |
| `GET /api/verify` | chain check |
| `GET /api/policy` | compiled rules |
| `GET /export.csv?since=&until=` | CSV, RFC3339 bounds |
| `GET /healthz` | liveness |

## FAQ

**Does the agent hang while waiting?** The call blocks until a decision or the
timeout. If the client supplied a progress token, Gatekeeper sends progress
notifications every 15s so the connection stays warm and the agent can tell
the user it's waiting. Set `approval_timeout` shorter than your client's tool
timeout if it has one.

**Can the agent see the inbox or approve itself?** Only if you give it the
token and network access to the inbox. Don't.

**What about tools that aren't MCP?** Not yet. MCP is where agent tool use is
converging; HTTP-API fronting is on the roadmap.

**Does it slow down allowed calls?** One policy evaluation and one log write
(fsynced) per call — under a millisecond on ordinary disks.

## Development

```sh
make test        # unit + end-to-end proxy tests
make build       # bin/gatekeeper
make release     # cross-compiled binaries in dist/
```

## License

Apache-2.0. The proxy, policy engine, audit log and inbox in this repository
are and will stay open source.
