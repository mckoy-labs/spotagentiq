# SpotAgentIQ

[![ci](https://github.com/mckoy-labs/spotagentiq/actions/workflows/ci.yml/badge.svg)](https://github.com/mckoy-labs/spotagentiq/actions/workflows/ci.yml)
[![audit log verified](https://github.com/mckoy-labs/spotagentiq/actions/workflows/verify.yml/badge.svg)](https://github.com/mckoy-labs/spotagentiq/actions/workflows/verify.yml)
[![release](https://img.shields.io/github/v/release/mckoy-labs/spotagentiq)](https://github.com/mckoy-labs/spotagentiq/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/mckoy-labs/spotagentiq.svg)](https://pkg.go.dev/github.com/mckoy-labs/spotagentiq)
[![license](https://img.shields.io/github/license/mckoy-labs/spotagentiq)](LICENSE)

**Your agent can send the email. SpotAgentIQ decides whether it should.**

An MCP proxy that lets tool calls through, holds them for a human, or blocks
them, and keeps a hash-chained audit log of every decision.

![spotagentiq demo: one call allowed, one blocked, one held then approved, one held then rejected](docs/demo.gif)

## Quickstart

```sh
# 1. Install: a signed binary from Releases (Linux, macOS, Windows), or
go install github.com/mckoy-labs/spotagentiq/cmd/spotagentiq@latest

# 2. Watch it work: four calls, one allowed, one blocked, two held for you
spotagentiq demo

# 3. Use it: write a config, then point your MCP client at SpotAgentIQ
spotagentiq init > spotagentiq.json
```

The policy is a short list of rules. First match wins:

```json
"rules": [
  { "match": "*",          "action": "deny",             "if_args_match": "\\b\\d{13,19}\\b", "reason": "Looks like a card number" },
  { "match": "send_email", "action": "allow",            "where": { "to": "^[^@\\s]+@yourcompany\\.com$" } },
  { "match": "send_*",     "action": "require_approval", "reason": "Outbound communication" },
  { "match": "delete_*",   "action": "require_approval", "reason": "Destructive" }
]
```

[Policy docs](https://www.spotagentiq.com/docs/policy) ·
[Install for real](#install-for-real) ·
[Security model](#security-model) ·
[Website](https://www.spotagentiq.com)

## How it works

SpotAgentIQ sits between an AI agent and the tools it calls. It's an MCP server
that wraps your real MCP servers. Every tool call passes through your policy:
let it through, hold it for a human, or block it. Everything is written to a
hash-chained audit log that proves what the agent did, who approved it, and
that nobody edited the record afterwards.

```
  Claude / Cursor / your agent
            │  MCP (stdio)
            ▼
     ┌─────────────┐      ┌──────────────┐
     │  SpotAgentIQ │─────▶│  Slack alert │
     │   policy    │      └──────────────┘
     │   audit log │◀──── human approves / rejects in the inbox
     └─────────────┘
            │  MCP (stdio)
            ▼
   your real MCP servers (CRM, email, DB, Stripe, filesystem, ...)
```

- **Zero dependencies.** One static Go binary. Nothing to `npm install`, no
  supply chain to audit, no database to run.
- **Works with any MCP server.** If your agent can call it today, SpotAgentIQ
  can front it. Multiple upstreams behind one gate.
- **Tamper-evident log.** Every entry carries the SHA-256 of the previous one.
  `spotagentiq verify` tells you if a line was edited or removed, and which one.
- **Agent-friendly failures.** A blocked call comes back as a tool result the
  agent can read and explain to its user, not a crash.

## The 60-second demo

`spotagentiq demo` starts a fake CRM tool server and a scripted agent.

Then open <http://localhost:8484> (token `demo-token`). A scripted agent will
read a customer (allowed), try to charge a card it pasted into a prompt
(blocked), email the customer (held — go approve it), and delete the customer
record (held — go reject it). Then verify the log:

```sh
spotagentiq verify --log /tmp/spotagentiq-demo-*/audit.jsonl
# OK: 9 entries, chain intact.
```

Edit one character in that file and run it again. CI does exactly that on
every push: the [audit log verified](https://github.com/mckoy-labs/spotagentiq/actions/workflows/verify.yml)
badge above is green only if the demo's log verifies and a one-character edit
is caught.

## Install for real

### 1. Write a config

```sh
spotagentiq init > spotagentiq.json
export SPOTAGENTIQ_TOKEN=$(openssl rand -hex 16)
```

A minimal config:

```json
{
  "agent": "support-bot",
  "listen": "127.0.0.1:8484",
  "token": "${SPOTAGENTIQ_TOKEN}",
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

A tool server that needs credentials gets them through its own `env` block.
It does not inherit your shell's environment, so one server can't read
another's keys:

```json
{ "name": "crm", "command": "npx", "args": ["-y", "@acme/crm-mcp"],
  "env": { "CRM_API_KEY": "${CRM_API_KEY}" } }
```

`${VAR}` is expanded from SpotAgentIQ's own environment in `env`, `args`,
`token` and `slack_webhook`.

### 2. Point your agent at SpotAgentIQ instead of the tool server

Claude Desktop (`claude_desktop_config.json`), Claude Code (`.mcp.json`),
Cursor (`mcp.json`) — same shape:

```json
{
  "mcpServers": {
    "spotagentiq": {
      "command": "/usr/local/bin/spotagentiq",
      "args": ["serve", "--config", "/path/to/spotagentiq.json"],
      "env": { "SPOTAGENTIQ_TOKEN": "..." }
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
| `listen` | Inbox address, e.g. `127.0.0.1:8484`. Required if any rule needs approval. `:8484` listens on every interface. |
| `public_url` | How humans reach the inbox; used in Slack links. Defaults from `listen`. |
| `token` | Inbox password. `${ENV}` expansion supported; falls back to `SPOTAGENTIQ_TOKEN`. |
| `log_path` | Audit log file (JSONL). |
| `approval_timeout` | How long a held call waits. Go duration (`10m`, `1h`). |
| `default_action` | `allow`, `require_approval` or `deny` when no rule matches. |
| `slack_webhook` | Optional incoming-webhook URL. |
| `upstreams[]` | `name`, `command`, `args`, `env`, `cwd`, `inherit_env`. SpotAgentIQ launches each one with a minimal environment plus its own `env`; see [Security model](#security-model). |
| `rules[]` | Evaluated top to bottom; first match wins. |
| `redact[]` | Argument keys (case-insensitive, nested) masked in logs and the inbox. |

### Rules

```json
{ "match": "send_email", "action": "allow", "where": { "to": "^[^@\\s]+@yourcompany\\.com$" } }
{ "match": "send_*", "action": "require_approval", "reason": "Outbound" }
{ "match": "*", "action": "deny", "if_args_match": "\\b\\d{13,19}\\b", "reason": "Card number" }
```

- `match` is a glob. Without a `/` it is tested against the tool name
  (`send_*`, `*`, `delete_user`). With a `/`, the part before the first `/` is
  the upstream server and the rest is the tool: `stripe/*`, `db/query`,
  `*/delete_*`. `*` matches anything, including `/`.
- `action` is `allow`, `require_approval` or `deny`.
- `where` maps an argument to a regex its value must match: `"to"`,
  `"customer.email"`. All entries must hold, a missing argument never matches,
  and for an array every element must match. Use this whenever a rule depends
  on what one specific argument is.
- `if_args_match` is a regex tested against the whole arguments document. It
  matches anywhere, which is what you want for tripwires ("deny anything that
  contains a card number") and not what you want for allow rules, where a
  decoy value in another field would satisfy it. SpotAgentIQ warns at startup
  about allow rules that use it.
- `reason` is what approvers see and what goes in the log.

Arguments are parsed and re-serialised into one canonical form (sorted keys, no
optional escapes, last value wins for a repeated key) before any rule sees
them, and that same canonical document is what the tool server receives. A
rule can't be dodged with `\u0034` for `4` or a duplicate key, because there is
no difference between what was checked and what runs.

Requests that aren't tool calls but read data or change state
(`resources/read`, `prompts/get`, and any method this version doesn't
recognise) go through the same rules and the same log. To policy they are tools
on a reserved upstream called `mcp`: `{ "match": "mcp/resources/read",
"action": "require_approval" }`. A bare `*` covers them too.

When two upstreams expose a tool with the same name, both are exposed as
`upstream__tool` so nothing is ambiguous.

## The audit log

Each line is one event:

```
spotagentiq.start · call.allowed · call.pending · call.approved · call.rejected
call.denied · call.timeout · call.completed · call.failed
```

with the agent, principal, upstream, tool, redacted arguments, matching rule,
reason, approver, a summary of the upstream's result, the previous entry's hash
and this entry's hash.

```sh
spotagentiq verify --log audit.jsonl          # exit 0 intact, 3 if tampered
spotagentiq export --log audit.jsonl > a.csv  # for the auditor
curl -H "Authorization: Bearer $SPOTAGENTIQ_TOKEN" \
  "http://localhost:8484/export.csv?since=2026-11-01T00:00:00Z"
```

The log is append-only and fsynced on every write. For stronger guarantees,
ship the file to object storage with versioning, or periodically record the
last hash somewhere the agent can't reach (a ticket, a Slack message, a
timestamping service). Anyone holding that hash can later prove the log hasn't
been rewritten up to that point.

The CSV export prefixes any cell that starts with `=`, `+`, `-` or `@` with an
apostrophe, so text an agent influenced can't run as a spreadsheet formula.
Hashes are computed over the JSONL file; verify against that, not the CSV.

## Security model

What SpotAgentIQ enforces:

- **What is checked is what runs.** Policy is evaluated on a canonical form of
  the arguments and the tool server receives that same form.
- **Everything that acts is gated.** Tool calls, resource reads, prompt
  fetches and unknown methods all pass through policy and the log. Only
  listings, pings and subscriptions are passed straight through.
- **Fails closed.** If a decision can't be written to the audit log (full
  disk, bad permissions), the call is refused. SpotAgentIQ won't start with an
  unwritable log.
- **Tool servers don't get your secrets.** Each upstream starts with a minimal
  environment (`PATH`, home and temp directories, locale, proxy settings) plus
  only the variables in its own `env` block. It can't read the inbox token or
  another server's API keys. `"inherit_env": true` passes the full environment
  to one server, still without the token; prefer listing what it needs.
- **Timeouts reject.** An unanswered approval is a refusal, never a yes.

What it does not do, so you can plan around it:

- **Patterns are tripwires, not parsers.** A regex that blocks `DROP TABLE`
  won't catch every phrasing, and `\d{13,19}` won't catch a card number with
  spaces in it. Deny the obvious early; require approval for what matters.
- **Allowed reads can still leak.** If an agent may read customer records and
  may post to Slack, it can combine them. Hold the send.
- **It can't see inside a tool server.** A server that ignores its arguments
  and does something else needs sandboxing and narrow credentials.
- **Tool descriptions pass through unchanged.** A malicious server can still
  put instructions in them.
- **The approver's name is typed, not verified,** and the inbox token is a
  shared secret. The examples listen on `127.0.0.1`; SpotAgentIQ warns at
  startup if the inbox is reachable from other machines, because it speaks
  plain HTTP. Put TLS in front of it before you expose it.
- **Result summaries in the log are not redacted.** Only argument keys listed
  in `redact` are masked.
- **Someone with write access to the log can rewrite all of it.** The hash
  chain makes edits evident only against a hash you stored somewhere else.

Found a way around a rule? See [SECURITY.md](SECURITY.md).

## Running it somewhere

```sh
docker build -t spotagentiq .
docker run -p 8484:8484 -e SPOTAGENTIQ_TOKEN=... \
  -v $PWD/spotagentiq.json:/etc/spotagentiq.json \
  -v spotagentiq-audit:/var/lib/spotagentiq spotagentiq
```

SpotAgentIQ launches upstreams as child processes, so the container needs
whatever they need. The default image includes Node and Python. Inside a
container the inbox has to listen on all interfaces for the port mapping to
work, so use `"listen": "0.0.0.0:8484"` in that config and publish the port
only to a private network.

Put the inbox behind your VPN or a reverse proxy with TLS. The token is a
shared secret, not an identity layer; it's fine for a team, not for the
internet.

## HTTP API

All endpoints except `/healthz` need `Authorization: Bearer <token>`. The token
is not accepted in the URL or a cookie. Ten wrong tokens in a minute from one
address locks that address out for five minutes.

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
timeout. If the client supplied a progress token, SpotAgentIQ sends progress
notifications every 15s so the connection stays warm and the agent can tell
the user it's waiting. Set `approval_timeout` shorter than your client's tool
timeout if it has one.

**Can the agent see the inbox or approve itself?** Only if you give it the
token and network access to the inbox. Don't. Tool servers never receive the
token: SpotAgentIQ strips it from their environment.

**What about tools that aren't MCP?** Not yet. MCP is where agent tool use is
converging; HTTP-API fronting is on the roadmap.

**Does it slow down allowed calls?** One policy evaluation and one log write
(fsynced) per call — under a millisecond on ordinary disks.

## Verifying a release

Release checksums are signed by this repository's CI with Sigstore (keyless, so
there is no signing key to steal):

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/mckoy-labs/spotagentiq/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS
```

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Development

```sh
make test        # unit + end-to-end proxy tests
make build       # bin/spotagentiq
make release     # cross-compiled binaries in dist/
goreleaser release --snapshot --clean   # what a tagged release will publish
```

## SpotAgentIQ Cloud

A hosted control plane for teams is in development: approvals from Slack and
your phone, per-person sign-in, managed log retention. The proxy in this
repository stays open source and keeps working on its own.
[Join the waitlist](https://www.spotagentiq.com/cloud), and star the repo if
you'd use it. It's how we decide what to build next.

## License

Apache-2.0. The proxy, policy engine, audit log and inbox in this repository
are and will stay open source.
