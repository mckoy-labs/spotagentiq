# Security policy

SpotAgentIQ sits on a trust boundary, so a way around it is a security bug even
if nothing crashes.

## Reporting a vulnerability

Email **security@spotagentiq.com**. Please don't open a public issue for
anything that lets a call skip policy, run unlogged, or reach the inbox without
the token.

Include what you did, what you expected, and what happened: a config and the
JSON-RPC request that gets through is ideal. You'll get a reply within three
working days. We'll confirm the problem, fix it, publish a release, and credit
you in the notes unless you'd rather we didn't.

Only the latest release is supported. Fixes are not backported.

## What counts

In scope:

- A tool call, resource read or other gated request that reaches an upstream
  server without the decision the policy calls for.
- A request the upstream receives that differs from what policy evaluated or
  what the approver was shown.
- A call that runs without a matching entry in the audit log.
- Edits, deletions or insertions in the log that `spotagentiq verify` accepts.
- An upstream server reading the inbox token or another upstream's credentials
  from its environment.
- Using the inbox API without the token, or script injection into the inbox
  page through tool names, arguments or results.

Out of scope, because these are documented limits rather than bugs:

- Rephrasing content so a regex in `if_args_match` no longer matches it.
  Patterns are tripwires; the README says so.
- Leaking data by combining calls the policy allows.
- What a tool server does internally with a call it was allowed to receive.
- Instructions hidden in tool descriptions, which pass through unchanged.
- Anyone holding the shared inbox token approving under any name.
- Rewriting the entire log with fresh hashes when no earlier hash was stored
  elsewhere.
- An attacker who already has administrator access to the host.

The full list of guarantees and limits is in the
[security model](https://www.spotagentiq.com/docs/security).

## Verifying a release

Release checksums are signed by this repository's GitHub Actions identity with
[Sigstore](https://www.sigstore.dev/). There is no long-lived signing key.

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/mckoy-labs/spotagentiq/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS
```

The first command proves the checksum file was produced by this repository's
release workflow. The second proves your download matches it.
