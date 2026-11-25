# Self-hosting Synkrita

Start with the [architecture and mandatory security controls](ARCHITECTURE.md#mandatory-controls-for-hosted-operators). The hosted entry point is `synkrita remote-mcp serve`. Use `synkrita serve` only for trusted local stdio sessions.

## Configuration reference

Copy the [OAuth example](../deploy/operator/oauth.example.json) to a protected location outside the checkout and replace the placeholders. Configure the authorization server and MCP clients independently.

| Field | Requirement |
| --- | --- |
| `issuer` | Canonical HTTPS issuer, exactly matching the token's `iss` including any trailing slash. |
| `resource` | The public-facing canonical HTTPS URL ending exactly in `/mcp`. It must be the token's sole audience. |
| `jwks_url` | An explicit HTTPS key-set URL on the same authority as the issuer. |
| `clients` | One to eight distinct approved OAuth client IDs, matching the access token's `client_id` claim. |
| `max_token_age` | Token lifetime bound in seconds, from 60 to 3600. The default is 900. Configure the provider to issue tokens within the bound. |
| `self_registration` | Boolean, default `false`. Keep it false for closed enrollment. Any move to self-registration needs its own approval and provider-side signup controls. |

Use lowercase HTTPS authorities without an explicit default port. Register exact client callbacks and require PKCE S256. Configure interoperable provider discovery and short-lived RFC 9068 RS256 user access tokens bearing `research:access`. Store private keys and credentials separately from config, source files and logs.

## Deployment quick start

- Install using the [source quick start](../README.md#install-from-source). The reproducible operator wheel profile is glibc Linux x86-64 with glibc 2.34 or newer and CPython 3.13. It uses the [hash-pinned dependency lock](../deploy/operator/linux-cp313.lock). Qualify a separate profile for other targets.
- Adapt the [systemd unit](../deploy/remote-mcp-staging/synkrita-staging.service) and [NGINX configuration](../deploy/remote-mcp-staging/nginx.conf.template) to the approved host. Preserve the canonical Host and proxy only `/mcp` and `/.well-known/oauth-protected-resource/mcp`. Deny other routes, disable response caching and forwarded identity, and enforce edge request and connection limits.
- On a dedicated host with ingress closed, use one unprivileged service account and one worker. Use encrypted private local storage with a service-owned state directory at `0700` and SQLite at `0600`. Initialize only a new database with `synkrita remote-mcp init --database FILE`. Start the worker with `synkrita remote-mcp serve --database FILE --config FILE`. It listens on `127.0.0.1:8765` by default. Use the operator package's checked backup and rollback procedure for existing state.
- Keep administrative commands local and OS-restricted. `synkrita remote-mcp admin --help` lists account, audit and review actions. `synkrita remote-mcp usage --help` describes the private report for recorded worker completions and collection gaps. Track edge traffic and sampled security audit separately. Apply approved retention and disk limits because usage rows are retained until operator-managed maintenance.

For client setup, see [Claude](CLAUDE_QUICKSTART.md), [Codex](CODEX_QUICKSTART.md) or [ChatGPT](CHATGPT_QUICKSTART.md). See the [collector configuration](REMOTE_MCP_QUALIFICATION.md) for approved outbound scientific sources.

## Operator package and acceptance

For this source release, obtain the separate **Synkrita 0.1.0.post2 operator package** through the approved release channel. Verify the authorized signature on its manifest with an independently pinned key and confirm its `REVISION` is `b79f1cad1e1ae2a5e30c3fbbe9f53350b9ab84eb`. A bundle built from this public checkout includes the public documentation. The matching verified operator package includes the full procedures and acceptance record below. Paths are relative to the extracted operator package.

| Gate | Required outcome | Operator package reference |
| --- | --- | --- |
| Prepare and install | Approve the exact signed release, confirm host isolation, storage and network controls, and verify offline installation and loopback startup with ingress closed. | `ADMIN-DEPLOYMENT.md`, `docs/DEPLOYMENT_SAFETY.md`, `docs/OPERATOR_QUICKSTART.md` |
| Restricted staging | Obtain approval for allowlisted HTTPS peers. Verify TLS, edge limits and live OAuth for every enabled client. Exercise discovery, renewal, revocation, account suspension, owner isolation and scoped evidence access with disposable staging records. | `docs/REMOTE_MCP_STAGING.md`, `docs/OPERATOR_ACCEPTANCE.md` |
| Public researcher access | Pass target-host acceptance before separate, named approval. Verify alert delivery, capacity and concurrent SQLite activity, audit and usage privacy and retention, upgrade and rollback, and encrypted off-host restore with replay of access and evidence withdrawals. Confirm source rights, privacy and enrollment approval. | `docs/OPERATOR_ACCEPTANCE.md`, `docs/OPERATOR_MONITORING.md`, `docs/OPERATOR.md` |

The operator package also documents the local action payloads in `docs/REMOTE_MCP_HANDOFF.md`. Keep each phase closed until its checks and approvals pass. Local verification alone does not qualify a target for researcher access.
