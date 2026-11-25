# Remote MCP qualification

The operator collector uses the official MCP SDK, source grants, SQLite receipts and bounded validation. It runs separately from the hosted worker.

## Source configuration

`examples/sources.toml` contains the provider-documented endpoints:

- GlyGen: `https://mcp.glygen.org/mcp` ([provider repository](https://github.com/glygener/glygen-mcp-server)).
- BiomarkerKB: `https://mcp.biomarkerkb.org/mcp` ([provider wiki](https://wiki.biomarkerkb.org/BiomarkerKB_MCP_Server); review the current provider contract before enabling any operation).

Both start with empty invocation allowlists. Discovery may observe declarations; it cannot confer invocation permissions or create a validated Finding. Configuration is local operator authority. A provider's tool annotation is not an authorization grant.

Each source binds an HTTPS URL, an authorized view, an explicit operation list and budgets. Redirects, user-info, query-bearing endpoint URLs and fragments are rejected. Request policy compares normalized scheme, host, effective port and path, and permits only the HTTP methods used by the SDK. Loopback HTTP requires an explicit `allow_local_http = true` exception, intended for fixtures. Arbitrary private-network HTTP is rejected.

Optional `authorization_env = "SYNKRITA_SOURCE_AUTHORIZATION"` names an environment variable containing the complete Authorization header value. Tokens never belong in TOML, URLs, CLI arguments, Findings or reports. Source credentials must actually correspond to the configured view; this is trusted operator configuration, not principal attestation. Source-specific minimization remains required before sensitive-data use.

The HTTP client honors operator environment proxies. Its exact-endpoint request policy still applies; proxy operation and TLS trust are the operator's infrastructure responsibilities. This policy confines this client's destinations. It does not constrain the remote server's own network activity or arbitrary endpoint arguments accepted by a remote tool. General routing, URL-fetch and query-execution tools require separate argument-level authorization before they can be permitted.

## Add a mock before proposing a live source

Use a disposable loopback MCP exposing a typed lookup. Discover it with an empty allowlist and confirm a lookup is denied. Add the exact mock operation only and confirm bounded invocation, a current receipt and provenance. Use the loopback HTTP exception for that mock. Start approved remote endpoints with an empty allowlist.

The collector registration authorizes neither hosted publication nor scientific reuse. For hosted publication, the operator must register the approved identity and add an exact operation, contract digest, public projection, licence and expiry with the hosted CLI. Then retain only eligible public output with provenance. Signed review independently governs qualified decisions. Use `synkrita remote-mcp admin --help` to see the local commands. The [matching operator package](SELF_HOSTING.md#operator-package-and-acceptance) documents the admin action payloads and approval steps.

## Run from a network-enabled terminal

Run from the Synkrita directory. These commands use only initialization/catalogue operations:

```sh
mkdir -p .local/remote-qualification
# Run only after approval for these exact source endpoints.

synkrita mcp-discover \
  --config examples/sources.toml --source glygen \
  --database .local/remote-qualification/registry.sqlite \
  --output .local/remote-qualification/glygen.json

synkrita mcp-discover \
  --config examples/sources.toml --source biomarkerkb \
  --database .local/remote-qualification/registry.sqlite \
  --output .local/remote-qualification/biomarkerkb.json
```

A blocked discovery exits nonzero and retains a diagnostic category, never raw exception text or invented server capabilities. Successful discovery retains a declaration receipt with full input/output schemas and negotiated protocol version, plus a compact report of tool names, output-schema availability and invocation permissions. Inspect the declaration using `synkrita inspect DATABASE DECLARATION_ID`.

Review actual operation semantics, schemas, result bounds, application errors and pagination before adding exact read-only operation names to a local source configuration. Do not assume a tool named in a wiki matches the deployed catalogue. Do not automatically permit tools merely because their names sound read-only.

After review, a permitted operation can run through the existing evidence workflow:

```sh
synkrita mcp-probe \
  --config .local/sources.toml --source SOURCE_NAME \
  --database .local/remote-qualification/registry.sqlite \
  --operation EXACT_REVIEWED_TOOL_NAME \
  --arguments-file .local/current-arguments.json \
  --probe-file .local/qualification-arguments.json \
  --output .local/remote-qualification/probe.json
```

The argument files must conform to the discovered input schema and contain bounded public queries. The core checks view, receipts, schemas and interface revision, fetches a fresh answer and retains limitations. Repeating with a different current input can reuse eligible capability knowledge. Successful invocation never licenses completeness, absence or scientific interpretation.

## Observed declarations: outer strings, unqualified inner data

A provider can declare `result` as a string with `x-fastmcp-wrap-result = true`. A JSON-encoded application error can satisfy that outer schema. Check the actual schema and payload contract for the configured operation.

`mcp-observe` is the next boundary: one explicitly permitted tool invocation, outer-schema checking, conservative payload-format inspection, retained provenance and **zero Findings admitted**. JSON decoding is syntax inspection, not application/scientific validation. Potential nested error fields are flagged; duplicates/nonfinite JSON are not silently normalized. Recognizable credential fields inside decoded JSON are checked before retention. `mcp-probe` withholds these wrapped-text contracts pending a qualified inner-data profile, while typed fixture contracts continue through the existing Finding workflow.

The first opt-in policy `examples/metadata-sources.toml` grants only `get_release_info` for each endpoint; `examples/sources.toml` remains discovery-only. Both discovered release tools take `{}`. Run:

```sh
for source in glygen biomarkerkb
do
  synkrita mcp-observe \
    --config examples/metadata-sources.toml --source "$source" \
    --operation get_release_info --arguments-file examples/empty-arguments.json \
    --database .local/remote-qualification/registry.sqlite \
    --output ".local/remote-qualification/$source-release.json"
done
```

Retain the response as a source statement. Release metadata does not establish scientific accuracy, dataset freshness or unchanged contents. Source permissions for release metadata do not extend to scientific search or detail calls.

## Budgets and measurement

Versioned local structural profiles and an offline `validate-payload` command are now implemented; see [inner payload contracts](INNER_PAYLOAD_CONTRACTS.md). They assess retained release-metadata responses without upstream calls, receipt mutation, or Finding admission. They do not open the wrapped-output reuse gate or establish application success semantics.

Defaults are 10 seconds per request, 30 seconds for a session, 32 HTTP requests, 1 MiB per HTTP response, 256 tools, 512 KiB of normalized catalogue schema/name data, and 16 discovery pages. Normalized individual tool results retain the adapter's existing 64 KiB bound. Compression is not accepted by this initial bounded HTTP profile. Event-stream responses are bounded per HTTP stream, so long sessions may need a separately qualified profile.

The session deadline applies to the async operation and cleanup. An OS DNS resolver thread can outlive async cancellation and delay interpreter shutdown; the TCP preflight avoids starting resolver threads in environments that categorically prohibit sockets. No claim of a process-level hard kill deadline is made.

HTTP counters include SDK initialization, notifications, GET/POST/DELETE attempts, status codes and received bytes; MCP counters count request messages, including SDK-triggered discovery, but not notifications. Planner-level operations remain separately measured. Retries to an unapproved destination are never authorized by a transport error.

## Known limits

This profile requires declared output schemas and structured MCP results before the core can qualify a reusable capability. JSON strings, text-only replies, missing schemas, SSE-only servers, OAuth discovery/refresh and alternate authentication destinations require separately qualified parsing or transport support. Their presence is an applicability gap, not evidence that the source is scientifically wrong. No automatic JSON-string coercion or schema inference is used to admit Findings.

This milestone does not implement cross-source joins, entity equivalence, scientific reasoning, complete enumeration, model orchestration, a general gateway, or domain-reference ingestion.
