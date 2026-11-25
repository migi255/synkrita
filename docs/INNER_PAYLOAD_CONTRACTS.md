# Release metadata structural contracts

`glygen-release-v1` and `biomarkerkb-release-v1` are operator-owned, narrow acceptance profiles implemented in `src/synkrita/payloads.py`. They are not provider guarantees or inferred universal schemas. Test these profiles against authorized responses and independent synthetic negative cases.

Each version binds an exact provider endpoint, public view, `get_release_info`, and empty arguments. No source alias confers that binding. Both require exactly the string wrapper `{"result": "..."}`, at most 64 KiB of UTF-8 inner JSON, no duplicate object keys, no nonfinite numbers (including exponent overflow), and exactly two component objects: one `api`, one `data`. Component ordering is unrestricted. Each object requires `component`, `version`, and `release_date`, each a nonblank string of at most 256 characters. Unknown fields, missing fields, duplicate components, scalar payloads, error envelopes, and error/status fields fail closed.

BiomarkerKB's data component additionally requires `version_list`, a nonempty list of at most 1024 nonblank strings of at most 256 characters each. Order and repeated entries are preserved exactly. GlyGen's profile does not accept that additional field. These bounds are conservative local acceptance limits, not established provider limits. Expansion or changes to these rules require a new contract identifier and new qualification evidence.

Dates and versions remain opaque source strings. The profiles do not validate calendar dates, release chronology, version ordering, historical semantics, uniqueness of versions, application-success guarantees, freshness, or underlying data contents. A matching version can at most mean no change was detected in that source statement. Unknown error representations that perfectly mimic the accepted shape cannot be distinguished by this structural check.

## Assess retained observations offline

```sh
synkrita validate-payload DATABASE OBSERVATION_RECEIPT \
  --contract glygen-release-v1
# For the other exact source, use biomarkerkb-release-v1.
```

The command verifies store checksums, active source registration and view, operation/arguments, the original output checksum, the supporting scoped declaration, and the declared outer input/output schemas. It then applies the explicit inner profile. An accepted response appends a `payload_validation` record with the contract version, source/view, original observation time, assessment time, dependency receipt IDs, output/payload hashes, zero upstream calls and zero Findings admitted. The original observation remains unchanged and retains its historical unqualified status. A rejected assessment exits nonzero without creating a validation record. Diagnostics omit payload contents.

This is local operator tooling, like `inspect`; it is not a new externally exposed MCP tool. Local checksums detect corruption rather than establish provider authenticity. An assessment concerns only one retained output. A different response, scope, declaration or parser contract requires a new assessment; assessment time cannot refresh observation time. Missing/corrupt evidence or revoked registration prevents reassessment.

## Qualification still pending

Use the [matching operator package](SELF_HOSTING.md#operator-package-and-acceptance) for release verification.

`mcp-observe` remains observation-only and `mcp-probe` still withholds wrapped-string capabilities. No retained structural assessment is selected by the deterministic Finding reuse path. Before enabling it, bind the versioned parser to witness admission, receipt replay and every current response, and test contract/interface/scope changes and malformed current responses. Measure initialization, all catalogue pages, SDK-internal requests, invocations, local validation, elapsed time and amortized preparation separately.

Live cold/warm/change reuse and one bounded scientific lookup per source remain pending. The metadata invocation grants are unchanged; no biological search/detail calls are enabled. Full transport qualification remains distinct from offline structural validation.
