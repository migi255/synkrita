# Synkrita

Synkrita is a self-hosted Python MCP service for reading scientific evidence and scoped integration decisions with provenance. An institution can fork it, operate its own identity and review policies, and deploy it with its own data and infrastructure. The source in this repository is derived from the verified 0.1.0.post2 candidate.

## What is implemented

- **Hosted MCP** exposes three read-only tools over stateless Streamable HTTP. `read_public_observation` returns an approved projection and citation, `read_qualified_decision` checks a qualified decision by ID, and `read_investigation` reads an investigation for the authenticated owner.
- **Operator controls** include issuer and JWKS pinning, approved client IDs and scope, enrollment, owner isolation, scoped signed reviews, revocation, rate and request limits, restricted audit, checked SQLite snapshots, and private per-account usage reports.
- **A separate operator collector** can discover, observe, and probe configured scientific MCP sources. Operations require explicit local grants. It retains checksummed evidence and supports bounded payload verification and inspectable citations. The trusted-local stdio command is for operator use.

The hosted API has no public search, write, administration, or arbitrary scientific invocation tool. A qualified decision applies to its reviewed use and evidence. Provenance and schema checks do not establish scientific truth, completeness, or current upstream contents. Coverage reports describe attributable worker requests. Edge-only and unattributed traffic are measured separately. This is a single-worker SQLite service. Live OAuth acceptance, capacity, target isolation and alert delivery depend on the deployment.

## Install from source

With an approved Python package index or mirror and Python 3.11 or later, run from the checkout root.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
synkrita remote-mcp --help
```

The source install checks the application entry point. For the locked Linux build profile and hosted setup, see [Self-hosting](docs/SELF_HOSTING.md).

## Self-hosting

Use the [reference architecture and mandatory security controls](docs/ARCHITECTURE.md) and the [configuration and deployment quick start](docs/SELF_HOSTING.md). The systemd and NGINX templates are included. The matching operator release package contains the detailed install, monitoring, recovery and target-host acceptance procedures.

Use [scientific source configuration](docs/REMOTE_MCP_QUALIFICATION.md) to set up the separate collector. Obtain approval for upstream data access, retention and redistribution before enabling a provider.

## License and contributions

Synkrita is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and dependency redistribution. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
