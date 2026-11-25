# Contributing to Synkrita

Describe the problem, affected version, and smallest reproducible case before proposing changes. Use the project's [security reporting process](SECURITY.md) for suspected vulnerabilities or disclosure. Use synthetic accounts, observations, reviews and source contracts in public test fixtures.

1. Use a fresh clone and virtual environment. Follow [installation](README.md#install-from-source) and install the optional test dependencies with `python -m pip install '.[dev]'`.
2. Add focused tests for changed behavior and run `python -m pytest -q`. For changes to hosted authentication, evidence, SQLite or deployment boundaries, describe the relevant protected paths and which checks ran locally. Keep target acceptance separate.
3. Include the result and any dependency, data-format, operator or rollback impact in the pull request. Keep the locked wheel set intact unless updating dependencies is the purpose of the change.
4. Preserve attribution and license notices. Identify any third-party code or data you propose to include and its redistribution terms. Submit only contributions you are authorized to license under [Apache-2.0](LICENSE).

Keep live credentials, tokens, signing keys, database files, private configurations, unpublished captures and host inventory out of commits, issue reports and CI logs. Test deployments only against approved, isolated infrastructure.
