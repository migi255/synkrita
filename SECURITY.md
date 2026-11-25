# Security

## Reporting

Use GitHub’s private vulnerability reporting under the repository’s Security tab when the maintainer has enabled it. Otherwise ask the maintainer privately for the approved reporting channel. Give the affected revision, a brief description, the observed impact and a synthetic reproduction if available. Keep real tokens, private identifiers, operator records and raw scientific captures out of public issues, pull requests and CI logs. Report suspected credential exposure promptly to the credential owner so they can revoke or rotate it.

## Supported boundaries

Follow the [mandatory security controls](docs/ARCHITECTURE.md#mandatory-controls-for-hosted-operators) and [deployment acceptance requirements](docs/SELF_HOSTING.md#operator-package-and-acceptance). Use the matching operator package for signed-release verification, preflight, monitoring and recovery procedures. Keep the local stdio interface limited to trusted operator or fixture sessions.

Report publication concerns through the same private channel. Check working files, reachable history, source and wheel archives, and generated reports before sharing. Secret scanning complements review of evidence and metadata. [GitHub secret scanning guidance](https://docs.github.com/en/code-security/tutorials/secure-your-organization/prevent-data-leaks)
