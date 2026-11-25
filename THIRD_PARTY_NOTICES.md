# Third-party notices

The public repository contains Synkrita source and reference configuration. It carries no dependency wheels, certificate bundles, compiled libraries or scientific datasets. Dependencies are obtained separately from their publishers or an approved mirror. Synkrita's Apache-2.0 license covers the project and does not change their licenses.

The table records the package-level declarations from the exact wheels in the [reference lock](deploy/operator/linux-cp313.lock). [License and attribution texts](third-party/LICENSES.txt) preserve the upstream wheel license and attribution entries verbatim, including pip's vendored notices. Package-level declarations can omit licenses of embedded native components. For development dependencies and alternate platforms, consult the terms shipped with the distributions you select.

| Package | Locked version | Declared license | Notice files |
| --- | --- | --- | --- |
| annotated-types | 0.8.0 | `MIT` | 1 |
| anyio | 4.16.0 | `MIT` | 1 |
| attrs | 26.1.0 | `MIT` | 1 |
| certifi | 2026.10.23 | `MPL-2.0` | 1 |
| cffi | 2.1.1 | `MIT-0` | 1 |
| click | 8.5.1 | `BSD-3-Clause` | 1 |
| cryptography | 50.0.2 | `Apache-2.0 OR BSD-3-Clause` | 3 |
| h11 | 0.16.0 | `MIT` | 1 |
| httpcore | 1.0.9 | `BSD-3-Clause` | 1 |
| httpx | 0.28.1 | `BSD-3-Clause` | 1 |
| httpx-sse | 0.4.3 | `MIT` | 1 |
| idna | 3.20 | `BSD-3-Clause` | 1 |
| jsonschema | 4.26.0 | `MIT` | 1 |
| jsonschema-specifications | 2025.9.1 | `MIT` | 1 |
| mcp | 1.30.0 | `MIT` | 1 |
| pip | 26.3 | `MIT` | 22 |
| pycparser | 3.12 | `BSD-3-Clause` | 1 |
| pydantic | 2.14.3 | `MIT` | 1 |
| pydantic_core | 2.50.4 | `MIT` | 1 |
| pydantic-settings | 2.16.3 | `MIT` | 1 |
| PyJWT | 2.15.1 | `MIT` | 2 |
| python-dotenv | 1.2.4 | `BSD-3-Clause` | 1 |
| python-multipart | 0.0.34 | `Apache-2.0` | 1 |
| referencing | 0.37.0 | `MIT` | 1 |
| rpds-py | 2026.9.1 | `MIT` | 1 |
| sse-starlette | 3.7.0 | `BSD-3-Clause` | 2 |
| starlette | 1.10.0 | `BSD-3-Clause` | 1 |
| typing_extensions | 4.16.0 | `PSF-2.0` | 1 |
| typing-inspection | 0.4.5 | `MIT` | 1 |
| uvicorn | 0.54.0 | `BSD-3-Clause` | 1 |

## Redistribution of an operator bundle

The builder copies dependency wheels unchanged. Preserve those wheels with all of their original notices and the notice files in the operator bundle. A redistribution of operator binaries needs its own review of the exact inventory, including vendor and native components. In particular:

- Certifi declares MPL-2.0. The locked pip wheel also contains a vendored CA bundle with an upstream MPL notice. Preserve those notices and make the applicable covered source available under the [Mozilla Public License](https://www.mozilla.org/en-US/MPL/2.0/) when required. The locked certifi wheel carries the Python modules and PEM data, and the upstream source release is listed with the [certifi distribution](https://pypi.org/project/certifi/2026.10.23/#files). Pip's vendored files and notices are in the unchanged pip wheel and corresponding [pip source release](https://pypi.org/project/pip/26.3/#files). Verify the corresponding source and provide a durable access path to recipients before redistributing.
- Review binary dependencies such as cryptography, cffi, pydantic-core and rpds-py for bundled native components and retain the applicable upstream notices and obligations for those components. The table inventories the inspected wheel metadata. It does not enumerate the components of a particular host OS or container.
- Upstream provider configuration examples use public endpoints as identifiers. Obtain separate permission for queries, downstream publication, evidence redistribution and retention. The examples do not sublicense the provider's data or service.

These notices accompany the source publication. A separately prepared operator archive and its signature require approval from their release owner.
