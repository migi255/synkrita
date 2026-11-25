# Reproduce a study-lineage decision

**Synthetic evidence.** In this exercise, a specimen inventory record and an assay manifest record each report `ALIQUOT_001` in fixture release `v1`. An operator approves using that pairing to trace the assay to the named aliquot within the release. The example uses invented records because live source permissions and suitable lineage evidence are outside this exercise.

## Run locally

[Install Synkrita from this checkout](../README.md#install-from-source), then run from the repository root with the same virtual environment active.

```sh
python examples/study_lineage.py
```

[The example script](../examples/study_lineage.py) runs the real collector and hosted MCP app through in-process HTTP transports. It uses two disposable SQLite files and creates signing keys and bearer tokens in memory. It needs no external source, credentials or listening port after installation. The real access verifier checks locally signed test tokens against a pinned fixture JWKS. Provider sign-in, OAuth exchange and refresh, TLS ingress, and target-host acceptance are outside this exercise. The script plays the operator and reviewer roles. Actual scientific review requires independently authorized people.

Expect the following results. Receipt IDs, decision IDs and checksums vary per run.

```text
Captured SPECIMEN_001: receipt=<id> capability_finding_reused=False
Captured ASSAY_001: receipt=<id> capability_finding_reused=True
Published specimen_record: receipt=<id> checksum=<sha256>
Published assay_record: receipt=<id> checksum=<sha256>
Activated <id>: use=trace_sample_lineage
First session: candidate withheld, decision available, private investigation available
Second session: same scoped decision and both citations, private investigation withheld
After policy withdrawal: observation and dependent decision withheld
Source tool calls: 3 during collection, 0 during hosted reads
```

## What the example verifies

1. **Collect.** The source configuration grants only `lookup_lineage`. The typed collector validates a witness and the current specimen response. The assay lookup reuses the capability Finding and still validates a fresh response. The three source tool executions are one witness and two current lookups. MCP initialization and catalogue requests are separate.
2. **Preserve and publish.** The operator reads the checksummed collector receipts, registers the source in the hosted store and creates a policy for the exact capability digest. `retain_public` imports each unchanged body and publishes only the approved scalar fields. The hosted receipt has its own ID. The script resolves the hosted citation and checks its checksum, source, operation, capture time and selected values against the collector evidence.
3. **Propose and qualify.** The operator proposes `trace_sample_lineage` using both published citations. The first account verifies that the candidate ID is unavailable as a decision. The reviewer signs the candidate digest and use, and the operator activates it through the same store methods the local admin CLI calls.
4. **Reuse and withhold.** After a separate MCP initialization, the second enrolled account calls `read_qualified_decision` and `read_public_observation` by supplied IDs. It receives the same scoped decision and both citations without another source call. `read_investigation` gives the first account access to its own notes and treats a foreign ID like a missing one. Withdrawing the publication policy withholds both the observation and the decision supported by it.

The fixture demonstrates inspectable support for a human-reviewed linkage. It cannot establish whether specimens really share a physical aliquot, whether measurements are independent or poolable, or whether an upstream dataset still reports the same linkage. A shared identifier outside this release requires independent evidence. The second session reuses an existing approval and supplies no new applicability context. See the [knowledge model](KNOWLEDGE_MODEL.md) for how the different records can be reused.
