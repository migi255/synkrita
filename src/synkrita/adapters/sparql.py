"""SPARQL extension contract only; no executor is shipped in milestone one."""
from typing import Protocol
from synkrita.models import SourceAdapter


class SparqlAdapter(SourceAdapter, Protocol):
    """Implementations must enforce authorized dataset/graph scope before execution,
    parse typed bindings, distinguish errors/empty results, bound rows/bytes/time,
    record query and effective dataset, and qualify pagination and completeness.
    A schema witness is not ontology meaning; counts are only change indicators.
    Credentials stay in transport configuration, never Findings.
    """
    async def validate_read_query(self, query: str, graphs: tuple[str, ...]) -> dict: ...
