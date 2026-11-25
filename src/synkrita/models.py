"""Small source-independent contracts; declarations never establish truth."""
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Protocol


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@dataclass
class Capability:
    name: str
    input_schema: dict
    output_schema: dict
    limitations: list[str] = field(default_factory=list)


class SourceAdapter(Protocol):
    """Adapters own discovery, transport, application errors and normalization.

    revision returns interface and data indicators separately. None means unknown.
    No adapter may infer enumeration completeness from protocol success.
    """
    identity: str
    async def revision(self) -> dict: ...
    async def discover(self) -> list[Capability]: ...
    async def invoke(self, name: str, arguments: dict) -> Any: ...


@dataclass
class Finding:
    source: str
    identity: str
    view: str
    capability: dict
    interface: str | None
    receipt: str
    observed_at: float
    max_age_seconds: int = 3600
    validator: str = "schema-witness-v1"
    intended_use: str = "invoke_candidate"
    assumptions: list[str] = field(default_factory=lambda: ["Current request must be validated independently"])
    dependencies: list[str] = field(default_factory=list)
    status: str = "validated"
