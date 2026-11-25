"""Operator-owned release metadata profiles; structure is not scientific truth."""
from dataclasses import dataclass
import json
import math

from synkrita.models import digest
from synkrita.privacy import retention_safe


def strict_json(text):
    """Reject ambiguous keys and nonfinite numbers, including exponent overflow."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON keys')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('Non-finite JSON constant')

    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError('Non-finite JSON number')
        return parsed

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)


@dataclass(frozen=True)
class ReleaseContract:
    identifier: str
    identity: str
    version_list: bool = False
    operation: str = 'get_release_info'
    view: str = 'public'
    max_bytes: int = 65536

    def validate(self, output):
        if not isinstance(output, dict) or set(output) != {'result'} or not isinstance(output['result'], str):
            raise ValueError('Require the exact result string wrapper')
        if len(output['result'].encode('utf-8')) > self.max_bytes:
            raise ValueError('Payload exceeds contract byte budget')
        try:
            payload = strict_json(output['result'])
        except (ValueError, RecursionError) as error:
            raise ValueError('Invalid or ambiguous inner JSON') from error
        retention_safe(payload)
        if not isinstance(payload, list) or len(payload) != 2:
            raise ValueError('Require exactly one api and one data component')
        components = []
        for row in payload:
            if not isinstance(row, dict):
                raise ValueError('Require component objects')
            expected = {'component', 'version', 'release_date'}
            if self.version_list and row.get('component') == 'data':
                expected.add('version_list')
            if set(row) != expected:
                raise ValueError('Unexpected or missing component fields')
            if any(not isinstance(row[key], str) or not row[key].strip() or len(row[key]) > 256
                   for key in ('component', 'version', 'release_date')):
                raise ValueError('Require bounded nonempty metadata strings')
            if 'version_list' in expected:
                versions = row['version_list']
                if (not isinstance(versions, list) or not 1 <= len(versions) <= 1024 or
                        any(not isinstance(v, str) or not v.strip() or len(v) > 256 for v in versions)):
                    raise ValueError('Require a bounded nonempty list of version strings')
            components.append(row['component'])
        if sorted(components) != ['api', 'data']:
            raise ValueError('Require distinct api and data components')
        return payload


CONTRACTS = {
    'glygen-release-v1': ReleaseContract('glygen-release-v1', 'https://mcp.glygen.org/mcp'),
    'biomarkerkb-release-v1': ReleaseContract('biomarkerkb-release-v1', 'https://mcp.biomarkerkb.org/mcp', True),
}


def validate_observation(store, receipt, contract_id):
    """Append an offline structural assessment; never mutate receipts or admit Findings."""
    import time
    from synkrita.core import validate

    if contract_id not in CONTRACTS:
        raise ValueError('Unknown payload contract version')
    contract = CONTRACTS[contract_id]
    observed = store.get(receipt)
    source = observed['source']
    if ((observed['identity'], observed['view'], observed['operation']) !=
            (contract.identity, contract.view, contract.operation) or
            store.source(source) != (contract.identity, contract.view)):
        raise ValueError('Contract source, operation or authorized view mismatch')
    if observed['arguments'] != {} or observed.get('outer_schema_validated') is not True:
        raise ValueError('Require an outer-validated no-argument observation')
    if digest(observed['output']) != observed['output_sha256']:
        raise ValueError('Observation output checksum mismatch')
    declaration = store.get(observed['declaration'])
    if ((declaration['source'], declaration['identity'], declaration['view']) !=
            (source, contract.identity, contract.view) or
            observed['capability'] not in declaration['capabilities'] or
            observed['capability']['name'] != contract.operation):
        raise ValueError('Supporting declaration mismatch')
    validate(observed['capability'], observed['arguments'], observed['output'])
    payload = contract.validate(observed['output'])
    record = {'status': 'structure_validated', 'contract': contract_id,
        'source': source, 'identity': contract.identity, 'view': contract.view,
        'operation': contract.operation, 'observation': receipt,
        'dependencies': [receipt, observed['declaration']],
        'output_sha256': observed['output_sha256'], 'payload_sha256': digest(payload),
        'observed_at': observed['observed_at'], 'validated_at': time.time(),
        'findings_admitted': 0, 'upstream_calls': 0,
        'limitations': ['Offline structural assessment of one retained response only',
                        'Application success semantics, freshness, completeness and scientific truth unestablished',
                        'No reusable capability admitted; changes require a new current-response assessment']}
    return {**record, 'validation_receipt': store.put('payload_validation', record)}
