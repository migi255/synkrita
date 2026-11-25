"""Protocol observations stay separate from data-contract and scientific qualification."""
from dataclasses import asdict
import time

from synkrita.core import schema_validator, validate
from synkrita.models import digest
from synkrita.privacy import retention_safe
from synkrita.payloads import strict_json


def wrapped_text_schema(schema):
    properties = schema.get('properties', {})
    return set(properties) == {'result'} and properties['result'].get('type') == 'string'


def inspect_payload(output):
    """Inspect one explicit wrapper; decoding is syntax inspection, not admission."""
    inspected = {'data_contract': 'unqualified', 'application_status': 'unestablished'}
    if isinstance(output, dict) and set(output) == {'result'} and isinstance(output['result'], str):
        inspected['format'] = 'wrapped_text'
        try:
            decoded = strict_json(output['result'])
        except (ValueError, RecursionError):
            inspected['json_syntax'] = 'invalid_or_non_json'
        else:
            retention_safe(decoded)
            inspected.update(json_syntax='valid', decoded_payload=decoded)
            if isinstance(decoded, dict) and any(decoded.get(key) for key in ('error', 'errors')):
                inspected['application_status'] = 'possible_error'
    else:
        retention_safe(output)
        inspected['format'] = 'structured'
    return inspected


async def observe_adapter(store, name, adapter, operation, arguments, *, protocol_version=None):
    """Invoke once and retain an outer-schema-checked observation, never a Finding."""
    if operation not in adapter.allowed_operations:
        raise ValueError('Operation is not explicitly permitted for this source')
    if store.source(name) != (adapter.identity, adapter.view):
        raise ValueError('Source identity or authorized view mismatch')
    retention_safe(arguments)
    revision = await adapter.revision()
    capabilities = await adapter.discover()
    matches = [asdict(cap) for cap in capabilities if cap.name == operation]
    if len(matches) != 1:
        raise ValueError('Capability missing or ambiguous')
    capability = matches[0]
    schema_validator(capability['input_schema']).validate(arguments)
    output = await adapter.invoke(operation, arguments)
    validate(capability, arguments, output)
    inspection = inspect_payload(output)
    after = await adapter.revision()
    if after != revision:
        raise ValueError('Source conditions changed during observation')
    declaration = store.put('declaration', {'source': name, 'identity': adapter.identity,
        'view': adapter.view, 'capabilities': [asdict(cap) for cap in capabilities],
        'observed_at': time.time(), 'protocol_version': protocol_version})
    record = {'source': name, 'identity': adapter.identity, 'view': adapter.view,
        'operation': operation, 'capability': capability, 'arguments': arguments,
        'output': output, 'output_sha256': digest(output), 'payload_inspection': inspection,
        'interface': revision['interface'], 'data_indicator': revision.get('data'),
        'declaration': declaration, 'protocol_version': protocol_version,
        'observed_at': time.time(), 'outer_schema_validated': True,
        'data_contract_qualified': False, 'scientific_interpretation_qualified': False}
    receipt = store.put('protocol_observation', record)
    return {'status': 'observed_protocol', 'source': name, 'operation': operation,
        'receipt': receipt, 'declaration': declaration, 'payload_inspection': inspection,
        'findings_admitted': 0,
        'limitations': ['Outer MCP response schema checked; inner data contract remains unqualified',
                        'No scientific meaning, completeness, absence or freshness conclusion established']}
