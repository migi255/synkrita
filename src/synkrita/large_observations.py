"""Offline GlyGen publication extraction, not a larger live MCP permission."""
import base64
from copy import deepcopy
import hashlib
import math

from synkrita.core import validate
from synkrita.models import canonical, digest
from synkrita.payloads import strict_json
from synkrita.privacy import retention_safe

PROFILE = 'glygen-publications-excerpt-v1'
ENDPOINT = 'https://mcp.glygen.org/mcp'
OPERATION = 'get_protein_publications'
MAX_RAW = 1048576
MAX_INNER = 524288
MAX_RECORDS = 512
MAX_RECORD = 16384
MAX_DEPTH = 24
MAX_NODES = 50000

STRING = {'type': 'string', 'minLength': 1, 'maxLength': 8192, 'pattern': r'\S'}
LINK = {'type': 'object', 'required': ['database', 'id', 'url'],
        'properties': {key: STRING for key in ('database', 'id', 'url')}, 'additionalProperties': False}
REF = {'type': 'object', 'required': ['type', 'id', 'url'], 'properties': {
    'type': {'const': 'PubMed'}, 'id': {'type': 'string', 'pattern': r'^[1-9][0-9]{0,11}$'},
    'url': STRING}, 'additionalProperties': False}
ROW_SCHEMA = {'type': 'object', 'required': ['title', 'journal', 'date', 'authors', 'evidence', 'reference'],
    'properties': {**{k: STRING for k in ('title', 'journal', 'date', 'authors')},
        'evidence': {'type': 'array', 'minItems': 1, 'maxItems': 128, 'items': LINK},
        'reference': {'type': 'array', 'minItems': 1, 'maxItems': 1, 'items': REF}},
    'additionalProperties': False}
CAPABILITY = {'name': OPERATION, 'input_schema': {'type': 'object',
    'properties': {'uniprot_ac': {'const': 'P01009'}}, 'required': ['uniprot_ac'],
    'additionalProperties': False}, 'output_schema': ROW_SCHEMA,
    'limitations': ['Offline extracted publication record; not original MCP output schema or callable capability']}


def bounded_json(text, maximum):
    if not isinstance(text, str) or len(text.encode('utf-8')) > maximum:
        raise ValueError('JSON byte budget exceeded')
    # Bound nesting before json.loads, including in separately decoded wrapper strings.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON nesting budget exceeded')
        elif char in ']}':
            depth -= 1
    try:
        value = strict_json(text)
    except (ValueError, RecursionError) as error:
        raise ValueError('Malformed or ambiguous JSON') from error
    pending, nodes = [(value, 0)], 0
    while pending:
        item, level = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or level > MAX_DEPTH:
            raise ValueError('JSON structure budget exceeded')
        if isinstance(item, dict):
            if len(item) > MAX_NODES:
                raise ValueError('Object budget exceeded')
            pending.extend((v, level + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, level + 1) for v in item)
        elif isinstance(item, str) and len(item) > MAX_INNER:
            raise ValueError('String budget exceeded')
    return value


def decode(raw, invocation, capability):
    """One complete UTF-8 SSE JSON-RPC result; no permissive text scraping."""
    if invocation.get('arguments') != {'uniprot_ac': 'P01009'}:
        raise ValueError('Extraction scope mismatch')
    return decode_records(raw, invocation, capability)


def decode_records(raw, invocation, capability):
    """Source-format validation only. Callers must separately establish entity scope.

    This offline parser grants no invocation permission and creates no Finding.
    The original decode entry point retains its P01009 restriction.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_RAW:
        raise ValueError('Raw response byte budget exceeded')
    args = invocation.get('arguments')
    import re
    if ((invocation.get('identity'), invocation.get('view'), invocation.get('operation')) !=
            (ENDPOINT, 'public', OPERATION) or not isinstance(args, dict) or
            set(args) != {'uniprot_ac'} or not isinstance(args['uniprot_ac'], str) or
            not re.fullmatch(r'[A-Z0-9]{6}(?:[A-Z0-9]{4})?', args['uniprot_ac'])):
        raise ValueError('Extraction scope mismatch')
    timestamp = invocation.get('observed_at')
    if type(timestamp) not in (float, int) or not math.isfinite(timestamp):
        raise ValueError('Missing retrieval time')
    if capability.get('name') != OPERATION:
        raise ValueError('Declaration operation mismatch')
    try:
        text = raw.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('Invalid UTF-8') from error
    # Exact captured SSE profile: one event, exactly one data line, optional event name.
    if not text.replace('\r\n', '\n').endswith('\n\n'):
        raise ValueError('Truncated SSE event')
    lines = text.replace('\r\n', '\n').strip().split('\n')
    if (sum(line.startswith('data:') for line in lines) != 1 or
            any(not (line.startswith('data:') or line == 'event: message') for line in lines)):
        raise ValueError('Unsupported or ambiguous SSE envelope')
    envelope = bounded_json(next(line[5:].strip() for line in lines if line.startswith('data:')), MAX_RAW)
    if (not isinstance(envelope, dict) or set(envelope) != {'jsonrpc', 'id', 'result'} or
            envelope['jsonrpc'] != '2.0' or type(envelope['id']) not in (str, int) or
            envelope['id'] != invocation.get('rpc_id')):
        raise ValueError('RPC response identity mismatch')
    result = envelope['result']
    if (not isinstance(result, dict) or result.get('isError') is not False or
            set(result) - {'_meta', 'content', 'structuredContent', 'isError'}):
        raise ValueError('Unsupported or failed MCP result')
    wrapper = result.get('structuredContent')
    if not isinstance(wrapper, dict) or set(wrapper) != {'result'}:
        raise ValueError('Require structured string wrapper')
    validate(capability, invocation['arguments'], wrapper)
    blocks = result.get('content')
    if (not isinstance(blocks, list) or len(blocks) != 1 or blocks[0].get('type') != 'text' or
            blocks[0].get('text') != wrapper['result']):
        raise ValueError('Conflicting text and structured response')
    payload = bounded_json(wrapper['result'], MAX_INNER)
    if not isinstance(payload, dict) or set(payload) != {'publication'}:
        raise ValueError('Unsupported publication envelope')
    rows = payload['publication']
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RECORDS:
        raise ValueError('Publication count budget exceeded')
    seen = set()
    for index, row in enumerate(rows):
        try:
            if len(canonical(row).encode()) > MAX_RECORD:
                raise ValueError('Individual record byte budget exceeded')
            validate({**CAPABILITY, 'input_schema': capability['input_schema']}, invocation['arguments'], row)
            retention_safe(row)
            pmid = row['reference'][0]['id']
            if pmid in seen:
                raise ValueError('Duplicate publication identifier')
            seen.add(pmid)
        except Exception as error:
            raise ValueError(f'Record {index} rejected: {type(error).__name__}: {error}') from error
    return rows


def put_once(store, kind, body):
    # Existing generic store, no migration/index; trusted single-process contract.
    rows = store.db.execute('SELECT id FROM records WHERE kind=? AND sha=?', (kind, digest(body))).fetchall()
    if rows:
        identifier = rows[0][0]
        if store.get(identifier) != body:
            raise ValueError('Existing record mismatch')
        return identifier
    return store.put(kind, body)


def ingest(store, raw, invocation, capability, expected_sha256):
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('Raw response checksum mismatch')
    if store.source('glygen') != (ENDPOINT, 'public'):
        raise ValueError('Active source scope required')
    rows = decode(raw, invocation, capability)  # All-or-nothing structural admission.
    artifact = {**deepcopy(invocation), 'profile': PROFILE, 'encoding': 'base64',
        'raw_base64': base64.b64encode(raw).decode('ascii'), 'raw_sha256': expected_sha256,
        'raw_bytes': len(raw), 'capability': deepcopy(capability)}
    artifact_id = put_once(store, 'raw_response_artifact', artifact)
    observations = []
    for index, row in enumerate(rows):
        observation = {**{k: deepcopy(invocation[k]) for k in
            ('identity', 'view', 'operation', 'arguments', 'rpc_id', 'observed_at')},
            'capability': CAPABILITY,
            'interface': 'offline-extraction:' + PROFILE, 'output': row,
            'extraction': {'profile': PROFILE, 'artifact': artifact_id,
                'outer_pointer': '/result/structuredContent/result',
                'decoded_pointer': f'/publication/{index}', 'index': index,
                'publication_id': row['reference'][0]['id']},
            'dependencies': [artifact_id], 'status': 'structure_validated_source_report',
            'scientific_truth_established': False, 'findings_admitted': 0}
        observations.append(put_once(store, 'extracted_observation', observation))
    return {'profile': PROFILE, 'artifact': artifact_id, 'observations': observations,
        'admitted': len(observations), 'rejected': 0, 'findings_admitted': 0, 'network_requests': 0}


def verify_extracted(store, receipt, *, view='public'):
    origin = receipt['extraction']
    if (origin.get('profile') != PROFILE or view != 'public' or
            receipt.get('capability') != CAPABILITY or receipt.get('dependencies') != [origin['artifact']]):
        raise ValueError('Unsupported extraction provenance')
    artifact = store.get_visible(origin['artifact'], view=view)
    encoded = artifact.get('raw_base64', '')
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_RAW + 2) // 3):
        raise ValueError('Raw artifact budget exceeded')
    raw = base64.b64decode(encoded, validate=True)
    if (len(raw) != artifact['raw_bytes'] or hashlib.sha256(raw).hexdigest() != artifact['raw_sha256'] or
            artifact.get('profile') != PROFILE):
        raise ValueError('Raw artifact checksum mismatch')
    if any(receipt.get(k) != artifact.get(k) for k in
           ('identity', 'view', 'operation', 'arguments', 'observed_at', 'rpc_id')):
        raise ValueError('Extraction invocation mismatch')
    from synkrita.validation_reuse import checked_artifact
    rows = checked_artifact(store, PROFILE, artifact, lambda: decode(raw, artifact, artifact['capability']))
    index = origin.get('index')
    if (type(index) is not int or not 0 <= index < len(rows) or
            origin.get('decoded_pointer') != f'/publication/{index}' or
            origin.get('outer_pointer') != '/result/structuredContent/result' or
            rows[index] != receipt['output'] or
            origin.get('publication_id') != rows[index]['reference'][0]['id']):
        raise ValueError('Extracted record does not match original evidence')
    return {**origin, 'raw_sha256': artifact['raw_sha256'], 'raw_bytes': len(raw),
        'representation': 'extracted_record_verified_against_complete_raw_SSE',
        'original_capability': artifact['capability']}
