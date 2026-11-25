"""Scope-separated offline publication processing; no network or semantic transfer."""
import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import time

from synkrita.core import validate
from synkrita.large_observations import (
    ENDPOINT, OPERATION, MAX_RAW, ROW_SCHEMA, bounded_json, decode, decode_records, put_once,
)

PROFILE = 'glygen-publications-identity-bound-v2-experiment'


def unpack(artifact):
    encoded = artifact['raw_base64']
    if len(encoded) > 4 * ((MAX_RAW + 2) // 3):
        raise ValueError('Artifact exceeds byte budget')
    raw = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(raw).hexdigest() != artifact['raw_sha256']:
        raise ValueError('Raw artifact checksum mismatch')
    return raw


def identity_fields(raw, metadata):
    if (metadata.get('status') != 200 or metadata.get('complete') is not True or
            metadata.get('requests') != 1 or metadata.get('method') != 'GET' or metadata.get('parameters') != {} or
            metadata.get('redirects') is not False or metadata.get('retries') != 0 or
            hashlib.sha256(raw).hexdigest() != metadata.get('sha256') or len(raw) != metadata.get('bytes')):
        raise ValueError('Identity capture status/checksum mismatch')
    data = bounded_json(raw.decode('utf-8'), MAX_RAW)
    accession = data['primaryAccession']
    if (metadata['endpoint'] != f'https://rest.uniprot.org/uniprotkb/{accession}.json' or
            data['organism']['taxonId'] != 9606):
        raise ValueError('Identity source or species scope mismatch')
    return {'accession': accession, 'taxon': data['organism']['taxonId'],
        'protein_name': data['proteinDescription']['recommendedName']['fullName']['value'],
        'genes': data.get('genes', []), 'entry_version': data.get('entryAudit', {}).get('entryVersion')}


def admit_identity(store, raw, metadata):
    fields = identity_fields(raw, metadata)
    endpoint = metadata['endpoint']
    store.register('target-uniprot-identity', endpoint)
    parent = put_once(store, 'raw_response_artifact', {'identity': endpoint, 'view': 'public',
        'profile': 'uniprot-human-identity-v1', 'raw_base64': base64.b64encode(raw).decode(),
        'raw_sha256': metadata['sha256'], 'metadata': metadata})
    capability = {'name': 'uniprot_identity', 'input_schema': {'const': {}},
        'output_schema': {'type': 'object', 'required': ['accession', 'taxon', 'protein_name']}}
    return put_once(store, 'identity_observation', {'identity': endpoint, 'view': 'public',
        'arguments': {}, 'capability': capability, 'output': fields,
        'observed_at': datetime.fromisoformat(metadata['completed_at']).timestamp(),
        'identity_artifact': parent, 'dependencies': [parent], 'findings_admitted': 0})


def check_identity(store, identifier, arguments):
    observed = store.get_visible(identifier)
    parent = store.get_visible(observed['identity_artifact'])
    if parent.get('profile') != 'uniprot-human-identity-v1':
        raise ValueError('Unsupported identity profile')
    fields = identity_fields(unpack(parent), parent['metadata'])
    if (fields != observed['output'] or observed['identity'] != parent['identity'] or
            observed['dependencies'] != [observed['identity_artifact']] or
            observed['observed_at'] != datetime.fromisoformat(parent['metadata']['completed_at']).timestamp() or
            arguments != {'uniprot_ac': fields['accession']}):
        raise ValueError('Identity evidence does not match publication query')
    return fields


def publication_capability(arguments):
    return {'name': OPERATION, 'input_schema': {'const': arguments},
        'output_schema': ROW_SCHEMA, 'limitations': ['Identity-bound historical extraction, no live capability admission']}


def ingest_target(store, raw, invocation, capability, expected_sha, identity_id):
    check_identity(store, identity_id, invocation['arguments'])
    if store.source('glygen') != (ENDPOINT, 'public') or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('Source scope or response checksum mismatch')
    rows = decode_records(raw, invocation, capability)
    artifact = {**invocation, 'identity': ENDPOINT, 'view': 'public', 'profile': PROFILE,
        'raw_base64': base64.b64encode(raw).decode(), 'raw_sha256': expected_sha,
        'capability': capability, 'identity_evidence': identity_id}
    parent = put_once(store, 'raw_response_artifact', artifact)
    derived = publication_capability(invocation['arguments'])
    result = []
    for index, row in enumerate(rows):
        receipt = {k: deepcopy(invocation[k]) for k in
                   ('identity', 'view', 'operation', 'arguments', 'observed_at', 'rpc_id')}
        receipt.update(output=row, capability=derived, interface=PROFILE,
            entity_extraction={'profile': PROFILE, 'artifact': parent, 'index': index,
                'pmid': row['reference'][0]['id'], 'identity_evidence': identity_id},
            dependencies=[parent, identity_id], findings_admitted=0)
        result.append(put_once(store, 'extracted_observation', receipt))
    return result


def verify(store, receipt, view):
    origin = receipt['entity_extraction']
    if view != 'public' or origin.get('profile') != PROFILE:
        raise ValueError('Unsupported entity extraction')
    artifact = store.get_visible(origin['artifact'], view=view)
    if (artifact['profile'] != PROFILE or artifact['identity_evidence'] != origin['identity_evidence'] or
            receipt['capability'] != publication_capability(artifact['arguments'])):
        raise ValueError('Extraction scope evidence mismatch')
    check_identity(store, origin['identity_evidence'], artifact['arguments'])
    raw = unpack(artifact)  # Always recheck bytes before consulting pure-validation reuse.
    from synkrita.validation_reuse import checked_artifact
    rows = checked_artifact(store, PROFILE, artifact, lambda: decode_records(raw, artifact, artifact['capability']))
    index = origin['index']
    if (type(index) is not int or not 0 <= index < len(rows) or rows[index] != receipt['output'] or
            rows[index]['reference'][0]['id'] != origin['pmid'] or
            receipt['dependencies'] != [origin['artifact'], origin['identity_evidence']] or
            any(receipt[k] != artifact[k] for k in
                ('identity', 'view', 'operation', 'arguments', 'observed_at', 'rpc_id'))):
        raise ValueError('Extracted record or invocation differs from original evidence')
    validate(receipt['capability'], receipt['arguments'], receipt['output'])
    return {**origin, 'raw_sha256': artifact['raw_sha256'],
        'outer_pointer': '/result/structuredContent/result', 'decoded_pointer': f'/publication/{index}',
        'representation': 'Identity-bound source record; not scientific equivalence or claim support',
        'original_capability': artifact['capability']}
