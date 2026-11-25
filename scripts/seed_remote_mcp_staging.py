"""Create an isolated synthetic catalogue for the two hosted MCP smoke tests."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from synkrita.models import canonical, digest
from synkrita.pilot_cli import read_object
from synkrita.pilot_storage import EVIDENCE_ERRORS, HostedStore, private_directory


def populate(store, issuer, subjects):
    participants = {}
    for host, subject in subjects.items():
        account = store.enroll(issuer, subject)
        investigation = store.create_private(
            account, f'Synthetic {host} question', f'Synthetic {host} private marker',
        )
        participants[host] = {'account': account, 'investigation_id': investigation}

    source = 'https://synkrita-staging-source.example.invalid/mcp'
    scope = {'kind': 'synthetic_reference'}
    uses = ['trace_reference']
    now = int(time.time())
    expires = now + 86400
    capability = {
        'name': 'lookup', 'input_schema': {'type': 'object'},
        'output_schema': {'type': 'object', 'required': ['record']},
    }
    store.authorize_source('synthetic_staging', source)
    policy = store.add_source_policy(
        identity=source, operation='lookup', contract_sha=digest(capability),
        license='Synthetic staging fixture, redistribution permitted', retain_until=expires,
        projection={'id': {'path': '/output/record/id', 'type': 'identifier'},
                    'value': {'path': '/output/record/value', 'type': 'number'}},
    )
    receipt = store.retain_public({
        'identity': source, 'view': 'public', 'observed_at': now, 'arguments': {},
        'capability': capability, 'output': {'record': {'id': 'STAGING_CONTROL_001', 'value': 21}},
    }, policy)
    references = {'source': store.public(receipt)['evidence']['reference']}
    candidate, checksum = store.propose(
        statement='Synthetic staging reference mapping', scope=scope, allowed_uses=uses,
        semantics={'source': 'synthetic-staging-v1'}, references=references,
        expires_at=expires, max_evidence_age=86400,
    )
    # This key attests only the fixture. Real reviews require an independent reviewer.
    key = Ed25519PrivateKey.generate()
    reviewer = store.add_reviewer(key.public_key().public_bytes_raw().hex(), scope, uses)
    attestation = {
        'purpose': 'synkrita-hosted-approval-v1', 'reviewer': reviewer, 'candidate': candidate,
        'candidate_sha256': checksum, 'verdict': 'approve', 'basis': 'Synthetic staging fixture',
        'reviewed_at': time.time(), 'use': uses[0],
    }
    decision = store.activate(attestation, key.sign(canonical(attestation).encode()).hex(), references)
    if store.public(receipt)['status'] != 'available' or store.qualified(decision)['status'] != 'available':
        raise ValueError('Synthetic catalogue did not qualify')
    return {'receipt': receipt, 'decision_id': decision, 'policy': policy, 'reviewer': reviewer,
            'candidate': candidate, 'missing_id': uuid4().hex, 'expires_at': expires, **participants}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path, help='Path to a new database')
    parser.add_argument('--input', default='-', help='Private JSON with issuer, chatgpt_sub and claude_sub')
    args = parser.parse_args()
    try:
        values = read_object(args.input, 8192)
        if set(values) != {'issuer', 'chatgpt_sub', 'claude_sub'} or values['chatgpt_sub'] == values['claude_sub']:
            raise ValueError('Expected two distinct staging subjects')
        private_directory(args.database)
        # Exclusive creation prevents touching an existing catalogue, including on concurrent runs.
        os.close(os.open(args.database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        with closing(HostedStore(args.database)) as store:
            manifest = populate(store, values['issuer'],
                                {'chatgpt': values['chatgpt_sub'], 'claude': values['claude_sub']})
    except (*EVIDENCE_ERRORS, OSError) as error:
        parser.exit(1, f'Staging fixture failed ({type(error).__name__}). Use a fresh path for a retry.\n')
    json.dump(manifest, sys.stdout, indent=2)
    print()


if __name__ == '__main__':
    main()
