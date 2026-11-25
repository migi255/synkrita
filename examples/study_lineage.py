"""Read an operator-approved assay-to-aliquot linkage using synthetic MCP evidence."""

import asyncio
from contextlib import closing
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from typing import TypedDict
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from synkrita.claims import resolve_evidence
from synkrita.models import canonical, digest
from synkrita.pilot_auth import AccessVerifier, OAuthConfig
from synkrita.pilot_storage import HostedStore
from synkrita.remote import RemoteSource, investigate_remote
from synkrita.remote_server import ACCESS, create_remote_app
from synkrita.store import Store


SOURCE = 'https://study.example.test/mcp'
CONFIG = OAuthConfig('https://issuer.example.test/', 'https://research.example.test/mcp',
                     'https://issuer.example.test/jwks', ('lineage-demo',))
SPECIMEN = 'SPECIMEN_001'
ASSAY = 'ASSAY_001'
ALIQUOT = 'ALIQUOT_001'
RELEASE = 'v1'
USE = 'trace_sample_lineage'


class LineageRecord(TypedDict):
    record_id: str
    aliquot_id: str
    release: str
    catalogue_note: str


async def collect(database):
    """Use the real collector against a deterministic, explicitly granted MCP tool."""
    fixture = FastMCP('Synthetic study records', stateless_http=True, json_response=True, log_level='CRITICAL',
                      transport_security=TransportSecuritySettings(
                          allowed_hosts=['study.example.test']))
    collected_ids = []

    @fixture.tool()
    def lookup_lineage(record_id: str) -> LineageRecord:
        if record_id not in (SPECIMEN, ASSAY):
            raise ValueError('Unknown fixture record')
        collected_ids.append(record_id)
        return {'record_id': record_id, 'aliquot_id': ALIQUOT, 'release': RELEASE,
                'catalogue_note': 'Synthetic catalogue note outside the public projection'}

    app = fixture.streamable_http_app()
    source = RemoteSource(SOURCE, allowed_operations=('lookup_lineage',))
    witness = {'record_id': SPECIMEN}
    bodies = {}
    with closing(Store(database)) as store:
        async with app.router.lifespan_context(app):
            for record_id, reuse in ((SPECIMEN, False), (ASSAY, True)):
                result = await investigate_remote(
                    store, 'study_fixture', source, 'lookup_lineage', {'record_id': record_id},
                    witness, http_transport=httpx.ASGITransport(app=app),
                )
                assert result['status'] == 'observed', result
                assert result['reused'] is reuse and result['assessment']['eligible']
                receipt = result['receipts'][-1]
                bodies[record_id] = store.get(receipt)
                assert bodies[record_id]['output']['record_id'] == record_id
                print(f'Captured {record_id}: receipt={receipt} capability_finding_reused={reuse}')
    return bodies, collected_ids


def publish(store, bodies, deadline):
    """Operator registers the source, approves the projection and verifies both citations."""
    store.authorize_source('study_fixture', SOURCE)
    projection = {field: {'path': f'/output/{field}', 'type': 'identifier'}
                  for field in ('record_id', 'aliquot_id', 'release')}
    policy = store.add_source_policy(
        identity=SOURCE, operation='lookup_lineage',
        contract_sha=digest(bodies[SPECIMEN]['capability']),
        license='Synthetic example records, redistribution permitted',
        retain_until=deadline, projection=projection,
    )
    references = {}
    for role, record_id in (('specimen_record', SPECIMEN), ('assay_record', ASSAY)):
        body = bodies[record_id]
        receipt = store.retain_public(body, policy)
        published = store.public(receipt)['evidence']
        references[role] = published['reference']
        resolved = resolve_evidence(store, references[role])
        assert resolved['receipt_sha256'] == digest(body) == published['receipt_sha256']
        assert (resolved['source_identity'], resolved['method'], resolved['observed_at']) == (
            SOURCE, 'lookup_lineage', body['observed_at'])
        assert resolved['selected'] == {'record_id': record_id, 'aliquot_id': ALIQUOT, 'release': RELEASE}
        print(f'Published {role}: receipt={receipt} checksum={resolved["receipt_sha256"]}')
    return policy, references


def approve(store, candidate, checksum, scope, references):
    # The example plays both roles. A real independent reviewer holds their own key.
    key = Ed25519PrivateKey.generate()
    reviewer = store.add_reviewer(key.public_key().public_bytes_raw().hex(), scope, [USE])
    attestation = {
        'purpose': 'synkrita-hosted-approval-v1', 'reviewer': reviewer, 'candidate': candidate,
        'candidate_sha256': checksum, 'verdict': 'approve', 'use': USE,
        'basis': 'Both cited fixture records report the same aliquot within this release.',
        'reviewed_at': time.time(),
    }
    decision = store.activate(attestation, key.sign(canonical(attestation).encode()).hex(), references)
    print(f'Activated {decision}: use={USE}')
    return decision


def token(key, subject):
    now = int(time.time())
    return jwt.encode({
        'iss': CONFIG.issuer, 'aud': CONFIG.resource, 'sub': subject, 'iat': now,
        'exp': now + 300, 'client_id': CONFIG.clients[0], 'jti': uuid4().hex, 'scope': ACCESS,
    }, key, algorithm='RS256', headers={'typ': 'at+jwt', 'kid': 'fixture-key'})


async def rpc(client, method, **params):
    request = {'jsonrpc': '2.0', 'method': method, 'params': params}
    notification = method == 'notifications/initialized'
    if not notification:
        request['id'] = 1  # Requests are sent sequentially.
    response = await client.post('/mcp', json=request)
    response.raise_for_status()
    if notification:
        assert response.status_code == 202
        return None
    return response.json()['result']


async def read(client, tool, **arguments):
    result = await rpc(client, 'tools/call', name=tool, arguments=arguments)
    assert not result.get('isError'), result
    return result['structuredContent']


async def open_session(client):
    result = await rpc(client, 'initialize', protocolVersion='2025-11-25', capabilities={},
                       clientInfo={'name': 'lineage-example', 'version': '1'})
    client.headers['MCP-Protocol-Version'] = result['protocolVersion']
    await rpc(client, 'notifications/initialized')


async def hosted_reads(store, policy, references, deadline):
    scope = {'study': 'FIXTURE_001', 'release': RELEASE}
    candidate, checksum = store.propose(
        statement='Associate ASSAY_001 with ALIQUOT_001 within fixture release v1.',
        scope=scope, allowed_uses=[USE], references=references, expires_at=deadline,
        max_evidence_age=3600, semantics={role: 'fixture-aliquot-link-v1' for role in references},
    )
    alice = store.enroll(CONFIG.issuer, 'fixture-alice')
    store.enroll(CONFIG.issuer, 'fixture-bob')
    question = 'Which aliquot did the fixture assay report?'
    investigation = store.create_private(alice, question, 'Synthetic study lineage exercise')

    # Only the issuer transport is a fixture. The hosted verifier checks real signatures and claims.
    key = generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid='fixture-key', alg='RS256', use='sig')

    def jwks(request):
        assert request.method == 'GET' and request.url == httpx.URL(CONFIG.jwks_url)
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps({'keys': [jwk]}).encode()))

    async with httpx.AsyncClient(transport=httpx.MockTransport(jwks), trust_env=False) as issuer:
        app = create_remote_app(store, CONFIG, AccessVerifier(CONFIG, issuer))

        def client_for(subject):
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=CONFIG.resource.removesuffix('/mcp'),
                headers={'Accept': 'application/json, text/event-stream',
                         'Authorization': f'Bearer {token(key, subject)}'},
                trust_env=False,
            )

        async with app.mcp.router.lifespan_context(app.mcp):
            async with client_for('fixture-alice') as first:
                await open_session(first)
                tools = {entry['name'] for entry in (await rpc(first, 'tools/list'))['tools']}
                assert tools == {'read_public_observation', 'read_qualified_decision', 'read_investigation'}
                withheld = await read(first, 'read_qualified_decision', decision_id=candidate)
                assert withheld['status'] == 'unavailable'
                decision = approve(store, candidate, checksum, scope, references)
                initial = await read(first, 'read_qualified_decision', decision_id=decision)
                assert initial['status'] == 'available' and initial['use'] == USE
                assert initial['context'] == scope and initial['evidence'] == references
                assert initial['scientific_truth_established'] is False
                own = await read(first, 'read_investigation', investigation_id=investigation)
                assert own['status'] == 'available' and own['question'] == question
                print('First session: candidate withheld, decision available, private investigation available')

            async with client_for('fixture-bob') as second:
                await open_session(second)
                reused = await read(second, 'read_qualified_decision', decision_id=decision)
                assert reused == initial
                for role, reference in reused['evidence'].items():
                    receipt = await read(second, 'read_public_observation', receipt=reference['record'])
                    assert receipt['status'] == 'available'
                    assert receipt['evidence'] == store.public(references[role]['record'])['evidence']
                foreign = await read(second, 'read_investigation', investigation_id=investigation)
                missing = await read(second, 'read_investigation', investigation_id=uuid4().hex)
                assert foreign == missing and foreign['status'] == 'unavailable'
                print('Second session: same scoped decision and both citations, private investigation withheld')
                store.withdraw_source_policy(policy)
                withdrawn = await read(second, 'read_qualified_decision', decision_id=decision)
                receipt = await read(second, 'read_public_observation', receipt=references['assay_record']['record'])
                assert withdrawn['status'] == receipt['status'] == 'unavailable'
                assert store.get(references['assay_record']['record'])['output']['record_id'] == ASSAY
                print('After policy withdrawal: observation and dependent decision withheld')


async def main():
    with TemporaryDirectory(prefix='synkrita-lineage-') as root:
        directory = Path(root)
        bodies, source_calls = await collect(directory / 'collector.sqlite')
        assert source_calls == [SPECIMEN, SPECIMEN, ASSAY]
        deadline = int(time.time()) + 3600
        with closing(HostedStore(directory / 'hosted.sqlite')) as store:
            policy, references = publish(store, bodies, deadline)
            await hosted_reads(store, policy, references, deadline)
        assert source_calls == [SPECIMEN, SPECIMEN, ASSAY]
        print('Source tool calls: 3 during collection, 0 during hosted reads')


if __name__ == '__main__':
    asyncio.run(main())
