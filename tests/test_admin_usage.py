"""Synthetic accounting controls with the real hosted SDK and private SQLite."""
import asyncio
from contextlib import asynccontextmanager, closing
import csv
import hashlib
import io
import json
import os
import sqlite3
import time
from uuid import uuid4

import httpx
import pytest

from synkrita import usage_report
from synkrita.pilot_auth import OAuthConfig, Principal
from synkrita.pilot_cli import run
from synkrita.pilot_storage import HostedStore, database_status
from synkrita.pilot_usage import UsageLedger, utc_ms
from synkrita.remote_server import ACCESS, Limits, RemoteBoundary, create_remote_app

CONFIG = OAuthConfig('https://issuer.example.test/', 'https://pilot.example.test/mcp',
                     'https://issuer.example.test/jwks', ('fixture',))
ACCEPT = 'application/json, text/event-stream'


class Verifier:
    config = CONFIG

    async def verify(self, token):
        subjects = {'opaque-alice-token': ('alice', {ACCESS}), 'opaque-bob-token': ('bob', {ACCESS}),
                    'opaque-scope-token': ('bob', {'other'})}
        if token in subjects:
            subject, scopes = subjects[token]
            return Principal(CONFIG.issuer, subject, 'fixture', 'jti', int(time.time()) + 60, frozenset(scopes))
        return None


@asynccontextmanager
async def service(store, ledger, *, limits=Limits()):
    app = create_remote_app(store, CONFIG, Verifier(), limits=limits, usage=ledger)
    async with app.mcp.router.lifespan_context(app.mcp), httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url='https://pilot.example.test',
    ) as client:
        yield client


async def rpc(client, actor, method, *, params=None):
    request = {'jsonrpc': '2.0', 'id': 1, 'method': method}
    if params is not None:
        request['params'] = params
    return await client.post('/mcp', json=request, headers={
        'Authorization': f'Bearer opaque-{actor}-token', 'Accept': ACCEPT,
        'MCP-Protocol-Version': '2025-11-25',
    })


def read_params(investigation):
    return {'name': 'read_investigation', 'arguments': {'investigation_id': investigation}}


def test_synthetic_mix_reconciles_http_messages_tools_and_outcomes(tmp_path, monkeypatch, capsys):
    database = tmp_path / 'hosted.sqlite'
    with closing(HostedStore(database)) as store:
        alice = store.enroll(CONFIG.issuer, 'alice')
        bob = store.enroll(CONFIG.issuer, 'bob')
        mine = store.create_private(alice, 'PRIVATE_MARKER_QUESTION', 'PRIVATE_MARKER_NOTES')
        foreign = store.create_private(bob, 'Other fixture', 'Other notes')

        def failing_read(*_):
            raise sqlite3.OperationalError('PRIVATE_MARKER_DB_DETAIL')

        async def mix(ledger):
            async with service(store, ledger, limits=Limits(requests_per_account=5)) as client:
                assert (await client.get('/.well-known/oauth-protected-resource/mcp')).status_code == 200
                assert (await rpc(client, 'invalid', 'tools/list')).status_code == 401
                assert (await rpc(client, 'alice', 'tools/list')).status_code == 200
                own = await rpc(client, 'alice', 'tools/call', params=read_params(mine))
                assert own.json()['result']['structuredContent']['question'] == 'PRIVATE_MARKER_QUESTION'
                denial = await rpc(client, 'alice', 'tools/call', params=read_params(foreign))
                assert denial.json()['result']['structuredContent']['status'] == 'unavailable'
                assert (await rpc(client, 'alice', 'tools/call', params=read_params('BAD_PRIVATE_ARG'))).status_code == 400
                with monkeypatch.context() as patch:
                    patch.setattr(store, 'private', failing_read)
                    failure = await rpc(client, 'alice', 'tools/call', params=read_params(mine))
                    assert failure.json()['result']['structuredContent']['status'] == 'temporarily_unavailable'
                for _ in range(2):
                    throttle = await rpc(client, 'alice', 'tools/list')
                    assert throttle.status_code == 429 and int(throttle.headers['retry-after']) > 0
                assert (await rpc(client, 'scope', 'tools/list')).status_code == 403
                assert (await rpc(client, 'bob', 'tools/call', params=read_params(foreign))).status_code == 200
            return len(own.request.content), len(own.content)

        with UsageLedger(database) as ledger:
            sent, received = asyncio.run(mix(ledger))
            rows = store.db.execute(
                '''SELECT request_id, account, operation, outcome, http_status, mcp_message, tool_executed,
                   request_bytes,response_bytes FROM hosted_usage ORDER BY id''',
            ).fetchall()
            assert len(rows) == len({row[0] for row in rows}) == 9
            assert rows[1][2:] == ('read_investigation', 'completed', 200, 1, 1, sent, received)
            assert [row[3:7] for row in rows] == [
                ('completed', 200, 1, 0), ('completed', 200, 1, 1), ('tool_unavailable', 200, 1, 1),
                ('rejected', 400, 1, 0), ('tool_error', 200, 1, 1), ('rejected', 429, 0, 0),
                ('rejected', 429, 0, 0), ('rejected', 403, 0, 0), ('completed', 200, 1, 1),
            ]
            assert [row[7] for row in rows[5:8]] == [None, None, None]
            assert {row[1] for row in rows} == {alice, bob}
            assert store.db.execute(
                "SELECT count(*) FROM hosted_audit WHERE action='http_reject' AND outcome='account_limit'",
            ).fetchone() == (1,)
            assert store.db.execute(
                "SELECT count(*) FROM hosted_audit WHERE request_id=? AND action='investigation_read'", (rows[1][0],),
            ).fetchone() == (1,)
        store.disable_account(alice)
    # A fresh process would use the same read-only path after restart.
    with closing(HostedStore(database)), UsageLedger(database):
        assert database_status(database)['usage_head'] == 9
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        report = usage_report.usage_report(database, window='1h', sort='requests')
        expected = {'requests': 9, 'mcp_messages': 6, 'tool_calls': 5, 'tool_executions': 4,
                    'failed': 2, 'rejected': 4}
        assert {key: report['totals'][key] for key in expected} == expected
        assert report['http_statuses'] == {200: 5, 400: 1, 403: 1, 429: 2}
        assert [(row['account'], row['status']) for row in report['accounts']] == [
            (alice, 'suspended'), (bob, 'enabled')]
        assert report['accounts'][0]['last_activity_utc'].endswith('+00:00')
        from argparse import ArgumentParser
        from synkrita.pilot_cli import add_parser
        parser = ArgumentParser()
        add_parser(parser.add_subparsers(required=True))
        run(parser.parse_args(['remote-mcp', 'usage', '--database', str(database), '--format', 'csv']), parser)
        output = capsys.readouterr().out
        exported = list(csv.DictReader(io.StringIO(output)))
        assert exported[0]['section'] == 'summary' and exported[0]['requests'] == '9'
        assert {item['account'] for item in exported if item['section'] == 'account'} == {alice, bob}
        for marker in ('PRIVATE_MARKER', 'BAD_PRIVATE_ARG', 'opaque-alice-token', mine, foreign, 'pilot.example'):
            assert marker not in output and marker not in repr(rows)
        assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def insert(ledger, account, at, elapsed):
    asyncio.run(ledger.complete((at, account, uuid4().hex, 'ping', 'completed', 200, 1, 0, elapsed, 8, 4)))


def test_windows_sort_bounds_and_interrupted_worker(tmp_path, monkeypatch):
    path = tmp_path / 'history.sqlite'
    now = utc_ms()
    with closing(HostedStore(path)) as store:
        first = store.enroll(CONFIG.issuer, 'first')
        second = store.enroll(CONFIG.issuer, 'second')
        store.db.execute('INSERT INTO hosted_usage_runs(started_ms) VALUES (?)', (now - 8 * 86400_000,))
        store.db.commit()
        with UsageLedger(path) as ledger:
            insert(ledger, first, now - 1, 10)
            insert(ledger, first, now - 3600_000, 10)
            insert(ledger, second, now - 2, 100)
            insert(ledger, second, now - 7200_000, 50)
            insert(ledger, first, now - 2 * 86400_000, 5)
            insert(ledger, first, now - 8 * 86400_000, 5)
            insert(ledger, first, now + 100, 5)
            for window, total in [('1h', 3), ('24h', 4), ('7d', 5)]:
                report = usage_report.usage_report(path, window=window, sort='duration', now=now)
                assert report['totals']['requests'] == total
                assert report['accounts'][0]['account'] == second
                assert any('interrupted' in gap for gap in report['gaps'])
            monkeypatch.setattr(usage_report, 'ROW_LIMIT', 2)
            report = usage_report.usage_report(path, window='1h', sort='requests', now=now)
            assert report['totals']['requests'] == 2 and any('limited' in gap for gap in report['gaps'])
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match='private'):
        usage_report.usage_report(path, window='1h', sort='requests')
    os.chmod(path, 0o600)


def test_lost_write_preserves_throttle_and_surfaces_gap(tmp_path, caplog):
    database = tmp_path / 'hosted.sqlite'
    with closing(HostedStore(database)) as store, UsageLedger(database) as ledger:
        store.enroll(CONFIG.issuer, 'alice')

        async def scenario():
            async with service(store, ledger, limits=Limits(requests_per_account=1)) as client:
                assert (await rpc(client, 'alice', 'tools/list')).status_code == 200
                assert (await rpc(client, 'alice', 'tools/list')).status_code == 429
                with closing(sqlite3.connect(database)) as locker, locker:
                    locker.execute('BEGIN IMMEDIATE')
                    # Repeat throttle skips sampled security audit. Accounting uses
                    # its own short transaction and must leave the response alone.
                    assert (await rpc(client, 'alice', 'tools/list')).status_code == 429
                    assert ledger.lost == 1
                assert (await rpc(client, 'alice', 'tools/list')).status_code == 429

        asyncio.run(scenario())
        report = usage_report.usage_report(database, window='1h', sort='requests')
        assert report['totals']['requests'] == 3
        assert any('1 recorded write loss' in gap for gap in report['gaps'])
        assert database_status(database)['usage_run_recorded_losses'] == 1
        assert '"state":"open"' in caplog.text and '"state":"recording_resumed"' in caplog.text


def test_partial_asgi_response_and_rpc_error(tmp_path):
    db = tmp_path / 'hosted.sqlite'
    with closing(HostedStore(db)) as store, UsageLedger(db) as ledger:
        store.enroll(CONFIG.issuer, 'alice')

        async def downstream(scope, receive, send):
            await receive()
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            if partial:
                await send({'type': 'http.response.body', 'body': b'private fragment', 'more_body': True})
                raise OSError('synthetic send interruption')
            await send({'type': 'http.response.body', 'body': b'{"error":{"message":"private"}}'})

        async def exercise():
            adapter = RemoteBoundary(downstream, store, CONFIG, Verifier(), Limits(), ledger)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=adapter), base_url='https://pilot.example.test') as client:
                if not partial:
                    assert (await rpc(client, 'alice', 'ping')).status_code == 200
                else:
                    with pytest.raises(OSError):
                        await rpc(client, 'alice', 'ping')

        partial = False
        asyncio.run(exercise())
        partial = True
        asyncio.run(exercise())
        outcome = store.db.execute('SELECT outcome,http_status,response_bytes FROM hosted_usage ORDER BY id').fetchall()
        assert outcome == [('rpc_error', 200, len(b'{"error":{"message":"private"}}')),
                           ('incomplete', 200, None)]


def test_old_database_is_read_only_until_service_opens_it(tmp_path):
    path = tmp_path / 'old.sqlite'
    with closing(HostedStore(path)) as store:
        account = store.enroll(CONFIG.issuer, 'alice')
        own = store.create_private(account, 'synthetic question', 'synthetic notes')
        with store.db:
            store.db.execute('DROP TABLE hosted_usage')
            store.db.execute('DROP TABLE hosted_usage_runs')

    before = path.read_bytes()
    report = usage_report.usage_report(path, window='7d', sort='requests')
    assert report['totals']['requests'] == 0
    assert 'schema unavailable' in report['gaps'][0]
    assert path.read_bytes() == before

    with closing(HostedStore(path)) as store, UsageLedger(path):
        assert store.private(account, own)['status'] == 'available'
        assert database_status(path)['usage_head'] == 0
        assert database_status(path)['usage_worker_started_ms'] is not None


def test_concurrent_completions_share_commit_even_when_waiter_is_cancelled(tmp_path):
    path = tmp_path / 'batched.sqlite'
    with closing(HostedStore(path)) as store, UsageLedger(path) as ledger:
        account = store.enroll(CONFIG.issuer, 'alice')
        statements = []
        ledger.db.set_trace_callback(statements.append)

        async def scenario():
            tasks = [asyncio.create_task(ledger.complete(
                (utc_ms(), account, uuid4().hex, 'ping', 'completed', 200, 1, 0, 10, 8, 4),
            )) for _ in range(7)]
            await asyncio.sleep(0)
            tasks[0].cancel()
            await asyncio.gather(*tasks[1:])
            with pytest.raises(asyncio.CancelledError):
                await tasks[0]

        asyncio.run(scenario())
        assert store.db.execute('SELECT count(*) FROM hosted_usage').fetchone() == (7,)
        assert statements.count('COMMIT') == 1


def test_serve_entry_point_enables_accounting(tmp_path, monkeypatch):
    from synkrita import pilot_cli

    path = tmp_path / 'serve.sqlite'
    with closing(HostedStore(path)) as store:
        store.enroll(CONFIG.issuer, 'alice')

    def local_server(app, port):
        class Server:
            started = True

            async def serve(self):
                async with app.mcp.router.lifespan_context(app.mcp), httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url='https://pilot.example.test',
                ) as client:
                    assert (await rpc(client, 'alice', 'ping')).status_code == 200
        return Server()

    monkeypatch.setattr(pilot_cli, 'http_server', local_server)
    monkeypatch.setattr(pilot_cli, 'AccessVerifier', lambda *_: Verifier())
    asyncio.run(pilot_cli.serve(path, CONFIG, 8765))
    status = database_status(path)
    assert status['usage_head'] == 1
    assert status['usage_worker_ended_ms'] is not None


def test_usage_run_is_checkpointed_before_asgi_shutdown_ack(tmp_path):
    path = tmp_path / 'lifespan.sqlite'
    with closing(HostedStore(path)) as store, UsageLedger(path) as ledger:
        app = create_remote_app(store, CONFIG, Verifier(), usage=ledger)
        messages = iter([{'type': 'lifespan.startup'}, {'type': 'lifespan.shutdown'}])
        events = []

        async def receive():
            return next(messages)

        async def send(message):
            events.append(message['type'])
            if message['type'] == 'lifespan.shutdown.complete':
                assert database_status(path)['usage_worker_ended_ms'] is not None

        asyncio.run(app({'type': 'lifespan', 'state': {}}, receive, send))
        assert events == ['lifespan.startup.complete', 'lifespan.shutdown.complete']
        ended = database_status(path)['usage_worker_ended_ms']

    assert database_status(path)['usage_worker_ended_ms'] == ended
