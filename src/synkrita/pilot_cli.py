"""Loopback service entry point and service-owner-only administration."""
import asyncio
from contextlib import closing
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys

import httpx

from synkrita.large_observations import bounded_json
from synkrita.pilot_auth import AccessVerifier, OAuthConfig
from synkrita.pilot_storage import (
    EVIDENCE_ERRORS, HostedStore, audit_events, database_status, lookup_account, private_directory,
    restore_snapshot,
)

from synkrita.pilot_usage import UsageLedger
from synkrita.usage_report import SORTS, WINDOWS, usage_report, write_report


ACTIONS = {
    'enroll': HostedStore.enroll,
    'disable-account': HostedStore.disable_account,
    'enable-account': HostedStore.enable_account,
    'revoke-grant': HostedStore.revoke_grant,
    'revoke-token': HostedStore.revoke_token,
    'investigation-create': HostedStore.create_private,
    'register-source': HostedStore.authorize_source,
    'add-source-policy': HostedStore.add_source_policy,
    'withdraw-source-policy': HostedStore.withdraw_source_policy,
    'retain-public': HostedStore.retain_public,
    'publish-receipt': HostedStore.publish,
    'add-reviewer': HostedStore.add_reviewer,
    'disable-reviewer': HostedStore.disable_reviewer,
    'propose': HostedStore.propose,
    'activate': HostedStore.activate,
    'revoke-decision': HostedStore.revoke_decision,
}
READ_ACTIONS = {'lookup-account': lookup_account, 'audit-events': audit_events}


def add_parser(commands):
    pilot = commands.add_parser('remote-mcp', help='Run or administer the read-only remote MCP pilot')
    modes = pilot.add_subparsers(dest='pilot_mode', required=True)
    serve = modes.add_parser('serve', help='Run Streamable HTTP on loopback behind a trusted HTTPS ingress')
    serve.add_argument('--database', required=True, type=Path)
    serve.add_argument('--config', required=True, type=Path)
    serve.add_argument('--port', type=int, default=8765)
    init = modes.add_parser('init', help='Initialize an empty private hosted database')
    init.add_argument('--database', required=True, type=Path)
    admin = modes.add_parser('admin', help='Local actions run as the database service owner')
    admin.add_argument('--database', required=True, type=Path)
    admin.add_argument('action', choices=(*ACTIONS, *READ_ACTIONS))
    admin.add_argument('--input', default='-', help='JSON object in a private file or on stdin')
    backup = modes.add_parser('backup', help='Create a checked online SQLite snapshot')
    backup.add_argument('--database', required=True, type=Path)
    backup.add_argument('--target', required=True, type=Path)
    restore = modes.add_parser('restore', help='Validate and restore a snapshot into a new SQLite file')
    restore.add_argument('--snapshot', required=True, type=Path)
    restore.add_argument('--target', required=True, type=Path)
    status = modes.add_parser('status', help='Read hosted database status without changing it')
    status.add_argument('--database', required=True, type=Path)
    usage = modes.add_parser('usage', help='Summarize private recorded worker usage')
    usage.add_argument('--database', required=True, type=Path)
    usage.add_argument('--window', choices=WINDOWS, default='24h')
    usage.add_argument('--sort', choices=SORTS, default='requests')
    usage.add_argument('--format', choices=('terminal', 'csv'), default='terminal')
    check = modes.add_parser('check-backup', help='Verify snapshot integrity, schema and foreign keys')
    check.add_argument('--snapshot', required=True, type=Path)


def read_object(path, maximum):
    if path == '-':
        data = sys.stdin.buffer.read(maximum + 1)
    else:
        with Path(path).open('rb') as file:
            data = file.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Administrative JSON exceeds byte budget')
    value = bounded_json(data.decode('utf-8'), maximum)
    if not isinstance(value, dict):
        raise ValueError('Expected an administrative JSON object')
    return value


def http_server(app, port):
    import uvicorn

    return uvicorn.Server(uvicorn.Config(
        app, host='127.0.0.1', port=port, access_log=False, proxy_headers=False,
        server_header=False, ws='none', workers=1, limit_concurrency=96,
        timeout_keep_alive=5, timeout_graceful_shutdown=5,
    ))


async def serve(database, config, port):
    from synkrita.remote_server import create_remote_app

    if not 1024 <= port <= 65535:
        raise ValueError('Expected a non-privileged loopback port')
    logging.getLogger('mcp').setLevel(logging.CRITICAL)
    with closing(HostedStore(database)) as store, UsageLedger(database) as usage:
        async with httpx.AsyncClient(
            timeout=3, trust_env=False, follow_redirects=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
        ) as client:
            app = create_remote_app(store, config, AccessVerifier(config, client), usage=usage)
            server = http_server(app, port)
            await server.serve()
            if not server.started:
                raise RuntimeError('Service startup did not complete')


def run(args, parser):
    mode = args.pilot_mode
    hint = 'Check service ownership, private file modes and free disk space.'
    try:
        if mode == 'serve':
            hint = 'Check OAuth JSON, canonical issuer/resource, pinned JWKS, client IDs and loopback port.'
            config = OAuthConfig(**read_object(args.config, 8192))
            private_directory(args.database)
            if not args.database.is_file():
                parser.error('Hosted database is missing. For an existing deployment, follow the restore runbook.')
            hint = 'Check the database with remote-mcp status and inspect the local service journal.'
            return asyncio.run(serve(args.database, config, args.port))
        if mode == 'restore':
            hint = 'Run check-backup and choose a new target in a private directory.'
            return restore_snapshot(args.snapshot, args.target)
        if mode == 'status':
            print(json.dumps(database_status(args.database)))
            return
        if mode == 'usage':
            hint = 'Check the private database path and try a shorter window if the query is busy.'
            write_report(usage_report(args.database, window=args.window, sort=args.sort), sys.stdout,
                         output=args.format)
            return
        if mode == 'check-backup':
            hint = 'Check for a complete, decrypted, service-owned snapshot in a private directory.'
            print(json.dumps(database_status(args.snapshot, snapshot=True)))
            return
        if mode == 'init':
            hint = 'Choose a new database path in a service-owned mode 0700 directory.'
            private_directory(args.database)
            os.close(os.open(args.database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        else:
            private_directory(args.database)
            if not args.database.is_file():
                parser.error('Hosted database is missing. Check the path or restore a verified snapshot.')
        if mode == 'admin':
            hint = 'Check the documented JSON fields, record IDs and current state for this action.'
            payload = read_object(args.input, 131072)
            if args.action in READ_ACTIONS:
                print(json.dumps(READ_ACTIONS[args.action](args.database, **payload)))
                return
        with closing(HostedStore(args.database)) as store:
            if mode == 'init':
                return
            if mode == 'backup':
                hint = 'Choose a new target in a private directory and check SQLite contention or disk space.'
                return store.backup(args.target)
            result = ACTIONS[args.action](store, **payload)
            if args.action == 'propose':
                result = dict(zip(('candidate', 'candidate_sha256'), result))
            if result is not None:
                print(json.dumps(result))
    except (*EVIDENCE_ERRORS, OSError, sqlite3.Error, RuntimeError) as error:
        # Never print validation diagnostics containing private input or receipt bodies.
        parser.error(f'Remote MCP {mode} failed ({type(error).__name__}). {hint}')
