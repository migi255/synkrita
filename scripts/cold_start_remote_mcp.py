"""Time a fresh offline bundle install and synthetic recovery on local loopback."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def invoke(command, *, cwd, payload=None, timeout=60):
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    result = subprocess.run(command, cwd=cwd, env=env, input=json.dumps(payload) if payload else None,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} exited {result.returncode}: {result.stderr.strip()}')
    return result.stdout


def cli(python, root, *args, payload=None):
    return invoke([str(python), '-I', '-m', 'synkrita', 'remote-mcp', *map(str, args)], cwd=root, payload=payload)


@contextmanager
def worker(python, bundle, root, db, config):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with (root / 'service.log').open('a') as log:
        process = subprocess.Popen([python, '-I', '-m', 'synkrita', 'remote-mcp', 'serve', '--config', config,
                                    '--database', db, '--port', str(port)], cwd=root, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Loopback startup failed; inspect service.log')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            invoke([str(python), '-I', str(bundle / 'scripts/check_remote_mcp_staging.py'),
                    '--config', str(config), '--loopback-port', str(port)], cwd=root)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError('Worker exceeded graceful shutdown deadline')


def verify(python, root, db, fixture, *, suspended):
    code = """
import json, sys
from synkrita.pilot_storage import HostedStore
from synkrita.pilot_auth import Principal
import time
path, fixture, disabled = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3] == 'True'
with __import__('contextlib').closing(HostedStore(path)) as store:
    a = fixture['chatgpt']
    b = fixture['claude']
    principal = Principal('https://issuer.example.invalid/', 'oidc|alice', 'fixture', 'synthetic',
                          int(time.time()) + 60, frozenset({'research:access'}))
    assert store.public(fixture['receipt'])['status'] == 'available'
    assert store.qualified(fixture['decision_id'])['status'] == 'available'
    assert store.private(a['account'], a['investigation_id'])['status'] == 'available'
    assert store.private(b['account'], a['investigation_id'])['status'] == 'unavailable'
    assert store.authorized_account(principal) == (None if disabled else a['account'])
"""
    invoke([str(python), '-I', '-c', code, str(db), json.dumps(fixture), str(suspended)], cwd=root)


def drill(args, report, root):
    @contextmanager
    def step(name):
        started = time.perf_counter()
        result = {'name': name, 'passed': False}
        report['steps'].append(result)
        try:
            yield
            result['passed'] = True
        finally:
            result['seconds'] = round(time.perf_counter() - started, 3)

    bundle, previous = args.bundle.resolve(), args.previous_bundle.resolve()
    candidate_venv, previous_venv = root / 'candidate', root / 'previous'
    python, old = candidate_venv / 'bin/python', previous_venv / 'bin/python'
    install = bundle / 'deploy/operator/install-venv.sh'
    with step('install candidate from checked bundle'):
        invoke(['bash', str(install), str(candidate_venv)], cwd=bundle)
    config = root / 'oauth.json'
    config.write_text(json.dumps({'issuer': 'https://issuer.example.invalid/',
                                  'resource': 'https://research.example.invalid/mcp',
                                  'jwks_url': 'https://issuer.example.invalid/jwks', 'clients': ['fixture']}))
    with step('render operator templates'):
        invoke([str(python), str(bundle / 'deploy/operator/render.py'), 'research.example.invalid',
                str(root / 'rendered')], cwd=root)
    with step('initialize and start empty candidate'):
        fresh = root / 'fresh.sqlite'
        cli(python, root, 'init', '--database', fresh)
        with worker(python, bundle, root, fresh, config):
            assert json.loads(cli(python, root, 'status', '--database', fresh))['accounts_active'] == 0

    with step('install previous wheel bundle'):
        invoke(['bash', str(install), str(previous_venv)], cwd=previous)
    db = root / 'previous.sqlite'
    with step('seed and start previous release'):
        fixture = json.loads(invoke([str(old), str(bundle / 'scripts/seed_remote_mcp_staging.py'),
                                     '--database', str(db)], cwd=root,
                                    payload={'issuer': 'https://issuer.example.invalid/', 'chatgpt_sub': 'oidc|alice',
                                             'claude_sub': 'oidc|bob'}))
        verify(old, root, db, fixture, suspended=False)
        with worker(old, bundle, root, db, config):
            pass

    with step('start candidate on previous database and take online snapshot'):
        snapshot = root / 'online.sqlite'
        with worker(python, bundle, root, db, config):
            verify(python, root, db, fixture, suspended=False)
            cli(python, root, 'backup', '--database', db, '--target', snapshot)
            assert json.loads(cli(python, root, 'check-backup', '--snapshot', snapshot))['integrity'] == 'ok'
            cli(python, root, 'admin', '--database', db, 'disable-account',
                payload={'account': fixture['chatgpt']['account']})
            verify(python, root, db, fixture, suspended=True)

    with step('roll back binary on upgraded database'):
        with worker(old, bundle, root, db, config):
            verify(old, root, db, fixture, suspended=True)

    with step('copy and verify snapshot in separate directories'):
        offsite = root / 'simulated-offsite'
        recovery = root / 'recovery'
        offsite.mkdir(mode=0o700)
        recovery.mkdir(mode=0o700)
        sent = shutil.copy2(snapshot, offsite / 'snapshot.sqlite')
        incoming = shutil.copy2(sent, recovery / 'snapshot.sqlite')
        assert hashlib.sha256(Path(incoming).read_bytes()).digest() == hashlib.sha256(snapshot.read_bytes()).digest()

    with step('restore, replay suspension and recover service'):
        restored = recovery / 'restored.sqlite'
        cli(python, root, 'restore', '--snapshot', incoming, '--target', restored)
        verify(python, root, restored, fixture, suspended=False)
        cli(python, root, 'admin', '--database', restored, 'disable-account',
            payload={'account': fixture['chatgpt']['account']})
        with worker(python, bundle, root, restored, config):
            verify(python, root, restored, fixture, suspended=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True, help='Candidate offline bundle directory')
    parser.add_argument('--previous-bundle', type=Path, required=True, help='Previous compatible bundle directory')
    parser.add_argument('--output', type=Path, required=True, help='New JSON report path')
    args = parser.parse_args()
    report = {'schema_version': 1, 'command': sys.argv, 'platform': platform.platform(),
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'candidate_revision': (args.bundle / 'REVISION').read_text().strip(),
              'previous_revision': (args.previous_bundle / 'REVISION').read_text().strip(),
              'candidate_manifest_sha256': hashlib.sha256((args.bundle / 'SHA256SUMS').read_bytes()).hexdigest(),
              'previous_manifest_sha256': hashlib.sha256((args.previous_bundle / 'SHA256SUMS').read_bytes()).hexdigest(),
              'manual_assistance_during_script': 0, 'steps': []}
    if report['candidate_manifest_sha256'] == report['previous_manifest_sha256']:
        parser.error('Use two distinct bundles for the compatibility drill')
    started = time.perf_counter()
    with args.output.open('x') as output, tempfile.TemporaryDirectory(prefix='synkrita-cold-') as temp:
        try:
            drill(args, report, Path(temp))
        except Exception as error:
            log = Path(temp) / 'service.log'
            if log.exists():
                print(log.read_text()[-4000:], file=sys.stderr)
            report['error_type'] = type(error).__name__
            raise
        finally:
            report['seconds'] = round(time.perf_counter() - started, 3)
            report['failed_steps'] = sum(not step['passed'] for step in report['steps'])
            json.dump(report, output, indent=2)
            output.write('\n')


if __name__ == '__main__':
    main()
