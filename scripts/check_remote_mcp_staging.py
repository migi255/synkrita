"""Check Synkrita discovery and ingress without sending credentials."""

import argparse
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

import httpx

from synkrita.pilot_auth import OAuthConfig
from synkrita.pilot_cli import read_object
from synkrita.remote_server import ACCESS, METADATA_PATH


def expect(condition, check):
    if not condition:
        raise ValueError(check)


def check_ingress(http, config, authority):
    host = urlsplit(config.resource).netloc
    origin = f'https://{host}'
    resource_metadata = origin + METADATA_PATH
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
               'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                          'clientInfo': {'name': 'synkrita-staging-check', 'version': '1'}}}
    headers = {'Host': host, 'Accept': 'application/json, text/event-stream'}
    response = http.post(authority + '/mcp', headers=headers, json=request)
    challenge = response.headers.get('www-authenticate', '')
    expect(response.status_code == 401 and challenge.startswith('Bearer ')
           and f'resource_metadata="{resource_metadata}"' in challenge and f'scope="{ACCESS}"' in challenge,
           'Unauthenticated initialize must return the exact 401 discovery challenge')
    expect(response.headers.get('cache-control') == 'no-store', 'Challenge is cacheable')
    if authority == origin:
        expect(bool(response.headers.get('strict-transport-security')), 'HTTPS ingress omitted HSTS')
    response = http.get(authority + METADATA_PATH, headers=headers)
    expect(response.status_code == 200 and response.headers.get('cache-control') == 'no-store',
           'Protected resource metadata unavailable or cacheable')
    expect(response.json() == {'resource': config.resource, 'authorization_servers': [config.issuer],
                               'scopes_supported': [ACCESS], 'bearer_methods_supported': ['header']},
           'Protected resource metadata differs from configuration')
    response = http.post(authority + '/mcp', headers=headers | {'Origin': 'https://foreign.example.invalid'},
                         json=request)
    expect(response.status_code == 403, 'Unexpected response to foreign Origin')
    response = http.post(authority + '/mcp', headers=headers | {'Authorization': 'Bearer invalid'}, json=request)
    expect(response.status_code == 401 and 'error="invalid_token"' in response.headers.get('www-authenticate', ''),
           'Unexpected response to an invalid bearer')
    response = http.get(authority + '/admin', headers=headers)
    expect(response.status_code == 404, 'Unexpected response on /admin')


def check_issuer(http, config):
    issuer = config.issuer.rstrip('/')
    for discovery_path in ('/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'):
        response = http.get(issuer + discovery_path)
        if response.status_code == 404:
            continue
        expect(response.status_code == 200, f'Issuer discovery failed at {discovery_path}')
        metadata = response.json()
        expect(metadata.get('issuer') == config.issuer and metadata.get('jwks_uri') == config.jwks_url,
               'Issuer or JWKS URL differs from the pinned configuration')
        expect('S256' in metadata.get('code_challenge_methods_supported', []), 'Issuer did not advertise S256')
        for field in ('authorization_endpoint', 'token_endpoint'):
            endpoint = urlsplit(metadata.get(field, ''))
            expect(endpoint.scheme == 'https' and endpoint.netloc == urlsplit(config.issuer).netloc
                   and not endpoint.username and not endpoint.fragment, f'Unexpected {field}')
        break
    else:
        raise ValueError('Issuer serves neither discovery document')
    response = http.get(config.jwks_url, headers={'Accept-Encoding': 'identity'})
    expect(response.status_code == 200 and len(response.content) <= 65536, 'Pinned JWKS unavailable or oversized')
    keys = response.json().get('keys', [])
    expect(1 <= len(keys) <= 16 and any(key.get('kty') == 'RSA' and key.get('alg', 'RS256') == 'RS256'
                                       for key in keys), 'Pinned JWKS lacks an eligible RSA key')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--loopback-port', type=int,
                        help='Check a local listener only, without TLS or issuer network requests')
    parser.add_argument('--monitor', action='store_true', help='Emit one allowlisted JSON monitoring sample')
    parser.add_argument('--test-alert', metavar='ID', help='Emit a failed synthetic probe without network access')
    args = parser.parse_args()
    if args.test_alert is not None:
        if args.config or args.loopback_port is not None or not re.fullmatch(r'[a-zA-Z0-9-]{1,40}', args.test_alert):
            parser.error('Supply only a short alphanumeric test ID, with optional hyphens')
        print(json.dumps({'event': 'synkrita_probe', 'ok': False, 'stage': 'ingress', 'elapsed_ms': 0,
                          'probe': 'external', 'synthetic': True, 'test_id': args.test_alert}))
        return
    if not args.config:
        parser.error('Supply --config or --test-alert')
    started = time.monotonic()
    stage = 'configuration'
    probe = 'local' if args.loopback_port is not None else 'external'

    def sample(ok):
        print(json.dumps({'event': 'synkrita_probe', 'ok': ok, 'stage': stage, 'probe': probe,
                          'elapsed_ms': round((time.monotonic() - started) * 1000, 3), 'synthetic': False}))

    try:
        config = OAuthConfig(**read_object(args.config, 8192))
        authority = config.resource.removesuffix('/mcp')
        if args.loopback_port is not None:
            expect(1024 <= args.loopback_port <= 65535, 'Expected a non-privileged loopback port')
            authority = f'http://127.0.0.1:{args.loopback_port}'
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as http:
            stage = 'ingress'
            check_ingress(http, config, authority)
            if args.loopback_port is None:
                stage = 'issuer'
                check_issuer(http, config)
    except (OSError, ValueError, TypeError, AttributeError, httpx.HTTPError) as error:
        if args.monitor:
            sample(False)
            raise SystemExit(1) from None
        detail = str(error) if type(error) is ValueError else type(error).__name__
        parser.exit(1, f'Preflight failed. {detail}\n')
    if args.monitor:
        stage = 'complete'
        sample(True)
        return
    print('Loopback preflight passed.' if args.loopback_port is not None else 'HTTPS and issuer preflight passed.')


if __name__ == '__main__':
    main()
