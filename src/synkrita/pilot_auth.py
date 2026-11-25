"""Bounded RFC 9068 verification against an operator-pinned HTTPS JWKS."""
import asyncio
from dataclasses import dataclass
import json
import re
import time
from urllib.parse import urlsplit

import httpx
import jwt


MAX_TOKEN = 8192
SAFE_ID = re.compile(r'[!-~]{1,256}', re.ASCII)
JWT_SEGMENTS = re.compile(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', re.ASCII)


def https_url(value):
    if not isinstance(value, str) or not re.fullmatch(r'https://[A-Za-z0-9./:_~-]+', value):
        raise ValueError('Expected a canonical HTTPS URL')
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.netloc != parsed.netloc.lower() or parsed.port == 443:
        raise ValueError('Expected a canonical HTTPS authority')
    return parsed


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    resource: str
    jwks_url: str
    clients: tuple[str, ...]
    max_token_age: int = 900

    self_registration: bool = False

    def __post_init__(self):
        if type(self.self_registration) is not bool:
            raise ValueError("self_registration must be boolean")
        issuer, resource, jwks = map(https_url, (self.issuer, self.resource, self.jwks_url))
        if (resource.path != '/mcp' or jwks.netloc != issuer.netloc or not jwks.path
                or not re.fullmatch(r'/.+', jwks.path)):
            raise ValueError('Require /mcp and a pinned JWKS path on the issuer authority')
        if (not isinstance(self.clients, (list, tuple)) or not 1 <= len(self.clients) <= 8
                or any(not isinstance(c, str) or not SAFE_ID.fullmatch(c) for c in self.clients)
                or len(set(self.clients)) != len(self.clients)):
            raise ValueError('Configure explicit OAuth client IDs')
        if type(self.max_token_age) is not int or not 60 <= self.max_token_age <= 3600:
            raise ValueError('Invalid access token lifetime bound')
        object.__setattr__(self, 'clients', tuple(self.clients))


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    client: str
    jti: str
    expires: int
    scopes: frozenset[str]


class KeysUnavailable(Exception):
    pass


class AccessVerifier:
    def __init__(self, config: OAuthConfig, client: httpx.AsyncClient):
        self.config = config
        self.client = client
        self.keys = {}
        self.valid_until = 0.0
        self.retry_after = 0.0
        self.lock = asyncio.Lock()

    async def _refresh(self):
        # Never take a key URL, issuer or algorithm from untrusted JWT headers.
        async with asyncio.timeout(3), self.client.stream(
            'GET', self.config.jwks_url,
            headers={'Accept': 'application/json', 'Accept-Encoding': 'identity'},
            follow_redirects=False,
        ) as response:
            response.raise_for_status()
            if response.headers.get('content-encoding', 'identity').lower() != 'identity':
                raise ValueError('Unsupported JWKS content encoding')
            raw = bytearray()
            async for chunk in response.aiter_raw(chunk_size=8192):
                if len(raw) + len(chunk) > 65536:
                    raise ValueError('JWKS exceeds byte budget')
                raw.extend(chunk)
        items = json.loads(raw)['keys']
        if not isinstance(items, list) or not 1 <= len(items) <= 16:
            raise ValueError('JWKS exceeds key budget')
        keys = {}
        for item in items:
            if item['kty'] != 'RSA' or item.get('use', 'sig') != 'sig' or item.get('alg', 'RS256') != 'RS256':
                continue
            kid = item['kid']
            if (not isinstance(kid, str) or not SAFE_ID.fullmatch(kid) or kid in keys
                    or 'd' in item or 'verify' not in item.get('key_ops', ['verify'])
                    or not 342 <= len(item['n']) <= 683 or item['e'] != 'AQAB'):
                raise ValueError('Invalid signing key metadata')
            key = jwt.PyJWK.from_dict(item, algorithm='RS256').key
            if not 2048 <= key.key_size <= 4096 or key.public_numbers().e != 65537:
                raise ValueError('Invalid RSA signing key parameters')
            keys[kid] = key
        if not keys:
            raise ValueError('No permitted signing keys')
        self.keys = keys
        self.valid_until = time.monotonic() + 300

    async def _key(self, kid):
        async with self.lock:
            now = time.monotonic()
            if now < self.valid_until and kid in self.keys:
                return self.keys[kid]
            if now >= self.retry_after:
                self.retry_after = now + 10
                try:
                    await self._refresh()
                except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError,
                        AttributeError, RecursionError, jwt.PyJWTError):
                    if time.monotonic() >= self.valid_until:
                        raise KeysUnavailable from None
            if time.monotonic() >= self.valid_until:
                raise KeysUnavailable
            return self.keys.get(kid)

    async def verify(self, token: str) -> Principal | None:
        if len(token) > MAX_TOKEN or not JWT_SEGMENTS.fullmatch(token):
            return None
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            if (header.get('alg') != 'RS256' or header.get('typ') not in ('at+jwt', 'application/at+jwt')
                    or not isinstance(kid, str) or not SAFE_ID.fullmatch(kid)
                    or any(field in header for field in ('jku', 'jwk', 'x5u', 'crit'))):
                return None
            key = await self._key(kid)
            if key is None:
                return None
            claims = jwt.decode(
                token, key, algorithms=['RS256'], issuer=self.config.issuer, audience=self.config.resource,
                options={'require': ['exp', 'iat', 'iss', 'sub', 'aud', 'client_id', 'jti']},
            )
            if claims['iss'] != self.config.issuer or claims['aud'] not in (
                self.config.resource, [self.config.resource],
            ):
                return None
            times = [claims['iat'], claims['exp']]
            if 'nbf' in claims:
                times.append(claims['nbf'])
            if any(type(value) is not int for value in times):
                return None
            if not 0 < claims['exp'] - claims['iat'] <= self.config.max_token_age:
                return None
            subject, client_id, jti = (claims[k] for k in ('sub', 'client_id', 'jti'))
            if (any(not isinstance(k, str) or not SAFE_ID.fullmatch(k) for k in (subject, client_id, jti))
                    or client_id not in self.config.clients or claims.get('azp', client_id) != client_id
                    or claims.get('gty') in ('client-credentials', 'client_credentials')
                    or subject.endswith('@clients') or 'cnf' in claims):
                return None
            scopes = claims.get('scope', '')
            if not isinstance(scopes, str) or len(scopes) > 2048:
                return None
            return Principal(claims['iss'], subject, client_id, jti, claims['exp'], frozenset(scopes.split(' ')))
        except (jwt.PyJWTError, ValueError, TypeError, OverflowError, RecursionError):
            return None
