"""Read-oriented Streamable HTTP boundary for the enrolled research pilot."""
import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
import logging
import re
import sqlite3
import time
from typing import Annotated, Any
from urllib.parse import urlsplit
from uuid import uuid4

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import JSONRPCMessage, ToolAnnotations
from pydantic import Field
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response

from synkrita.large_observations import bounded_json
from synkrita.pilot_auth import MAX_TOKEN, AccessVerifier, KeysUnavailable, OAuthConfig, Principal
from synkrita.pilot_storage import EVIDENCE_ERRORS, ROW_ID, UNAVAILABLE, HostedStore
from synkrita.pilot_usage import METHODS, TOOLS, sdk_outcome, utc_ms


ACCESS = 'research:access'
logger = logging.getLogger(__name__)
# FastMCP configures the root logger at CRITICAL. Keep Synkrita's redacted storage events visible.
logger.setLevel(logging.WARNING)
METADATA_PATH = '/.well-known/oauth-protected-resource/mcp'
BODY_LIMIT = 16384
RECORD_ID = Annotated[str, Field(pattern=r'^[0-9a-f]{32}$')]
@dataclass(frozen=True)
class Limits:
    window_seconds: int = 60
    requests_per_window: int = 6000
    requests_per_peer: int = 1800
    requests_per_account: int = 120
    concurrent_requests: int = 32


class Quota:
    """One fixed window with bounded cardinality, reset on a monotonic clock."""

    def __init__(self, limits):
        self.limits = limits
        self.ends = 0
        self.counts = {}
        self.reported = set()

    def admit(self, *buckets):
        now = time.monotonic()
        if now >= self.ends:
            self.ends = now + self.limits.window_seconds
            self.counts.clear()
            self.reported.clear()
        if any(self.counts.get(key, 0) >= cap for key, cap in buckets):
            return False
        for key, _ in buckets:
            self.counts[key] = self.counts.get(key, 0) + 1
        return True


@dataclass
class RequestUsage:
    request_id: str
    account: str | None = None
    operation: str = 'unclassified'
    mcp_message: bool = False
    tool_executed: bool = False
    tool_outcome: str | None = None


@dataclass(frozen=True)
class RequestIdentity:
    principal: Principal
    account: str
    usage: RequestUsage


identity: ContextVar[RequestIdentity | None] = ContextVar('pilot_request_identity', default=None)


class RemoteBoundary:
    def __init__(self, mcp, store, config, verifier, limits, usage):
        self.mcp = mcp
        self.store = store
        self.self_registration = config.self_registration
        self.verifier = verifier
        self.usage = usage
        self.limits = limits
        self.quota = Quota(limits)
        self.active = 0
        self.host = urlsplit(config.resource).netloc
        self.origin = f'https://{self.host}'
        self.metadata_url = self.origin + METADATA_PATH
        self.metadata = {'resource': config.resource, 'authorization_servers': [config.issuer],
                         'scopes_supported': [ACCESS], 'bearer_methods_supported': ['header']}

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            async def send_lifespan(message):
                if self.usage is not None and message['type'] == 'lifespan.shutdown.complete':
                    # Uvicorn re-raises the process signal after ASGI shutdown.
                    # Persist the run boundary before acknowledging shutdown.
                    self.usage.finish()
                await send(message)

            return await self.mcp(scope, receive, send_lifespan)
        if scope['type'] == 'websocket':
            return await send({'type': 'websocket.close', 'code': 1008})

        usage = RequestUsage(uuid4().hex)
        started = time.monotonic_ns()
        status = None
        request_bytes = response_bytes = 0
        request_complete = response_complete = False
        outcome = 'incomplete'
        forwarded = False
        disconnected = False

        async def receive_counted():
            nonlocal request_bytes, request_complete, disconnected
            message = await receive()
            if message['type'] == 'http.request':
                request_bytes += len(message.get('body', b''))
                request_complete = not message.get('more_body')
            elif message['type'] == 'http.disconnect' and not response_complete:
                disconnected = True
            return message

        async def send_uncached(message):
            nonlocal status, response_bytes, response_complete, outcome
            if message['type'] == 'http.response.start':
                message['headers'] = [*message.get('headers', []), (b'cache-control', b'no-store'),
                                      (b'x-content-type-options', b'nosniff')]
            await send(message)
            if message['type'] == 'http.response.start':
                status = message['status']
            elif message['type'] == 'http.response.body':
                single_chunk = response_bytes == 0
                response_bytes += len(message.get('body', b''))
                response_complete = not message.get('more_body')
                if response_complete:
                    if status is None or disconnected:
                        outcome = 'incomplete'
                    elif status >= 500:
                        outcome = 'http_error'
                    elif status >= 400:
                        outcome = 'rejected'
                    elif forwarded and single_chunk:
                        outcome = sdk_outcome(message, usage.operation, usage.tool_outcome)
                    else:
                        outcome = usage.tool_outcome if usage.tool_outcome in (
                            'tool_unavailable', 'tool_error',
                        ) else 'unclassified'

        try:
            response, body, context = await self.check(Request(scope, receive_counted), usage)
            if response is not None:
                return await response(scope, receive_counted, send_uncached)

            # Replay the bounded request to the SDK without counting it again.
            received = False
            forwarded = True

            async def receive_checked():
                nonlocal received
                if received:
                    return await receive_counted()
                received = True
                return {'type': 'http.request', 'body': body, 'more_body': False}

            bound = identity.set(context)
            try:
                await self.mcp(scope, receive_checked, send_uncached)
            finally:
                identity.reset(bound)
                self.active -= 1
        finally:
            if self.usage is not None and usage.account is not None:
                await self.usage.complete((
                    utc_ms(), usage.account, usage.request_id, usage.operation, outcome, status,
                    usage.mcp_message, usage.tool_executed, (time.monotonic_ns() - started) // 1000,
                    request_bytes if request_complete else None,
                    response_bytes if response_complete and not disconnected else None,
                ))

    async def check(self, request, usage):
        request_id = usage.request_id

        def deny(status, reason, *, context=None, challenge=None, audit=True):
            headers = {}
            if challenge is not None:
                headers['WWW-Authenticate'] = challenge
            if status == 429:
                headers['Retry-After'] = str(max(1, int(self.quota.ends - time.monotonic()) + 1))
            if audit:
                try:
                    with self.store.db:
                        self.store.audit(
                            'http_reject', reason, request_id=request_id,
                            actor=context.account if context else None,
                            client=context.principal.client if context else None,
                        )
                except sqlite3.Error:
                    logger.warning('{"event":"hosted_storage_error","operation":"audit"}')
                    return JSONResponse({'error': 'service_unavailable'}, status_code=503), None, None
            return JSONResponse({'error': reason}, status_code=status, headers=headers), None, None

        def throttled(reason, context=None):
            audit = reason not in self.quota.reported
            self.quota.reported.add(reason)
            return deny(429, reason, context=context, audit=audit)

        peer = request.client.host if request.client else 'unknown'
        if not self.quota.admit(('ingress', self.limits.requests_per_window),
                                (('peer', peer), self.limits.requests_per_peer)):
            return throttled('ingress_limit')

        headers = request.headers
        if len(request.scope['headers']) > 48 or sum(
                len(key) + len(value) for key, value in request.scope['headers']) > 16384:
            return deny(431, 'headers_too_large')
        if headers.getlist('host') != [self.host]:
            return deny(421, 'invalid_host')
        if headers.getlist('origin') not in ([], [self.origin]):
            return deny(403, 'invalid_origin')
        if request.scope.get('query_string'):
            return deny(400, 'query_not_supported')
        if request.url.path == METADATA_PATH and request.method == 'GET':
            return JSONResponse(self.metadata), None, None
        if request.url.path != '/mcp':
            return deny(404, 'unknown_path')
        if self.active >= self.limits.concurrent_requests:
            return throttled('concurrency_limit')

        self.active += 1
        proceed = False
        try:
            metadata = f'resource_metadata="{self.metadata_url}"'
            auth = headers.getlist('authorization')
            if not auth:
                return deny(401, 'authentication_required', challenge=f'Bearer {metadata}, scope="{ACCESS}"')
            if len(auth) != 1 or len(auth[0]) > MAX_TOKEN + 7 or not auth[0].lower().startswith('bearer '):
                return deny(400, 'invalid_authorization')
            try:
                principal = await self.verifier.verify(auth[0][7:])
            except KeysUnavailable:
                return deny(503, 'verification_unavailable')
            account = self.store.authorized_account(principal) if principal else None
            if (account is None and self.self_registration and principal and ACCESS in principal.scopes
                    and request.method == 'POST'):
                account = self.store.register_verified_account(principal)
            if account is None:
                return deny(401, 'invalid_token', challenge=f'Bearer {metadata}, error="invalid_token"')
            usage.account = account
            context = RequestIdentity(principal, account, usage)
            if not self.quota.admit((('account', account), self.limits.requests_per_account),
                                    (('client', account, principal.client), self.limits.requests_per_account)):
                return throttled('account_limit', context)
            if ACCESS not in principal.scopes:
                challenge = f'Bearer {metadata}, error="insufficient_scope", scope="{ACCESS}"'
                return deny(403, 'insufficient_scope', context=context, challenge=challenge)
            if request.method != 'POST':
                return Response(status_code=405, headers={'Allow': 'POST'}), None, None

            content_type = headers.getlist('content-type')
            length = headers.getlist('content-length')
            if (len(content_type) != 1 or content_type[0].split(';', 1)[0].strip().lower() != 'application/json'
                    or headers.getlist('content-encoding') not in ([], ['identity'])):
                return deny(415, 'unsupported_content', context=context)
            if length and (len(length) != 1 or not re.fullmatch(r'[0-9]{1,10}', length[0])):
                return deny(400, 'invalid_content_length', context=context)
            if length and int(length[0]) > BODY_LIMIT:
                return deny(413, 'body_too_large', context=context)
            body = bytearray()
            try:
                async with asyncio.timeout(3):
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > BODY_LIMIT:
                            return deny(413, 'body_too_large', context=context)
                        body.extend(chunk)
            except TimeoutError:
                return deny(408, 'body_timeout', context=context)
            except ClientDisconnect:
                return deny(400, 'body_disconnected', context=context)

            try:
                payload = bounded_json(bytes(body).decode('utf-8'), BODY_LIMIT)
                JSONRPCMessage.model_validate(payload)
            except (ValueError, RecursionError):
                return deny(400, 'invalid_message', context=context)
            usage.mcp_message = True
            method = payload.get('method')
            if not isinstance(method, str) or method not in METHODS:
                return deny(400, 'unsupported_method', context=context)
            usage.operation = method
            if method == 'tools/call':
                params = payload.get('params') or {}
                name = params.get('name')
                argument = TOOLS.get(name) if isinstance(name, str) else None
                if argument:
                    usage.operation = name
                arguments = params.get('arguments')
                if (not argument or not isinstance(arguments, dict) or set(arguments) != {argument}
                        or not isinstance(arguments[argument], str) or not ROW_ID.fullmatch(arguments[argument])):
                    return deny(400, 'invalid_tool_call', context=context)
            else:
                with self.store.db:
                    self.store.audit('mcp_protocol', 'accepted', actor=account, client=principal.client,
                                     request_id=request_id)
            proceed = True
            return None, bytes(body), context
        except sqlite3.Error:
            logger.warning('{"event":"hosted_storage_error","operation":"authorization"}')
            return deny(503, 'storage_unavailable', audit=False)
        finally:
            if not proceed:
                self.active -= 1


def create_remote_app(store: HostedStore, config: OAuthConfig, verifier: AccessVerifier, *, limits=Limits(), usage=None):
    if verifier.config != config:
        raise ValueError('OAuth verifier and MCP resource configurations must match')
    authority = urlsplit(config.resource).netloc
    mcp = FastMCP(
        'Synkrita research pilot', stateless_http=True, json_response=True, log_level='CRITICAL',
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[authority],
            allowed_origins=[f'https://{authority}'],
        ),
    )
    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)

    next_steps = {
        'public_read': 'Use another supplied receipt only if it supports the same question. Otherwise report the evidence gap.',
        'decision_read': 'Report that the requested use lacks a verified decision. A receipt alone cannot authorize that use.',
        'investigation_read': 'Ask the signed-in researcher for their investigation ID before trying another read.',
    }

    def read(action, target, operation):
        access = identity.get()
        if access is None or ACCESS not in access.principal.scopes:
            return UNAVAILABLE
        access.usage.tool_executed = True
        try:
            with store.transaction():
                account = store.authorized_account(access.principal)
                if account != access.account:
                    result = UNAVAILABLE
                else:
                    try:
                        result = operation(account)
                    except EVIDENCE_ERRORS:
                        result = UNAVAILABLE
                store.audit(action, result['status'], actor=access.account, client=access.principal.client,
                            target=target, request_id=access.usage.request_id)
                if result['status'] == 'unavailable':
                    access.usage.tool_outcome = 'tool_unavailable'
                    return {**result, 'retry_same_id': False, 'next_step': next_steps[action]}
                access.usage.tool_outcome = 'completed'
                return result
        except sqlite3.Error:
            access.usage.tool_outcome = 'tool_error'
            logger.warning('{"event":"hosted_storage_error","operation":"read"}')
            return {'status': 'temporarily_unavailable', 'next_step': 'Wait before retrying once.'}

    @mcp.tool(annotations=read_only)
    async def read_public_observation(receipt: RECORD_ID) -> dict[str, Any]:
        """Read the projected values and citation for a published observation.

        Supply its exact 32-character lowercase hexadecimal receipt ID from onboarding or a citation.
        A source accession or a research question cannot be used as the receipt ID."""
        return read('public_read', receipt, lambda _: store.public(receipt))

    @mcp.tool(annotations=read_only)
    async def read_qualified_decision(decision_id: RECORD_ID) -> dict[str, Any]:
        """Check an active integration decision, its approved use, context and supporting evidence.

        Supply the exact 32-character lowercase hexadecimal decision ID from onboarding.
        Candidate IDs and receipt IDs cannot establish an approved decision."""
        return read('decision_read', decision_id, lambda _: store.qualified(decision_id))

    @mcp.tool(annotations=read_only)
    async def read_investigation(investigation_id: RECORD_ID) -> dict[str, Any]:
        """Read the signed-in researcher's private question and notes.

        Use their supplied 32-character lowercase hexadecimal investigation ID.
        If the ID is unavailable, ask the researcher to confirm it before another read."""
        return read('investigation_read', investigation_id, lambda owner: store.private(owner, investigation_id))

    return RemoteBoundary(mcp.streamable_http_app(), store, config, verifier, limits, usage)
