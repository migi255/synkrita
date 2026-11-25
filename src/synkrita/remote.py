"""Explicit endpoint policy and bounded official-SDK Streamable HTTP connections."""
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
import ipaddress
import os
import socket
import time
import tomllib
from urllib.parse import urlsplit

import httpx

from synkrita.adapters.mcp import McpAdapter
from synkrita.metrics import UpstreamMetrics
from synkrita.models import digest
from synkrita.runtime import measured_session


@dataclass(frozen=True)
class RemoteSource:
    endpoint: str
    view: str = 'public'
    allowed_operations: tuple[str, ...] = ()
    authorization_env: str | None = None
    timeout_seconds: float = 10
    max_session_seconds: float = 30
    max_http_requests: int = 32
    max_response_bytes: int = 1048576
    max_tools: int = 256
    max_catalogue_bytes: int = 524288
    allow_local_http: bool = False

    def __post_init__(self):
        if not isinstance(self.endpoint, str) or not isinstance(self.view, str) or not self.view:
            raise ValueError('Endpoint and nonempty authorized view are required')
        url = urlsplit(self.endpoint)
        local = url.hostname == 'localhost'
        if url.hostname:
            try:
                local = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                pass
        if (not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment or
                any(c in self.endpoint for c in ('\\', '\n', '\r')) or
                url.scheme != 'https' and not (self.allow_local_http and local and url.scheme == 'http')):
            raise ValueError('Require a credential-free HTTPS endpoint; HTTP is explicit loopback-only')
        if type(self.allow_local_http) is not bool:
            raise ValueError('allow_local_http must be an explicit boolean')
        if self.authorization_env is not None and (not isinstance(self.authorization_env, str) or not self.authorization_env):
            raise ValueError('Authorization must name a nonempty environment variable')
        if not url.path or url.path == '/':
            raise ValueError('An explicit MCP endpoint path is required')
        _ = url.port  # Reject invalid ports before any connection.
        if (not isinstance(self.allowed_operations, (tuple, list)) or
                any(not isinstance(name, str) or not name for name in self.allowed_operations) or
                len(set(self.allowed_operations)) != len(self.allowed_operations)):
            raise ValueError('Allowed operations must be unique explicit tool names')
        object.__setattr__(self, 'allowed_operations', tuple(self.allowed_operations))
        if not 0 < self.max_session_seconds <= 300:
            raise ValueError('Session deadline must be within 300 seconds')
        if not 0 < self.timeout_seconds <= 120:
            raise ValueError('Request timeout must be within 120 seconds')
        for value, upper in [(self.max_http_requests, 128), (self.max_response_bytes, 4194304),
                             (self.max_tools, 1024), (self.max_catalogue_bytes, 2097152)]:
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError('Invalid source request or size budget')

    def check_request(self, request):
        # Compare complete httpx-normalized URLs, including scheme, port and path.
        if request.url != httpx.URL(self.endpoint) or request.method not in {'GET', 'POST', 'DELETE'}:
            raise ValueError('Request exceeds the configured MCP endpoint policy')


def load_sources(path):
    with open(path, 'rb') as file:
        config = tomllib.load(file)
    if set(config) != {'sources'} or not isinstance(config['sources'], dict):
        raise ValueError('Expected a sources table')
    return {name: RemoteSource(**values) for name, values in config['sources'].items()}


class BoundedStream(httpx.AsyncByteStream):
    def __init__(self, stream, limit, counters):
        self.stream, self.limit, self.counters = stream, limit, counters
        self.size = 0

    async def __aiter__(self):
        async for chunk in self.stream:
            self.size += len(chunk)
            self.counters['response_bytes'] += len(chunk)
            if self.size > self.limit:
                raise ValueError('MCP HTTP response exceeds the byte budget')
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


@asynccontextmanager
async def remote_session(source, *, http_transport=None):
    """Only trusted callers inject a transport (ASGI/offline contract tests).

    HTTP redirects are disabled; authentication challenges cannot authorize new
    destinations. Proxy settings may come from the operator's environment.
    """
    import anyio
    from mcp.client.streamable_http import streamable_http_client

    rpc = UpstreamMetrics()
    wire = {'requests': 0, 'methods': {}, 'statuses': {}, 'response_bytes': 0}
    headers = {'Accept-Encoding': 'identity'}
    if source.authorization_env:
        value = os.environ.get(source.authorization_env)
        if not value:
            raise ValueError('Configured source authorization is unavailable')
        headers['Authorization'] = value

    async def before(request):
        source.check_request(request)
        if wire['requests'] >= source.max_http_requests:
            raise ValueError('MCP HTTP request budget exhausted')
        wire['requests'] += 1
        wire['methods'][request.method] = wire['methods'].get(request.method, 0) + 1

    async def after(response):
        status = str(response.status_code)
        wire['statuses'][status] = wire['statuses'].get(status, 0) + 1
        if 300 <= response.status_code < 400:
            raise ValueError('MCP endpoint redirects require explicit reconfiguration')
        if response.headers.get('content-encoding', 'identity').lower() != 'identity':
            raise ValueError('Compressed MCP responses are not qualified by this profile')
        if response.is_stream_consumed:
            wire['response_bytes'] += len(response.content)
            if len(response.content) > source.max_response_bytes:
                raise ValueError('MCP HTTP response exceeds the byte budget')
        else:
            response.stream = BoundedStream(response.stream, source.max_response_bytes, wire)

    if http_transport is None:
        # Fail before DNS worker threads when the execution environment disallows
        # TCP sockets entirely. Creating this socket contacts no destination.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            pass

    with anyio.fail_after(source.max_session_seconds):
        async with httpx.AsyncClient(
            transport=http_transport, headers=headers, timeout=httpx.Timeout(source.timeout_seconds),
            follow_redirects=False, event_hooks={'request': [before], 'response': [after]},
        ) as client:
            async with streamable_http_client(source.endpoint, http_client=client) as (read, write, _):
                async with measured_session(read, write, rpc, source.timeout_seconds) as session:
                    initialized = await session.initialize()
                    adapter = McpAdapter(session, source.endpoint, view=source.view,
                        allowed_operations=source.allowed_operations, metrics=rpc,
                        max_tools=source.max_tools, max_catalogue_bytes=source.max_catalogue_bytes)
                    yield adapter, {
                        'protocol_version': initialized.protocolVersion,
                        'server_declaration': initialized.serverInfo.model_dump(mode='json'),
                        'rpc_metrics': rpc, 'http_metrics': wire,
                    }

def exception_category(error):
    """Unwrap task groups without persisting exception text or credentials."""
    leaves = []
    def visit(item):
        if isinstance(item, BaseExceptionGroup):
            for nested in item.exceptions:
                visit(nested)
        else:
            leaves.append(type(item).__name__)
    visit(error)
    return sorted(set(leaves))


async def discover_remote(store, name, source):
    """Retain catalogue declarations only. This never admits a Finding."""
    from dataclasses import asdict
    started = time.perf_counter()
    result = {'source': name, 'identity': source.endpoint, 'view': source.view,
              'transport': 'streamable-http', 'status': 'blocked',
              'limitations': ['Tool declarations do not establish scientific validity, completeness or data freshness']}
    store.register(name, source.endpoint, source.view)
    try:
        async with remote_session(source) as (adapter, metadata):
            tools = await adapter.discover()
            declaration = {'source': name, 'identity': source.endpoint, 'view': source.view,
                'capabilities': [asdict(tool) for tool in tools],
                'protocol_version': metadata['protocol_version'],
                'server_declaration': metadata['server_declaration'],
                'observed_at': time.time()}
            declaration_id = store.put('declaration', declaration)
            result.update(status='discovered', declaration=declaration_id,
                protocol_version=metadata['protocol_version'],
                interface=digest(declaration['capabilities']),
                tools=[{'name': tool.name, 'output_schema_declared': bool(tool.output_schema),
                        'invocation_allowed': tool.name in source.allowed_operations} for tool in tools],
                rpc_metrics=metadata['rpc_metrics'].snapshot(), http_metrics=metadata['http_metrics'])
    except Exception as error:
        result.update(status='blocked', error_categories=exception_category(error))
    result['elapsed_ms'] = round((time.perf_counter() - started) * 1000, 3)
    result['report_receipt'] = store.put('qualification', result)
    return result


async def investigate_remote(store, name, source, operation, arguments, probe, *, http_transport=None):
    """Require an explicit tool grant before starting any connection."""
    from synkrita.core import Investigator
    from synkrita.privacy import retention_safe
    if operation not in source.allowed_operations:
        raise ValueError('Operation is not explicitly permitted for this source')
    retention_safe(arguments)
    retention_safe(probe)
    store.register(name, source.endpoint, source.view)
    try:
        async with remote_session(source, http_transport=http_transport) as (adapter, metadata):
            from synkrita.observations import wrapped_text_schema
            capabilities = await adapter.discover()
            if any(cap.name == operation and wrapped_text_schema(cap.output_schema) for cap in capabilities):
                return {'status': 'withheld', 'source': name, 'output': None,
                    'reason': 'wrapped_text_contract_unqualified', 'findings_admitted': 0,
                    'limitations': ['Use mcp-observe to capture the response before qualifying its inner data contract']}
            result = await Investigator(store, {name: adapter}, timeout_seconds=source.timeout_seconds).investigate(
                name, operation, arguments, probe=probe, view=source.view)
            result.update(source=name, identity=source.endpoint, view=source.view,
                rpc_metrics=metadata['rpc_metrics'].snapshot(), http_metrics=metadata['http_metrics'])
            return result
    except Exception as error:
        return {'status': 'withheld', 'output': None, 'source': name,
                'error_categories': exception_category(error),
                'limitations': ['Remote transport initialization or shutdown obligation unresolved']}


async def observe_remote(store, name, source, operation, arguments, *, http_transport=None):
    """Single permitted observation, independent of reusable Finding admission."""
    from synkrita.observations import observe_adapter
    from synkrita.privacy import retention_safe
    if operation not in source.allowed_operations:
        raise ValueError('Operation is not explicitly permitted for this source')
    retention_safe(arguments)
    store.register(name, source.endpoint, source.view)
    try:
        async with remote_session(source, http_transport=http_transport) as (adapter, metadata):
            result = await observe_adapter(store, name, adapter, operation, arguments,
                protocol_version=metadata['protocol_version'])
            result.update(rpc_metrics=metadata['rpc_metrics'].snapshot(), http_metrics=metadata['http_metrics'])
            return result
    except Exception as error:
        return {'status': 'withheld', 'source': name, 'findings_admitted': 0,
            'error_categories': exception_category(error),
            'limitations': ['Protocol observation obligation unresolved; no Finding admitted']}
