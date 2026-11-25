"""Operator-configured fixture connections using SDK-owned lifecycle."""
from contextlib import asynccontextmanager
from datetime import timedelta
import sys
from synkrita.adapters.mcp import McpAdapter
from synkrita.metrics import UpstreamMetrics


def measured_session(read, write, metrics, timeout_seconds):
    """The same SDK request observer for stdio and HTTP."""
    from mcp import ClientSession
    class MeasuredSession(ClientSession):
        async def send_request(self, request, *args, **kwargs):
            start = metrics.record(request.root.method)
            failed = True
            try:
                result = await super().send_request(request, *args, **kwargs)
                failed = False
                return result
            finally:
                metrics.finish(start, failed)
    return MeasuredSession(read, write, read_timeout_seconds=timedelta(seconds=timeout_seconds))


@asynccontextmanager
async def stdio_session(command, args, *, timeout_seconds=10):
    from mcp import StdioServerParameters
    from mcp.client.stdio import stdio_client
    metrics = UpstreamMetrics()
    params = StdioServerParameters(command=command, args=args)
    async with stdio_client(params) as (read, write):
        async with measured_session(read, write, metrics, timeout_seconds) as session:
            await session.initialize()
            yield session, metrics


@asynccontextmanager
async def fixture_mcp(state_path, *, timeout_seconds=10):
    async with stdio_session(sys.executable, ['-m', 'synkrita', 'fixture-mcp', str(state_path)],
                             timeout_seconds=timeout_seconds) as (session, metrics):
        yield McpAdapter(session, 'fixture:mcp:catalogue', metrics=metrics)
