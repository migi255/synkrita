"""Official SDK session adapter. Session lifecycle belongs to the caller."""
from synkrita.models import Capability, digest, canonical
from synkrita.core import schema_validator
from synkrita.metrics import UpstreamMetrics


class McpAdapter:
    def __init__(self, session, identity, *, view='public', allowed_operations=('lookup',), metrics=None,
                 max_tools=256, max_catalogue_bytes=524288):
        self.session = session
        self.identity = identity
        self.view = view
        self.allowed_operations = frozenset(allowed_operations)
        self.upstream = metrics or UpstreamMetrics()
        self._catalogue_checked = False
        self.max_tools, self.max_catalogue_bytes = max_tools, max_catalogue_bytes

    async def _list_page(self, cursor):
        if cursor is None:
            return await self.session.list_tools()
        from mcp.types import PaginatedRequestParams
        return await self.session.list_tools(params=PaginatedRequestParams(cursor=cursor))

    async def _tools(self):
        self._catalogue_checked = False
        tools = []
        cursor = None
        seen = set()
        for _ in range(16):
            page = await self._list_page(cursor)
            tools.extend(page.tools)
            if len(tools) > self.max_tools or sum(len(canonical({'name': t.name, 'input': t.inputSchema, 'output': t.outputSchema}).encode()) for t in tools) > self.max_catalogue_bytes:
                raise ValueError('MCP catalogue exceeds its tool or byte budget')
            cursor = page.nextCursor
            for tool in page.tools:
                schema_validator(tool.inputSchema)
                if tool.outputSchema is not None:
                    schema_validator(tool.outputSchema)
            if not cursor:
                names = [tool.name for tool in tools]
                if len(names) != len(set(names)):
                    raise ValueError('Ambiguous duplicate MCP tool')
                self._catalogue_checked = True
                return tools
            if cursor in seen:
                raise ValueError('Repeated MCP discovery cursor')
            seen.add(cursor)
        raise ValueError("Tool discovery page bound exceeded")

    async def revision(self):
        # A full catalogue digest observes interface shape, never backing data.
        tools = await self._tools()
        return {'interface': digest(sorted([t.model_dump(mode='json') for t in tools], key=lambda t: t['name'])),
                'data': None}

    async def discover(self):
        return [Capability(t.name, t.inputSchema, t.outputSchema or {},
                           ['MCP catalogue is a declaration; backing data revision unknown'])
                for t in await self._tools()]

    async def invoke(self, name, arguments):
        if name not in self.allowed_operations:
            raise ValueError('MCP operation not authorized by operator policy')
        if not self._catalogue_checked:
            await self._tools()
        result = await self.session.call_tool(name, arguments)
        if result.isError:
            raise ValueError("MCP tool application error")
        if len(result.model_dump_json().encode()) > 65536:
            raise ValueError("MCP response exceeds byte bound")
        if result.structuredContent is None:
            raise ValueError("This MCP profile requires structured output")
        return result.structuredContent
