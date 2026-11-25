"""Explicit REST manifest/revision/read-only profile; no universal REST discovery."""
from urllib.parse import urlsplit
from synkrita.models import Capability
from synkrita.metrics import UpstreamMetrics


class RestAdapter:
    def __init__(self, client, base_url, *, view='public', max_pages=16):
        url = urlsplit(base_url)
        if (url.scheme not in ('http', 'https') or not url.hostname or url.username or
                url.password or url.query or url.fragment):
            raise ValueError('Use a credential-free configured HTTP base URL')
        self.client, self.view, self.max_pages = client, view, max_pages
        self.identity = base_url.rstrip('/')
        self.upstream = UpstreamMetrics()

    async def _get(self, path, params=None):
        # Stream bytes to enforce the bound before buffering an entire response.
        start = self.upstream.record('GET ' + path)
        failed = True
        try:
            async with self.client.stream('GET', self.identity + path, params=params, follow_redirects=False) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 65536:
                        raise ValueError('Response exceeds byte bound')
                import json
                result = json.loads(body)
                if isinstance(result, dict) and 'error' in result:
                    raise ValueError('Source application error')
                failed = False
                return result
        finally:
            self.upstream.finish(start, failed)

    async def revision(self):
        return await self._get('/revision')

    async def discover(self):
        capabilities, cursor, seen = [], None, set()
        for _ in range(self.max_pages):
            result = await self._get('/capabilities', {'cursor': cursor} if cursor else None)
            if isinstance(result, list):
                items, cursor = result, None
            else:
                if set(result) != {'items', 'next_cursor'}:
                    raise ValueError('Invalid capability page')
                items, cursor = result['items'], result['next_cursor']
            capabilities.extend(Capability(**item) for item in items)
            if not cursor:
                names = [c.name for c in capabilities]
                if len(names) != len(set(names)):
                    raise ValueError('Ambiguous duplicate capability')
                return capabilities
            if not isinstance(cursor, str) or cursor in seen:
                raise ValueError('Invalid or repeated capability cursor')
            seen.add(cursor)
        raise ValueError('Capability discovery page bound exceeded')

    async def invoke(self, name, arguments):
        if name != 'lookup':
            raise ValueError('Operation not authorized by this REST profile')
        result = await self._get('/lookup', arguments)
        if isinstance(result, dict) and ('next_cursor' in result or 'next' in result):
            raise ValueError('Paginated lookup requires a separately qualified adapter')
        if isinstance(result, dict) and result.get('identifier') != arguments.get('identifier'):
            raise ValueError('Lookup response identifier mismatch')
        return result
