"""Thin client-facing MCP service over a configured core; no arbitrary execution tool."""
from typing import Any

from mcp.server.fastmcp import FastMCP
from synkrita.core import Investigator
from synkrita.store import Store


def create_server(store, rest_url=None):
    import httpx
    from synkrita.adapters.rest import RestAdapter
    app = FastMCP('Synkrita')

    @app.tool()
    async def inspect_evidence(receipt_id: str) -> dict[str, Any]:
        """Inspect an existing local evidence record (configured public view only)."""
        return store.get_visible(receipt_id, view='public')

    @app.tool()
    async def investigate(identifier: str) -> dict[str, Any]:
        """Investigate the operator-configured REST fixture in the public view."""
        if rest_url is None:
            return {'status': 'withheld', 'limitations': ['No source configured']}
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            adapter = RestAdapter(client, rest_url)
            store.register('rest', adapter.identity)
            return await Investigator(store, {'rest': adapter}).investigate('rest', 'lookup',
                                  {'identifier': identifier}, probe={'identifier': 'item:1'})
    return app


def serve(database, rest_url=None):
    store = Store(database)
    try:
        app = create_server(store, rest_url)
        app.run(transport='stdio')
    finally:
        store.close()
