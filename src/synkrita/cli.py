import argparse
import asyncio
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(prog='synkrita')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('render-answer', 'resolve-citation'):
        cited = commands.add_parser(name, help='Render retained claims or resolve an exact answer citation')
        cited.add_argument('database')
        cited.add_argument('answer')
        cited.add_argument('--view', default='public')
        if name == 'render-answer':
            cited.add_argument('--format', choices=('markdown', 'json'), default='markdown')
            cited.add_argument('--output', type=Path)
        else:
            cited.add_argument('citation')
    for name in ('mcp-discover', 'mcp-observe', 'mcp-probe'):
        remote = commands.add_parser(name, help='Bounded remote MCP declaration discovery or explicitly permitted investigation')
        remote.add_argument('--config', type=Path, required=True)
        remote.add_argument('--source', required=True)
        remote.add_argument('--database', required=True)
        remote.add_argument('--output', type=Path)
        if name != 'mcp-discover':
            remote.add_argument('--operation', required=True)
            remote.add_argument('--arguments-file', type=Path, required=True)
        if name == 'mcp-probe':
            remote.add_argument('--probe-file', type=Path, required=True)
    serve = commands.add_parser('serve', help='Expose local evidence and configured investigation through MCP stdio')
    serve.add_argument('--database', default='synkrita.sqlite')
    serve.add_argument('--rest-url')
    inspect = commands.add_parser('inspect')
    inspect.add_argument('database')
    inspect.add_argument('receipt')
    payload = commands.add_parser('validate-payload', help='Assess retained metadata structure offline; admit no Findings')
    payload.add_argument('database')
    payload.add_argument('receipt')
    payload.add_argument('--contract', required=True)
    from synkrita import pilot_cli
    pilot_cli.add_parser(commands)
    args = parser.parse_args()
    if args.command == 'remote-mcp':
        pilot_cli.run(args, parser)
    elif args.command in ('render-answer', 'resolve-citation'):
        from synkrita.claims import resolve_answer, resolve_citation
        from synkrita.citations import render_markdown
        from synkrita.store import Store
        store = Store(args.database)
        try:
            if args.command == 'render-answer':
                result = resolve_answer(store, args.answer, view=args.view)
                rendered = render_markdown(result) if args.format == 'markdown' else json.dumps(result, indent=2) + '\n'
                if args.output:
                    args.output.write_text(rendered)
            else:
                rendered = json.dumps(resolve_citation(store, args.answer, args.citation, view=args.view), indent=2) + '\n'
            print(rendered, end='')
        except (ValueError, KeyError) as error:
            parser.error(f'Claim evidence unavailable: {type(error).__name__}')
        finally:
            store.close()
    elif args.command in ('mcp-discover', 'mcp-observe', 'mcp-probe'):
        from synkrita.remote import load_sources, discover_remote, observe_remote, investigate_remote
        from synkrita.store import Store
        try:
            source = load_sources(args.config)[args.source]
        except (KeyError, ValueError, TypeError) as error:
            parser.error(f'Invalid source policy: {type(error).__name__}')
        store = Store(args.database)
        try:
            if args.command == 'mcp-discover':
                result = asyncio.run(discover_remote(store, args.source, source))
            elif args.command == 'mcp-observe':
                result = asyncio.run(observe_remote(store, args.source, source, args.operation,
                    json.loads(args.arguments_file.read_text())))
            else:
                result = asyncio.run(investigate_remote(store, args.source, source, args.operation,
                    json.loads(args.arguments_file.read_text()), json.loads(args.probe_file.read_text())))
            rendered = json.dumps(result, indent=2)
            if args.output:
                args.output.write_text(rendered + '\n')
                args.output.chmod(0o600)
            print(rendered)
            if result['status'] in ('blocked', 'withheld'):
                raise SystemExit(1)
        except ValueError as error:
            parser.error(str(error))
        finally:
            store.close()
    elif args.command == 'serve':
        from synkrita.server import serve
        serve(args.database, args.rest_url)
    else:
        from synkrita.store import Store
        store = Store(args.database)
        try:
            if args.command == 'validate-payload':
                from synkrita.payloads import validate_observation
                try:
                    result = validate_observation(store, args.receipt, args.contract)
                except (ValueError, KeyError) as error:
                    parser.error(f'Payload validation withheld: {type(error).__name__}')
            else:
                result = store.get(args.receipt)
            print(json.dumps(result, indent=2))
        finally:
            store.close()
