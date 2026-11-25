"""Render production service and ingress files into a NEW directory for inspection."""
import argparse
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('host')
parser.add_argument('output', type=Path)
args = parser.parse_args()
label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
if len(args.host) > 253 or not re.fullmatch(rf'{label}(?:\.{label})+', args.host):
    parser.error('expected a lowercase DNS name')
templates = Path(__file__).resolve().parents[1] / 'remote-mcp-staging'
proxy = (templates / 'nginx.conf.template').read_text().replace('__STAGING_HOST__', args.host)
proxy = proxy.replace('synkrita-staging', 'synkrita').replace('    server_name _;', '    server_name _;\n    access_log off;')
proxy = ("log_format synkrita_counts '$time_iso8601 $status $request_time $limit_req_status';\n"
         + proxy.replace('    access_log off;\n    error_log', '    access_log /var/log/nginx/synkrita-counts.log synkrita_counts;\n    error_log'))
unit = (templates / 'synkrita-staging.service').read_text().replace('synkrita-staging', 'synkrita')
unit = unit.replace('synthetic MCP staging', 'remote MCP').replace('staging.sqlite', 'research.sqlite')
unit = unit.replace('[Service]', 'AssertPathExists=/var/lib/synkrita/research.sqlite\nAssertPathExists=/etc/synkrita/oauth.json\n\n[Service]\nLimitCORE=0')
args.output.mkdir(mode=0o700)
(args.output / 'synkrita.service').write_text(unit)
(args.output / 'synkrita.conf').write_text(proxy)
