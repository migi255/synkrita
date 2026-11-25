"""Bounded offline PubMed XML evidence; no network or support classifier."""
import base64
from datetime import datetime
import hashlib
import xml.etree.ElementTree as ET

from synkrita.core import validate
from synkrita.large_observations import put_once

PROFILE = 'pubmed-two-abstracts-v1'
ENDPOINT = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi'
PARAMS = {'db': 'pubmed', 'id': '2785270,8390218', 'retmode': 'xml', 'tool': 'synkrita'}
IDS = {'2785270', '8390218'}
CAP = {'name': 'efetch_pubmed_abstracts', 'input_schema': {'const': PARAMS},
    'output_schema': {'type': 'object', 'required': ['pmid', 'title', 'sections'], 'properties': {
        'pmid': {'enum': sorted(IDS)}, 'title': {'type': 'string', 'maxLength': 4096},
        'sections': {'type': 'array', 'maxItems': 16, 'items': {'type': 'object',
            'required': ['label', 'text'], 'properties': {'label': {'type': 'string', 'maxLength': 256},
            'text': {'type': 'string', 'maxLength': 16000}}, 'additionalProperties': False}}},
        'additionalProperties': False}, 'limitations': ['Parsed abstract, not scientific verification']}


def parse(raw):
    if len(raw) > 65536 or b'<!ENTITY' in raw.upper():
        raise ValueError('XML budget exceeded or entity declarations forbidden')
    try:
        if '\x00' in raw.decode('utf-8'):
            raise ValueError('Require UTF-8 XML without NUL bytes')
    except UnicodeError as error:
        raise ValueError('Require UTF-8 XML') from error
    parser = ET.XMLPullParser(events=('start', 'end'))
    depth = nodes = 0
    try:
        for offset in range(0, len(raw), 1024):
            parser.feed(raw[offset:offset + 1024])
            for event, node in parser.read_events():
                if event == 'start':
                    depth += 1
                    nodes += 1
                    if depth > 24 or nodes > 5000:
                        raise ValueError('XML structure budget exceeded')
                else:
                    depth -= 1
                    if len(node.text or '') > 16000 or len(node.tail or '') > 16000:
                        raise ValueError('XML text budget exceeded')
        parser.close()
        root = ET.fromstring(raw)  # Bounded document; external DTDs are not fetched.
    except ET.ParseError as error:
        raise ValueError('Malformed or truncated XML') from error
    if root.tag != 'PubmedArticleSet' or any(x.tag != 'PubmedArticle' for x in root):
        raise ValueError('Unsupported PubMed envelope')
    records = {}
    for article in root:
        pmids = article.findall('MedlineCitation/PMID')
        if len(pmids) != 1 or pmids[0].text not in IDS or pmids[0].text in records:
            raise ValueError('Unexpected or duplicate publication')
        pmid = pmids[0].text
        titles = article.findall('MedlineCitation/Article/ArticleTitle')
        if len(titles) != 1:
            raise ValueError('Missing or ambiguous article title')
        row = {'pmid': pmid, 'title': ''.join(titles[0].itertext()), 'sections': [
            {'label': x.get('Label', ''), 'text': ''.join(x.itertext())}
            for x in article.findall('MedlineCitation/Article/Abstract/AbstractText')]}
        validate(CAP, PARAMS, row)
        records[pmid] = row
    if set(records) != IDS:
        raise ValueError('Requested publication missing')
    return records


def ingest(store, raw, metadata):
    if (metadata.get('endpoint'), metadata.get('method'), metadata.get('parameters'),
            metadata.get('request_attempts'), metadata.get('status'), metadata.get('complete_body_received')) != (
            ENDPOINT, 'GET', PARAMS, 1, 200, True):
        raise ValueError('Retrieval scope or status mismatch')
    if metadata.get('retries') != 0 or metadata.get('redirects') is not False:
        raise ValueError('Retrieval exceeded approved boundary')
    sha = hashlib.sha256(raw).hexdigest()
    if sha != metadata.get('sha256') or len(raw) != metadata.get('bytes'):
        raise ValueError('XML capture checksum mismatch')
    if store.source('pubmed') != (ENDPOINT, 'public'):
        raise ValueError('Historical source registration mismatch')
    records = parse(raw)
    artifact = {'identity': ENDPOINT, 'view': 'public', 'profile': PROFILE,
        'raw_base64': base64.b64encode(raw).decode(), 'raw_sha256': sha, 'metadata': metadata}
    parent = put_once(store, 'raw_response_artifact', artifact)
    result = {}
    for pmid, row in records.items():
        receipt = {'identity': ENDPOINT, 'view': 'public', 'operation': CAP['name'], 'arguments': PARAMS,
            'observed_at': datetime.fromisoformat(metadata['completed_at']).timestamp(),
            'capability': CAP, 'interface': PROFILE, 'output': row,
            'literature_origin': {'profile': PROFILE, 'artifact': parent, 'pmid': pmid},
            'dependencies': [parent], 'findings_admitted': 0}
        result[pmid] = put_once(store, 'literature_observation', receipt)
    return result


def verify(store, receipt, view):
    origin = receipt['literature_origin']
    artifact = store.get_visible(origin['artifact'], view=view)
    if origin.get('profile') != PROFILE or artifact.get('profile') != PROFILE or receipt['capability'] != CAP:
        raise ValueError('Unsupported literature provenance')
    encoded = artifact['raw_base64']
    if len(encoded) > 4 * ((65536 + 2) // 3):
        raise ValueError('XML artifact budget exceeded')
    raw = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(raw).hexdigest() != artifact['raw_sha256']:
        raise ValueError('XML artifact checksum mismatch')
    pmid = origin['pmid']
    from synkrita.validation_reuse import checked_artifact
    rows = checked_artifact(store, PROFILE, artifact, lambda: parse(raw))
    if (receipt['output'] != rows.get(pmid) or receipt['arguments'] != PARAMS or
            receipt['identity'] != ENDPOINT or receipt['dependencies'] != [origin['artifact']] or
            receipt['observed_at'] != datetime.fromisoformat(artifact['metadata']['completed_at']).timestamp()):
        raise ValueError('Literature projection differs from original XML')
    return {'profile': PROFILE, 'artifact': origin['artifact'], 'raw_sha256': artifact['raw_sha256'],
        'raw_bytes': len(raw), 'outer_pointer': f"/PubmedArticleSet/PubmedArticle[MedlineCitation/PMID='{pmid}']",
        'decoded_pointer': 'MedlineCitation/Article/Abstract/AbstractText (zero-based sections; XML itertext)',
        'representation': 'XML projection verified against original response', 'original_capability': CAP}
