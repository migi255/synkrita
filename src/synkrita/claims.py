"""Small evidence-linked records in Store, not a general claim graph or arbiter.

Reported statements are attributed projections of retained responses. Derivation
is restricted to comparing reports; citations never confer semantic authority.
"""
from copy import deepcopy
import math
import re

from synkrita.core import validate
from synkrita.models import canonical, digest


VERSION = 'claim-v1'
FRAME = ('unit', 'context', 'version', 'definition')


def select(value, pointer):
    """Resolve a canonical RFC 6901 pointer; no queries or code evaluation."""
    if not isinstance(pointer, str) or not pointer.startswith('/') or len(pointer) > 2048:
        raise ValueError('Require a bounded non-root JSON Pointer')
    for token in pointer[1:].split('/'):
        if re.search(r'~(?![01])', token):
            raise ValueError('Invalid JSON Pointer escape')
        token = token.replace('~1', '/').replace('~0', '~')
        try:
            if isinstance(value, list):
                if not re.fullmatch(r'0|[1-9][0-9]*', token):
                    raise ValueError('Invalid array selector')
                value = value[int(token)]
            elif isinstance(value, dict):
                value = value[token]
            else:
                raise ValueError('Selector traverses a scalar')
        except (KeyError, IndexError) as error:
            raise ValueError('Evidence selector is missing') from error
    return deepcopy(value)


def evidence_id(reference):
    return 'ev-' + digest(reference)


def resolve_evidence(store, reference, *, view='public'):
    if (set(reference) != {'record', 'selectors', 'kind'} or reference['kind'] not in ('observation', 'diagnostic') or
            not isinstance(reference['selectors'], dict) or not 1 <= len(reference['selectors']) <= 16 or
            any(not isinstance(key, str) or not 0 < len(key) <= 128 for key in reference['selectors'])):
        raise ValueError('Unsupported evidence reference')
    receipt = store.get_visible(reference['record'], view=view)
    extraction_origin = None
    if 'extraction' in receipt:
        from synkrita.large_observations import verify_extracted
        extraction_origin = verify_extracted(store, receipt, view=view)
    if 'literature_origin' in receipt:
        from synkrita.literature import verify
        extraction_origin = verify(store, receipt, view)
    if 'entity_extraction' in receipt:
        from synkrita.experiments.publication_transfer import verify
        extraction_origin = verify(store, receipt, view)
    if reference['kind'] == 'observation':
        validate(receipt['capability'], receipt['arguments'], receipt['output'])
        observed_at = receipt.get('observed_at')
        if type(observed_at) not in (int, float) or not math.isfinite(observed_at):
            raise ValueError('Observation retrieval time is unresolved')
        if any(not isinstance(path, str) or not path.startswith('/output/')
               for path in reference['selectors'].values()):
            raise ValueError('Observation selectors must identify response data')
        method, arguments = receipt['capability']['name'], receipt['arguments']
    else:
        if 'output' in receipt or 'category' not in receipt or set(reference['selectors'].values()) != {'/category'}:
            raise ValueError('Diagnostics cannot stand in for source observations')
        method, arguments = receipt.get('operation'), None
    selected = {name: select(receipt, path) for name, path in reference['selectors'].items()}
    return {'id': evidence_id(reference), 'reference': deepcopy(reference), 'selected': selected,
        **({'extraction_origin': extraction_origin} if extraction_origin is not None else {}),
        'source_identity': receipt['identity'], 'view': receipt['view'], 'method': method,
        'arguments': arguments, 'observed_at': receipt.get('observed_at'), 'interface': receipt.get('interface'),
        'receipt_sha256': digest(receipt), 'freshness': 'retained_observation_only; current source contents unchecked'}


def reported_claim(store, receipt, selectors, *, subject_scope=None, single_valued=False, view='public'):
    """Select a literal source report. The caller cannot supply a fabricated value."""
    reference = {'record': receipt, 'selectors': deepcopy(selectors), 'kind': 'observation'}
    evidence = resolve_evidence(store, reference, view=view)
    if {'subject', 'predicate', 'value'} <= set(selectors) and any(
            not isinstance(evidence['selected'][key], str) or not evidence['selected'][key]
            for key in ('subject', 'predicate')):
        raise ValueError('Require explicit subject and predicate strings')
    if subject_scope is not None and (not isinstance(subject_scope, str) or not 0 < len(subject_scope) <= 256):
        raise ValueError('Invalid operator-declared subject scope')
    if type(single_valued) is not bool:
        raise ValueError('Value cardinality must be an explicit operator condition')
    return store.put('claim', {'version': VERSION, 'kind': 'reported', 'view': view,
        'projection': 'literal-response-fields-v1', 'evidence': [reference],
        'subject_scope': subject_scope, 'identity_authority': 'operator_configured; not source identity proof',
        'value_semantics': 'single_value_per_frame' if single_valued else 'unspecified',
        'dependencies': [receipt]})


def interpretation(store, text, *, dependencies=(), evidence=(), view='public'):
    """Keep an interpretation inspectable without promoting its cited content."""
    if not isinstance(text, str) or not 0 < len(text) <= 4096 or len(dependencies) > 16 or len(evidence) > 16:
        raise ValueError('Interpretation exceeds the bounded contract')
    for identifier in dependencies:
        resolve_claim(store, identifier, view=view)
    for reference in evidence:
        resolve_evidence(store, reference, view=view)
    return store.put('claim', {'version': VERSION, 'kind': 'interpretation', 'view': view,
        'text': text, 'claim_dependencies': list(dependencies), 'evidence': deepcopy(list(evidence)),
        'dependencies': list(dependencies) + [item['record'] for item in evidence]})


def comparison(left, right):
    """Classify comparability; never choose which source is true."""
    if left['kind'] != 'reported' or right['kind'] != 'reported':
        raise ValueError('Comparison accepts attributed reports only')
    a, b = left['fields'], right['fields']
    if any(not {'subject', 'predicate', 'value'} <= set(item) for item in (a, b)):
        return {'classification': 'insufficient_information', 'differences': ['proposition_unestablished']}
    if a['subject'] != b['subject'] or a['predicate'] != b['predicate']:
        return {'classification': 'different_propositions', 'differences': ['subject_or_predicate']}
    if not left['subject_scope'] or left['subject_scope'] != right['subject_scope']:
        return {'classification': 'insufficient_information', 'differences': ['subject_identity_unestablished']}
    if any(item['value_semantics'] != 'single_value_per_frame' for item in (left, right)):
        return {'classification': 'insufficient_information', 'differences': ['value_semantics_unestablished']}
    missing = [key for key in FRAME if any(not isinstance(item.get(key), str) or not item[key] for item in (a, b))]
    if missing:
        return {'classification': 'insufficient_information', 'differences': missing}
    differences = [key for key in FRAME if canonical(a[key]) != canonical(b[key])]
    if differences:
        return {'classification': 'different_conditions', 'differences': differences}
    def category(value):
        return 'number' if type(value) in (int, float) else type(value).__name__
    if a['value'] is None or b['value'] is None:
        return {'classification': 'insufficient_information', 'differences': ['value_unavailable']}
    if category(a['value']) != category(b['value']) or category(a['value']) not in ('number', 'str', 'bool'):
        return {'classification': 'insufficient_information', 'differences': ['value_type']}
    equal = a['value'] == b['value']
    if left['sources'] == right['sources'] and left['observed_at'] != right['observed_at'] and not equal:
        return {'classification': 'historical_change', 'differences': ['observation_time']}
    return {'classification': 'agreement' if equal else 'conflicting_reports', 'differences': []}


def compare_claims(store, left, right, *, view='public'):
    # Validate before admission; read-time resolution will replay the same rule.
    comparison(resolve_claim(store, left, view=view), resolve_claim(store, right, view=view))
    return store.put('claim', {'version': VERSION, 'kind': 'derived', 'view': view,
        'rule': 'compare-source-reports-v1', 'claim_dependencies': [left, right], 'dependencies': [left, right],
        'assumptions': ['Literal context/unit/version/definition equality under the configured shared subject scope',
                        'The operator declares one value per subject, predicate and comparison frame',
                        'Reports may conflict; no scientific truth, source ranking or completeness inferred']})


def resolve_claim(store, identifier, *, view='public', _depth=0, _budget=None):
    if _budget is None:
        _budget = [128]
    _budget[0] -= 1
    if _depth >= 16 or _budget[0] < 0:
        raise ValueError('Claim dependency depth exceeded')
    record = store.get(identifier)
    if record.get('version') != VERSION or record.get('view') != view:
        raise ValueError('Unsupported claim version or view')
    kind = record['kind']
    if len(record.get('evidence', [])) > 16 or len(record.get('claim_dependencies', [])) > 16:
        raise ValueError('Claim dependency budget exceeded')
    evidence = [resolve_evidence(store, ref, view=view) for ref in record.get('evidence', [])]
    parents = [resolve_claim(store, key, view=view, _depth=_depth + 1, _budget=_budget)
               for key in record.get('claim_dependencies', [])]
    if len(evidence) > 16 or len(parents) > 16:
        raise ValueError('Claim dependency budget exceeded')
    if kind == 'reported':
        if (record.get('projection') != 'literal-response-fields-v1' or len(evidence) != 1 or parents or
                evidence[0]['reference']['kind'] != 'observation'):
            raise ValueError('Unsupported report projection')
        fields = evidence[0]['selected']
        if {'subject', 'predicate', 'value'} <= set(fields) and any(
                not isinstance(fields[key], str) or not fields[key] for key in ('subject', 'predicate')):
            raise ValueError('Invalid attributed proposition')
        content = {'status': 'source_attributed', 'fields': fields, 'subject_scope': record['subject_scope'],
                   'value_semantics': record['value_semantics'],
                   'sources': [evidence[0]['source_identity']], 'observed_at': [evidence[0]['observed_at']]}
    elif kind == 'derived':
        if record.get('rule') != 'compare-source-reports-v1' or len(parents) != 2 or evidence:
            raise ValueError('No validated derivation rule for this claim')
        content = {'status': 'derived_from_reports', 'rule': record['rule'], 'assessment': comparison(*parents),
                   'assumptions': record['assumptions']}
    elif kind == 'interpretation':
        content = {'status': 'requires_validation', 'text': record['text']}
    else:
        raise ValueError('Unsupported claim kind')
    references = {item['id']: item for item in evidence}
    for parent in parents:
        references.update({item['id']: item for item in parent['evidence']})
    return {'id': identifier, 'kind': kind, **content, 'evidence': list(references.values()),
        'claim_dependencies': record.get('claim_dependencies', []),
        'scientific_truth_established': False, 'current_source_contents_checked': False}


def cited_answer(store, claim_ids, *, view='public'):
    if not 1 <= len(claim_ids) <= 64:
        raise ValueError('Answer claim budget exceeded')
    claims = [resolve_claim(store, identifier, view=view) for identifier in claim_ids]
    citations = {item['id']: item['reference'] for claim in claims for item in claim['evidence']}
    return store.put('cited_answer', {'version': 'cited-answer-v1', 'view': view,
        'claims': list(claim_ids), 'citations': citations, 'dependencies': list(claim_ids)})


def resolve_answer(store, identifier, *, view='public'):
    answer = store.get(identifier)
    if answer.get('version') != 'cited-answer-v1' or answer.get('view') != view or not 1 <= len(answer['claims']) <= 64:
        raise ValueError('Unsupported answer or view')
    claims = [resolve_claim(store, key, view=view) for key in answer['claims']]
    citations = {item['id']: item for claim in claims for item in claim['evidence']}
    if answer['citations'] != {key: item['reference'] for key, item in citations.items()}:
        raise ValueError('Citation manifest does not match claim evidence')
    return {'id': identifier, 'version': 'cited-answer-v1', 'claims': claims, 'citations': citations}


def resolve_citation(store, answer_id, citation, *, view='public'):
    answer = resolve_answer(store, answer_id, view=view)
    if citation not in answer['citations']:
        raise ValueError('Citation is not part of this answer')
    return answer['citations'][citation]
