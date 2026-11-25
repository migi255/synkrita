"""Experimental reviewed-decision contract, not scientific inference or a planner.

Authority is supplied by the trusted operator, never by source payloads. Fixture
reviews stay fixture reviews. Review assertions are not cryptographic identities.
"""
from copy import deepcopy
import math

from synkrita.claims import resolve_evidence
from synkrita.models import canonical, digest
from jsonschema.exceptions import ValidationError, SchemaError


VERSION = 'reviewed-integration-decision-v1-experiment'


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 1024


def _context(value):
    return (isinstance(value, dict) and 1 <= len(value) <= 12 and
            all(_text(k) and _text(v) for k, v in value.items()))


def _time(value):
    return type(value) in (int, float) and math.isfinite(value)


def snapshot(store, references, *, view):
    """Recheck exact premises through the existing scoped citation resolver."""
    if (not isinstance(references, dict) or not 1 <= len(references) <= 4 or
            any(not _text(role) for role in references)):
        raise ValueError('Require one to four explicitly bound evidence roles')
    result = {}
    for role, reference in references.items():
        if not isinstance(reference, dict) or reference.get('kind') != 'observation':
            raise ValueError('Decision premises must be observations')
        evidence = resolve_evidence(store, reference, view=view)
        result[role] = {'reference': deepcopy(reference), 'source': evidence['source_identity'],
            'method': evidence['method'], 'arguments': evidence['arguments'],
            'selectors': reference['selectors'], 'selected_sha256': digest(evidence['selected'])}
    return result


def propose(store, *, statement, scope, allowed_uses, semantics, references, now,
            expires_at, max_evidence_age=60, view='public'):
    """Retain a supplied candidate; this does not approve or discover its meaning."""
    if (not _text(statement) or not _context(scope) or not _context(semantics) or
            not isinstance(allowed_uses, list) or not 1 <= len(allowed_uses) <= 4 or
            any(not _text(use) for use in allowed_uses) or len(set(allowed_uses)) != len(allowed_uses) or
            not _time(now) or not _time(expires_at) or not now < expires_at or
            not _time(max_evidence_age) or not 0 <= max_evidence_age <= 86400):
        raise ValueError('Invalid bounded decision scope or validity interval')
    premises = snapshot(store, references, view=view)
    if set(semantics) != set(premises):
        raise ValueError('Semantic contracts must cover every evidence role')
    record = {'version': VERSION, 'state': 'pending_review', 'view': view,
        'statement': statement, 'scope': deepcopy(scope), 'allowed_uses': list(allowed_uses),
        'semantics': deepcopy(semantics), 'premises': premises, 'created_at': now,
        'expires_at': expires_at, 'max_evidence_age': max_evidence_age,
        'dependencies': [r['record'] for r in references.values()],
        'reassessment_triggers': ['review authority revoked', 'expired decision or evidence',
            'changed selected premises', 'changed retrieval binding', 'changed semantic contract',
            'incompatible context or use', 'unavailable evidence or authorization'],
        'limitations': ['Supplied interpretation; no autonomous scientific discovery',
            'Unobserved semantic changes cannot be detected from unchanged evidence']}
    if len(canonical(record).encode()) > 32768:
        raise ValueError('Decision exceeds byte budget')
    return store.put('experimental_integration_candidate', record)


def record_review(store, candidate_id, *, authority, mode, verdict, basis, reviewed_at):
    """Record an externally supplied attestation, including explicit fixture mode."""
    candidate = store.get(candidate_id)
    if (candidate.get('version') != VERSION or candidate.get('state') != 'pending_review' or
            not _text(authority) or mode not in ('controlled_fixture', 'independent_scientific_review') or
            verdict not in ('approve', 'reject') or not _text(basis) or not _time(reviewed_at) or
            not candidate['created_at'] <= reviewed_at < candidate['expires_at']):
        raise ValueError('Invalid review attestation')
    return store.put('experimental_integration_review', {'version': VERSION, 'candidate': candidate_id,
        'candidate_sha256': digest(candidate), 'authority': authority, 'mode': mode,
        'verdict': verdict, 'basis': basis, 'reviewed_at': reviewed_at,
        'independence': 'simulated_only' if mode == 'controlled_fixture' else 'operator_attested'})


def _authority(review, candidate, policy, review_id):
    grant = policy.get(review['authority'], {})
    if (grant.get('mode') != review['mode'] or grant.get('scope') != candidate['scope'] or
            grant.get('allowed_uses') != candidate['allowed_uses'] or
            review_id in grant.get('revoked_reviews', [])):
        raise ValueError('Review authority or scope is not currently authorized')


def qualify(store, candidate_id, review_id, *, authority_policy, now):
    """Technical admission of the supplied review; never an operational Finding."""
    candidate, review = store.get(candidate_id), store.get(review_id)
    if (candidate.get('version') != VERSION or candidate.get('state') != 'pending_review' or
            review.get('version') != VERSION or review.get('candidate') != candidate_id or
            review.get('candidate_sha256') != digest(candidate) or review.get('verdict') != 'approve' or
            not _time(now) or not review['reviewed_at'] <= now < candidate['expires_at']):
        raise ValueError('Approval is absent, mismatched or expired')
    _authority(review, candidate, authority_policy, review_id)
    original = {role: premise['reference'] for role, premise in candidate['premises'].items()}
    if snapshot(store, original, view=candidate['view']) != candidate['premises']:
        raise ValueError('Reviewed evidence changed')
    return store.put('experimental_integration_decision', {'version': VERSION,
        'state': 'qualified_for_controlled_fixture' if review['mode'] == 'controlled_fixture'
                 else 'qualified_under_operator_attested_review',
        'candidate': candidate_id, 'candidate_sha256': digest(candidate), 'review': review_id,
        'review_sha256': digest(review), 'qualified_at': now,
        'dependencies': [candidate_id, review_id, *candidate['dependencies']]})


def assess(store, decision_id, *, context, use, semantics, current_references,
           authority_policy, now, view='public', allow_fixture=False):
    """Read current bindings, never infer that an old observation is current."""
    try:
        decision = store.get(decision_id)
        if decision.get('version') != VERSION or decision.get('state') not in (
                'qualified_for_controlled_fixture', 'qualified_under_operator_attested_review'):
            raise ValueError('Not a qualified integration decision')
        candidate, review = store.get(decision['candidate']), store.get(decision['review'])
        if (digest(candidate) != decision['candidate_sha256'] or digest(review) != decision['review_sha256'] or
                review['candidate'] != decision['candidate'] or review['candidate_sha256'] != digest(candidate) or
                review['verdict'] != 'approve' or decision['dependencies'] !=
                [decision['candidate'], decision['review'], *candidate['dependencies']]):
            raise ValueError('Decision dependencies or approval changed')
        _authority(review, candidate, authority_policy, decision['review'])
        if review['mode'] == 'controlled_fixture' and not allow_fixture:
            raise ValueError('Simulated review cannot authorize scientific reuse')
        if (not _time(now) or not review['reviewed_at'] <= decision['qualified_at'] <= now < candidate['expires_at']):
            raise ValueError('Decision expired or invalid time')
        if view != candidate['view'] or context != candidate['scope'] or use not in candidate['allowed_uses']:
            raise ValueError('Incompatible context, view or use')
        if semantics != candidate['semantics']:
            raise ValueError('Semantic contract changed')
        # Historical support must remain resolvable even when new receipts have
        # identical selected values. No current binding can erase old premises.
        original = {role: p['reference'] for role, p in candidate['premises'].items()}
        if snapshot(store, original, view=view) != candidate['premises']:
            raise ValueError('Historical premises changed')
        current = snapshot(store, current_references, view=view)
        if set(current) != set(candidate['premises']):
            raise ValueError('Evidence roles changed')
        for role, premise in current.items():
            old = candidate['premises'][role]
            if any(premise[key] != old[key] for key in ('source', 'method', 'arguments', 'selectors')):
                raise ValueError('Retrieval binding changed')
            if premise['selected_sha256'] != old['selected_sha256']:
                raise ValueError('Selected evidence changed')
            observed_at = store.get_visible(premise['reference']['record'], view=view)['observed_at']
            if not _time(observed_at) or not 0 <= now - observed_at <= candidate['max_evidence_age']:
                raise ValueError('Current evidence is stale or future dated')
        return {'eligible': True, 'reason': 'reviewed_scope_and_premises_match',
            'decision': decision_id, 'review_mode': review['mode'],
            'evidence': deepcopy(current_references), 'scientific_truth_established': False,
            'freshness': 'caller_supplied_snapshot; no live source check'}
    except (ValueError, KeyError, TypeError, ValidationError, SchemaError) as error:
        return {'eligible': False, 'reason': str(error), 'decision': decision_id}


def reassess(store, decision_id, **conditions):
    """Append an assessment; withholding neither rewrites nor revokes history."""
    result = assess(store, decision_id, **conditions)
    record = {'version': VERSION, 'decision': decision_id, 'outcome': result,
        'context': deepcopy(conditions['context']), 'use': conditions['use'],
        'semantics': deepcopy(conditions['semantics']), 'view': conditions.get('view', 'public'),
        'assessed_at': conditions['now'], 'evidence': deepcopy(conditions['current_references']),
        'dependencies': [decision_id, *[r['record'] for r in conditions['current_references'].values()]]}
    return {**result, 'assessment': store.put('experimental_integration_reassessment', record)}
