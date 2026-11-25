"""Pure Markdown presentation of a resolved answer; no storage or truth decisions."""
import json
import re


def text(value):
    value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True, sort_keys=True)
    value = value.replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'([\\`*_{}\[\]<>()#+!|])', r'\\\1', value)


def render_markdown(answer):
    lines = ['# Evidence-backed source reports', '',
        'These are attributed observations and limited comparisons, not established scientific truth. '
        'Retained evidence does not establish current source contents or completeness.', '',
        'Comparisons use an explicit shared-subject contract and a single-value-per-frame assumption; '
        'matching labels alone do not establish entity identity.', '']
    for claim in answer['claims']:
        citations = ''.join(f"[^{item['id']}]" for item in claim['evidence'])
        if claim['kind'] == 'reported':
            fields = claim['fields']
            if {'subject', 'predicate', 'value'} <= set(fields):
                scope = '; '.join(f'{key}={text(fields.get(key, "unspecified"))}'
                                  for key in ('unit', 'context', 'version', 'definition'))
                body = (f"{text(claim['sources'][0])} reported {text(fields['subject'])}: "
                        f"{text(fields['predicate'])} = {text(json.dumps(fields['value'], ensure_ascii=True, sort_keys=True))} ({scope}).")
            else:
                body = f"{text(claim['sources'][0])} returned selected response fields (local labels): {text(fields)}."
        elif claim['kind'] == 'derived':
            assessment = claim['assessment']
            labels = {'conflicting_reports': 'Unresolved conflicting reports under comparable declared conditions',
                'agreement': 'Reports agree under comparable declared conditions',
                'different_conditions': 'Apparent disagreement: reports have different conditions',
                'insufficient_information': 'Insufficient information to determine whether reports contradict',
                'different_propositions': 'Reports concern different propositions',
                'historical_change': 'Historical observations changed; earlier evidence remains retained'}
            body = labels[assessment['classification']]
            if assessment['differences']:
                body += ': ' + ', '.join(text(item) for item in assessment['differences'])
            body += '. No source is selected as correct.'
        else:
            body = 'Unvalidated interpretation (not established by its citations): ' + text(claim['text'])
        lines.append(f'- {body} {citations}')
        lines.append('')
    lines += ['## Evidence', '']
    for identifier, evidence in answer['citations'].items():
        reference = evidence['reference']
        origin = evidence.get('extraction_origin')
        origin_note = (f" Extracted representation; original raw artifact {text(origin['artifact'])}; "
            f"SHA-256 {text(origin['raw_sha256'])}; source locator {text(origin['outer_pointer'])}, "
            f"decoded record {text(origin['decoded_pointer'])}; profile {text(origin['profile'])}."
            if origin else '')
        lines.append(f"[^{identifier}]: {text(reference['kind'])}; source {text(evidence['source_identity'])}; "
            f"method {text(evidence['method'])}; arguments {text(evidence['arguments'])}; "
            f"observed_at {text(evidence['observed_at'])}; receipt {text(reference['record'])}; "
            f"selectors {text(reference['selectors'])}; selected data {text(evidence['selected'])}. "
            'This citation resolves to retained evidence, not a source homepage.' + origin_note)
        lines.append('')
    return '\n'.join(lines)
