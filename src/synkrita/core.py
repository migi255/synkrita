"""Deterministic bounded discovery, witness admission and current-use validation."""
import asyncio
from dataclasses import asdict
import time
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError, SchemaError
from synkrita.models import Finding
from synkrita.privacy import retention_safe


def schema_validator(schema):
    # Source schemas are data, not authority to retrieve remote schemas.
    def check(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ('$ref', '$dynamicRef') and (not isinstance(child, str) or not child.startswith('#')):
                    raise ValueError('External schema references are not authorized')
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(schema)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate(capability, arguments, output):
    schema_validator(capability['input_schema']).validate(arguments)
    if not capability['output_schema']:
        raise ValueError('No qualified output schema')
    schema_validator(capability['output_schema']).validate(output)


def assess(store, finding, identity, view, revision, use, now, metrics=None):
    reasons = []
    if (finding['identity'], finding['view']) != (identity, view):
        reasons.append('source or authorized view mismatch')
    if finding['status'] != 'validated' or finding['validator'] != 'schema-witness-v1':
        reasons.append('unsupported validation status')
    if use != finding['intended_use']:
        reasons.append('requested use is not licensed by a schema witness')
    if not revision.get('interface') or finding['interface'] != revision['interface']:
        reasons.append('interface changed or unknown')
    if now - finding['observed_at'] > finding['max_age_seconds']:
        reasons.append('witness expired')
    try:
        receipt = store.get(finding['receipt'])
        if (receipt['identity'], receipt['view'], receipt['capability'], receipt['interface']) != (
                identity, view, finding['capability'], finding['interface']):
            raise ValueError('receipt scope mismatch')
        def validate_witness():
            if metrics is not None:
                metrics['local_output_validations'] += 1
            validate(receipt['capability'], receipt['arguments'], receipt['output'])
        from synkrita.validation_reuse import checked_artifact
        checked_artifact(store, 'schema-witness-v1', receipt, validate_witness)
        for dependency in finding['dependencies']:
            if store.get(dependency).get('status') != 'validated':
                raise ValueError('dependency ineligible')
    except (ValueError, KeyError, ValidationError, SchemaError) as error:
        reasons.append(str(error) if isinstance(error, (ValueError, KeyError)) else 'Supporting schema validation failed')
    return {'eligible': not reasons, 'reasons': reasons,
            'limitations': ['Witness supports a candidate invocation only; no completeness or meaning claim']}


class Investigator:
    def __init__(self, store, adapters, *, clock=time.time, max_calls=8, timeout_seconds=10):
        self.store, self.adapters, self.clock, self.max_calls = store, adapters, clock, max_calls
        self.timeout_seconds = timeout_seconds

    async def investigate(self, source, operation, arguments, *, probe, view='public', use='invoke_candidate'):
        start = time.perf_counter()
        metrics = {'tool_calls': 0, 'exploratory_calls': 0, 'validation_calls': 0,
                   'answer_calls': 0, 'local_output_validations': 0, 'model_tokens': 0, 'model_cost_usd': 0}
        receipts, rejected = [], []
        adapter = self.adapters[source]
        identity, authorized_view = self.store.source(source)
        if (identity, authorized_view, getattr(adapter, 'view', None)) != (adapter.identity, view, view):
            raise ValueError('Source identity or authorized view mismatch')

        def checked(capability, arguments, output):
            metrics['local_output_validations'] += 1
            validate(capability, arguments, output)

        async def call(role, action, *args):
            if metrics['tool_calls'] >= self.max_calls:
                raise ValueError('Investigation call budget exhausted')
            metrics['tool_calls'] += 1
            metrics[role + '_calls'] += 1
            return await asyncio.wait_for(action(*args), timeout=self.timeout_seconds)

        try:
            retention_safe(arguments)
            retention_safe(probe)
            revision = await call('validation', adapter.revision)
            selected = None
            for identifier, finding in self.store.findings(source, operation, identity=identity, view=view):
                assessment = assess(self.store, finding, identity, view, revision, use, self.clock(), metrics=metrics)
                if assessment['eligible']:
                    selected = (identifier, finding)
                    break
                rejected.append({'finding': identifier, **assessment})
            reused = selected is not None
            if selected is None:
                if use != 'invoke_candidate':
                    raise ValueError('Requested conclusion requires evidence beyond a schema witness')
                declarations = await call('exploratory', adapter.discover)
                declaration_id = self.store.put('declaration', {'source': source, 'identity': identity,
                                               'view': view, 'capabilities': [asdict(c) for c in declarations]})
                matches = [asdict(c) for c in declarations if c.name == operation]
                if len(matches) != 1:
                    raise ValueError('Capability missing or ambiguous')
                capability = matches[0]
                schema_validator(capability['input_schema']).validate(probe)
                output = await call('validation', adapter.invoke, operation, probe)
                checked(capability, probe, output)
                receipt = self.store.put('receipt', {'identity': identity, 'view': view,
                    'capability': capability, 'interface': revision.get('interface'), 'arguments': probe,
                    'output': output, 'observed_at': self.clock(), 'declaration': declaration_id})
                receipts.append(receipt)
                finding = asdict(Finding(source, identity, view, capability, revision.get('interface'),
                                         receipt, self.clock()))
                identifier = self.store.put('finding', finding)
                selected = (identifier, finding)
            identifier, finding = selected
            capability = finding['capability']
            schema_validator(capability['input_schema']).validate(arguments)
            output = await call('answer', adapter.invoke, operation, arguments)
            checked(capability, arguments, output)
            # Close discovery/execution races conservatively before emitting an answer.
            after = await call('validation', adapter.revision)
            if after != revision:
                raise ValueError('Source conditions changed during investigation')
            receipt = self.store.put('receipt', {'identity': identity, 'view': view, 'capability': capability,
                'interface': revision.get('interface'), 'data_indicator': revision.get('data'),
                'arguments': arguments, 'output': output, 'observed_at': self.clock()})
            receipts.append(receipt)
            result = {'status': 'observed', 'output': output, 'reused': reused, 'finding': identifier,
                      'assessment': assess(self.store, finding, identity, view, revision, use, self.clock(), metrics=metrics),
                      'limitations': capability['limitations'] + ['Current response only; data freshness and completeness unproven']}
        except Exception as error:
            # Store a bounded diagnostic, not transport messages that might contain credentials.
            failure = self.store.put('failure', {'source': source, 'identity': identity, 'view': view, 'operation': operation,
                                                'category': type(error).__name__})
            receipts.append(failure)
            result = {'status': 'withheld', 'output': None, 'reused': False,
                      'limitations': ['Validation, applicability or execution obligation unresolved'],
                      'failure_category': type(error).__name__}
        metrics['elapsed_ms'] = round((time.perf_counter() - start) * 1000, 3)
        result.update(metrics=metrics, receipts=receipts, rejected=rejected)
        return result
