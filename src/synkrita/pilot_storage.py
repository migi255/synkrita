"""Typed hosted catalogue and owner-scoped data over the existing receipt store."""
from contextlib import closing, contextmanager
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema.exceptions import SchemaError, ValidationError

from synkrita.claims import resolve_evidence
from synkrita.experiments import integration_decisions as decisions
from synkrita.models import canonical, digest
from synkrita.pilot_auth import SAFE_ID, Principal, https_url
from synkrita.pilot_usage import USAGE_SCHEMA
from synkrita.privacy import retention_safe
from synkrita.store import Store


ROW_ID = re.compile(r'[0-9a-f]{32}')
SHA = re.compile(r'[0-9a-f]{64}')
LABEL = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}')
PUBLIC_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}')
UNAVAILABLE = {'status': 'unavailable'}
EVIDENCE_ERRORS = (ValueError, TypeError, KeyError, SchemaError, ValidationError, RecursionError)
REVIEW_MODE = 'independent_scientific_review'


SCHEMA = """
CREATE TABLE IF NOT EXISTS hosted_schema (version INTEGER PRIMARY KEY CHECK(version=1));
INSERT OR IGNORE INTO hosted_schema VALUES (1);
CREATE INDEX IF NOT EXISTS hosted_source_identity ON sources(identity, view);
CREATE TABLE IF NOT EXISTS hosted_accounts (
    id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), UNIQUE(issuer, subject)
);
CREATE TABLE IF NOT EXISTS hosted_revoked_grants (
    account TEXT NOT NULL REFERENCES hosted_accounts(id), client TEXT NOT NULL,
    PRIMARY KEY(account, client)
);
CREATE TABLE IF NOT EXISTS hosted_revoked_tokens (digest TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS hosted_investigations (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES hosted_accounts(id),
    question TEXT NOT NULL, notes TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS hosted_owner ON hosted_investigations(owner, id);
CREATE TABLE IF NOT EXISTS hosted_source_policies (
    id TEXT PRIMARY KEY, identity TEXT NOT NULL, operation TEXT NOT NULL,
    contract_sha TEXT NOT NULL, license TEXT NOT NULL, retain_until INTEGER NOT NULL,
    projection TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS hosted_public (
    receipt TEXT PRIMARY KEY REFERENCES records(id), policy TEXT NOT NULL REFERENCES hosted_source_policies(id),
    sha TEXT NOT NULL, UNIQUE(policy, sha)
);
CREATE TABLE IF NOT EXISTS hosted_reviewers (
    id TEXT PRIMARY KEY, public_key TEXT NOT NULL, scope TEXT NOT NULL, uses TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
);
CREATE TABLE IF NOT EXISTS hosted_decisions (
    decision TEXT PRIMARY KEY REFERENCES records(id), candidate TEXT NOT NULL UNIQUE REFERENCES records(id),
    reviewer TEXT NOT NULL REFERENCES hosted_reviewers(id), review_hash TEXT NOT NULL UNIQUE,
    binding TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS hosted_audit (
    id INTEGER PRIMARY KEY, occurred INTEGER NOT NULL, request_id TEXT NOT NULL,
    actor TEXT, client_hash TEXT, action TEXT NOT NULL, outcome TEXT NOT NULL, target TEXT
);
"""


def require_id(value):
    if not isinstance(value, str) or not ROW_ID.fullmatch(value):
        raise ValueError('Expected an internal record ID')
    return value


def private_directory(path):
    parent = Path(path).parent
    status = parent.lstat()
    if (not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid()
            or status.st_mode & 0o077):
        raise ValueError('Database directory must be service-owned and private')
    try:
        status = Path(path).lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid() or status.st_mode & 0o077:
        raise ValueError('Database must be a service-owned private file')


@contextmanager
def read_hosted_database(path):
    private_directory(path)
    with closing(sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro', uri=True,
                                 timeout=0.25)) as db:
        db.execute('PRAGMA trusted_schema=OFF')
        if db.execute('SELECT version FROM hosted_schema').fetchall() != [(1,)]:
            raise ValueError('Unsupported hosted store version')
        yield db


def database_status(path, *, snapshot=False):
    with read_hosted_database(path) as db, db:
        db.execute('BEGIN')
        if snapshot:
            check_integrity(db)
            return {'schema_version': 1, 'integrity': 'ok', 'bytes': Path(path).stat().st_size}
        accounts, active = db.execute('SELECT count(*), coalesce(sum(enabled), 0) FROM hosted_accounts').fetchone()
        audit_head = db.execute('SELECT coalesce(max(id), 0) FROM hosted_audit').fetchone()[0]
        result = {'schema_version': 1, 'database_readable': True, 'bytes': Path(path).stat().st_size,
                  'accounts_active': active, 'accounts_suspended': accounts - active,
                  'audit_head': audit_head}
        if db.execute("SELECT 1 FROM sqlite_schema WHERE name='hosted_usage' AND type='table'").fetchone():
            head = db.execute('SELECT id,observed_ms FROM hosted_usage ORDER BY id DESC LIMIT 1').fetchone()
            run = db.execute(
                'SELECT started_ms,ended_ms,lost,last_loss_ms FROM hosted_usage_runs ORDER BY id DESC LIMIT 1',
            ).fetchone()
            result.update(usage_head=head[0] if head else 0,
                          usage_last_completion_ms=head[1] if head else None,
                          usage_worker_started_ms=run[0] if run else None,
                          usage_worker_ended_ms=run[1] if run else None,
                          usage_run_recorded_losses=run[2] if run else 0,
                          usage_run_last_loss_ms=run[3] if run else None)
        return result


def lookup_account(path, issuer, subject):
    with read_hosted_database(path) as db:
        row = db.execute('SELECT id, enabled FROM hosted_accounts WHERE issuer=? AND subject=?',
                         (issuer, subject)).fetchone()
        return {'account': row[0], 'enabled': bool(row[1])} if row else {'account': None}


def audit_events(path, after=0, limit=100):
    if type(after) is not int or not 0 <= after < 2**63 or type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError('Invalid audit cursor or limit')
    with read_hosted_database(path) as db:
        db.row_factory = sqlite3.Row
        events = [dict(row) for row in db.execute(
            '''SELECT id, occurred, request_id, actor, client_hash, action, outcome, target
               FROM hosted_audit WHERE id > ? ORDER BY id LIMIT ?''', (after, limit),
        )]
        return {'events': events, 'next_after': events[-1]['id'] if events else after}


class HostedStore(Store):
    def __init__(self, path):
        private_directory(path)
        super().__init__(path)
        try:
            self.db.execute('PRAGMA busy_timeout=250')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA synchronous=FULL')
            if self.db.execute('PRAGMA journal_mode').fetchone()[0] not in ('delete', 'truncate', 'persist'):
                raise ValueError('Hosted SQLite requires a durable rollback journal')
            self.db.executescript('BEGIN IMMEDIATE;\n' + SCHEMA + USAGE_SCHEMA + '\nCOMMIT;')
            if self.db.execute('SELECT version FROM hosted_schema').fetchall() != [(1,)]:
                raise ValueError('Unsupported hosted store version')
        except BaseException:
            self.close()
            raise

    @contextmanager
    def transaction(self):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            yield

    def put(self, kind, record):
        # Qualification writes both legacy records inside the activation transaction.
        if self.db.in_transaction:
            return self._insert_record(kind, record)
        return super().put(kind, record)

    def audit(self, action, outcome, *, actor=None, client=None, target=None, request_id=None):
        self.db.execute(
            '''INSERT INTO hosted_audit(occurred, request_id, actor, client_hash, action, outcome, target)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (int(time.time()), request_id or uuid4().hex, actor, digest(client) if client else None,
             action, outcome, target),
        )

    def operator_audit(self, action, target=None):
        self.audit(action, 'committed', actor=f'local-uid:{os.geteuid()}', target=target)

    def enroll(self, issuer, subject):
        https_url(issuer)
        if not isinstance(subject, str) or not SAFE_ID.fullmatch(subject) or subject.endswith('@clients'):
            raise ValueError('Invalid account subject')
        retention_safe(subject)
        account = uuid4().hex
        with self.transaction():
            self.db.execute('INSERT INTO hosted_accounts VALUES (?, ?, ?, 1)', (account, issuer, subject))
            self.operator_audit('account_enroll', account)
        return account

    def disable_account(self, account):
        with self.transaction():
            if not self.db.execute('UPDATE hosted_accounts SET enabled=0 WHERE id=? AND enabled=1',
                                   (require_id(account),)).rowcount:
                raise ValueError('Active account unavailable')
            self.operator_audit('account_disable', account)

    def enable_account(self, account):
        with self.transaction():
            if not self.db.execute('UPDATE hosted_accounts SET enabled=1 WHERE id=? AND enabled=0',
                                   (require_id(account),)).rowcount:
                raise ValueError('Suspended account unavailable')
            self.operator_audit('account_enable', account)

    def revoke_grant(self, account, client):
        if not isinstance(client, str) or not SAFE_ID.fullmatch(client):
            raise ValueError('Invalid OAuth client')
        with self.transaction():
            self.db.execute('INSERT OR IGNORE INTO hosted_revoked_grants VALUES (?, ?)',
                            (require_id(account), client))
            self.operator_audit('grant_revoke', account)

    def revoke_token(self, issuer, jti):
        https_url(issuer)
        if not isinstance(jti, str) or not SAFE_ID.fullmatch(jti):
            raise ValueError('Invalid token ID')
        token_id = digest([issuer, jti])
        with self.transaction():
            self.db.execute('INSERT OR IGNORE INTO hosted_revoked_tokens VALUES (?)', (token_id,))
            self.operator_audit('token_revoke')

    def register_verified_account(self, principal: Principal):
        """First use after token verification. Existing account state always wins."""
        try:
            retention_safe(principal.subject)
        except ValueError:
            return None
        with self.transaction():
            if principal.expires <= time.time():
                return None
            account = uuid4().hex
            inserted = self.db.execute(
                """INSERT INTO hosted_accounts (id, issuer, subject, enabled)
                   SELECT ?, ?, ?, 1 WHERE NOT EXISTS
                   (SELECT 1 FROM hosted_revoked_tokens WHERE digest=?)
                   ON CONFLICT(issuer, subject) DO NOTHING""",
                (account, principal.issuer, principal.subject, digest([principal.issuer, principal.jti])),
            ).rowcount
            if inserted:
                self.audit('account_register', 'committed', actor=account, client=principal.client)
            return self.authorized_account(principal)

    def authorized_account(self, principal: Principal):
        if principal.expires <= time.time():
            return None
        row = self.db.execute(
            '''SELECT a.id FROM hosted_accounts a
               WHERE a.issuer=? AND a.subject=? AND a.enabled=1
               AND NOT EXISTS (SELECT 1 FROM hosted_revoked_grants g WHERE g.account=a.id AND g.client=?)
               AND NOT EXISTS (SELECT 1 FROM hosted_revoked_tokens t WHERE t.digest=?)''',
            (principal.issuer, principal.subject, principal.client, digest([principal.issuer, principal.jti])),
        ).fetchone()
        return row[0] if row else None

    def create_private(self, owner, question, notes):
        if any(not isinstance(text, str) or not 1 <= len(text.encode()) <= 4096 for text in (question, notes)):
            raise ValueError('Private fields exceed the byte budget')
        retention_safe([question, notes])
        investigation = uuid4().hex
        with self.transaction():
            if not self.db.execute('SELECT 1 FROM hosted_accounts WHERE id=? AND enabled=1',
                                   (require_id(owner),)).fetchone():
                raise ValueError('Active owner unavailable')
            self.db.execute('INSERT INTO hosted_investigations VALUES (?, ?, ?, ?)',
                            (investigation, owner, question, notes))
            self.operator_audit('investigation_create', investigation)
        return investigation

    def private(self, owner, investigation):
        row = self.db.execute(
            # Both missing and foreign IDs miss the same owner-scoped index lookup.
            'SELECT question, notes FROM hosted_investigations INDEXED BY hosted_owner WHERE owner=? AND id=?',
            (owner, investigation),
        ).fetchone()
        if row is None:
            return UNAVAILABLE
        return {'status': 'available', 'investigation_id': investigation, 'question': row[0], 'notes': row[1]}

    def authorize_source(self, name, identity):
        https_url(identity)
        if not isinstance(name, str) or not LABEL.fullmatch(name):
            raise ValueError('Invalid source name')
        with self.transaction():
            self.db.execute("INSERT OR IGNORE INTO sources VALUES (?, ?, 'public')", (name, identity))
            if self.source(name) != (identity, 'public'):
                raise ValueError('Source already has a different registration')
            self.operator_audit('source_register')

    def add_source_policy(self, *, identity, operation, contract_sha, license, retain_until, projection):
        https_url(identity)
        if (not isinstance(operation, str) or not PUBLIC_ID.fullmatch(operation)
                or not isinstance(contract_sha, str) or not SHA.fullmatch(contract_sha)
                or not isinstance(license, str) or not 1 <= len(license) <= 256
                or type(retain_until) is not int or retain_until <= time.time()
                or not isinstance(projection, dict) or not 1 <= len(projection) <= 8):
            raise ValueError('Invalid public source policy')
        for label, rule in projection.items():
            if (not isinstance(label, str) or not LABEL.fullmatch(label) or not isinstance(rule, dict)
                    or set(rule) != {'path', 'type'} or not isinstance(rule['path'], str)
                    or rule['type'] not in ('identifier', 'number', 'boolean')
                    or not re.fullmatch(r'/output(?:/[a-zA-Z0-9_.~-]{1,64}){1,8}', rule['path'])):
                raise ValueError('Invalid structured projection')
        retention_safe([identity, license, projection])
        policy = uuid4().hex
        with self.transaction():
            if not self.db.execute('SELECT 1 FROM sources WHERE identity=? AND view=?',
                                   (identity, 'public')).fetchone():
                raise ValueError('Source registration unavailable')
            self.db.execute('INSERT INTO hosted_source_policies VALUES (?, ?, ?, ?, ?, ?, ?, 1)',
                            (policy, identity, operation, contract_sha, license, retain_until, canonical(projection)))
            self.operator_audit('source_policy_add', policy)
        return policy

    def withdraw_source_policy(self, policy):
        with self.transaction():
            if not self.db.execute('UPDATE hosted_source_policies SET active=0 WHERE id=? AND active=1',
                                   (require_id(policy),)).rowcount:
                raise ValueError('Active source policy unavailable')
            self.operator_audit('source_policy_withdraw', policy)

    def _source_policy(self, policy):
        row = self.db.execute(
            '''SELECT identity, operation, contract_sha, projection FROM hosted_source_policies
               WHERE id=? AND active=1 AND retain_until>?''', (policy, time.time()),
        ).fetchone()
        if row is None:
            raise ValueError('Public source policy unavailable')
        return *row[:3], json.loads(row[3])

    def _project(self, receipt, policy):
        identity, operation, contract_sha, projection = self._source_policy(policy)
        body = self.get_visible(receipt)
        if (body['identity'] != identity or body['capability']['name'] != operation
                or digest(body['capability']) != contract_sha
                or {'extraction', 'literature_origin', 'entity_extraction'}.intersection(body)):
            raise ValueError('Receipt falls outside the admitted direct observation contract')
        reference = {'kind': 'observation', 'record': receipt,
                     'selectors': {label: rule['path'] for label, rule in projection.items()}}
        result = resolve_evidence(self, reference)
        if result['observed_at'] > time.time():
            raise ValueError('Future-dated observation')
        for label, value in result['selected'].items():
            kind = projection[label]['type']
            valid = (kind == 'identifier' and isinstance(value, str) and PUBLIC_ID.fullmatch(value)
                     or kind == 'boolean' and type(value) is bool
                     or kind == 'number' and type(value) in (int, float)
                     and -1e100 <= value <= 1e100 and math.isfinite(value))
            if not valid:
                raise ValueError('Observation does not match the structured projection')
        return {key: result[key] for key in ('id', 'reference', 'selected', 'source_identity', 'method',
                                             'observed_at', 'receipt_sha256', 'freshness')}

    def publish(self, receipt, policy):
        require_id(receipt)
        require_id(policy)
        with self.transaction():
            return self._publish(receipt, policy)

    def _publish(self, receipt, policy):
        row = self.db.execute(
            """SELECT sha FROM records WHERE id=? AND kind IN ('receipt','observation')
               AND length(CAST(body AS BLOB))<=65536""", (receipt,),
        ).fetchone()
        if row is None:
            raise ValueError('Bounded observation unavailable')
        self._project(receipt, policy)
        previous = self.db.execute('SELECT receipt FROM hosted_public WHERE policy=? AND sha=?',
                                   (policy, row[0])).fetchone()
        if previous:
            if canonical(self.get(previous[0])) != canonical(self.get(receipt)):
                raise ValueError('Published receipt checksum collision')
            return previous[0]
        self.db.execute('INSERT INTO hosted_public VALUES (?, ?, ?)', (receipt, policy, row[0]))
        self.operator_audit('evidence_publish', receipt)
        return receipt

    def retain_public(self, body, policy):
        require_id(policy)
        if not isinstance(body, dict) or len(canonical(body).encode()) > 65536:
            raise ValueError('Observation exceeds byte budget')
        with self.transaction():
            row = self.db.execute('SELECT receipt FROM hosted_public WHERE policy=? AND sha=?',
                                  (policy, digest(body))).fetchone()
            if row:
                if canonical(self.get(row[0])) != canonical(body):
                    raise ValueError('Published receipt checksum collision')
                self.public(row[0])
                return row[0]
            return self._publish(self.put('observation', body), policy)

    def public(self, receipt):
        row = self.db.execute(
            '''SELECT p.policy FROM hosted_public p JOIN records r ON p.receipt=r.id AND p.sha=r.sha
               WHERE p.receipt=? AND length(CAST(r.body AS BLOB))<=65536''', (receipt,),
        ).fetchone()
        if row is None:
            raise ValueError('Public observation unavailable')
        return {'status': 'available', 'evidence': self._project(receipt, row[0])}

    def add_reviewer(self, public_key, scope, uses):
        if (not isinstance(public_key, str) or not SHA.fullmatch(public_key)
                or not isinstance(scope, dict) or not 1 <= len(scope) <= 12
                or not isinstance(uses, list) or not 1 <= len(uses) <= 4
                or any(not isinstance(s, str) or not 1 <= len(s) <= 1024
                       for s in [*scope.keys(), *scope.values(), *uses])
                or len(set(uses)) != len(uses)):
            raise ValueError('Invalid scoped reviewer grant')
        retention_safe([scope, uses])
        reviewer = uuid4().hex
        with self.transaction():
            self.db.execute('INSERT INTO hosted_reviewers VALUES (?, ?, ?, ?, 1)',
                            (reviewer, public_key, canonical(scope), canonical(uses)))
            self.operator_audit('reviewer_add', reviewer)
        return reviewer

    def disable_reviewer(self, reviewer):
        with self.transaction():
            if not self.db.execute('UPDATE hosted_reviewers SET enabled=0 WHERE id=? AND enabled=1',
                                   (require_id(reviewer),)).rowcount:
                raise ValueError('Active reviewer unavailable')
            self.operator_audit('reviewer_disable', reviewer)

    def _reviewer(self, reviewer):
        row = self.db.execute('SELECT public_key, scope, uses FROM hosted_reviewers WHERE id=? AND enabled=1',
                              (reviewer,)).fetchone()
        if row is None:
            raise ValueError('Reviewer authority unavailable')
        return row[0], {reviewer: {'mode': REVIEW_MODE, 'scope': json.loads(row[1]),
                                  'allowed_uses': json.loads(row[2])}}

    def _check_references(self, references):
        if not isinstance(references, dict) or not 1 <= len(references) <= 4:
            raise ValueError('Bounded public references required')
        for ref in references.values():
            published = self.public(require_id(ref['record']))['evidence']['reference']
            if ref != published:
                raise ValueError('Reference must match the approved public projection')

    def propose(self, *, statement, scope, allowed_uses, semantics, references, expires_at, max_evidence_age=60):
        with self.transaction():
            self._check_references(references)
            identifier = decisions.propose(
                self, statement=statement, scope=scope, allowed_uses=allowed_uses, semantics=semantics,
                references=references, expires_at=expires_at, max_evidence_age=max_evidence_age, now=time.time(),
            )
            self.operator_audit('candidate_create', identifier)
            return identifier, digest(self.get(identifier))

    def activate(self, attestation, signature, references):
        fields = {'purpose', 'reviewer', 'candidate', 'candidate_sha256', 'verdict', 'basis', 'reviewed_at', 'use'}
        if (not isinstance(attestation, dict) or set(attestation) != fields
                or attestation['purpose'] != 'synkrita-hosted-approval-v1'
                or attestation['verdict'] != 'approve'
                or not isinstance(signature, str) or not re.fullmatch(r'[0-9a-f]{128}', signature)
                or len(canonical(attestation).encode()) > 4096):
            raise ValueError('Invalid review attestation')
        reviewer = require_id(attestation['reviewer'])
        candidate_id = require_id(attestation['candidate'])
        with self.transaction():
            key, policy = self._reviewer(reviewer)
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                    bytes.fromhex(signature), canonical(attestation).encode(),
                )
            except InvalidSignature:
                raise ValueError('Review signature is invalid') from None
            if self.db.execute('SELECT 1 FROM hosted_decisions WHERE candidate=?', (candidate_id,)).fetchone():
                raise ValueError('Candidate already has an activation')
            if not self.db.execute(
                """SELECT 1 FROM records WHERE id=? AND kind='experimental_integration_candidate'
                   AND length(CAST(body AS BLOB))<=32768""", (candidate_id,),
            ).fetchone():
                raise ValueError('Candidate unavailable')
            candidate = self.get(candidate_id)
            if candidate['view'] != 'public' or digest(candidate) != attestation['candidate_sha256']:
                raise ValueError('Review must bind the exact public candidate')
            self._check_references({role: premise['reference'] for role, premise in candidate['premises'].items()})
            self._check_references(references)
            use = attestation['use']
            now = time.time()
            review = decisions.record_review(
                self, candidate_id, authority=reviewer, mode=REVIEW_MODE, verdict=attestation['verdict'],
                basis=attestation['basis'], reviewed_at=attestation['reviewed_at'],
            )
            decision = decisions.qualify(self, candidate_id, review, authority_policy=policy, now=now)
            binding = {'context': candidate['scope'], 'use': use, 'semantics': candidate['semantics'],
                       'current_references': references}
            result = decisions.assess(self, decision, **binding, authority_policy=policy, now=now)
            if not result['eligible']:
                raise ValueError('Decision does not qualify for this use')
            # Retain the signed approval separately for audit. No reviewer private key enters the service.
            review_artifact = self.put('hosted_signed_review', {'attestation': attestation, 'signature': signature,
                                                             'review': review})
            self.db.execute('INSERT INTO hosted_decisions VALUES (?, ?, ?, ?, ?, 1)',
                            (decision, candidate_id, reviewer, digest(attestation),
                             canonical({**binding, 'review_artifact': review_artifact})))
            self.operator_audit('decision_activate', decision)
        return decision

    def revoke_decision(self, decision):
        with self.transaction():
            if not self.db.execute('UPDATE hosted_decisions SET active=0 WHERE decision=? AND active=1',
                                   (require_id(decision),)).rowcount:
                raise ValueError('Active decision unavailable')
            self.operator_audit('decision_revoke', decision)

    def qualified(self, decision):
        row = self.db.execute(
            'SELECT candidate, reviewer, review_hash, binding FROM hosted_decisions WHERE decision=? AND active=1',
            (decision,),
        ).fetchone()
        if row is None:
            return UNAVAILABLE
        candidate_id, reviewer, review_hash, body = row
        key, policy = self._reviewer(reviewer)
        binding = json.loads(body)
        artifact = self.get(binding.pop('review_artifact'))
        attestation = artifact['attestation']
        candidate = self.get(candidate_id)
        record = self.get(decision)
        if (digest(attestation) != review_hash or attestation['candidate'] != candidate_id
                or attestation['candidate_sha256'] != digest(candidate) or attestation['reviewer'] != reviewer
                or attestation['use'] != binding['use'] or record['candidate'] != candidate_id
                or artifact['review'] != record['review']):
            return UNAVAILABLE
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                bytes.fromhex(artifact['signature']), canonical(attestation).encode(),
            )
        except InvalidSignature:
            return UNAVAILABLE
        self._check_references({role: premise['reference'] for role, premise in candidate['premises'].items()})
        self._check_references(binding['current_references'])
        checked = decisions.assess(self, decision, **binding, authority_policy=policy, now=time.time())
        if not checked['eligible'] or checked['review_mode'] != REVIEW_MODE:
            return UNAVAILABLE
        return {'status': 'available', 'decision_id': decision, 'statement': candidate['statement'],
                'use': binding['use'], 'context': binding['context'], 'evidence': checked['evidence'],
                'scientific_truth_established': False}

    def backup(self, target):
        copy_snapshot(self.db, target)


def check_integrity(db):
    if (db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]
            or db.execute('PRAGMA foreign_key_check').fetchone() is not None
            or db.execute('SELECT version FROM hosted_schema').fetchall() != [(1,)]):
        raise ValueError('Snapshot validation failed')


def copy_snapshot(source, target):
    private_directory(target)
    with tempfile.NamedTemporaryFile(dir=Path(target).parent) as staging:
        destination = sqlite3.connect(staging.name)
        deadline = time.monotonic() + 30

        def progress(*_):
            if time.monotonic() > deadline:
                raise TimeoutError('Snapshot exceeded its time budget')

        try:
            source.backup(destination, pages=100, progress=progress, sleep=0.05)
            check_integrity(destination)
        finally:
            destination.close()
        # Publish the complete snapshot atomically and never overwrite an existing file.
        os.link(staging.name, target)
        fd = os.open(Path(target).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def restore_snapshot(source, target):
    private_directory(source)
    if not Path(source).is_file() or Path(source).is_symlink():
        raise ValueError('Expected a private snapshot file')
    db = sqlite3.connect(Path(source).absolute().as_uri() + '?mode=ro', uri=True)
    try:
        copy_snapshot(db, target)
    finally:
        db.close()
