"""Versioned SQLite registry and checksummed evidence; local integrity, not signatures."""
from dataclasses import asdict
import os
import json
import sqlite3
import uuid
from synkrita.models import canonical, digest
from synkrita.privacy import retention_safe


class Store:
    def __init__(self, path):
        if str(path) != ':memory:':
            # Refuse links and create private storage before sqlite opens it.
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path)
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            self.db.close()
            raise ValueError('Unsupported store version')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, identity TEXT, view TEXT);
        CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT, body TEXT, sha TEXT);
        PRAGMA user_version=1;
        ''')

    def close(self):
        self.db.close()

    def register(self, name, identity, view='public'):
        retention_safe(identity)
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO sources VALUES (?,?,?)', (name, identity, view))

    def source(self, name):
        row = self.db.execute('SELECT identity,view FROM sources WHERE name=?', (name,)).fetchone()
        if row is None:
            raise ValueError('Unregistered source')
        return row

    def put(self, kind, record):
        with self.db:
            return self._insert_record(kind, record)

    def _insert_record(self, kind, record):
        """Insert within the caller's transaction."""
        if hasattr(record, '__dataclass_fields__'):
            record = asdict(record)
        retention_safe(record)
        identifier = uuid.uuid4().hex
        self.db.execute('INSERT INTO records VALUES (?,?,?,?)',
                        (identifier, kind, canonical(record), digest(record)))
        return identifier

    def get(self, identifier):
        row = self.db.execute('SELECT body,sha FROM records WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise ValueError('Missing evidence')
        record = json.loads(row[0])
        if digest(record) != row[1]:
            raise ValueError('Evidence checksum mismatch')
        return record

    def get_visible(self, identifier, *, view='public'):
        record = self.get(identifier)
        # Unknown scope is withheld rather than treated as public.
        if record.get('view') != view or not record.get('identity'):
            raise ValueError('Evidence unavailable in this view')
        current = self.db.execute('SELECT 1 FROM sources WHERE identity=? AND view=?',
                                  (record['identity'], view)).fetchone()
        if current is None:
            raise ValueError('Evidence source authorization is no longer active')
        return record

    def findings(self, source, operation, *, identity=None, view=None):
        rows = self.db.execute("SELECT id FROM records WHERE kind='finding' ORDER BY rowid DESC").fetchall()
        for (identifier,) in rows:
            record = self.get(identifier)
            if (record['source'] == source and record['capability']['name'] == operation
                    and (identity is None or record['identity'] == identity)
                    and (view is None or record['view'] == view)):
                yield identifier, record
