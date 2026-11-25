"""Local usage ledger. No credentials, record targets or payloads enter SQLite."""
import asyncio
from contextlib import closing
import json
import logging
from pathlib import Path
import sqlite3
import time

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

TOOLS = {
    'read_public_observation': 'receipt',
    'read_qualified_decision': 'decision_id',
    'read_investigation': 'investigation_id',
}
METHODS = {'initialize', 'notifications/initialized', 'notifications/cancelled', 'ping',
           'tools/list', 'tools/call', 'resources/list', 'resources/templates/list', 'prompts/list'}
TOOL_OPERATIONS = tuple(sorted(TOOLS.keys() | {'tools/call'}))
OPERATIONS = sorted(METHODS | TOOLS.keys() | {'unclassified'})
OUTCOMES = ('completed', 'rejected', 'http_error', 'rpc_error', 'tool_error',
            'tool_unavailable', 'incomplete', 'unclassified')
FAILURES = ('http_error', 'rpc_error', 'tool_error', 'tool_unavailable', 'incomplete', 'unclassified')
BATCH_SIZE = 32
BATCH_DELAY = 0.001

# Values in the embedded lists are constants, never obtained from an incoming request.
USAGE_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS hosted_usage_runs (
    id INTEGER PRIMARY KEY, started_ms INTEGER NOT NULL, ended_ms INTEGER,
    interrupted INTEGER NOT NULL DEFAULT 0 CHECK(interrupted IN (0,1)),
    lost INTEGER NOT NULL DEFAULT 0 CHECK(lost>=0), last_loss_ms INTEGER
);
CREATE TABLE IF NOT EXISTS hosted_usage (
    id INTEGER PRIMARY KEY,
    observed_ms INTEGER NOT NULL CHECK(observed_ms>=0),
    account TEXT NOT NULL REFERENCES hosted_accounts(id),
    request_id TEXT NOT NULL UNIQUE CHECK(length(request_id)=32 AND request_id NOT GLOB '*[^0-9a-f]*'),
    operation TEXT NOT NULL CHECK(operation IN {tuple(OPERATIONS)}),
    outcome TEXT NOT NULL CHECK(outcome IN {OUTCOMES}),
    http_status INTEGER CHECK(http_status BETWEEN 100 AND 599),
    mcp_message INTEGER NOT NULL CHECK(mcp_message IN (0,1)),
    tool_executed INTEGER NOT NULL CHECK(tool_executed IN (0,1) AND tool_executed<=mcp_message),
    elapsed_us INTEGER NOT NULL CHECK(elapsed_us>=0),
    request_bytes INTEGER CHECK(request_bytes>=0), response_bytes INTEGER CHECK(response_bytes>=0)
);
CREATE INDEX IF NOT EXISTS hosted_usage_time ON hosted_usage(observed_ms, id);
"""


def utc_ms():
    return time.time_ns() // 1_000_000


class UsageLedger:
    """Batch completed responses into short, independent, durable commits."""

    def __init__(self, database):
        self.database = database
        self.lost = 0
        self.last_loss_ms = None
        self.pending = []
        self.timer = None
        self.finished = False

    def __enter__(self):
        self.db = sqlite3.connect(Path(self.database).absolute().as_uri() + '?mode=rw',
                                  uri=True, timeout=0.01)
        try:
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA synchronous=FULL')
            now = utc_ms()
            with self.db:
                # The hosted deployment has one worker. A prior open run has
                # unknown coverage near the interruption and restart.
                self.db.execute('UPDATE hosted_usage_runs SET ended_ms=?, interrupted=1 WHERE ended_ms IS NULL',
                                (now,))
                self.run = self.db.execute('INSERT INTO hosted_usage_runs(started_ms) VALUES (?)',
                                           (now,)).lastrowid
        except BaseException:
            self.db.close()
            raise
        return self

    def _flush_losses(self):
        self.db.execute(
            'UPDATE hosted_usage_runs SET lost=lost+?, last_loss_ms=? WHERE id=?',
            (self.lost, self.last_loss_ms, self.run),
        )

    async def complete(self, fields):
        loop = asyncio.get_running_loop()
        committed = loop.create_future()
        self.pending.append((fields, committed))
        if len(self.pending) >= BATCH_SIZE:
            self._flush()
        elif self.timer is None:
            self.timer = loop.call_later(BATCH_DELAY, self._flush)
        # Cancellation while waiting must not cancel the queued accounting write.
        await asyncio.shield(committed)

    def _flush(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        try:
            with self.db:
                self.db.executemany(
                    '''INSERT INTO hosted_usage(observed_ms, account, request_id, operation, outcome,
                       http_status, mcp_message, tool_executed, elapsed_us, request_bytes, response_bytes)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (fields for fields, _ in batch),
                )
                if self.lost:
                    self._flush_losses()
        except sqlite3.Error:
            self.last_loss_ms = utc_ms()
            if not self.lost:
                logger.warning('{"event":"hosted_usage_gap","state":"open"}')
            self.lost += len(batch)
        else:
            if self.lost:
                logger.warning('{"event":"hosted_usage_gap","state":"recording_resumed","lost":%d}', self.lost)
                self.lost = 0
        finally:
            for _, committed in batch:
                committed.set_result(None)

    def finish(self):
        if self.finished:
            return
        self._flush()
        try:
            with self.db:
                if self.lost:
                    self._flush_losses()
                self.db.execute('UPDATE hosted_usage_runs SET ended_ms=? WHERE id=?', (utc_ms(), self.run))
        except sqlite3.Error:
            logger.warning('{"event":"hosted_usage_gap","state":"shutdown_checkpoint_failed"}')
        else:
            self.finished = True

    def __exit__(self, *_):
        with closing(self.db):
            self.finish()


def sdk_outcome(message, operation, tool_outcome):
    """Inspect the pinned JSON response envelope in memory for status only."""
    body = message.get('body', b'')
    fallback = tool_outcome if tool_outcome in ('tool_unavailable', 'tool_error') else 'unclassified'
    if not body:
        return fallback if operation in TOOL_OPERATIONS else 'completed'
    if message.get('more_body') or len(body) > 131072:
        return fallback
    try:
        envelope = json.loads(body)
    except (ValueError, RecursionError):
        return fallback
    if not isinstance(envelope, dict):
        return 'unclassified'
    if 'error' in envelope:
        return 'rpc_error'
    result = envelope.get('result')
    if isinstance(result, dict) and result.get('isError') is True:
        return 'tool_error'
    if operation in TOOL_OPERATIONS:
        return (tool_outcome or 'unclassified') if isinstance(result, dict) else fallback
    return 'completed' if 'result' in envelope else 'unclassified'
