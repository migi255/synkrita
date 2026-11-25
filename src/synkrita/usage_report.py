"""Bounded, read-only aggregation for the database service owner."""
from collections import defaultdict
import csv
from datetime import datetime, timezone
import sqlite3
import time

from synkrita.pilot_storage import read_hosted_database
from synkrita.pilot_usage import FAILURES, TOOL_OPERATIONS, utc_ms

WINDOWS = {'1h': 3600, '24h': 86400, '7d': 604800}
SORTS = {'requests': 'requests', 'tools': 'tool_executions', 'failures': 'failed',
         'rejections': 'rejected', 'duration': 'elapsed_us', 'request-bytes': 'request_bytes',
         'response-bytes': 'response_bytes', 'last-activity': 'last_activity_ms'}
ROW_LIMIT = 100_000
RUN_LIMIT = 1000
TALLY = ('requests', 'mcp_messages', 'tool_calls', 'tool_executions', 'failed', 'rejected',
         'elapsed_us', 'request_bytes', 'response_bytes', 'request_bytes_known', 'response_bytes_known')
COLUMNS = ('account', 'status', 'last_activity_utc', *TALLY)


def iso_utc(timestamp):
    if timestamp is None:
        return ''
    return datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat(timespec='milliseconds')


def usage_report(path, *, window, sort, now=None):
    """Read a consistent snapshot, bounded in time and rows, without locks for writes."""
    with read_hosted_database(path) as db, db:
        db.row_factory = sqlite3.Row
        deadline = time.monotonic() + 0.20
        db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        db.execute('BEGIN')
        cutoff = utc_ms() if now is None else now
        start = cutoff - WINDOWS[window] * 1000
        counts = db.execute('SELECT count(*),coalesce(sum(enabled),0) FROM hosted_accounts').fetchone()
        report = {
            'window': window, 'start_utc': iso_utc(start), 'cutoff_utc': iso_utc(cutoff),
            'accounts_enabled': counts[1], 'accounts_suspended': counts[0] - counts[1],
            'gaps': [], 'accounts': [], 'operations': [], 'http_statuses': {}, 'totals': dict.fromkeys(TALLY, 0),
        }
        if db.execute("SELECT 1 FROM sqlite_schema WHERE name='hosted_usage' AND type='table'").fetchone() is None:
            report['gaps'].append('Usage schema unavailable. Historical audit is not usage data.')
            return report

        runs = db.execute(
            '''SELECT started_ms, ended_ms, interrupted, lost, last_loss_ms FROM hosted_usage_runs
               WHERE started_ms<=? AND (ended_ms IS NULL OR ended_ms>=?)
               ORDER BY started_ms, id LIMIT ?''', (cutoff, start, RUN_LIMIT + 1),
        ).fetchall()
        _coverage(report['gaps'], runs, start, cutoff)
        if db.execute(
            '''SELECT 1 FROM hosted_usage WHERE observed_ms>=? AND observed_ms<=?
               ORDER BY observed_ms DESC,id DESC LIMIT 1 OFFSET ?''', (start, cutoff, ROW_LIMIT),
        ).fetchone():
            report['gaps'].append(f'Report limited to the latest {ROW_LIMIT} records. Use a shorter window.')
        rows = db.execute(
            f'''SELECT account, enabled, operation, http_status, max(observed_ms) AS last_activity_ms,
               count(*) AS requests, sum(mcp_message) AS mcp_messages,
               sum(operation IN {TOOL_OPERATIONS}) AS tool_calls,
               sum(tool_executed) AS tool_executions,
               sum(outcome IN {FAILURES}) AS failed, sum(outcome='rejected') AS rejected,
               sum(elapsed_us) AS elapsed_us,
               coalesce(sum(request_bytes),0) AS request_bytes,
               coalesce(sum(response_bytes),0) AS response_bytes,
               count(request_bytes) AS request_bytes_known, count(response_bytes) AS response_bytes_known
               FROM (SELECT * FROM hosted_usage WHERE observed_ms>=? AND observed_ms<=?
                     ORDER BY observed_ms DESC,id DESC LIMIT ?) AS recent
               JOIN hosted_accounts ON hosted_accounts.id=recent.account
               GROUP BY account, operation, http_status''', (start, cutoff, ROW_LIMIT),
        ).fetchall()

    accounts = {}
    statuses = defaultdict(int)
    operations = defaultdict(lambda: dict.fromkeys(TALLY, 0))
    for row in rows:
        account = accounts.setdefault(row['account'], dict.fromkeys(TALLY, 0) | {
            'account': row['account'], 'status': 'enabled' if row['enabled'] else 'suspended',
            'last_activity_ms': 0,
        })
        account['last_activity_ms'] = max(account['last_activity_ms'], row['last_activity_ms'])
        statuses[row['http_status']] += row['requests']
        operation = operations[row['operation']]
        for key in TALLY:
            account[key] += row[key]
            operation[key] += row[key]
            report['totals'][key] += row[key]
    report['accounts'] = sorted(accounts.values(), key=lambda row: (-row[SORTS[sort]], row['account']))
    for account in report['accounts']:
        account['last_activity_utc'] = iso_utc(account.pop('last_activity_ms'))
    report['http_statuses'] = dict(statuses)
    report['operations'] = [{'operation': name, **count} for name, count in sorted(operations.items())]
    return report


def _coverage(gaps, runs, start, cutoff):
    if len(runs) > RUN_LIMIT:
        gaps.append('Worker run history exceeded the report limit.')
        runs = runs[:RUN_LIMIT]
    covered = start
    interrupted = 0
    losses = 0
    unobserved = 0
    for run in runs:
        opened, ended, abrupt, lost, last_loss = run
        if opened > covered:
            unobserved += 1
        covered = max(covered, cutoff if ended is None else ended)
        interrupted += abrupt
        if last_loss is not None and last_loss >= start:
            losses += lost
    unobserved += int(covered < cutoff)
    if unobserved:
        gaps.append(f'{unobserved} interval(s) without an accounting worker, including pre-upgrade history.')
    if interrupted:
        gaps.append(f'{interrupted} interrupted worker run(s). Coverage before restart is uncertain.')
    if losses:
        gaps.append(f'{losses} recorded write loss(es) in overlapping runs (run totals, not window counts).')


def write_report(report, stream, *, output):
    scope = ('Worker records only. Edge traffic, unattributed requests and sampled audit are separate. '
             'Commit failures awaiting a checkpoint appear in the worker journal.')
    if output == 'csv':
        fields = ('section', 'window', 'start_utc', 'cutoff_utc', 'scope', 'gap', 'accounts_enabled',
                  'accounts_suspended', 'accounts_observed', 'operation', 'http_status', *COLUMNS)
        writer = csv.DictWriter(stream, fields, lineterminator='\n')
        writer.writeheader()
        for section, data in (
            ('summary', [report['totals'] | {
                'scope': scope, 'accounts_enabled': report['accounts_enabled'],
                'accounts_suspended': report['accounts_suspended'], 'accounts_observed': len(report['accounts']),
            }]),
            ('gap', [{'gap': gap} for gap in report['gaps']]),
            ('account', report['accounts']), ('operation', report['operations']),
            ('http_status', [{'http_status': key or 'no_response', 'requests': count}
                             for key, count in sorted(report['http_statuses'].items(), key=lambda item: item[0] or 0)]),
        ):
            for row in data:
                writer.writerow({'section': section, **{key: report[key] for key in fields[1:4]}, **row})
        return

    print(f"Usage {report['window']} | {report['start_utc']} to {report['cutoff_utc']}", file=stream)
    print(scope, file=stream)
    for gap in report['gaps']:
        print(f'Gap: {gap}', file=stream)
    print(f"Accounts: {report['accounts_enabled']} enabled, {report['accounts_suspended']} suspended, "
          f"{len(report['accounts'])} observed", file=stream)
    print('Totals: ' + ', '.join(f'{key}={report["totals"][key]}' for key in TALLY), file=stream)
    print('Worker HTTP: ' + ', '.join(f'{status or "no response"}={count}'
          for status, count in sorted(report['http_statuses'].items(), key=lambda item: item[0] or 0)), file=stream)
    print('\t'.join(COLUMNS), file=stream)
    for row in report['accounts']:
        print('\t'.join(str(row[key]) for key in COLUMNS), file=stream)
    operation_columns = ('operation', 'requests', 'mcp_messages', 'tool_calls', 'tool_executions', 'failed', 'rejected')
    print('\t'.join(operation_columns), file=stream)
    for row in report['operations']:
        print('\t'.join(str(row[key]) for key in operation_columns), file=stream)
