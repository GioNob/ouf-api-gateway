"""Coordinate the finite schema startup budget across workers of a local store."""
from contextlib import closing
from pathlib import Path
import random
import re
import sqlite3
import time


# Schema startup profile v2. Gunicorn workers share the same short boot window.
DELAYS = (0.25, 0.75, 2.0)
WINDOW = 5


def _tokens(sql):
    # The owned DDL uses only unquoted identifiers, integers and punctuation.
    return re.findall(r'\w+|[^\w\s]', sql.lower())


def _install(uri, statements, prerequisite, now, deadline):
    def missing(db):
        schema = {name.lower(): (kind, sql) for name, kind, sql in
                  db.execute("select name, type, sql from sqlite_master where type in ('table','view','index')")}
        if prerequisite and schema.get(prerequisite, (None,))[0] != 'table':
            raise ValueError('existing Gateway operational store required')
        absent = []
        for statement in statements:
            # sqlite_master omits IF NOT EXISTS from the stored definition.
            definition = _tokens(statement.replace(' if not exists ', ' ', 1))
            name = definition[2]
            if name not in schema:
                absent.append(statement)
            elif definition != _tokens(schema[name][1] or ''):
                raise ValueError('incompatible store schema')
        return absent

    with closing(sqlite3.connect(uri, uri=True, timeout=0, isolation_level=None)) as db:
        db.set_progress_handler(lambda: now() >= deadline, 1000)
        if not missing(db):
            return
        db.execute('begin exclusive')
        # A different initializer may have committed since the read-only check.
        for statement in missing(db):
            db.execute(statement)
        if now() >= deadline:
            raise TimeoutError('schema startup deadline reached')
        db.commit()


def _step(ledger, role, uri, statements, prerequisite, now, boot_deadline):
    # Exclusive locking mode retains this sidecar lock across commits, including
    # the durable attempt reservation. Process death releases it automatically.
    ledger.execute('pragma locking_mode=exclusive')
    ledger.execute('begin exclusive')
    ledger.execute("""create table if not exists schema_boot_v2 (
        role text primary key, attempts integer not null, deadline real not null,
        next_at real not null, state text not null)""")
    ledger.commit()
    row = ledger.execute('select attempts, deadline, next_at, state from schema_boot_v2 where role=?',
                         (role,)).fetchone()
    current = now()
    if row is None and current >= boot_deadline:
        # A late waiter may arrive after another worker resolved the incident.
        # It has no authority to open an exhausted incident for a healthy store.
        raise TimeoutError('schema startup deadline reached')
    attempts, deadline, next_at, state = row or (0, boot_deadline, current, 'ACTIVE')

    def pause():
        ledger.execute("insert or replace into schema_boot_v2 values (?,?,?,?,'EXHAUSTED')",
                       (role, attempts, deadline, next_at))
        raise RuntimeError('schema startup budget exhausted')

    if state not in ('ACTIVE', 'RETRY_WAIT'):
        raise RuntimeError('schema startup requires intervention')
    if attempts >= len(DELAYS) + 1 or max(current, next_at) >= deadline or current < deadline - WINDOW:
        pause()
    if current < next_at:
        return next_at - current

    # Reserve before touching the target. Even a crash before the result is
    # recorded consumes this attempt and preserves its earliest retry time.
    delay = DELAYS[attempts] * random.uniform(1, 1.2) if attempts < len(DELAYS) else 0
    attempts += 1
    next_at = current + delay
    ledger.execute('insert or replace into schema_boot_v2 values (?,?,?,?,?)',
                   (role, attempts, deadline, next_at, 'ACTIVE'))
    try:
        if now() >= deadline:
            raise TimeoutError('schema startup deadline reached')
        _install(uri, statements, prerequisite, now, deadline)
    except Exception as exc:
        code = getattr(exc, 'sqlite_errorcode', 0) & 0xff
        if isinstance(exc, TimeoutError) or code == sqlite3.SQLITE_INTERRUPT:
            pause()
        if not isinstance(exc, sqlite3.OperationalError) or code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
            ledger.execute("update schema_boot_v2 set state='BLOCKED' where role=?", (role,))
            raise
        next_at = now() + delay
        if not delay or next_at >= deadline:
            pause()
        ledger.execute("update schema_boot_v2 set next_at=?, state='RETRY_WAIT' where role=?", (next_at, role))
        return delay

    if now() >= deadline:
        pause()
    ledger.execute('delete from schema_boot_v2 where role=?', (role,))
    return None


def initialize_schema(path, role, statements, *, prerequisite=None):
    path = Path(path).resolve(strict=True)
    uri = path.as_uri() + '?mode=rw'
    ledger_path = path.with_name(path.name + '.schema-boot.sqlite')
    wall, start = time.time(), time.monotonic()
    boot_deadline = wall + WINDOW

    def now():
        return max(time.time(), wall + (time.monotonic() - start))

    while True:
        with closing(sqlite3.connect(ledger_path, timeout=max(0, boot_deadline - now()),
                                     isolation_level=None)) as ledger:
            delay = _step(ledger, role, uri, statements, prerequisite, now, boot_deadline)
        if delay is None:
            return uri
        time.sleep(delay)
