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


def _matches_index(db, name, table, columns):
    # The owned indexes are non-unique, unfiltered, ascending BINARY keys.
    flags = db.execute('select "unique", partial from pragma_index_list(?) where name = ? collate nocase',
                       (table, name)).fetchone()
    if flags != (0, 0):
        return False
    keys = db.execute('select lower(name) from pragma_index_info(?) order by seqno', (name,))
    if [column for column, in keys] != columns:
        return False
    return all(not desc and coll.lower() == 'binary' for desc, coll in
               db.execute('select "desc", coll from pragma_index_xinfo(?) where key', (name,)))


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
            elif definition[1] == 'index':
                # Owned DDL: CREATE INDEX name ON table (column, ...).
                table, columns = definition[4], definition[6:-1:2]
                if not _matches_index(db, name, table, columns):
                    raise ValueError('incompatible store schema')
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
    ledger.execute('begin immediate')
    if ledger.execute('pragma journal_mode').fetchone() != ('wal',):
        # Serialize the one-time conversion among initializers. Closing this
        # connection releases exclusive mode before any attempt is reserved.
        if ledger.execute("select 1 from sqlite_master where name='schema_boot_v2'").fetchone():
            # A rollback-mode reader can prevent *any* durable write. Require
            # a quiescent cutover instead of granting a new wait at every boot.
            ledger.execute('pragma busy_timeout=0')
        ledger.execute('pragma locking_mode=exclusive')
        ledger.commit()
        if ledger.execute('pragma journal_mode=wal').fetchone() != ('wal',):
            raise RuntimeError('schema startup ledger requires WAL')
        return 0
    ledger.execute("""create table if not exists schema_boot_v2 (
        role text primary key, attempts integer not null, deadline real not null,
        next_at real not null, state text not null)""")
    read_budget = 'select attempts, deadline, next_at, state from schema_boot_v2 where role=?'
    row = ledger.execute(read_budget, (role,)).fetchone()
    current = now()
    if row is None and current >= boot_deadline:
        # A late waiter may arrive after another worker resolved the incident.
        # It has no authority to open an exhausted incident for a healthy store.
        raise TimeoutError('schema startup deadline reached')
    attempts, deadline, next_at, state = row or (0, boot_deadline, current, 'ACTIVE')

    def pause():
        ledger.execute("insert or replace into schema_boot_v2 values (?,?,?,?,'EXHAUSTED')",
                       (role, attempts, deadline, next_at))
        ledger.commit()
        raise RuntimeError('schema startup budget exhausted')

    if state not in ('ACTIVE', 'RETRY_WAIT'):
        raise RuntimeError('schema startup requires intervention')
    if current >= deadline or current < deadline - WINDOW:
        pause()
    if state == 'ACTIVE' and attempts == len(DELAYS) + 1:
        # Allow the final reservation to reacquire the writer lock and finish.
        return min(DELAYS[0], deadline - current)
    if attempts >= len(DELAYS) + 1 or next_at >= deadline:
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
    ledger.commit()
    # A replacement may have taken over between the durable reservation and
    # reacquiring the writer lock. Only the current reservation can touch the store.
    ledger.execute('begin immediate')
    reserved = ledger.execute(read_budget, (role,)).fetchone()
    if reserved is None:
        return None
    if reserved != (attempts, deadline, next_at, 'ACTIVE'):
        return 0
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
            ledger.commit()
            raise
        next_at = now() + delay
        if not delay or next_at >= deadline:
            pause()
        ledger.execute("update schema_boot_v2 set next_at=?, state='RETRY_WAIT' where role=?", (next_at, role))
        ledger.commit()
        return delay

    if now() >= deadline:
        pause()
    ledger.execute('delete from schema_boot_v2 where role=?', (role,))
    ledger.commit()
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
        if delay:
            time.sleep(delay)
