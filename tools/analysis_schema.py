"""Initialize the existing SQLite store within one worker startup budget."""
from contextlib import closing
from pathlib import Path
import os
import random
import re
import sqlite3
import time


# Profile v3 covers brief lock contention during Gunicorn worker startup.
WINDOW_SECONDS = 5


def _parameter(name, default, maximum):
    value = os.environ.get(name, str(default))
    if not re.fullmatch('[1-9][0-9]{0,2}', value) or int(value) > maximum:
        raise ValueError(f'{name} outside supported range')
    return int(value)


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


def _install(uri, statements, prerequisite, deadline):
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
        db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        if not missing(db):
            return
        db.execute('begin exclusive')
        # A different initializer may have committed since the read-only check.
        for statement in missing(db):
            db.execute(statement)
        if time.monotonic() >= deadline:
            raise TimeoutError('schema startup deadline reached')
        db.commit()


def initialize_schema(path, statements, *, prerequisite=None):
    max_attempts = _parameter('OUF_SCHEMA_MAX_ATTEMPTS', 4, 4)
    delay = _parameter('OUF_SCHEMA_INITIAL_DELAY_MS', 250, 500) / 1000
    deadline = time.monotonic() + WINDOW_SECONDS
    uri = Path(path).resolve(strict=True).as_uri() + '?mode=rw'
    for attempt in range(1, max_attempts + 1):
        if time.monotonic() >= deadline:
            break
        try:
            _install(uri, statements, prerequisite, deadline)
        except sqlite3.OperationalError as exc:
            code = getattr(exc, 'sqlite_errorcode', 0) & 0xff
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or attempt == max_attempts:
                raise
        else:
            if time.monotonic() < deadline:
                return uri
            break

        # _install has closed its connection, including any unfinished transaction.
        wait = delay * random.uniform(1, 1.2)
        if time.monotonic() + wait >= deadline:
            break
        time.sleep(wait)
        delay *= 2
    raise TimeoutError('schema startup deadline reached')
