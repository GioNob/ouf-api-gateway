"""Additive mandate tables in the existing Gateway SQLite database."""
from contextlib import closing, contextmanager
from pathlib import Path
import json
import sqlite3

from tools.analysis_protocol import Rejected, require, wire

DDL = """
create table if not exists analysis_mandate_v1 (
 id text primary key, scope text not null, plan text not null, record blob not null,
 unique(scope, plan));
create table if not exists analysis_command_v1 (
 actor text not null, command text not null, fingerprint text not null, reply blob not null,
 primary key(actor, command));
create table if not exists analysis_attempt_v1 (
 mandate text not null, attempt text not null, intent text not null, operation text not null,
 fence integer not null, phase text not null, crossed_revocation integer not null default 0,
 evidence blob not null, primary key(mandate, attempt));
create index if not exists analysis_fence_v1 on analysis_attempt_v1(mandate,intent,operation,fence);
create index if not exists analysis_phase_v1 on analysis_attempt_v1(mandate,phase);
create table if not exists analysis_discovery_v1 (
 mandate text not null, intent text not null, subject_ref text not null, owner_key_hash text not null,
 arguments_hash text not null, primary key(mandate,intent), unique(subject_ref,owner_key_hash));
create table if not exists analysis_audit_v1 (
 sequence integer primary key, decision text not null, evidence blob not null);
"""


class MandateStore:
    def __init__(self, path):
        # A missing volume must not silently create a second authority.
        self.uri = Path(path).resolve().as_uri() + '?mode=rw'
        with closing(self.connect()) as db:
            if not db.execute("""select 1 from sqlite_master where type='table'
                                 and name='gateway_operational_incident'""").fetchone():
                raise ValueError('existing Gateway operational store required')
            db.executescript(DDL)

    def connect(self):
        return sqlite3.connect(self.uri, uri=True, isolation_level=None, timeout=1)

    @contextmanager
    def transaction(self):
        with closing(self.connect()) as db:
            try:
                db.execute('begin immediate')
                yield db
                db.commit()
            except sqlite3.OperationalError as exc:
                if getattr(exc, 'sqlite_errorcode', 0) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                    raise Rejected(429, retry_after='1') from exc
                raise

    def get(self, mandate):
        with closing(self.connect()) as db:
            return self.read(db, mandate)

    @staticmethod
    def read(db, mandate):
        row = db.execute('select record from analysis_mandate_v1 where id=?', (mandate,)).fetchone()
        require(row is not None, 404)
        return json.loads(row[0])

    @staticmethod
    def command(db, actor, b, fingerprint):
        row = db.execute('select fingerprint, reply from analysis_command_v1 where actor=? and command=?',
                         (actor, b['commandKey'])).fetchone()
        if row:
            require(row[0] == fingerprint, 409, 'COMMAND_CONFLICT')
            return json.loads(row[1])

    @staticmethod
    def save_command(db, actor, b, fingerprint, reply):
        db.execute('insert into analysis_command_v1 values (?,?,?,?)',
                   (actor, b['commandKey'], fingerprint, wire(reply)))

    @staticmethod
    def audit(db, ref, evidence):
        db.execute('insert into analysis_audit_v1(decision,evidence) values (?,?)', (ref, wire(evidence)))

    @staticmethod
    def admit(db, m, b, evidence):
        previous = db.execute('select max(fence) from analysis_attempt_v1 where mandate=? and intent=? and operation=?',
                              (m['id'], b['intentKey'], b['operation'])).fetchone()[0]
        require(previous is None or previous <= int(b['fence']), 409)
        if b['operation'] == 'semantic.discovery.request':
            effect = (m['id'], b['intentKey'], evidence['subjectRef'], evidence['ownerKeyHash'], evidence['argumentsHash'])
            db.execute('insert or ignore into analysis_discovery_v1 values (?,?,?,?,?)', effect)
            pinned = db.execute('select * from analysis_discovery_v1 where mandate=? and intent=?', effect[:2]).fetchone()
            require(pinned == effect, 409, 'COMMAND_CONFLICT')
        try:
            db.execute("""insert into analysis_attempt_v1(mandate,attempt,intent,operation,fence,phase,evidence)
                          values (?,?,?,?,?,'ADMITTED',?)""",
                       (m['id'], b['attemptId'], b['intentKey'], b['operation'], int(b['fence']), wire(evidence)))
        except sqlite3.IntegrityError as exc:
            raise Rejected(409) from exc
        MandateStore.audit(db, evidence['decisionRef'], {**evidence, 'outcome': 'ADMITTED'})

    def finish(self, evidence, status, request_id=None):
        with self.transaction() as db:
            key = (evidence['mandateId'], evidence['attemptId'])
            phase = 'UNCERTAIN' if status is None or status >= 500 else 'RETURNED'
            crossed, = db.execute('select crossed_revocation from analysis_attempt_v1 where mandate=? and attempt=?',
                                  key).fetchone()
            newer = db.execute("""select 1 from analysis_attempt_v1
                                  where mandate=? and intent=? and operation=? and fence>? limit 1""",
                               (key[0], evidence['intentKey'], evidence['operation'], int(evidence['fence']))).fetchone()
            outcome = {**evidence, 'outcome': phase, 'crossedRevocation': bool(crossed),
                       'superseded': bool(newer), 'status': status}
            if request_id:
                outcome['requestId'] = request_id
            db.execute('update analysis_attempt_v1 set phase=?,evidence=? where mandate=? and attempt=?',
                       (phase, wire(outcome), *key))
            self.audit(db, evidence['decisionRef'], outcome)
            return bool(crossed or newer)
