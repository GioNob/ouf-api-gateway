"""Additive D-104 tables in the Gateway's existing operational SQLite store."""
import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from tools.analysis_batch_protocol import Denied, wire


DDL = """
create table if not exists analysis_batch_mandate_v1 (
    installation text not null, ref text not null, storage_epoch text not null,
    issuer text not null, tenant text not null, subject text not null, client text not null,
    workload text not null, command_key text not null, plan blob not null,
    analysis_id text, authority blob, operations blob not null,
    generation integer not null, version integer not null,
    state text not null check(state in ('PENDING','ACTIVE','REVOKED','EXPIRED')),
    expires_ms integer not null,
    primary key (installation, ref),
    unique (installation, issuer, tenant, subject, command_key),
    unique (installation, analysis_id)
);
create index if not exists analysis_batch_mandate_expiry_v1
    on analysis_batch_mandate_v1(installation, storage_epoch, state, expires_ms);
create table if not exists analysis_batch_discovery_v1 (
    installation text not null, ref text not null, work_ref text not null, actor_hash text not null,
    owner_key_hash text not null, arguments_hash text not null, request_id text,
    primary key (installation, ref, work_ref),
    unique (installation, actor_hash, owner_key_hash),
    unique (installation, request_id),
    foreign key (installation, ref) references analysis_batch_mandate_v1(installation, ref)
);
create table if not exists analysis_batch_audit_v1 (
    sequence integer primary key, installation text not null, event blob not null
);
create table if not exists analysis_batch_clock_v1 (
    installation text primary key, storage_epoch text not null, latest_ms integer not null
);
create table if not exists analysis_batch_quota_v1 (
    installation text not null, operation text not null, window_end_ms integer not null, count integer not null,
    primary key (installation, operation)
);
"""


class BatchMandateStore:
    def __init__(self, path, installation, storage_epoch, *, initialize=True):
        self.uri = Path(path).resolve().as_uri() + '?mode=rw'
        self.installation, self.storage_epoch = installation, storage_epoch
        self.initialized = False
        if initialize:
            self.initialize()

    def initialize(self):
        if self.initialized:
            return
        with closing(self.connect()) as db:
            if not db.execute("select 1 from sqlite_master where name='gateway_operational_incident' and type='table'").fetchone():
                raise Denied(503, 'ANALYSIS_REGISTRY_NOT_PROVISIONED')
            db.executescript(DDL)
        self.initialized = True

    def connect(self):
        db = sqlite3.connect(self.uri, uri=True, isolation_level=None, timeout=1)
        db.row_factory = sqlite3.Row
        db.execute('pragma foreign_keys=on')
        db.execute('pragma synchronous=full')
        return db

    @contextmanager
    def transaction(self):
        with closing(self.connect()) as db:
            db.execute('begin immediate')
            yield db
            db.commit()

    def get(self, ref):
        with closing(self.connect()) as db:
            return self.read(db, ref)

    def read(self, db, ref):
        row = db.execute('select * from analysis_batch_mandate_v1 where installation=? and ref=?',
                         (self.installation, ref)).fetchone()
        if row is None:
            raise Denied(404, 'ANALYSIS_MANDATE_NOT_FOUND')
        return dict(row)

    def reserve(self, db, record):
        actor = tuple(record[k] for k in ('installation', 'issuer', 'tenant', 'subject', 'command_key'))
        existing = db.execute("""select * from analysis_batch_mandate_v1
            where installation=? and issuer=? and tenant=? and subject=? and command_key=?""", actor).fetchone()
        if existing:
            return dict(existing), False
        db.execute("""insert into analysis_batch_mandate_v1
            (installation,ref,storage_epoch,issuer,tenant,subject,client,workload,command_key,
             plan,operations,generation,version,state,expires_ms)
            values (:installation,:ref,:storage_epoch,:issuer,:tenant,:subject,:client,:workload,:command_key,
                    :plan,:operations,1,1,'PENDING',:expires_ms)""", record)
        return self.read(db, record['ref']), True

    def activate(self, db, row, analysis_id, authority, expires_ms):
        try:
            count = db.execute("""update analysis_batch_mandate_v1
                set analysis_id=?, authority=?, expires_ms=?, state='ACTIVE', version=version+1
                where installation=? and ref=? and state='PENDING' and version=? and storage_epoch=?""",
                (analysis_id, wire(authority), expires_ms, self.installation,
                 row['ref'], row['version'], self.storage_epoch)).rowcount
        except sqlite3.IntegrityError as exc:
            raise Denied(409, 'ANALYSIS_MANDATE_BINDING_CONFLICT') from exc
        if count != 1:
            raise Denied(409, 'ANALYSIS_MANDATE_VERSION_CHANGED')
        return self.read(db, row['ref'])

    def terminate(self, db, row, state):
        changed = db.execute("""update analysis_batch_mandate_v1 set state=?, version=version+1
            where installation=? and ref=? and version=? and storage_epoch=? and state in ('PENDING','ACTIVE')""",
            (state, self.installation, row['ref'], row['version'], self.storage_epoch)).rowcount
        if changed != 1:
            raise Denied(409, 'ANALYSIS_MANDATE_VERSION_CHANGED')
        return self.read(db, row['ref'])

    def due(self, db, now_ms, limit):
        return [dict(row) for row in db.execute("""select * from analysis_batch_mandate_v1
            where installation=? and storage_epoch=? and state in ('ACTIVE','PENDING') and expires_ms<=?
            order by expires_ms, ref limit ?""", (self.installation, self.storage_epoch, now_ms, limit))]

    def observe_clock(self, db, now_ms):
        clock = db.execute('select storage_epoch, latest_ms from analysis_batch_clock_v1 where installation=?',
                           (self.installation,)).fetchone()
        if clock and (clock['storage_epoch'] != self.storage_epoch or now_ms < clock['latest_ms']):
            raise Denied(503, 'ANALYSIS_CLOCK_OR_STORAGE_EPOCH_UNVERIFIED')
        db.execute("""insert into analysis_batch_clock_v1 values (?,?,?)
            on conflict(installation) do update set latest_ms=excluded.latest_ms""",
            (self.installation, self.storage_epoch, now_ms))

    def pin_discovery(self, db, ref, work_ref, actor_hash, owner_key_hash, arguments_hash):
        values = self.installation, ref, work_ref, actor_hash, owner_key_hash, arguments_hash
        db.execute("""insert into analysis_batch_discovery_v1
            (installation,ref,work_ref,actor_hash,owner_key_hash,arguments_hash) values (?,?,?,?,?,?)
            on conflict do nothing""", values)
        pin = db.execute("""select actor_hash,owner_key_hash,arguments_hash from analysis_batch_discovery_v1
            where installation=? and ref=? and work_ref=?""", values[:3]).fetchone()
        if pin is None or tuple(pin) != values[3:]:
            raise Denied(409, 'ANALYSIS_DISCOVERY_KEY_CONFLICT')

    def charge(self, db, operation, now_ms, limit):
        key = self.installation, operation
        row = db.execute('select window_end_ms,count from analysis_batch_quota_v1 where installation=? and operation=?',
                         key).fetchone()
        if row and now_ms < row['window_end_ms']:
            if row['count'] >= limit:
                remaining = (row['window_end_ms'] - now_ms + 999) // 1000
                raise Denied(429, 'ANALYSIS_ROUTE_RATE_LIMITED', str(remaining))
            db.execute('update analysis_batch_quota_v1 set count=count+1 where installation=? and operation=?', key)
        else:
            db.execute("""insert into analysis_batch_quota_v1 values (?,?,?,1)
                on conflict(installation,operation) do update set window_end_ms=excluded.window_end_ms,count=1""",
                (*key, now_ms + 60_000))

    def bind_request(self, ref, work_ref, request_id):
        with self.transaction() as db:
            try:
                changed = db.execute("""update analysis_batch_discovery_v1 set request_id=?
                    where installation=? and ref=? and work_ref=? and (request_id is null or request_id=?)""",
                    (request_id, self.installation, ref, work_ref, request_id)).rowcount
            except sqlite3.IntegrityError as exc:
                raise Denied(503, 'ANALYSIS_DISCOVERY_RECEIPT_CONFLICT') from exc
            if changed != 1:
                raise Denied(503, 'ANALYSIS_DISCOVERY_RECEIPT_CONFLICT')

    def owns_request(self, db, ref, work_ref, request_id):
        return db.execute("""select 1 from analysis_batch_discovery_v1
            where installation=? and ref=? and work_ref=? and request_id=?""",
            (self.installation, ref, work_ref, request_id)).fetchone() is not None

    def audit(self, db, event):
        db.execute('insert into analysis_batch_audit_v1(installation,event) values (?,?)',
                   (self.installation, wire(event)))

    def check(self, now_ms):
        with closing(self.connect()) as db:
            clock = db.execute('select storage_epoch,latest_ms from analysis_batch_clock_v1 where installation=?',
                               (self.installation,)).fetchone()
        return not clock or (clock['storage_epoch'] == self.storage_epoch and now_ms >= clock['latest_ms'])

    @staticmethod
    def binding(row):
        return {
            **{k: row[k] for k in ('issuer', 'tenant', 'subject', 'client', 'workload')},
            'analysisId': row['analysis_id'], 'generation': row['generation'],
            'startRef': row['ref'], **json.loads(row['plan']),
        }
