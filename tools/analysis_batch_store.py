"""Local redacted D-104 audit in the Gateway operational SQLite store."""
import sqlite3
from contextlib import closing
from pathlib import Path

from tools.analysis_batch_protocol import wire


class BatchMandateAudit:
    def __init__(self, path, installation):
        self.uri = Path(path).resolve().as_uri() + '?mode=rw'
        self.installation = installation

    def write(self, event):
        with closing(sqlite3.connect(self.uri, uri=True, isolation_level=None, timeout=0.1)) as db:
            if not db.execute("select 1 from sqlite_master where name='gateway_operational_incident' and type='table'").fetchone():
                raise sqlite3.OperationalError('operational store must be provisioned')
            db.execute("""create table if not exists analysis_batch_audit_v1 (
                sequence integer primary key, installation text not null, event blob not null
            )""")
            db.execute('insert into analysis_batch_audit_v1(installation,event) values (?,?)',
                       (self.installation, wire(event)))
