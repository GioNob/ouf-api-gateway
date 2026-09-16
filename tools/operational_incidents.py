from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class OperationalIncident:
    incident_id: str
    module: str
    event_type: str
    lifecycle_state: str
    severity: str
    first_seen_at: str
    last_seen_at: str
    resolved_at: str | None
    correlation_id: str | None
    endpoint_ref: str | None
    error_code: str | None
    impact_summary: str
    action_required: bool
    dedup_key: str
    occurrence_count: int
    visibility_class: str


class SQLiteOperationalIncidentStore:
    """Durable reference adapter for Gateway-owned semantic incidents.

    This stores only safe, normalized operational state. Raw logs, hostnames,
    credentials and telemetry payloads are deliberately outside this contract.
    """

    def __init__(self, path: Path | str, clock=None):
        self.path = str(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("pragma journal_mode=WAL")
        self.db.execute(
            """
            create table if not exists gateway_operational_incident(
              incident_id text primary key,
              dedup_key text not null unique,
              module text not null,
              event_type text not null,
              lifecycle_state text not null check(lifecycle_state in('OPEN','RECOVERING','RESOLVED')),
              severity text not null check(severity in('INFO','WARNING','ERROR','CRITICAL')),
              first_seen_at text not null,
              last_seen_at text not null,
              resolved_at text,
              correlation_id text,
              endpoint_ref text,
              error_code text,
              impact_summary text not null,
              action_required integer not null check(action_required in(0,1)),
              occurrence_count integer not null check(occurrence_count>0),
              visibility_class text not null
            )
            """
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def open_incident(
        self,
        *,
        dedup_key: str,
        event_type: str,
        severity: str,
        error_code: str | None,
        impact_summary: str,
        correlation_id: str | None = None,
        endpoint_ref: str | None = None,
        action_required: bool = True,
        visibility_class: str = "RESTRICTED_OPERATIONAL",
    ) -> OperationalIncident:
        if severity not in {"INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid severity")
        if not dedup_key or not event_type or not impact_summary:
            raise ValueError("incident identity and safe impact summary are required")
        now = self._now()
        existing = self.db.execute(
            "select incident_id,first_seen_at,occurrence_count from gateway_operational_incident where dedup_key=?",
            (dedup_key,),
        ).fetchone()
        if existing is None:
            incident_id = str(uuid.uuid4())
            first_seen = now
            occurrences = 1
            self.db.execute(
                """insert into gateway_operational_incident(
                incident_id,dedup_key,module,event_type,lifecycle_state,severity,first_seen_at,last_seen_at,resolved_at,
                correlation_id,endpoint_ref,error_code,impact_summary,action_required,occurrence_count,visibility_class
                ) values(?,?, 'GATEWAY', ?, 'OPEN', ?, ?, ?, null, ?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, dedup_key, event_type, severity, first_seen, now, correlation_id, endpoint_ref,
                 error_code, impact_summary, int(action_required), occurrences, visibility_class),
            )
        else:
            incident_id = existing["incident_id"]
            first_seen = existing["first_seen_at"]
            occurrences = int(existing["occurrence_count"]) + 1
            self.db.execute(
                """update gateway_operational_incident set event_type=?,lifecycle_state='OPEN',severity=?,last_seen_at=?,
                resolved_at=null,correlation_id=coalesce(?,correlation_id),endpoint_ref=coalesce(?,endpoint_ref),error_code=?,
                impact_summary=?,action_required=?,occurrence_count=?,visibility_class=? where dedup_key=?""",
                (event_type, severity, now, correlation_id, endpoint_ref, error_code, impact_summary,
                 int(action_required), occurrences, visibility_class, dedup_key),
            )
        self.db.commit()
        return self.get(incident_id)

    def recovering(self, dedup_key: str, impact_summary: str) -> OperationalIncident | None:
        row = self.db.execute("select incident_id from gateway_operational_incident where dedup_key=?", (dedup_key,)).fetchone()
        if row is None:
            return None
        self.db.execute(
            "update gateway_operational_incident set lifecycle_state='RECOVERING',last_seen_at=?,impact_summary=?,action_required=0 where dedup_key=?",
            (self._now(), impact_summary, dedup_key),
        )
        self.db.commit()
        return self.get(row["incident_id"])

    def resolve_incident(self, dedup_key: str, impact_summary: str) -> OperationalIncident | None:
        row = self.db.execute("select incident_id from gateway_operational_incident where dedup_key=?", (dedup_key,)).fetchone()
        if row is None:
            return None
        now = self._now()
        self.db.execute(
            """update gateway_operational_incident set lifecycle_state='RESOLVED',last_seen_at=?,resolved_at=?,
            impact_summary=?,action_required=0 where dedup_key=?""",
            (now, now, impact_summary, dedup_key),
        )
        self.db.commit()
        return self.get(row["incident_id"])

    def get(self, incident_id: str) -> OperationalIncident:
        row = self.db.execute("select * from gateway_operational_incident where incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise KeyError(incident_id)
        return self._incident(row)

    def list_incidents(self, *, lifecycle_state: str | None = None, limit: int = 100) -> list[OperationalIncident]:
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        params: list[object] = []
        where = ""
        if lifecycle_state is not None:
            if lifecycle_state not in {"OPEN", "RECOVERING", "RESOLVED"}:
                raise ValueError("invalid lifecycle state")
            where = " where lifecycle_state=?"
            params.append(lifecycle_state)
        params.append(limit)
        rows = self.db.execute(
            f"select * from gateway_operational_incident{where} order by last_seen_at desc limit ?", params
        ).fetchall()
        return [self._incident(row) for row in rows]

    def summary(self, limit: int = 100) -> dict:
        items = self.list_incidents(limit=limit)
        open_count = sum(i.lifecycle_state == "OPEN" for i in items)
        recovering_count = sum(i.lifecycle_state == "RECOVERING" for i in items)
        return {
            "module": "GATEWAY",
            "status": "DEGRADED" if open_count else ("RECOVERING" if recovering_count else "HEALTHY"),
            "openIncidents": open_count,
            "recoveringIncidents": recovering_count,
            "items": [asdict(i) for i in items],
            "partial": False,
        }

    @staticmethod
    def _incident(row: sqlite3.Row) -> OperationalIncident:
        return OperationalIncident(
            incident_id=row["incident_id"], module=row["module"], event_type=row["event_type"],
            lifecycle_state=row["lifecycle_state"], severity=row["severity"], first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"], resolved_at=row["resolved_at"], correlation_id=row["correlation_id"],
            endpoint_ref=row["endpoint_ref"], error_code=row["error_code"], impact_summary=row["impact_summary"],
            action_required=bool(row["action_required"]), dedup_key=row["dedup_key"],
            occurrence_count=int(row["occurrence_count"]), visibility_class=row["visibility_class"],
        )

    def export_json(self, *, lifecycle_state: str | None = None, limit: int = 100) -> str:
        return json.dumps([asdict(i) for i in self.list_incidents(lifecycle_state=lifecycle_state, limit=limit)], sort_keys=True)
