from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
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
        self.db.execute(
            """
            create table if not exists gateway_operational_collector_state(
              source text primary key,
              last_observed_at text not null,
              last_event_at text
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

    def has_restricted_incidents(self) -> bool:
        return self.db.execute("select 1 from gateway_operational_incident where visibility_class not in ('PUBLIC_OPERATIONAL','TENANT_OPERATIONAL') limit 1").fetchone() is not None

    def active_incident_keys(self, prefix: str | None = None) -> set[str]:
        if prefix is None:
            rows = self.db.execute(
                "select dedup_key from gateway_operational_incident where lifecycle_state in ('OPEN','RECOVERING')"
            ).fetchall()
        else:
            rows = self.db.execute(
                "select dedup_key from gateway_operational_incident where lifecycle_state in ('OPEN','RECOVERING') and dedup_key like ?",
                (prefix + "%",),
            ).fetchall()
        return {row["dedup_key"] for row in rows}

    def mark_collector_observed(self, source: str, *, event: bool = False) -> None:
        if source not in {"APISIX", "ETCD"}:
            raise ValueError("unknown collector source")
        now = self._now()
        self.db.execute(
            """insert into gateway_operational_collector_state(source,last_observed_at,last_event_at)
               values(?,?,?)
               on conflict(source) do update set
                 last_observed_at=excluded.last_observed_at,
                 last_event_at=case when excluded.last_event_at is not null then excluded.last_event_at else gateway_operational_collector_state.last_event_at end""",
            (source, now, now if event else None),
        )
        self.db.commit()

    def collector_freshness(self, max_age_seconds: int, required_sources=("APISIX", "ETCD")) -> dict[str, bool]:
        if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 3600:
            raise ValueError("invalid collector freshness")
        now = self.clock().astimezone(timezone.utc)
        rows = {
            row["source"]: row["last_observed_at"]
            for row in self.db.execute(
                "select source,last_observed_at from gateway_operational_collector_state"
            ).fetchall()
        }
        result = {}
        for source in required_sources:
            value = rows.get(source)
            try:
                observed = datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
            except ValueError:
                observed = None
            result[source] = bool(observed and observed.tzinfo is not None and now - observed <= timedelta(seconds=max_age_seconds))
        return result

    def summary(self, limit: int = 100, since: str | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid limit")
        if since is not None and not isinstance(since, str):
            raise ValueError("invalid time window")
        now = self.clock().astimezone(timezone.utc)
        start = now - timedelta(days=1) if since is None else datetime.fromisoformat(since.replace("Z", "+00:00"))
        if start.tzinfo is None or start > now or start < now - timedelta(days=30):
            raise ValueError("invalid time window")
        # Current health is independent of the catch-up page and time filter.
        counts = dict(self.db.execute("select lifecycle_state,count(*) from gateway_operational_incident group by lifecycle_state").fetchall())
        rows = self.db.execute("select * from gateway_operational_incident where julianday(last_seen_at)>=julianday(?) and julianday(last_seen_at)<=julianday(?) order by last_seen_at desc,incident_id limit ?", (start.isoformat(), now.isoformat(), limit+1)).fetchall()
        partial = len(rows)>limit
        open_count = counts.get("OPEN", 0); recovering_count = counts.get("RECOVERING", 0)
        result = {"module":"GATEWAY", "status":"DEGRADED" if open_count else "RECOVERING" if recovering_count else "HEALTHY",
                  "items":[asdict(self._incident(row)) for row in rows[:limit]], "partial":partial}
        result.update(openIncidents=open_count, recoveringIncidents=recovering_count)
        return result

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
