from __future__ import annotations

import base64
import hashlib
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
        self.db.execute("create table if not exists gateway_incident_transition(sequence_id integer primary key autoincrement, incident_id text not null, projection text not null)")
        fields=list(OperationalIncident.__dataclass_fields__)
        pairs=",".join("'%s',new.%s" % (k,k) for k in fields)
        for event in ("insert","update"):
            self.db.execute(f"create trigger if not exists gateway_incident_capture_{event} after {event} on gateway_operational_incident begin insert into gateway_incident_transition(incident_id,projection) values(new.incident_id,json_object({pairs})); end")
        # Existing incidents get one baseline snapshot, without inventing earlier transitions.
        old_pairs=",".join("'%s',i.%s" % (k,k) for k in fields)
        self.db.execute(f"insert into gateway_incident_transition(incident_id,projection) select incident_id,json_object({old_pairs}) from gateway_operational_incident i where not exists(select 1 from gateway_incident_transition t where t.incident_id=i.incident_id)")
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

    def incident_page(self, query: dict, principal_binding: str) -> dict:
        allowed={"limit","state","sourceId","jobId","severity","since","until","cursor"}
        if set(query)-allowed:
            raise ValueError("unknown query field")
        limit=query.get("limit",50); state=query.get("state"); severity=query.get("severity")
        if type(limit) is not int or not 1<=limit<=100 or state not in {None,"OPEN","RECOVERING","RESOLVED"} or severity not in {None,"INFO","WARNING","ERROR","CRITICAL"}:
            raise ValueError("invalid filter")
        if query.get("sourceId") is not None or query.get("jobId") is not None:
            # Gateway incidents have endpoint references, never ingestion source/job identifiers.
            return {"items":[],"partial":False,"hasMore":False,"authorization":"AUTHORIZED"}
        now=self.clock().astimezone(timezone.utc)
        binding=hashlib.sha256(json.dumps([principal_binding,state,severity,limit],separators=(",",":")).encode()).hexdigest()
        def timestamp(value):
            if not isinstance(value,str): raise ValueError("timestamp required")
            parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
            if parsed.tzinfo is None: raise ValueError("timezone required")
            return parsed
        token=query.get("cursor")
        if token is not None:
            try:
                if not isinstance(token,str) or len(token)>4096: raise ValueError("invalid cursor")
                c=json.loads(base64.urlsafe_b64decode(token+"="*((-len(token))%4)))
                if c["binding"]!=binding or not now<timestamp(c["expires"])<=now+timedelta(minutes=16): raise ValueError("cursor expired")
                if type(c["snapshot"]) is not int or c["snapshot"]<0 or type(c["before"]) is not int or c["before"]<1: raise ValueError("invalid cursor")
                for field in ("since","until"):
                    if query.get(field) is not None and timestamp(query[field])!=timestamp(c[field]): raise ValueError("cursor filter changed")
            except (KeyError,TypeError,ValueError,OverflowError) as e: raise ValueError("invalid cursor") from e
        else:
            until=timestamp(query["until"]) if query.get("until") else now
            since=timestamp(query["since"]) if query.get("since") else until-timedelta(days=1)
            c={"snapshot":self.db.execute("select coalesce(max(sequence_id),0) from gateway_incident_transition").fetchone()[0],"before":9223372036854775807,
               "since":since.isoformat(),"until":until.isoformat(),"expires":(now+timedelta(minutes=15)).isoformat(),"binding":binding}
        since=timestamp(c["since"]);until=timestamp(c["until"])
        if not since<=until<=now+timedelta(seconds=1) or until-since>timedelta(days=30): raise ValueError("invalid window")
        rows=self.db.execute("""with latest as (
            select max(sequence_id) sequence_id from gateway_incident_transition where sequence_id<=?
             and julianday(json_extract(projection,'$.last_seen_at'))<=julianday(?) group by incident_id)
            select t.sequence_id,t.projection from gateway_incident_transition t join latest l using(sequence_id)
             where t.sequence_id<? and julianday(json_extract(projection,'$.last_seen_at'))>=julianday(?)
             and (? is null or json_extract(projection,'$.lifecycle_state')=?)
             and (? is null or json_extract(projection,'$.severity')=?) order by t.sequence_id desc limit ?""",
             (c["snapshot"],c["until"],c["before"],c["since"],state,state,severity,severity,limit+1)).fetchall()
        items=[];partial=False
        for row in rows[:limit]:
            item=json.loads(row["projection"])
            if item["visibility_class"] not in {"PUBLIC_OPERATIONAL","TENANT_OPERATIONAL"}: partial=True;continue
            item["action_required"]=bool(item["action_required"]);items.append(item)
        out={"items":items,"partial":partial,"authorization":"REDACTED" if partial else "AUTHORIZED","hasMore":len(rows)>limit,"since":c["since"],"until":c["until"]}
        if len(rows)>limit:
            c["before"]=rows[limit-1]["sequence_id"]
            out["nextCursor"]=base64.urlsafe_b64encode(json.dumps(c,separators=(",",":")).encode()).decode().rstrip("=")
        return out

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
