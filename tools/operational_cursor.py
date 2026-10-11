"""Bounded reference owner snapshots; no operator receipt or recovery authority."""
from __future__ import annotations
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

PROFILE = "ouf.incident-owner-cursor.v1"
MAX_ITEMS = 20_000
MAX_BYTES = 512 * 1024


class CursorRejected(ValueError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def digest(items):
    return hashlib.sha256(json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class OwnerIncidentCursor:
    def __init__(self, store):
        self.store = store
        db = store.db
        # SQLite admits one writer at a time: these revisions commit in order.
        # This argument does NOT apply to a PostgreSQL bigserial sequence.
        # Fixed projection: future database columns cannot silently become public.
        fields = ["incident_id", "dedup_key", "module", "event_type", "lifecycle_state", "severity",
                  "first_seen_at", "last_seen_at", "resolved_at", "correlation_id", "endpoint_ref",
                  "error_code", "impact_summary", "action_required", "occurrence_count", "visibility_class"]
        pairs = []
        for key in fields:
            value = "json(case when new.action_required=1 then 'true' else 'false' end)" if key == "action_required" else "new." + key
            pairs.extend(["'" + key + "'", value])
        body = "json_object(" + ",".join(pairs) + ")"
        db.executescript(f"""
        create table if not exists gateway_incident_history_baseline(singleton integer primary key check(singleton=1),created_at text not null);
        create table if not exists gateway_incident_transition(revision integer primary key autoincrement,incident_id text not null,body text not null);
        create trigger if not exists gateway_incident_transition_insert after insert on gateway_operational_incident begin
          insert into gateway_incident_transition(incident_id,body) values(new.incident_id,{body}); end;
        create trigger if not exists gateway_incident_transition_update after update on gateway_operational_incident begin
          insert into gateway_incident_transition(incident_id,body) values(new.incident_id,{body}); end;
        create trigger if not exists gateway_incident_transition_immutable_update before update on gateway_incident_transition begin
          select raise(abort,'IMMUTABLE_INCIDENT_HISTORY'); end;
        create trigger if not exists gateway_incident_transition_immutable_delete before delete on gateway_incident_transition begin
          select raise(abort,'IMMUTABLE_INCIDENT_HISTORY'); end;
        create table if not exists gateway_incident_session(
          session_id text primary key, principal text not null,tenant text not null,fingerprint text not null,policy_ref text not null,
          page_limit integer not null check(page_limit between 1 and 100),created_at text not null,expires_at text not null,
          history_gap integer not null,watermark integer not null,item_count integer not null default 0);
        create table if not exists gateway_incident_page_item(session_id text not null references gateway_incident_session(session_id) on delete cascade,
          position integer not null check(position between 0 and 19999),body text not null,primary key(session_id,position));
        create table if not exists gateway_incident_page_cursor(token text primary key,session_id text not null references gateway_incident_session(session_id) on delete cascade,
          position integer not null check(position between 0 and 20000),unique(session_id,position));
        create index if not exists gateway_incident_transition_latest on gateway_incident_transition(incident_id,revision desc);
        create index if not exists gateway_incident_session_expiry on gateway_incident_session(expires_at);
        """)
        db.execute("pragma foreign_keys=ON")
        with db:
            admitted = db.execute("insert or ignore into gateway_incident_history_baseline values(1,?)", (store._now(),)).rowcount
            if admitted:
                # Honest baseline: preexisting rows have no invented earlier history.
                for row in db.execute("select * from gateway_operational_incident").fetchall():
                    item = {key: row[key] for key in fields}
                    item["action_required"] = bool(item["action_required"])
                    db.execute("insert into gateway_incident_transition(incident_id,body) values(?,?)", (row["incident_id"], json.dumps(item)))

    def page(self, query, identity, policy_ref, authorize_item):
        token = query.get("cursor")
        if token is not None:
            if set(query) != {"cursor"}:
                raise CursorRejected(400, "CURSOR_FILTER_CHANGE")
            try:
                token = str(uuid.UUID(token))
            except (ValueError, TypeError, AttributeError):
                raise CursorRejected(400, "CURSOR_INVALID")
        else:
            token = self._capture(query, identity, policy_ref)
        db = self.store.db
        frame = db.execute("""select s.*,c.position from gateway_incident_page_cursor c
            join gateway_incident_session s using(session_id) where c.token=?""", (token,)).fetchone()
        if frame is None or frame["principal"] != identity["principal"] or frame["tenant"] != identity["tenant"] or frame["fingerprint"] != digest(identity):
            raise CursorRejected(404, "CURSOR_NOT_FOUND")
        if frame["policy_ref"] != policy_ref:
            raise CursorRejected(409, "CURSOR_POLICY_CHANGED")
        if frame["expires_at"] <= self.store._now():
            raise CursorRejected(410, "CURSOR_EXPIRED")
        rows = db.execute("""select body from gateway_incident_page_item where session_id=? and position>=?
            order by position limit ?""", (frame["session_id"], frame["position"], frame["page_limit"])).fetchall()
        # No policy evaluation or external I/O inside a write transaction.
        items = [json.loads(r["body"]) for r in rows]
        visible = [item for item in items if authorize_item(item)]
        partial = len(visible) != len(items) or bool(frame["history_gap"])
        next_pos = frame["position"] + len(rows)
        result = {"module": "GATEWAY", "items": visible, "partial": partial,
                  "truncated": next_pos < frame["item_count"], "cursor": token,
                  "snapshotRef": frame["session_id"], "snapshotAt": frame["created_at"], "expiresAt": frame["expires_at"],
                  "priorityProfile": "ouf.incident-priority.v1", "cursorProfile": PROFILE,
                  "itemsDigest": digest(visible), "consultationRecorded": False,
                  "coverage": {"kind": "SQLITE_REFERENCE_PLATFORM", "publicationLag": False, "historyGap": bool(frame["history_gap"])}}
        if len(visible) != len(items):
            result["unavailable"] = [{"module": "GATEWAY", "reason": "REDACTED_BY_CURRENT_POLICY"}]
        if result["truncated"]:
            with db:
                db.execute("insert into gateway_incident_page_cursor values(?,?,?) on conflict(session_id,position) do nothing",
                           (str(uuid.uuid4()), frame["session_id"], next_pos))
                result["nextCursor"] = db.execute("select token from gateway_incident_page_cursor where session_id=? and position=?", (frame["session_id"], next_pos)).fetchone()[0]
        if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_BYTES:
            raise CursorRejected(503, "OPERATIONAL_RESPONSE_CAPACITY")
        return result

    def _capture(self, query, identity, policy_ref, lower_revision=None):
        db = self.store.db
        now = self.store._now()
        limit = query.get("limit", 50)
        sid, token = str(uuid.uuid4()), str(uuid.uuid4())
        expiry = (self.store.clock().astimezone(timezone.utc) + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
        db.execute("begin immediate")
        try:
            expired = db.execute("select session_id from gateway_incident_session where expires_at<=? order by expires_at limit 1", (now,)).fetchone()
            if expired:
                db.execute("delete from gateway_incident_session where session_id=?", (expired[0],))
            counts = db.execute("""select count(*) total,sum(tenant=?) tenant_count,sum(tenant=? and principal=?) principal_count
                from gateway_incident_session""", (identity["tenant"], identity["tenant"], identity["principal"])).fetchone()
            if counts["total"] >= 4096 or (counts["tenant_count"] or 0) >= 128 or (counts["principal_count"] or 0) >= 16:
                raise CursorRejected(503, "OPERATIONAL_SESSION_CAPACITY")
            used = db.execute("""select coalesce(sum(item_count),0) total,coalesce(sum(case when tenant=? then item_count else 0 end),0) tenant_items
                from gateway_incident_session""", (identity["tenant"],)).fetchone()
            available = min(MAX_ITEMS, limit * 200, 200000 - used["total"], 64000 - used["tenant_items"])
            if available < 0:
                raise CursorRejected(503, "OPERATIONAL_ITEM_CAPACITY")
            watermark = db.execute("select coalesce(max(revision),0) from gateway_incident_transition").fetchone()[0]
            baseline = db.execute("select created_at from gateway_incident_history_baseline").fetchone()[0]
            conditions, params = [], [watermark]
            if query.get("state"):
                conditions.append("json_extract(t.body,'$.lifecycle_state')=?")
                params.append(query["state"])
            if query.get("since"):
                conditions.append("json_extract(t.body,'$.last_seen_at')>=?")
                params.append(query["since"])
            if lower_revision is not None:
                if type(lower_revision) is not int or not 0 <= lower_revision <= watermark:
                    raise CursorRejected(409, "BOOKMARK_PUBLICATION_CONFLICT")
                conditions.append("t.revision>?")
                params.append(lower_revision)
            where = " where " + " and ".join(conditions) if conditions else ""
            params.append(available + 1)
            rows = db.execute("""select t.body from gateway_incident_transition t
                join (select incident_id,max(revision) rev from gateway_incident_transition where revision<=? group by incident_id) latest
                on latest.rev=t.revision""" + where + """ order by
                case json_extract(t.body,'$.lifecycle_state') when 'RESOLVED' then 1 else 0 end,
                case json_extract(t.body,'$.severity') when 'CRITICAL' then 4 when 'ERROR' then 3 when 'WARNING' then 2 else 1 end desc,
                json_extract(t.body,'$.action_required') desc,json_extract(t.body,'$.last_seen_at') desc,t.incident_id asc limit ?""", params).fetchall()
            if len(rows) > available:
                raise CursorRejected(503, "OPERATIONAL_ITEM_CAPACITY")
            db.execute("insert into gateway_incident_session values(?,?,?,?,?,?,?,?,?,?,?)",
                       (sid, identity["principal"], identity["tenant"], digest(identity), policy_ref, limit, now, expiry,
                        int(bool(query.get("since") and query["since"] < baseline)), watermark, len(rows)))
            db.executemany("insert into gateway_incident_page_item values(?,?,?)", [(sid, i, r["body"]) for i, r in enumerate(rows)])
            db.execute("insert into gateway_incident_page_cursor values(?,?,?)", (token, sid, 0))
            db.commit()
            return token
        except Exception:
            db.rollback()
            raise
