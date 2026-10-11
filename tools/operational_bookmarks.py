"""Private owner coverage bookmarks: publication positions, never consultation."""
import json
import math
import uuid
from datetime import timedelta, timezone
from tools.operational_cursor import CursorRejected, MAX_BYTES, digest

PROFILE = "ouf.owner-publication-bookmark.v1"


class PublicationBookmarks:
    """Reference primitive; the host must supply its fresh owner-local SDK."""
    def __init__(self, store, authorize_collection=None):
        self.store, self.authorize_collection = store, authorize_collection
        store.db.create_function("ouf_bookmark_now", 0, store._now)
        store.db.executescript("""
        create table if not exists gateway_bookmark_scope(
          session_id text primary key references gateway_incident_session(session_id) on delete cascade,
          filters text not null,parent_token text);
        create table if not exists gateway_bookmark_page(
          session_id text not null references gateway_incident_session(session_id) on delete cascade,
          position integer not null,digest text not null,complete integer not null check(complete in(0,1)),
          primary key(session_id,position));
        create trigger if not exists gateway_bookmark_scope_immutable
          before update on gateway_bookmark_scope begin select raise(abort,'IMMUTABLE_BOOKMARK_SCOPE'); end;
        create table if not exists gateway_publication_bookmark(
          token text primary key,session_id text not null unique,principal text not null,tenant text not null,
          identity_digest text not null,policy_ref text not null,filters text not null,
          watermark integer not null check(watermark>=0),parent_token text,
          created_at text not null,expires_at text not null);
        create trigger if not exists gateway_publication_bookmark_immutable
          before update on gateway_publication_bookmark begin select raise(abort,'IMMUTABLE_PUBLICATION_BOOKMARK'); end;
        create trigger if not exists gateway_publication_bookmark_retention
          before delete on gateway_publication_bookmark when old.expires_at>ouf_bookmark_now()
          begin select raise(abort,'LIVE_PUBLICATION_BOOKMARK'); end;
        create index if not exists gateway_publication_bookmark_expiry on gateway_publication_bookmark(expires_at);
        create table if not exists gateway_publication_history_floor(
          singleton integer primary key check(singleton=1),revision integer not null check(revision>=0));
        insert or ignore into gateway_publication_history_floor values(1,0);
        create trigger if not exists gateway_publication_history_floor_monotone
          before update on gateway_publication_history_floor when new.revision<old.revision
          begin select raise(abort,'HISTORY_FLOOR_CANNOT_REWIND'); end;
        """)

    @staticmethod
    def _identity(identity):
        # A new login does not erase a read boundary. Claims are not grants:
        # current collection/row decisions are still mandatory on every call.
        return digest({k: identity.get(k) for k in
                       ("principal", "tenant", "actor", "servicePrincipal", "issuer", "audience")})

    def _authorize(self, identity, policy):
        if (not isinstance(identity, dict)
                or any(not isinstance(identity.get(k), str) or not 1 <= len(identity[k]) <= 200 for k in ("principal", "tenant"))
                or not isinstance(identity.get("actor"), str) or identity["actor"] not in {"HUMAN", "SERVICE", "AI_AGENT"}
                or not isinstance(policy, str) or not 1 <= len(policy) <= 1024):
            raise CursorRejected(403, "BOOKMARK_IDENTITY_UNPROVEN")
        if self.authorize_collection is None:
            raise CursorRejected(503, "BOOKMARK_OWNER_AUTHORIZATION_UNAVAILABLE")
        if self.authorize_collection(identity, policy) is not True:
            raise CursorRejected(403, "BOOKMARK_OWNER_AUTHORIZATION_DENIED")

    @staticmethod
    def _query(query):
        if not isinstance(query, dict) or set(query) - {"state", "limit"}:
            raise CursorRejected(400, "BOOKMARK_QUERY_INVALID")
        if type(query.get("limit", 50)) is not int or not 1 <= query.get("limit", 50) <= 100:
            raise CursorRejected(400, "BOOKMARK_QUERY_INVALID")
        if "state" in query and (not isinstance(query["state"], str) or query["state"] not in {"OPEN", "RECOVERING", "RESOLVED"}):
            raise CursorRejected(400, "BOOKMARK_QUERY_INVALID")
        return {k: v for k, v in query.items() if k != "limit"}

    def start(self, query, identity, policy, authorize_item):
        self._authorize(identity, policy)
        filters = self._query(query)
        token = self.store.cursors._capture(query, identity, policy)
        self._scope(token, filters, None)
        return self.page(token, identity, policy, authorize_item)

    def resume(self, bookmark, identity, policy, authorize_item, limit=50):
        self._authorize(identity, policy)
        self._query({"limit": limit})
        try:
            if str(uuid.UUID(bookmark)) != bookmark or uuid.UUID(bookmark).int == 0:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise CursorRejected(400, "BOOKMARK_INVALID")
        row = self.store.db.execute("select * from gateway_publication_bookmark where token=?", (bookmark,)).fetchone()
        if row is None or row["identity_digest"] != self._identity(identity):
            raise CursorRejected(404, "BOOKMARK_NOT_FOUND")
        if row["policy_ref"] != policy:
            raise CursorRejected(409, "BOOKMARK_POLICY_CHANGED")
        floor = self.store.db.execute("select revision from gateway_publication_history_floor").fetchone()[0]
        if row["expires_at"] <= self.store._now() or row["watermark"] < floor:
            raise CursorRejected(410, "BOOKMARK_HISTORY_GAP")
        filters = json.loads(row["filters"])
        query = dict(filters, limit=limit)
        token = self.store.cursors._capture(query, identity, policy, lower_revision=row["watermark"])
        self._scope(token, filters, bookmark)
        return self.page(token, identity, policy, authorize_item)

    def _scope(self, token, filters, parent):
        # No remote authorization or waiting inside these short metadata writes.
        with self.store.db:
            self.store.db.execute("""insert into gateway_bookmark_scope
                select session_id,?,? from gateway_incident_page_cursor where token=?""",
                (json.dumps(filters, sort_keys=True, separators=(",", ":")), parent, token))

    def page(self, token, identity, policy, authorize_item):
        self._authorize(identity, policy)
        if not callable(authorize_item):
            raise CursorRejected(503, "BOOKMARK_ROW_AUTHORIZATION_UNAVAILABLE")
        result = self.store.cursors.page({"cursor": token}, identity, policy, authorize_item)
        db = self.store.db
        row = db.execute("""select s.*,c.position,b.filters,b.parent_token from gateway_incident_page_cursor c
            join gateway_incident_session s using(session_id) join gateway_bookmark_scope b using(session_id)
            where c.token=?""", (token,)).fetchone()
        if row is None:
            raise CursorRejected(404, "BOOKMARK_SCOPE_NOT_FOUND")
        with db:
            db.execute("""insert into gateway_bookmark_page values(?,?,?,?)
                on conflict(session_id,position) do update set digest=excluded.digest,complete=excluded.complete""",
                (row["session_id"], row["position"], result["itemsDigest"], int(not result["partial"])))
        result["bookmarkProfile"] = PROFILE
        result["coverage"]["bookmarkKind"] = "READ_POSITION_NOT_OPERATOR_CONFIRMATION"
        if not result["truncated"] and not result["partial"]:
            expected = max(1, math.ceil(row["item_count"] / row["page_limit"]))
            complete = db.execute("select count(*) from gateway_bookmark_page where session_id=? and complete=1",
                                  (row["session_id"],)).fetchone()[0]
            if complete == expected:
                result["publicationBookmark"] = self._issue(row, identity, policy)
                result["coverage"]["parentBookmark"] = row["parent_token"]
        if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_BYTES:
            raise CursorRejected(503, "OPERATIONAL_RESPONSE_CAPACITY")
        return result

    def _issue(self, frame, identity, policy):
        db = self.store.db
        now = self.store._now()
        expiry = (self.store.clock().astimezone(timezone.utc) + timedelta(days=90)).isoformat().replace("+00:00", "Z")
        db.execute("begin immediate")
        try:
            expected = max(1, math.ceil(frame["item_count"] / frame["page_limit"]))
            complete = db.execute("select count(*) from gateway_bookmark_page where session_id=? and complete=1",
                                  (frame["session_id"],)).fetchone()[0]
            if complete != expected:
                raise CursorRejected(409, "BOOKMARK_COVERAGE_INCOMPLETE")
            if frame["expires_at"] <= now:
                raise CursorRejected(410, "BOOKMARK_SNAPSHOT_EXPIRED")
            existing = db.execute("select token from gateway_publication_bookmark where session_id=?",
                                  (frame["session_id"],)).fetchone()
            if existing:
                db.commit()
                return existing[0]
            # One bounded cleanup; no silent replacement of live positions.
            db.execute("""delete from gateway_publication_bookmark where token in
                (select token from gateway_publication_bookmark where expires_at<=? order by expires_at limit 1)""", (now,))
            counts = db.execute("""select count(*) total,coalesce(sum(tenant=?),0) tenant_count,
                coalesce(sum(tenant=? and principal=?),0) principal_count from gateway_publication_bookmark""",
                (identity["tenant"], identity["tenant"], identity["principal"])).fetchone()
            if counts["total"] >= 32768 or counts["tenant_count"] >= 4096 or counts["principal_count"] >= 512:
                raise CursorRejected(503, "BOOKMARK_CAPACITY_UNAVAILABLE")
            token = str(uuid.uuid4())
            db.execute("insert into gateway_publication_bookmark values(?,?,?,?,?,?,?,?,?,?,?)",
                       (token, frame["session_id"], identity["principal"], identity["tenant"], self._identity(identity),
                        policy, frame["filters"], frame["watermark"], frame["parent_token"], now, expiry))
            db.commit()
            return token
        except Exception:
            db.rollback()
            raise

