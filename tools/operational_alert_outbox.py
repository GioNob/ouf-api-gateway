"""Inert owner-local reference alert outbox. No SMTP/client/recipient defaults.

The host supplies current local authorization and a qualified transport. Only
proven not-accepted transient errors retry; ambiguous effects remain UNKNOWN.
"""
from __future__ import annotations
import hashlib
import json
import random
import re
import uuid
from dataclasses import dataclass

PROFILE = 'ouf.alert-delivery.finite.v1'
BACKOFF = (5, 15, 60, 300, 900)


class AlertBlocked(ValueError): pass


@dataclass(frozen=True)
class AlertDestination:
    destination_ref: str
    recipient_ref: str
    transport_ref: str
    transport_secret_ref: str
    policy_ref: str
    minimum_severity: str = 'ERROR'


@dataclass(frozen=True)
class AlertOutcome:
    kind: str  # ACCEPTED / TRANSIENT_NOT_ACCEPTED / PERMANENT / UNKNOWN
    receipt_ref: str = ''
    retry_after_seconds: int = 0


class AlertOutbox:
    def __init__(self, store, authorize=None, jitter=None):
        self.store, self.authorize = store, authorize
        self.jitter = jitter or (lambda: random.uniform(.8,1.2))
        store.db.executescript('''
        create table if not exists gateway_alert_destination(destination_ref text primary key,config text not null,config_hash text not null,authority_tenant text not null);
        create table if not exists gateway_alert_transition_receipt(destination_ref text not null,revision integer not null,primary key(destination_ref,revision));
        create table if not exists gateway_alert_delivery(
          delivery_id text primary key,incident_id text not null,destination_ref text not null,episode integer not null,phase text not null,
          payload text not null,config_hash text not null,state text not null,version integer not null default 0,
          total_attempts integer not null default 0,next_due real not null,lease_until real,claim_token text,receipt_ref text,
          active_session text not null,reconciliation_attempts integer not null default 0,unique(incident_id,destination_ref,episode,phase));
        create table if not exists gateway_alert_budget_session(session_id text primary key,delivery_id text not null,
          actor text not null,actor_type text not null,tenant_id text not null,reason text not null,decision_ref text not null,profile text not null,started_at real not null,
          deadline real not null,max_attempts integer not null,attempts integer not null default 0,state text not null);
        create table if not exists gateway_alert_config_audit(event_id text primary key,destination_ref text not null,principal text not null,
          decision_ref text not null,policy_ref text not null,tenant_id text not null,occurred_at real not null);
        create index if not exists gateway_alert_due on gateway_alert_delivery(state,next_due);
        ''')

    def _now(self): return self.store.clock().timestamp()

    def _authorize(self, action, destination, delivery_id=None, human=False):
        if self.authorize is None: raise AlertBlocked('ALERT_OWNER_AUTHORIZATION_UNAVAILABLE')
        resource={'module':'GATEWAY','scope':'PLATFORM','destinationRef':destination,'deliveryRef':delivery_id,
                  'detailLevel':'RESTRICTED_OPERATIONAL'}
        grant=self.authorize(action,resource)
        if not isinstance(grant,dict) or grant.get('allowed') is not True or grant.get('resource') != resource or not grant.get('decisionRef') or not grant.get('principal') or not grant.get('policyRef') or grant.get('actor') not in {'HUMAN','SERVICE'}:
            raise AlertBlocked('ALERT_OWNER_AUTHORIZATION_DENIED')
        if not isinstance(grant.get('tenant'),str) or not 1<=len(grant['tenant'])<=200 or any(not isinstance(grant.get(key),str) or not 1<=len(grant[key])<=200 for key in ('principal','decisionRef','policyRef')):
            raise AlertBlocked('ALERT_VERIFIED_IDENTITY_UNPROVEN')
        existing=self.store.db.execute('select authority_tenant from gateway_alert_destination where destination_ref=?',(destination,)).fetchone()
        if existing is not None and existing[0]!=grant['tenant']: raise AlertBlocked('ALERT_TENANT_CONTEXT_MISMATCH')
        if human and grant['actor'] != 'HUMAN': raise AlertBlocked('ALERT_HUMAN_REQUIRED')
        return grant

    def configure(self, destination: AlertDestination):
        from dataclasses import asdict
        if not isinstance(destination,AlertDestination) or any(not isinstance(value,str) or not 1<=len(value)<=200 for value in asdict(destination).values()) or destination.minimum_severity not in {'WARNING','ERROR','CRITICAL'}:
            raise AlertBlocked('ALERT_DESTINATION_INVALID')
        refs=(destination.destination_ref,destination.recipient_ref,destination.transport_ref,destination.transport_secret_ref)
        if any(re.fullmatch(r'[a-z][a-z0-9+.-]*://[A-Za-z0-9/_:.~-]+',value) is None for value in refs):
            raise AlertBlocked('ALERT_REFERENCE_REQUIRED')
        grant=self._authorize('CONFIGURE',destination.destination_ref,human=True)
        if grant['policyRef'] != destination.policy_ref: raise AlertBlocked('ALERT_DESTINATION_POLICY_UNPROVEN')
        config=json.dumps(asdict(destination),sort_keys=True,separators=(',',':'))
        fingerprint=hashlib.sha256(config.encode()).hexdigest();db=self.store.db
        db.execute('begin immediate')
        try:
            old=db.execute('select config_hash from gateway_alert_destination where destination_ref=?',(destination.destination_ref,)).fetchone()
            if old:
                if old[0] != fingerprint: raise AlertBlocked('ALERT_DESTINATION_INTENT_CONFLICT')
            else:
                if db.execute('select count(*) from gateway_alert_destination').fetchone()[0]>=32: raise AlertBlocked('ALERT_DESTINATION_CAPACITY')
                db.execute('insert into gateway_alert_destination values(?,?,?,?)',(destination.destination_ref,config,fingerprint,grant['tenant']))
                db.execute('insert into gateway_alert_config_audit values(?,?,?,?,?,?,?)',(str(uuid.uuid4()),destination.destination_ref,grant['principal'],grant['decisionRef'],grant['policyRef'],grant['tenant'],self._now()))
            db.commit()
        except Exception: db.rollback();raise

    def reconcile_owner_transitions(self, destination_ref, limit=64):
        """Durable reconciliation from owner history; never calls a transport.

        Current critical state is prioritized even when historical changes remain.
        Capacity failure rolls back receipts, retaining the unprocessed history.
        """
        if type(limit) is not int or not 1<=limit<=64: raise AlertBlocked('ALERT_RECONCILE_LIMIT')
        grant=self._authorize('ENQUEUE',destination_ref)
        db=self.store.db;db.execute('begin immediate')
        try:
            config=db.execute('select * from gateway_alert_destination where destination_ref=?',(destination_ref,)).fetchone()
            if config is None: raise AlertBlocked('ALERT_DESTINATION_UNCONFIGURED')
            if db.execute('select count(*) from gateway_alert_transition_receipt').fetchone()[0]+limit>200000:
                raise AlertBlocked('ALERT_RECEIPT_CAPACITY')
            rows=db.execute('''select min(t.revision) revision,t.incident_id from gateway_incident_transition t
                join gateway_operational_incident i on i.incident_id=t.incident_id
                where not exists(select 1 from gateway_alert_transition_receipt r where r.revision=t.revision and r.destination_ref=?)
                group by t.incident_id order by case i.lifecycle_state when 'RESOLVED' then 1 else 0 end,
                case i.severity when 'CRITICAL' then 4 when 'ERROR' then 3 when 'WARNING' then 2 else 1 end desc,t.revision limit ?''',(destination_ref,limit)).fetchall()
            for row in rows:
                self._enqueue_current(row['incident_id'],config,grant)
                db.execute('insert into gateway_alert_transition_receipt values(?,?)',(destination_ref,row['revision']))
            pending=db.execute('select exists(select 1 from gateway_incident_transition t where not exists(select 1 from gateway_alert_transition_receipt r where r.revision=t.revision and r.destination_ref=?))',(destination_ref,)).fetchone()[0]
            db.commit()
            return {'processedTransitions':len(rows),'deliveryAttempted':False,'historyReceiptIsOperatorConsultation':False,'ownerTransitionsPending':bool(pending),'partial':bool(pending)}
        except Exception: db.rollback();raise

    def _enqueue_current(self, incident_id, config, grant):
        db=self.store.db
        item=db.execute('select * from gateway_operational_incident where incident_id=?',(incident_id,)).fetchone()
        settings=json.loads(config['config']);rank={'INFO':1,'WARNING':2,'ERROR':3,'CRITICAL':4}
        # Count actual owner lifecycle crossings, not repeated RESOLVED metadata.
        closures=db.execute('''select count(*) from (select json_extract(body,'$.lifecycle_state') state,
            lag(json_extract(body,'$.lifecycle_state')) over(order by revision) previous from gateway_incident_transition where incident_id=?)
            where state='RESOLVED' and (previous is null or previous!='RESOLVED')''',(incident_id,)).fetchone()[0]
        episode=closures if item['lifecycle_state']=='RESOLVED' else closures+1
        phase='RECOVERY' if item['lifecycle_state']=='RESOLVED' else ('CRITICAL' if item['severity']=='CRITICAL' else 'PROBLEM')
        if phase=='RECOVERY':
            if not db.execute("select 1 from gateway_alert_delivery where incident_id=? and destination_ref=? and episode=? and phase!='RECOVERY'",(incident_id,config['destination_ref'],episode)).fetchone(): return
        elif rank[item['severity']]<rank[settings['minimum_severity']]: return
        if db.execute('select 1 from gateway_alert_delivery where incident_id=? and destination_ref=? and episode=? and phase=?',(incident_id,config['destination_ref'],episode,phase)).fetchone(): return
        total=db.execute('select count(*) from gateway_alert_delivery').fetchone()[0]
        active=db.execute("select count(*) from gateway_alert_delivery where state not in('ACCEPTED','CANCELLED')").fetchone()[0]
        scoped=db.execute("select count(*) from gateway_alert_delivery where destination_ref=? and state not in('ACCEPTED','CANCELLED')",(config['destination_ref'],)).fetchone()[0]
        if total>=4096 or active>=1024 or scoped>=128: raise AlertBlocked('ALERT_OUTBOX_CAPACITY')
        payload={'module':'GATEWAY','incidentRef':incident_id,'episode':episode,'phase':phase,'severity':item['severity'],
                 'errorCode':item['error_code'],'impactSummary':item['impact_summary'],'requiresCurrentAuthorization':True}
        encoded=json.dumps(payload,sort_keys=True,separators=(',',':'))
        if len(encoded.encode())>4096: raise AlertBlocked('ALERT_PAYLOAD_CAPACITY')
        delivery,sid=str(uuid.uuid4()),str(uuid.uuid4());now=self._now()
        db.execute('''insert into gateway_alert_delivery(delivery_id,incident_id,destination_ref,episode,phase,payload,config_hash,state,next_due,active_session)
            values(?,?,?,?,?,?,?,'PENDING',?,?)''',(delivery,incident_id,config['destination_ref'],episode,phase,encoded,config['config_hash'],now,sid))
        db.execute("insert into gateway_alert_budget_session values(?,?,?,?,?,'OWNER_INCIDENT_TRANSITION',?,?,?,?,128,0,'ACTIVE')",(sid,delivery,grant['principal'],grant['actor'],grant['tenant'],grant['decisionRef'],PROFILE,now,now+86400))

    def send_once(self, destination_ref, transport):
        self._authorize('DISPATCH',destination_ref)
        db=self.store.db;now=self._now();claim=str(uuid.uuid4())
        preview=db.execute("select delivery_id from gateway_alert_delivery where destination_ref=? and state='PENDING' and next_due<=? order by case phase when 'CRITICAL' then 0 when 'PROBLEM' then 1 else 2 end,next_due limit 1",(destination_ref,now)).fetchone()
        if preview is not None:
            self._authorize('DISPATCH',destination_ref,preview['delivery_id'])
        db.execute('begin immediate')
        try:
            config=db.execute('select * from gateway_alert_destination where destination_ref=?',(destination_ref,)).fetchone()
            if config is None: raise AlertBlocked('ALERT_DESTINATION_UNCONFIGURED')
            settings=json.loads(config['config'])
            if getattr(transport,'transport_ref',None)!=settings['transport_ref']: raise AlertBlocked('ALERT_TRANSPORT_UNPROVEN')
            # Lost worker outcome is ambiguous. No restart-created retry budget.
            db.execute("update gateway_alert_delivery set state='UNKNOWN',version=version+1,claim_token=null where state='IN_FLIGHT' and lease_until<=?",(now,))
            db.execute("""update gateway_alert_delivery set state='EXHAUSTED',version=version+1 where state='PENDING' and active_session in
                (select session_id from gateway_alert_budget_session where deadline<=? or attempts>=max_attempts)""",(now,))
            db.execute("update gateway_alert_budget_session set state='EXHAUSTED' where session_id in(select active_session from gateway_alert_delivery where state='EXHAUSTED')")
            db.execute("update gateway_alert_budget_session set state='UNKNOWN' where session_id in(select active_session from gateway_alert_delivery where state='UNKNOWN')")
            if db.execute("select count(*) from gateway_alert_delivery where state='IN_FLIGHT'").fetchone()[0]>=16 or db.execute("select count(*) from gateway_alert_delivery where state='IN_FLIGHT' and destination_ref=?",(destination_ref,)).fetchone()[0]>=2:
                db.commit();return {'status':'CAPACITY_PAUSED','providerCalls':0}
            row=db.execute("""select d.*,b.deadline,b.attempts,b.max_attempts from gateway_alert_delivery d join gateway_alert_budget_session b on b.session_id=d.active_session
                where d.destination_ref=? and d.delivery_id=? and d.state='PENDING' and d.next_due<=? order by case d.phase when 'CRITICAL' then 0 when 'PROBLEM' then 1 else 2 end,d.next_due limit 1""",(destination_ref,preview['delivery_id'] if preview is not None else '',now)).fetchone()
            if row is None: db.commit();return {'status':'NO_ELIGIBLE_DELIVERY','providerCalls':0}
            if row['config_hash']!=config['config_hash'] or row['deadline']-now<5:
                db.execute("update gateway_alert_delivery set state='EXHAUSTED',version=version+1 where delivery_id=?",(row['delivery_id'],));db.commit();return {'status':'EXHAUSTED','providerCalls':0}
            db.execute("update gateway_alert_delivery set state='IN_FLIGHT',version=version+1,total_attempts=total_attempts+1,claim_token=?,lease_until=? where delivery_id=? and version=?",(claim,min(now+10,row['deadline']),row['delivery_id'],row['version']))
            db.execute('update gateway_alert_budget_session set attempts=attempts+1 where session_id=?',(row['active_session'],));db.commit()
        except Exception: db.rollback();raise
        # Transport has a 5s finite attempt contract and no internal retry loop.
        try:
            outcome=transport.send(json.loads(row['payload']),settings['recipient_ref'],settings['transport_secret_ref'],row['delivery_id'],5)
        except Exception: outcome=AlertOutcome('UNKNOWN')
        if not isinstance(outcome,AlertOutcome) or outcome.kind not in {'ACCEPTED','TRANSIENT_NOT_ACCEPTED','PERMANENT','UNKNOWN'} or type(outcome.retry_after_seconds) is not int or not 0<=outcome.retry_after_seconds<=86400 or not isinstance(outcome.receipt_ref,str) or len(outcome.receipt_ref)>200 or (outcome.kind=='ACCEPTED' and not outcome.receipt_ref):
            outcome=AlertOutcome('UNKNOWN')
        return self._finish(row['delivery_id'],claim,row['version']+1,outcome)

    def _finish(self, delivery, claim, version, outcome):
        db=self.store.db;now=self._now();db.execute('begin immediate')
        try:
            row=db.execute('''select d.*,b.deadline,b.attempts,b.max_attempts from gateway_alert_delivery d join gateway_alert_budget_session b on b.session_id=d.active_session where d.delivery_id=?''',(delivery,)).fetchone()
            if row is None or row['state']!='IN_FLIGHT' or row['claim_token']!=claim or row['version']!=version or row['lease_until']<=now:
                raise AlertBlocked('ALERT_STALE_DISPATCH_RESULT')
            due=now;state={'ACCEPTED':'ACCEPTED','PERMANENT':'PAUSED','UNKNOWN':'UNKNOWN'}.get(outcome.kind,'PENDING')
            if state=='PENDING':
                factor=self.jitter()
                if not isinstance(factor,(int,float)) or not .8<=factor<=1.2: raise AlertBlocked('ALERT_JITTER_INVALID')
                delay=max(BACKOFF[min(row['attempts']-1,len(BACKOFF)-1)]*factor,outcome.retry_after_seconds)
                due=now+delay
                if row['attempts']>=row['max_attempts'] or due+5>=row['deadline']: state='EXHAUSTED'
            db.execute('''update gateway_alert_delivery set state=?,version=version+1,next_due=?,claim_token=null,lease_until=null,receipt_ref=? where delivery_id=?''',(state,due,outcome.receipt_ref,delivery))
            if state!='PENDING': db.execute('update gateway_alert_budget_session set state=? where session_id=?',(state,row['active_session']))
            db.commit();return {'status':state,'providerCalls':1,'providerAccepted':state=='ACCEPTED','humanReadProven':False,'incidentResolved':False,'newBudgetGranted':False}
        except Exception: db.rollback();raise

    def renew_exhausted_budget(self, delivery, expected_version, reason):
        row=self.store.db.execute('select * from gateway_alert_delivery where delivery_id=?',(delivery,)).fetchone()
        if row is None: raise AlertBlocked('ALERT_DELIVERY_NOT_FOUND')
        grant=self._authorize('RENEW_EXHAUSTED_BUDGET',row['destination_ref'],delivery,human=True)
        if type(expected_version) is not int or not isinstance(reason,str) or not 1<=len(reason)<=1000: raise AlertBlocked('ALERT_RECOVERY_INTENT_INVALID')
        db=self.store.db;db.execute('begin immediate')
        try:
            row=db.execute('select * from gateway_alert_delivery where delivery_id=?',(delivery,)).fetchone()
            if row['state']!='EXHAUSTED' or row['version']!=expected_version: raise AlertBlocked('ALERT_RECOVERY_CONFLICT')
            sid=str(uuid.uuid4());now=self._now()
            db.execute("update gateway_alert_budget_session set state='EXHAUSTED' where session_id=?",(row['active_session'],))
            db.execute("insert into gateway_alert_budget_session values(?,?,?,?,?,?,?,?,?,?,128,0,'ACTIVE')",(sid,delivery,grant['principal'],grant['actor'],grant['tenant'],reason,grant['decisionRef'],PROFILE,now,now+86400))
            db.execute("update gateway_alert_delivery set active_session=?,state='PENDING',next_due=?,version=version+1 where delivery_id=?",(sid,now,delivery));db.commit()
            return {'newBudgetSession':sid,'maxAttempts':128,'deadline':now+86400,'incidentResolved':False,'oldBudgetHistoryRetained':True}
        except Exception: db.rollback();raise

    def reconcile_ambiguous_delivery(self, delivery, expected_version, transport):
        row=self.store.db.execute('select * from gateway_alert_delivery where delivery_id=?',(delivery,)).fetchone()
        if row is None: raise AlertBlocked('ALERT_DELIVERY_NOT_FOUND')
        self._authorize('RECONCILE',row['destination_ref'],delivery)
        config=self.store.db.execute('select config from gateway_alert_destination where destination_ref=?',(row['destination_ref'],)).fetchone()
        if config is None or getattr(transport,'transport_ref',None)!=json.loads(config['config'])['transport_ref']:
            raise AlertBlocked('ALERT_TRANSPORT_UNPROVEN')
        if row['state']!='UNKNOWN' or type(expected_version) is not int or row['version']!=expected_version:
            raise AlertBlocked('ALERT_RECONCILIATION_CONFLICT')
        # Finite independent read-control allowance; exhaustion never resends.
        with self.store.db:
            updated=self.store.db.execute("update gateway_alert_delivery set reconciliation_attempts=reconciliation_attempts+1 where delivery_id=? and version=? and state='UNKNOWN' and reconciliation_attempts<8",(delivery,expected_version)).rowcount
        if updated!=1: raise AlertBlocked('ALERT_RECONCILIATION_CONTROL_EXHAUSTED')
        # Authoritative read, outside a DB lock. No SMTP assumption that a timeout
        # means not delivered. An unsupported/ambiguous query leaves UNKNOWN.
        try: outcome=transport.query(delivery,5)
        except Exception: return {'status':'UNKNOWN','deliveryAttempted':False}
        if not isinstance(outcome,AlertOutcome) or outcome.kind not in {'ACCEPTED','TRANSIENT_NOT_ACCEPTED'} or (outcome.kind=='ACCEPTED' and (not outcome.receipt_ref or len(outcome.receipt_ref)>200)):
            return {'status':'UNKNOWN','deliveryAttempted':False}
        db=self.store.db;db.execute('begin immediate')
        try:
            current=db.execute('select d.*,b.deadline,b.attempts,b.max_attempts from gateway_alert_delivery d join gateway_alert_budget_session b on b.session_id=d.active_session where d.delivery_id=?',(delivery,)).fetchone()
            if current['state']!='UNKNOWN' or current['version']!=expected_version:
                raise AlertBlocked('ALERT_RECONCILIATION_CONFLICT')
            state='ACCEPTED' if outcome.kind=='ACCEPTED' else ('PENDING' if current['attempts']<current['max_attempts'] and self._now()+5<current['deadline'] else 'EXHAUSTED')
            db.execute('update gateway_alert_delivery set state=?,version=version+1,next_due=?,receipt_ref=? where delivery_id=?',(state,self._now(),outcome.receipt_ref,delivery))
            db.execute('update gateway_alert_budget_session set state=? where session_id=?',('ACTIVE' if state=='PENDING' else state,current['active_session']))
            db.commit();return {'status':state,'deliveryAttempted':False,'humanReadProven':False,'incidentResolved':False}
        except Exception: db.rollback();raise
