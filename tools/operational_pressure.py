"""Persistent bounded owner pressure decisions, independent of retry authority.

Reference profile; sampling must come from trusted current owner metrics. A quota
never grants execution, resets an exhausted budget or advances a checkpoint.
"""
from __future__ import annotations
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

PROFILE = 'ouf.operational-pressure.reference.v1'


@dataclass(frozen=True)
class PressureObservation:
    observed_at: datetime
    window_seconds: int
    attempts: int
    failures: int
    dependency_unavailable_seconds: int
    capacity_fraction: float
    oldest_backlog_seconds: int


class PressureConflict(ValueError): pass


class PersistentPressureController:
    MAX_SCOPES = 1024
    FRESH_SECONDS = 30
    CONTROL_SLOTS = 2
    BUSINESS_SLOTS = 8

    def __init__(self, store):
        self.store = store
        store.db.execute('''create table if not exists gateway_pressure_scope(
            scope_ref text primary key,profile text not null,version integer not null,
            mode text not null check(mode in('NORMAL','CAUTIOUS','PAUSED','PROBE','RECOVERING')),
            slots integer not null,last_observed_at real,last_digest text,
            high_since real,low_since real,stage_since real)''')
        store.db.commit()

    def register_scope(self, scope_ref):
        """Governed installation config, never create one scope per object/job."""
        if not isinstance(scope_ref,str) or not 1 <= len(scope_ref) <= 200 or '://' not in scope_ref:
            raise ValueError('PRESSURE_SCOPE_INVALID')
        db = self.store.db
        db.execute('begin immediate')
        try:
            existing=db.execute('select profile from gateway_pressure_scope where scope_ref=?',(scope_ref,)).fetchone()
            if existing:
                if existing['profile'] != PROFILE: raise PressureConflict('PRESSURE_PROFILE_CHANGED')
            else:
                count=db.execute('select count(*) from gateway_pressure_scope').fetchone()[0]
                if count >= self.MAX_SCOPES: raise PressureConflict('PRESSURE_SCOPE_CAPACITY')
                db.execute("insert into gateway_pressure_scope values(?,?,0,'NORMAL',8,null,null,null,null,null)",(scope_ref,PROFILE))
            db.commit()
        except Exception:
            db.rollback();raise

    def observe(self, scope_ref, observation: PressureObservation, expected_version):
        if type(expected_version) is not int or expected_version < 0:
            raise PressureConflict('PRESSURE_VERSION_INVALID')
        now=self.store.clock().astimezone(timezone.utc).timestamp()
        self._validate(observation,now)
        observed=observation.observed_at.timestamp()
        safe=asdict(observation);safe['observed_at']=observed
        fingerprint=hashlib.sha256(json.dumps(safe,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        db=self.store.db
        db.execute('begin immediate')
        try:
            frame=db.execute('select * from gateway_pressure_scope where scope_ref=?',(scope_ref,)).fetchone()
            if frame is None: raise PressureConflict('PRESSURE_SCOPE_UNREGISTERED')
            if frame['profile'] != PROFILE: raise PressureConflict('PRESSURE_PROFILE_CHANGED')
            if observed == frame['last_observed_at'] and fingerprint == frame['last_digest']:
                db.commit();return self.decision(scope_ref)
            if frame['version'] != expected_version or (frame['last_observed_at'] is not None and observed <= frame['last_observed_at']):
                raise PressureConflict('PRESSURE_OBSERVATION_CONFLICT')
            rate=observation.failures/observation.attempts if observation.attempts else 0
            rate_high=observation.attempts >= 20 and rate >= 0.5
            hard=observation.capacity_fraction >= 0.9 or observation.dependency_unavailable_seconds >= 300 or (
                observation.oldest_backlog_seconds >= 900 and observation.capacity_fraction >= 0.7)
            high=hard or rate_high
            low=(observation.capacity_fraction <= 0.7 and observation.oldest_backlog_seconds < 300
                 and observation.dependency_unavailable_seconds == 0 and rate <= 0.1)
            mode,slots=frame['mode'],frame['slots']
            gap=frame['last_observed_at'] is None or observed-frame['last_observed_at'] > self.FRESH_SECONDS
            high_since=None if not high else (observed if gap or frame['high_since'] is None else frame['high_since'])
            low_since=None if not low else (observed if gap or frame['low_since'] is None else frame['low_since'])
            stage_since=frame['stage_since']
            if hard or (high and high_since is not None and observed-high_since >= 90):
                mode,slots,stage_since='PAUSED',0,None
            elif high:
                if mode not in {'PAUSED','PROBE'}: mode,slots,stage_since='CAUTIOUS',2,None
            elif mode == 'PAUSED':
                if low and observed-low_since >= 120: mode,slots,stage_since='PROBE',1,observed
            elif mode == 'PROBE':
                if not low: mode,slots,stage_since='PAUSED',0,None
                elif not gap and observed-stage_since >= 30 and observation.attempts > 0 and observation.failures == 0:
                    mode,slots,stage_since='RECOVERING',2,observed
            elif mode == 'RECOVERING':
                if not low: mode,slots,stage_since='CAUTIOUS',2,None
                elif gap: stage_since=observed
                elif observed-stage_since >= 30 and observation.attempts > 0 and observation.failures == 0:
                    slots=min(self.BUSINESS_SLOTS,slots*2);stage_since=observed
                    if slots == self.BUSINESS_SLOTS: mode='NORMAL'
            elif mode == 'CAUTIOUS':
                if low and observed-low_since >= 120: mode,slots,stage_since='RECOVERING',2,observed
            db.execute('''update gateway_pressure_scope set version=version+1,mode=?,slots=?,last_observed_at=?,last_digest=?,
                high_since=?,low_since=?,stage_since=? where scope_ref=? and version=?''',
                (mode,slots,observed,fingerprint,high_since,low_since,stage_since,scope_ref,expected_version))
            db.commit()
        except Exception:
            db.rollback();raise
        return self.decision(scope_ref)

    def decision(self, scope_ref):
        frame=self.store.db.execute('select * from gateway_pressure_scope where scope_ref=?',(scope_ref,)).fetchone()
        if frame is None: raise PressureConflict('PRESSURE_SCOPE_UNREGISTERED')
        now=self.store.clock().astimezone(timezone.utc).timestamp()
        fresh=(frame['profile']==PROFILE and frame['last_observed_at'] is not None
               and -5 <= now-frame['last_observed_at'] <= self.FRESH_SECONDS)
        return {'scopeRef':scope_ref,'profile':PROFILE,'version':frame['version'],
                'mode':frame['mode'] if fresh else 'UNKNOWN','businessSlots':frame['slots'] if fresh else 0,
                'reservedControlSlots':self.CONTROL_SLOTS,'evidenceFresh':fresh,
                'executionAuthorized':False,'retryBudgetRenewed':False}

    @staticmethod
    def _validate(sample, now):
        if not isinstance(sample,PressureObservation) or not isinstance(sample.observed_at,datetime) or sample.observed_at.tzinfo is None:
            raise ValueError('PRESSURE_OBSERVATION_INVALID')
        if not -5 <= now-sample.observed_at.timestamp() <= 30 or sample.window_seconds != 300:
            raise ValueError('PRESSURE_OBSERVATION_STALE_OR_WINDOW_INVALID')
        for value in (sample.window_seconds,sample.attempts,sample.failures,sample.dependency_unavailable_seconds,sample.oldest_backlog_seconds):
            if type(value) is not int or value < 0 or value > 1_000_000_000:
                raise ValueError('PRESSURE_OBSERVATION_INVALID')
        if sample.failures > sample.attempts or type(sample.capacity_fraction) not in (float,int) or not math.isfinite(sample.capacity_fraction) or not 0 <= sample.capacity_fraction <= 1:
            raise ValueError('PRESSURE_OBSERVATION_INVALID')
