"""Process-local WSGI admission and bounded Gateway metric series."""
from collections import deque
from contextlib import closing, contextmanager
from threading import BoundedSemaphore, Lock
import time

from tools.analysis_protocol import Rejected, capacity_profile


class TrafficPool:
    def __init__(self, limit, profile, clock):
        self.limit = limit
        self.slots = BoundedSemaphore(limit)
        self.lock = Lock()
        self.clock = clock
        self.retry_after = str(profile['retryAfterSeconds'])
        self.window = profile['latencyWindowSeconds']
        self.wait = deque(maxlen=profile['latencyWindowSamples'])
        self.service = deque(maxlen=profile['latencyWindowSamples'])
        self.active = self.refused = self.connections = self.opened = 0

    @contextmanager
    def admit(self):
        start = self.clock()
        with self.lock:
            admitted = self.slots.acquire(blocking=False)
            now = self.clock()
            self.wait.append((now, now - start))
            if not admitted:
                self.refused += 1
                raise Rejected(429, retry_after=self.retry_after)
            self.active += 1
        try:
            yield
        finally:
            with self.lock:
                end = self.clock()
                self.service.append((end, end - now))
                self.active -= 1
                self.slots.release()

    @contextmanager
    def connection(self, store):
        db = store.connect()
        with self.lock:
            self.connections += 1
            self.opened += 1
        try:
            with closing(db):
                yield db
        finally:
            with self.lock:
                self.connections -= 1

    def metrics(self, name, processes):
        with self.lock:
            cutoff = self.clock() - self.window
            gauges = {
                'gateway_inflight_requests': self.active,
                'gateway_analysis_slot_limit': self.limit,
                'gateway_analysis_instance_slot_limit': self.limit * processes,
                'gateway_analysis_pressure_refusals_total': self.refused,
                'gateway_analysis_sqlite_connections': self.connections,
                'gateway_analysis_sqlite_connections_opened_total': self.opened,
            }
            windows = (('gateway_analysis_admission_wait_seconds', tuple(self.wait)),
                       ('gateway_request_duration_seconds', tuple(self.service)))
        labels = f'service="analysis_mandate",traffic_class="{name}"'
        for metric, value in gauges.items():
            yield f'{metric}{{{labels}}} {value}'
        for metric, window in windows:
            values = sorted(value for end, value in window if end > cutoff)
            yield f'{metric}_window_samples{{{labels}}} {len(values)}'
            for p in (50, 95, 99):
                # Nearest rank, also for small windows. Empty windows have no percentile.
                value = values[(p * len(values) - 1) // 100] if values else 'NaN'
                yield f'{metric}{{{labels},quantile="0.{p}"}} {value}'


class Capacity:
    def __init__(self, fields, *, clock=time.perf_counter):
        profile = capacity_profile(fields)
        self.processes = profile['processes']
        self.pools = {name: TrafficPool(profile[field], profile, clock) for name, field in
                      [('data', 'dataSlots'), ('control', 'ControlReservedSlots'), ('relay', 'relaySlots')]}

    def metrics(self):
        # Prometheus text groups samples of the same metric together.
        lines = sorted(line for name, pool in self.pools.items() for line in pool.metrics(name, self.processes))
        return ('\n'.join(lines) + '\n').encode('ascii')
