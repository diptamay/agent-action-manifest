"""Bounded in-process metrics, derived only from committed gate events.

No identifiers/payloads in labels. These metrics are diagnostic, never authorization
inputs. Counters rebuild from the retained local audit history on restart. This is
Prometheus text exposition, not an HTTP endpoint or an OpenTelemetry collector.
"""
from __future__ import annotations
import threading
from collections import Counter


class Metrics:
    def __init__(self):
        self._lock=threading.Lock()
        self._counts=Counter()
        self.append_failures=0
        self.telemetry_failures=0
        self.export_failures=0
        self._latency=Counter()

    def observe(self, events):
        with self._lock:
            for event in events:
                self._counts[(event['event_type'],event.get('result','NONE'))]+=1

    def timing(self, method, seconds):
        # Caller uses a fixed method-name allowlist, never request/user-provided labels.
        with self._lock:
            self._latency[(method,'sum')]+=max(0,seconds)
            self._latency[(method,'count')]+=1

    def text(self, *, unresolved, oldest_age, restrictions, backlog, degraded):
        with self._lock:
            lines=['# TYPE aam_events_total counter']
            for (kind,result),count in sorted(self._counts.items()):
                lines.append(f'aam_events_total{{event_type="{kind}",result="{result}"}} {count}')
            for name,value in [('aam_execution_unknown_current',unresolved),
                ('aam_execution_unknown_oldest_age_seconds',oldest_age),
                ('aam_active_restrictions',restrictions),('aam_audit_export_backlog',backlog),
                ('aam_runtime_degraded',int(degraded))]:
                lines.extend([f'# TYPE {name} gauge',f'{name} {value}'])
            for name,value in [('aam_audit_append_failures_total',self.append_failures),
                ('aam_telemetry_failures_total',self.telemetry_failures),
                ('aam_audit_export_failures_total',self.export_failures)]:
                lines.extend([f'# TYPE {name} counter',f'{name} {value}'])
            lines.append('# TYPE aam_gate_method_seconds summary')
            for (method,suffix),value in sorted(self._latency.items()):
                lines.append(f'aam_gate_method_seconds_{suffix}{{method="{method}"}} {value}')
            return '\n'.join(lines)+'\n'
