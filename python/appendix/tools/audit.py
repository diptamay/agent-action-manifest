"""Transactional lifecycle recording for ManagedGate.

A bounded reference deliberately checkpoints complete JSON state, not an ORM or a
production event-sourcing framework. AuditTransactionLock replaces only the core
ledger mutex. On outermost exit it persists ledger changes, allowlisted events and
protective feedback in ONE transaction, before returning to the caller/adapter.
No external exporter, executor, or StateProvider callback belongs inside this lock.
Read-only exits do not write. On failure the local snapshot is restored and admission
is latched unavailable until restart. Commit-ack uncertainty is never automatically
retried. Core Gate remains the volatile conformance engine; ManagedGate uses this path.
"""
from __future__ import annotations
import copy
import hashlib
import hmac
import threading
import uuid
from check_containment import canonical, digest
from runtime_store import AuditUnavailable

ATTRS = ('_manifests','_decisions','_approvals','_executions','_outcomes','_dispatches',
         '_execution_events','_reconciliations','_publication_signoffs',
         '_runtime_profiles','_runtime_meta','_control','_aggregate_state',
         '_campaign_observations','_campaign_holds')


def snapshot(gate):
    result={k:copy.deepcopy(getattr(gate,k)) for k in ATTRS}
    result['_action_dispatches']=[[list(k),v] for k,v in sorted(gate._action_dispatches.items())]
    return result


def restore(gate, state):
    extension_defaults = {
        '_aggregate_state': {'reservations': {}},
        '_campaign_observations': {},
        '_campaign_holds': {},
    }
    for k in ATTRS:
        if k in state:
            value = state[k]
        elif k in extension_defaults and not hasattr(gate, '_aggregate'):
            # A base ManagedGate may reopen a v0.3.7 snapshot written before the
            # optional v0.4 bookkeeping fields existed. V4ManagedGate still
            # fails closed and requires an explicit, state-preserving migration.
            value = extension_defaults[k]
        else:
            raise AuditUnavailable('persistent snapshot is missing required state: ' + k)
        setattr(gate,k,copy.deepcopy(value))
    gate._action_dispatches={tuple(k):v for k,v in state['_action_dispatches']}


def signed_snapshot(gate,state):
    return {'state':state,'state_mac':hmac.new(gate._secret,canonical(state).encode(),hashlib.sha256).hexdigest()}


def checked_snapshot(gate,stored):
    if not isinstance(stored,dict) or set(stored)!={'state','state_mac'}:
        raise AuditUnavailable('malformed persistent snapshot')
    expected=signed_snapshot(gate,stored['state'])['state_mac']
    if not hmac.compare_digest(expected,stored['state_mac']):
        raise AuditUnavailable('persistent snapshot integrity failed')
    return stored['state']


def event(gate,kind,ref,record, *, result='NONE',signal=None):
    manifest_id=record.get('manifest_id')
    m=gate._manifests.get(manifest_id) or {}
    action=m.get('action_target',{})
    profile_id=record.get('profile_id') or m.get('profile_ref',{}).get('profile_id')
    if not isinstance(profile_id,str): profile_id=None
    tool=record.get('tool') or action.get('tool')
    operation=record.get('operation_name') or action.get('operation')
    program=(m.get('program_context') or {}).get('program_id') or record.get('program_id')
    actor_group=(m.get('aggregate_execution') or {}).get('actor_group_id') or record.get('actor_group_id')
    v4 = hasattr(gate, '_aggregate')
    scope={**gate._runtime_scope,'profile_id':profile_id,'tool':tool,'operation':operation}
    if v4:
        scope.update(program_id=program, actor_group_id=actor_group)
    out={'record_type':'AuditEvent','schema_version':'0.4.0' if v4 else '0.3.7','event_id':'event:'+uuid.uuid4().hex,
         'event_type':kind,'record_ref':str(ref),'record_digest':digest(record),
         'recorded_at':gate._clock(),'occurred_at':next((record[k] for k in
             ('decided_at','verified_at','reconciled_at','approved_at','at','dispatched_at','issued_at')
             if record.get(k)),gate._clock()),
         'gate_id':gate.gate_id,'scope':scope,
         'result':result,'manifest_id':manifest_id,
         'execution_id':record.get('execution_id'),
         'action_id':record.get('action_id') or action.get('action_id'),
         'signal_code':signal,
         'actor_ref_digest':digest(record.get('actor') or record.get('approved_by') or gate.gate_id)}
    if v4:
        out['campaign_indicator']=None
    # Deliberately no reasons, free text, evidence bodies, receipt, token, or material parameters.
    return out


def changes(gate,before,after):
    out=[]
    maps=(('_manifests','MANIFEST_BUILT','NONE'),('_decisions','GATE_DECISION',None),
          ('_approvals','APPROVAL_RECORDED',None),('_outcomes','OUTCOME_VERIFIED',None),
          ('_reconciliations','RECONCILIATION_RECORDED',None),
          ('_publication_signoffs','READBACK_SIGNOFFS_RECORDED','NONE'))
    for attr,kind,result in maps:
        for key,raw in after[attr].items():
            if key in before[attr]:
                continue
            rec=raw['record'] if attr=='_approvals' else raw
            if not isinstance(rec,dict):
                rec={'signoffs':rec}
            signal=None
            if attr=='_outcomes':
                result='VERIFIED' if rec['verified'] else 'UNRESOLVED'
                signal=('EVIDENCE_CONFLICT' if any(r.get('evidence_conflict') for r in rec['results'])
                        else ('VERIFICATION_FAILED' if not rec['postconditions_verified'] else None))
            elif attr=='_decisions':
                result=rec['decision']
            elif attr=='_approvals':
                result={'approved':'APPROVED','rejected':'REJECTED','more_evidence':'MORE_EVIDENCE'}[rec['decision']]
            elif attr=='_reconciliations':
                result='APPLIED' if rec['applied'] else 'UNRESOLVED'
            out.append(event(gate,kind,key,rec,result=result,signal=signal))
    for key,value in after['_approvals'].items():
        prior=before['_approvals'].get(key)
        if prior and prior['consumed_by'] is None and value['consumed_by'] is not None:
            rec={**value['record'],'execution_id':value['consumed_by']}
            out.append(event(gate,'APPROVAL_CONSUMED',key,rec,result='CONSUMED'))
    for rec in after['_execution_events'][len(before['_execution_events']):]:
        out.append(event(gate,'EXECUTION_TRANSITION',rec['execution_id'],rec,result=rec['execution_state'],
                         signal='EXECUTION_UNKNOWN' if rec['execution_state']=='EXECUTION_UNKNOWN' else None))
    old,new=before['_runtime_profiles'],after['_runtime_profiles']
    for key in sorted(set(old)|set(new)):
        if old.get(key)!=new.get(key):
            rec=new.get(key) or {'profile_id':key}
            out.append(event(gate,'PROFILE_PUBLISHED' if key in new else 'PROFILE_REVOKED',key,rec))
    for category in ('adapters','verifiers'):
        old=before['_runtime_meta'][category];new=after['_runtime_meta'][category]
        for key in sorted(set(old)|set(new)):
            if old.get(key)!=new.get(key):
                out.append(event(gate,'ADAPTER_REGISTERED' if category=='adapters' else 'VERIFIER_REGISTERED',key,new.get(key) or {}))
    for key,rec in after['_control']['external_signals'].items():
        if key not in before['_control']['external_signals']:
            out.append(event(gate,'CONTROL_SIGNAL',key,rec,signal=rec.get('signal_code')))
    for key,rec in after['_aggregate_state'].get('reservations',{}).items():
        if key not in before['_aggregate_state'].get('reservations',{}):
            out.append(event(gate,'AGGREGATE_BUDGET_RESERVED',key,rec,result='RESERVED'))
    for key,rec in after['_campaign_observations'].items():
        if key not in before['_campaign_observations']:
            item=event(gate,'CAMPAIGN_OBSERVATION',key,rec,result='OBSERVED')
            item['campaign_indicator']=rec.get('indicator')
            out.append(item)
    for key,rec in after['_campaign_holds'].items():
        prior=before['_campaign_holds'].get(key)
        if prior==rec: continue
        kind='CAMPAIGN_RESTRICTION_ACTIVATED' if rec.get('active') else 'CAMPAIGN_RESTRICTION_RESTORED'
        item=event(gate,kind,key,rec,result=rec.get('mode','NONE'))
        item['campaign_indicator']=rec.get('indicator')
        out.append(item)
    return out


def control_changes(gate,before,after):
    out=[]
    for key,rec in after['_control']['transitions'].items():
        if key not in before['_control']['transitions']:
            out.append(event(gate,'RESTRICTION_ACTIVATED' if rec['operation']=='activate' else 'RESTRICTION_RESTORED',
                             key,rec,result=rec['mode']))
    return out


class AuditTransactionLock:
    def __init__(self, gate):
        self.gate=gate
        self._mutex=threading.RLock()
        self._local=threading.local()

    def __enter__(self):
        self._mutex.acquire()
        depth=getattr(self._local,'depth',0)
        self._local.depth=depth+1
        if depth==0:
            self._local.before=snapshot(self.gate)
        return self

    def __exit__(self,typ,value,tb):
        depth=self._local.depth-1
        self._local.depth=depth
        try:
            if depth:
                return False
            gate=self.gate;before=self._local.before
            if typ is not None:
                restore(gate,before)
                return False
            finalize=getattr(gate,'_finalize_transaction_state',None)
            if finalize:
                finalize()
            after=snapshot(gate)
            if after==before:
                return False
            try:
                if gate._runtime_failed:
                    raise AuditUnavailable('runtime is latched unavailable; restart required')
                events=changes(gate,before,after)
                gate._feedback.process(gate._control,events,gate._clock())
                after=snapshot(gate)
                events.extend(control_changes(gate,before,after))
                gate._store_revision=gate.runtime_store.commit(gate._store_revision,signed_snapshot(gate,after),events)
            except Exception as exc:
                restore(gate,before)
                gate._runtime_failed=True
                try:
                    gate.metrics.append_failures+=1
                except Exception:
                    pass
                if isinstance(exc,AuditUnavailable):
                    raise
                raise AuditUnavailable('mandatory runtime/audit transaction failed') from exc
            try:
                gate.metrics.observe(events)
            except Exception:
                # Metrics are diagnostics; a metrics callback cannot undo committed control state.
                try:
                    gate.metrics.telemetry_failures+=1
                except Exception:
                    pass
        finally:
            self._mutex.release()
        return False
