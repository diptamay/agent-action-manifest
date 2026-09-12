"""AAM v0.4.0 Python managed reference: audit + persistence + governed feedback.

Trusted service API, NOT an HTTP server/security sandbox. Run agents outside this
process; they must not access constructors, stores, registration, signing keys or
administrative methods. One gate/store/tenant/environment, POSIX/local disk for SQLite.
Core Gate behavior is reused; admission and state updates checkpoint synchronously.
Remote effects remain outside all local transactions. No automatic retry/resume.
"""
from __future__ import annotations
import copy
import functools
import hashlib
import json
import threading
import time
import uuid
from datetime import timedelta

from gate import (Gate, InMemoryProfileStore, ProfileStore, DependencyUnavailable,
                  ExecutorNotAttempted)
from check_containment import digest, canonical, profile_digest, parse_time, Malformed
from runtime_store import AuditUnavailable, InMemoryRuntimeStore
from audit import AuditTransactionLock, snapshot, restore, checked_snapshot, signed_snapshot
from feedback import FeedbackController, empty_control, scope_key
from telemetry import Metrics


def guarded(fn):
    """RuntimeFailure is explicit and is never represented as a durably saved record."""
    @functools.wraps(fn)
    def wrapper(self,*args,**kwargs):
        started=time.monotonic()
        try:
            if self._runtime_failed:
                raise AuditUnavailable('runtime is latched unavailable')
            return fn(self,*args,**kwargs)
        except AuditUnavailable:
            self._runtime_failed=True
            return {'record_type':'RuntimeFailure','operation':fn.__name__,
                    'decision':'INDETERMINATE','reason_code':'AUDIT_OR_RUNTIME_UNAVAILABLE',
                    'audit_persisted':False,'restart_and_reconcile_required':True,
                    'message':'No further dispatch is permitted. A prior admission/effect may exist; inspect the persisted reservation before recovery. Never retry automatically.'}
        finally:
            try:
                self.metrics.timing(fn.__name__,time.monotonic()-started)
            except Exception:
                pass
    return wrapper


class _RuntimeProfiles(ProfileStore):
    def __init__(self,gate): self.gate=gate
    def active(self,pid):
        with self.gate._lock:
            return copy.deepcopy(self.gate._runtime_profiles.get(pid))
    def publish(self,profile):
        with self.gate._lock:
            self.gate._runtime_profiles[profile['profile_id']]=copy.deepcopy(profile)
    def revoke(self,pid):
        with self.gate._lock:
            self.gate._runtime_profiles.pop(pid,None)


class ManagedGate(Gate):
    _managed_profile_versions = ('0.3.7',)

    def __init__(self,state,secret,*,runtime_store,feedback_policy,tenant,environment,
                 trust_roots=None,clock=None,gate_id='managed-gate/0.3.7',
                 restoration_principals=None,signal_principals=None,approval_principals=None,metrics=None,**kwargs):
        if not isinstance(tenant,str) or not tenant.strip() or not isinstance(environment,str) or not environment.strip():
            raise ValueError('trusted tenant and environment are required')
        self._managed_runtime=True
        self._feedback=FeedbackController(feedback_policy)
        self._runtime_scope={'tenant':tenant,'environment':environment}
        self._restoration_principals=frozenset(restoration_principals or [])
        self._signal_principals=copy.deepcopy(signal_principals or {})
        self._approval_principals=copy.deepcopy(approval_principals or {})
        for principal,roles in self._approval_principals.items():
            if not isinstance(principal,str) or not principal or not isinstance(roles,list) or any(not isinstance(role,str) or not role for role in roles):
                raise ValueError('invalid authenticated-principal approval-role mapping')
        if any(not isinstance(p,str) or not p for p in self._restoration_principals):
            raise ValueError('restoration principal identities must be non-empty')
        for principal,acl in self._signal_principals.items():
            if (not isinstance(principal,str) or not principal or not isinstance(acl,dict)
                or set(acl)!={'signals','profile_ids'} or not isinstance(acl['signals'],list)
                or not set(acl['signals']) <= {'EVALUATION_REGRESSION','ADAPTER_MISMATCH'}
                or not isinstance(acl['profile_ids'],list) or not acl['profile_ids']
                or any(not isinstance(p,str) or not p for p in acl['profile_ids'])):
                raise ValueError('invalid signal source ACL')
        self.runtime_store=runtime_store
        self.metrics=metrics if metrics is not None else Metrics()
        self._runtime_failed=False
        super().__init__(state,InMemoryProfileStore(),secret,gate_id=gate_id,
                         trust_roots=trust_roots,clock=clock,**kwargs)
        self._runtime_profiles={}
        self._runtime_meta={'adapters':{},'verifiers':{}}
        self._control=empty_control()
        # A v0.4 extension may finalize interrupted transactions during base
        # initialization, before its subclass has loaded persisted state.
        self._aggregate_state = {"reservations": {}}
        self._campaign_observations={}
        self._campaign_holds={}
        # Binding excludes secret material but detects accidental reuse under another gate/key/config.
        trust_binding={k:{n:(v.hex() if isinstance(v,bytes) else v) for n,v in root.items()}
                       for k,root in self.trust_roots.items()}
        binding={'format':'aam-runtime-v1','gate_id':gate_id,'scope':self._runtime_scope,
                 'gate_key_fingerprint':hashlib.sha256(secret).hexdigest(),
                 'profile_trust_digest':digest(trust_binding),'feedback_policy':self._feedback.reference,
                 'restoration_principals':sorted(self._restoration_principals),
                 'signal_principals':self._signal_principals,
                 'approval_principals':self._approval_principals,
                 'require_readback_signoffs':self.require_readback_signoffs,
                 'readback_trust_digest':digest(json.loads(json.dumps(self.readback_trust_roots,default=lambda x:x.hex() if isinstance(x,bytes) else str(x)))),
                 'observation_clock_skew_seconds':self.observation_clock_skew_seconds,
                 'reconciliation_max_age_seconds':self.reconciliation_max_age_seconds}
        v4_binding = getattr(self, '_v4_binding', None)
        if v4_binding is not None:
            binding.update(format='aam-runtime-v2', v4_extension=copy.deepcopy(v4_binding))
        self._store_revision,saved=runtime_store.attach(binding)
        if saved is not None:
            restore(self,checked_snapshot(self,saved))
            if any(not self._manifest_ok(m) for m in self._manifests.values()):
                raise AuditUnavailable('stored Manifest integrity failed')
            if any(not self._sealed_ok(e) for e in self._execution_events):
                raise AuditUnavailable('stored execution integrity failed')
        self._lock=AuditTransactionLock(self)
        self.profiles=_RuntimeProfiles(self)
        if saved is None:
            self._store_revision=runtime_store.commit(self._store_revision,signed_snapshot(self,snapshot(self)),[])
        try:
            position=0
            while batch:=runtime_store.events(position,1000):
                self.metrics.observe(batch);position=batch[-1]['sequence']
        except Exception:
            # A store failure is not a metrics-only failure.
            if not runtime_store.verify_chain():
                raise AuditUnavailable('cannot restore audit state')
        # Crash recovery never invokes an adapter. DISPATCHED means locally admitted,
        # not proof that the callback actually ran or that a remote effect committed.
        with self._lock:
            for ex in list(self._executions.values()):
                if ex['execution_state']=='DISPATCHED':
                    updated=copy.deepcopy(ex)
                    updated.update(execution_state='EXECUTION_UNKNOWN',execution_unknown_at=self._clock(),
                                   reconciliation_required=True)
                    self._finish(updated,'ALLOW',['recovered unresolved dispatch reservation; no automatic retry'],locked=True)

    def policy_reference(self):
        return copy.deepcopy(self._feedback.reference)

    def _profile_scope_ok(self,profile):
        scope=profile.get('authority_scope') or {}
        return all(scope.get(k)==v for k,v in self._runtime_scope.items())

    @guarded
    def publish_profile(self,profile,*,readback_signoffs=None):
        if (not isinstance(profile,dict) or not self._profile_scope_ok(profile)
            or profile.get('monitoring_policy_ref')!=self._feedback.reference
            or profile.get('schema_version') not in self._managed_profile_versions):
            self._admin_record('PROFILE_PUBLICATION_REJECTED',None)
            return {'published':False,'reasons':['managed publication requires matching tenant/environment and a supported Profile bound to the configured feedback policy']}
        # Core validation/sign-off verification is local and the profile store is gate-owned.
        # The Profile and required sign-offs therefore commit together.
        with self._lock:
            result=super().publish_profile(profile,readback_signoffs=readback_signoffs)
            if not result['published']:
                self._admin_record('PROFILE_PUBLICATION_REJECTED',profile.get('profile_id'))
            return result

    @guarded
    def revoke_profile(self,profile_id):
        # Trusted administrative method; transport authentication is required by the service host.
        self.profiles.revoke(profile_id)
        return {'revoked':True,'profile_id':profile_id}

    @guarded
    def register_executor(self,tool,operation,fn,*,with_context=False,adapter_id=None,adapter_version='1'):
        if not all(isinstance(x,str) and x for x in (tool,operation,adapter_version)):
            raise ValueError('bounded named operation and adapter version required')
        key=scope_key('*',tool,operation)
        with self._lock:
            old=self._runtime_meta['adapters'].get(key)
            same_rehydration=(old and (tool,operation) not in self._executors
                              and old['adapter_id']==(adapter_id or tool+'.'+operation)
                              and old['adapter_version']==adapter_version and old['with_context']==with_context)
            super().register_executor(tool,operation,fn,with_context=with_context)
            self._runtime_meta['adapters'][key]={'tool':tool,'operation_name':operation,
                'adapter_id':adapter_id or tool+'.'+operation,'adapter_version':adapter_version,
                'with_context':with_context,'revision':old['revision'] if same_rehydration else (old['revision']+1 if old else 1)}
        return {'registered':True,'adapter':copy.deepcopy(self._runtime_meta['adapters'][key])}

    @guarded
    def register_verifier(self,verifier_id,secret,*,sources,methods):
        with self._lock:
            super().register_verifier(verifier_id,secret,sources=sources,methods=methods)
            self._runtime_meta['verifiers'][verifier_id]={'verifier_id':verifier_id,
                'key_fingerprint':hashlib.sha256(secret).hexdigest(),'sources':sorted(sources),'methods':sorted(methods)}
        return {'registered':True}

    def _context(self,manifest):
        a=manifest['action_target'];pid=manifest['profile_ref']['profile_id']
        c=self._feedback.context(self._control,pid,a['tool'],a['operation'],a['action_id'])
        c['adapter_revision']=self._runtime_meta['adapters'].get(scope_key('*',a['tool'],a['operation']),{}).get('revision',0)
        return c

    def _prepare_manifest_context(self,profile,manifest):
        with self._lock:
            context=self._context(manifest)
        manifest['operational_context']=context
        if context['mode']=='REQUIRE_APPROVAL' and manifest['autonomy_approval']['mode']!='recommend' and not manifest['autonomy_approval']['approval_required']:
            a=manifest['autonomy_approval'];p=profile['approval_policy']
            entry=next(e for e in profile['permissions']['allowed'] if e['tool']==manifest['action_target']['tool'] and e['operation']==manifest['action_target']['operation'])
            a.update(mode='request_approval',approval_required=True,approver_roles=list(entry.get('approver_roles') or p['approver_roles']),
                     required_evidence=list(p.get('required_evidence',[])),
                     dual_approval_required=(manifest['action_target']['tool']+'.'+manifest['action_target']['operation']) in p.get('dual_approval_for',[]),
                     approval_timeout_minutes=p.get('approval_timeout_minutes',profile['authority_scope']['max_review_window_minutes']))

    def _runtime_issues(self,manifest):
        with self._lock:
            return self._admission_issues(manifest)

    def _admission_issues(self,manifest):
        if self._runtime_failed:
            raise AuditUnavailable('runtime unavailable')
        self.runtime_store._check()
        context=self._context(manifest)
        errors=[]
        if manifest.get('operational_context')!=context:
            errors.append('CONTROL_CONTEXT_CHANGED: build a replacement for this unexecuted proposal and obtain any required approval')
        if context['mode']=='SUSPENDED':
            errors.append('RUNTIME_SUSPENDED: a preapproved protective restriction is active')
        if context['mode']=='REQUIRE_APPROVAL' and not manifest['autonomy_approval']['approval_required']:
            errors.append('ADDITIONAL_APPROVAL_REQUIRED')
        profile=self._runtime_profiles.get(manifest['profile_ref']['profile_id'])
        if not profile or profile_digest(profile)!=manifest['profile_ref']['profile_digest']:
            errors.append('ACTIVE_PROFILE_CHANGED')
        pol=self._feedback.policy
        if self.runtime_store.event_count()-self.runtime_store.cursor(pol['audit_consumer'])>=pol['max_export_backlog']:
            errors.append('AUDIT_EXPORT_BACKLOG_LIMIT: new effects held; recording and recovery remain available')
        return errors

    def _validate_approval(self,profile,manifest,approval,at):
        reasons=super()._validate_approval(profile,manifest,approval,at)
        for person in approval.get('approved_by',[]):
            if person.get('role') not in self._approval_principals.get(person.get('principal'),[]):
                reasons.append('APPROVAL_ROLE_NOT_AUTHORIZED: principal has no configured binding to this role')
        return reasons

    @guarded
    def propose(self,*args,**kwargs): return super().propose(*args,**kwargs)
    @guarded
    def reevaluate(self,*args,**kwargs): return super().reevaluate(*args,**kwargs)
    @guarded
    def record_approval(self,*args,**kwargs): return super().record_approval(*args,**kwargs)
    @guarded
    def execute(self,*args,**kwargs): return super().execute(*args,**kwargs)
    @guarded
    def verify_outcome(self,*args,**kwargs): return super().verify_outcome(*args,**kwargs)
    @guarded
    def reconcile(self,*args,**kwargs): return super().reconcile(*args,**kwargs)

    def _admin_record(self,code,profile_id,actor='gate:admin',**extra):
        record={'signal_id':'admin:'+uuid.uuid4().hex,'at':self._clock(),'code':code,
                'profile_id':profile_id,'actor':actor,**extra}
        with self._lock:
            self._control['external_signals'][record['signal_id']]=record
        return record

    @guarded
    def ingest_signal(self,signal,*,principal,auth_ref):
        """Trusted integration principal, authenticated by StateProvider, supplies evidence.

        No free-text analyzer is implemented. Evidence truth and key/principal assurance
        are deployment responsibilities. Auth references must be non-secret handles.
        """
        accepted=False;reason='INVALID_SIGNAL'
        try:
            fields={'signal_id','signal_code','profile_id','profile_digest','tool','operation','observed_at','evidence_ref'}
            if (not isinstance(signal,dict) or set(signal)!=fields or
                any(not isinstance(v,str) or not v or len(v)>512 for v in signal.values())):
                raise ValueError('invalid signal shape')
            acl=self._signal_principals.get(principal)
            if not acl or signal['signal_code'] not in acl['signals'] or signal['profile_id'] not in acl['profile_ids']:
                reason='SIGNAL_SOURCE_NOT_AUTHORIZED';raise ValueError(reason)
            if self._require_state_bool('authenticated',principal,auth_ref) is not True:
                reason='SIGNAL_AUTHENTICATION_FAILED';raise ValueError(reason)
            observed=parse_time(signal['observed_at']);now=parse_time(self._clock())
            if observed>now or (now-observed).total_seconds()>self._feedback.policy['signal_max_age_seconds']:
                reason='SIGNAL_STALE_OR_FUTURE';raise ValueError(reason)
            with self._lock:
                profile=self._runtime_profiles.get(signal['profile_id'])
                if not profile or profile_digest(profile)!=signal['profile_digest']:
                    reason='SIGNAL_PROFILE_VERSION_MISMATCH';raise ValueError(reason)
                if not any(a['tool']==signal['tool'] and a['operation']==signal['operation'] for a in profile['permissions']['allowed']):
                    reason='SIGNAL_OPERATION_OUT_OF_SCOPE';raise ValueError(reason)
                key=digest({'principal':principal,'signal_id':signal['signal_id']})
                prior=self._control['external_signals'].get(key)
                body={**copy.deepcopy(signal),'actor':principal,'operation_name':signal['operation']}
                if prior:
                    comparable={k:v for k,v in prior.items() if k!='at'}
                    if comparable!=body:
                        reason='SIGNAL_ID_CONTENT_CONFLICT';raise ValueError(reason)
                    return {'accepted':True,'duplicate':True,'signal_id':signal['signal_id']}
                body['at']=self._clock()
                self._control['external_signals'][key]=body
            return {'accepted':True,'duplicate':False,'signal_id':signal['signal_id']}
        except (ValueError,TypeError,KeyError,Malformed,DependencyUnavailable):
            self._admin_record('SIGNAL_REJECTED',signal.get('profile_id') if isinstance(signal,dict) else None,
                               actor=principal,reason_code=reason)
            return {'accepted':False,'reason_code':reason}

    @guarded
    def restore_restriction(self,restriction_id,expected_revision,*,principal,auth_ref,reason,evidence_ref):
        if (principal not in self._restoration_principals or not isinstance(reason,str) or not reason.strip()
            or len(reason)>2000 or not isinstance(evidence_ref,str) or not evidence_ref.strip() or len(evidence_ref)>512):
            self._admin_record('RESTORATION_REJECTED',None,actor=principal)
            return {'restored':False,'reason_code':'RESTORATION_NOT_AUTHORIZED_OR_INCOMPLETE'}
        try:
            if self._require_state_bool('authenticated',principal,auth_ref) is not True:
                raise DependencyUnavailable('not authenticated')
        except DependencyUnavailable:
            self._admin_record('RESTORATION_REJECTED',None,actor=principal)
            return {'restored':False,'reason_code':'RESTORATION_AUTHENTICATION_FAILED'}
        with self._lock:
            r=self._control['restrictions'].get(restriction_id)
            if r:
                pid,tool,op,action=json.loads(r['scope_key'])
                for ex in self._executions.values():
                    m=self._manifests.get(ex['manifest_id'])
                    if not m or ex['execution_state'] not in ('DISPATCHED','EXECUTION_UNKNOWN'):
                        continue
                    a=m['action_target']
                    if (m['profile_ref']['profile_id']==pid and (tool=='*' or tool==a['tool'])
                        and (op=='*' or op==a['operation']) and (action=='*' or action==a['action_id'])):
                        self._admin_record('RESTORATION_REJECTED',pid,actor=principal,reason_code='UNRESOLVED_EXECUTION')
                        return {'restored':False,'reason_code':'UNRESOLVED_EXECUTION'}
            result=self._feedback.restore(self._control,restriction_id,expected_revision,principal,reason,evidence_ref,self._clock())
            if not result['restored']:
                self._admin_record('RESTORATION_REJECTED',r['profile_id'] if r else None,actor=principal,reason_code=result['reason_code'])
            return result

    @guarded
    def watchdog(self):
        """Call from a trusted scheduler. No background thread or executor is created."""
        now=parse_time(self._clock());pol=self._feedback.policy;created=0
        with self._lock:
            for ex in self._executions.values():
                if ex['execution_state'] not in ('DISPATCHED','EXECUTION_UNKNOWN','ACKNOWLEDGED','COMMITTED'):
                    continue
                m=self._manifests.get(ex['manifest_id'])
                if not m:continue
                unresolved=ex['execution_state'] in ('DISPATCHED','EXECUTION_UNKNOWN')
                if not unresolved and any(o['execution_id']==ex['execution_id'] and o['verified'] for o in self._outcomes.values()):
                    continue
                code='OVERDUE_EXECUTION' if unresolved else 'OVERDUE_VERIFICATION'
                seconds=pol['overdue_execution_seconds'] if unresolved else pol['overdue_verification_seconds']
                key=ex['execution_id']+'|'+code
                if (now-parse_time(ex['dispatched_at'])).total_seconds()<=seconds or key in self._control['watchdog_seen']:
                    continue
                self._control['watchdog_seen'][key]=self._clock()
                a=m['action_target'];record={'signal_id':key,'signal_code':code,'profile_id':m['profile_ref']['profile_id'],
                    'manifest_id':m['manifest_id'],'execution_id':ex['execution_id'],'action_id':a['action_id'],
                    'tool':a['tool'],'operation_name':a['operation'],'at':self._clock(),'actor':'gate:watchdog'}
                self._control['external_signals'][key]=record;created+=1
        return {'signals_created':created}

    def restrictions(self):
        with self._lock:return copy.deepcopy(list(self._control['restrictions'].values()))

    def control_snapshot(self):
        """Protected administrative projection; not a replacement for the action Card."""
        version = '0.4.0' if hasattr(self, '_aggregate') else '0.3.7'
        return {'record_type':'RuntimeControlSnapshot','schema_version':version,
                'policy_ref':copy.deepcopy(self._feedback.reference),**self._runtime_scope,
                'observed_at':self._clock(),'restrictions':self.restrictions()}

    def metrics_text(self):
        now=parse_time(self._clock())
        with self._lock:
            unresolved=[e for e in self._executions.values() if e['execution_state'] in ('DISPATCHED','EXECUTION_UNKNOWN')]
            oldest=max((max(0,(now-parse_time(e['dispatched_at'])).total_seconds()) for e in unresolved),default=0)
            active=sum(r['active'] for r in self._control['restrictions'].values())
        try:
            backlog=self.runtime_store.event_count()-self.runtime_store.cursor(self._feedback.policy['audit_consumer'])
        except AuditUnavailable:
            backlog=-1
        return self.metrics.text(unresolved=len(unresolved),oldest_age=oldest,restrictions=active,
                                 backlog=backlog,degraded=self._runtime_failed)

    def export_audit(self,send,*,batch_size=100,max_batches=10):
        from audit_export import drain
        try:
            return drain(self.runtime_store,self._feedback.policy['audit_consumer'],send,
                         batch_size=batch_size,max_batches=max_batches)
        except Exception:
            try:self.metrics.export_failures+=1
            except Exception:pass
            raise

    def close(self):
        self._runtime_failed=True
        self.runtime_store.close()
