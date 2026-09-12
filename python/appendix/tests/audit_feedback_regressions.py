#!/usr/bin/env python3
"""Audit/feedback acceptance suite; synthetic fixtures and POSIX process-crash tests.

Uses no network/real industrial integrations. Process termination is tested; hardware
power-loss, torn storage writes, privileged rollback and replicated operation are not.
"""
from __future__ import annotations
import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from managed_demo_support import *
from runtime_store import InMemoryRuntimeStore,SQLiteRuntimeStore,AuditUnavailable,StoreConflict
from audit_export import drain,SQLiteAuditReceiver
from evidence import make_observation,seal_attestation
from render_card import project,coverage,check_parity
from gate import Gate,InMemoryProfileStore,PROFILE_V,MANIFEST_V,schema_errors,ExecutorNotAttempted
from check_containment import canonical
from feedback import FeedbackController
from validation_support import strict_format_checker
from jsonschema import Draft202012Validator

class FailStore(SQLiteRuntimeStore):
    fail=False
    lose_ack=False
    def commit(self,revision,state,events):
        if self.fail:raise AuditUnavailable('synthetic mandatory append failure')
        result=super().commit(revision,state,events)
        if self.lose_ack and any(e['event_type']=='EXECUTION_TRANSITION' and e['result']=='DISPATCHED' for e in events):
            raise AuditUnavailable('synthetic lost commit acknowledgment')
        return result

class AuditFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'runtime.db';self.gates=[]
    def tearDown(self):
        for g in reversed(self.gates):
            try:g.close()
            except Exception:pass
        self.tmp.cleanup()
    def fresh(self,*,store=None,policy=None,autonomous=False,metrics=None):
        store=store or SQLiteRuntimeStore(self.path)
        g,s,c=gate(store,policy=policy,**({'metrics':metrics} if metrics else {}));self.gates.append(g)
        p=profile(policy,autonomous);self.assertTrue(g.publish_profile(p)['published'])
        self.assertTrue(g.register_executor('email','draft_email',s.executor,with_context=True)['registered'])
        return SimpleNamespace(g=g,s=s,c=c,p=p,store=store)
    def act(self,f,aid='act-1'):
        m,a=approved(f.g,f.c,aid);f.c[0]=TE;x=f.g.execute(m['manifest_id'],a['approval_id'])
        return m,a,x
    def sig(self,f,code='EVALUATION_REGRESSION',sid='signal-1'):
        f.c[0]=TV
        return f.g.ingest_signal(signal(f.p,code,sid),principal='svc:evaluation',auth_ref='session:evaluation')
    def clear(self,f,r,**kw):
        args=dict(principal='user:owner',auth_ref='session:owner',reason='reviewed correction',evidence_ref='review:case-1');args.update(kw)
        return f.g.restore_restriction(r['restriction_id'],r['revision'],**args)
    def reopen(self,f):
        f.g.close();g,s,c=gate(SQLiteRuntimeStore(self.path),clock=[TV]);self.gates.append(g)
        g.register_executor('email','draft_email',s.executor,with_context=True)
        return SimpleNamespace(g=g,s=s,c=c,p=f.p,store=g.runtime_store)

    def test_01_durable_lifecycle_and_schema(self):
        f=self.fresh();m,a,x=self.act(f);self.assertEqual(x['execution_state'],'ACKNOWLEDGED')
        f.c[0]=TV;self.assertTrue(f.g.verify_outcome(x['execution_id'])['verified'])
        events=f.store.events();self.assertTrue(f.store.verify_chain())
        v=Draft202012Validator(json.loads((ROOT/'schemas/audit-event.schema.json').read_text()),format_checker=strict_format_checker())
        for e in events:v.validate(e)
        self.assertIn('APPROVAL_CONSUMED',{e['event_type'] for e in events})
        self.assertEqual(schema_errors(MANIFEST_V,m),[])
        recovered=self.reopen(f);self.assertEqual(recovered.g.get_execution(x['execution_id']),x)
    def test_02_memory_store_same_lifecycle_without_durability_claim(self):
        f=self.fresh(store=InMemoryRuntimeStore());self.assertFalse(f.store.durable)
        m,a,x=self.act(f);self.assertEqual(x['execution_state'],'ACKNOWLEDGED');self.assertGreater(f.store.event_count(),0)
    def test_03_required_append_failure_before_dispatch(self):
        f=self.fresh(store=FailStore(self.path));m,a=approved(f.g,f.c);f.store.fail=True;f.c[0]=TE
        r=f.g.execute(m['manifest_id'],a['approval_id']);self.assertEqual(r['record_type'],'RuntimeFailure');self.assertFalse(f.s.calls)
        self.assertIn('aam_runtime_degraded 1',f.g.metrics_text())
    def test_04_persistence_failure_after_effect_latches_and_recovers_unknown(self):
        f=self.fresh(store=FailStore(self.path));calls=[]
        def effect(req,ctx):calls.append(ctx);f.store.fail=True;return {'accepted':True}
        f.g.register_executor('email','draft_email',effect,with_context=True)
        m,a,x=self.act(f);self.assertEqual(x['record_type'],'RuntimeFailure');self.assertEqual(len(calls),1)
        self.assertEqual(f.g.execute(m['manifest_id'],a['approval_id'])['record_type'],'RuntimeFailure')
        recovered=self.reopen(f);eid=calls[0]['execution_id'];self.assertEqual(recovered.g.get_execution(eid)['execution_state'],'EXECUTION_UNKNOWN')
        self.assertNotEqual(recovered.g.execute(m['manifest_id'],a['approval_id'])['decision'],'ALLOW');self.assertFalse(recovered.s.calls)
    def test_05_lost_local_commit_ack_never_invokes_adapter(self):
        f=self.fresh(store=FailStore(self.path));m,a=approved(f.g,f.c);f.store.lose_ack=True;f.c[0]=TE
        r=f.g.execute(m['manifest_id'],a['approval_id']);self.assertEqual(r['record_type'],'RuntimeFailure');self.assertFalse(f.s.calls)
        recovered=self.reopen(f);self.assertEqual(len(recovered.g._dispatches),1)
        self.assertEqual(next(iter(recovered.g._executions.values()))['execution_state'],'EXECUTION_UNKNOWN')
        self.assertIsNotNone(recovered.g._approvals[a['approval_id']]['consumed_by'])
    def test_06_admission_consumption_and_audit_commit_precede_callback(self):
        f=self.fresh();seen=[]
        def effect(req,ctx):
            state=f.store._state['state'];ex=state['_executions'][ctx['execution_id']]
            self.assertEqual(ex['execution_state'],'DISPATCHED')
            self.assertEqual(state['_approvals'][ex['approval_id']]['consumed_by'],ctx['execution_id'])
            self.assertTrue(any(e['execution_id']==ctx['execution_id'] and e['result']=='DISPATCHED' for e in f.store.events()))
            seen.append(1);return {'ok':True}
        f.g.register_executor('email','draft_email',effect,with_context=True);self.act(f);self.assertEqual(seen,[1])
    def test_07_process_exit_after_remote_effect(self):
        effect_path=Path(self.tmp.name)/'effect.txt'
        code='''from managed_demo_support import *
from runtime_store import SQLiteRuntimeStore
import os,sys
s=SQLiteRuntimeStore(sys.argv[1]);g,st,c=gate(s);g.publish_profile(profile())
def effect(req,ctx):
 with open(sys.argv[2],'w') as f: f.write(ctx['execution_id']);f.flush();os.fsync(f.fileno())
 os._exit(23)
g.register_executor('email','draft_email',effect,with_context=True)
m,a=approved(g,c);c[0]=TE;g.execute(m['manifest_id'],a['approval_id'])
'''
        env={**os.environ,'PYTHONPATH':str(ROOT/'tests')+os.pathsep+str(ROOT/'tools')}
        done=subprocess.run([sys.executable,'-c',code,str(self.path),str(effect_path)],env=env,capture_output=True,timeout=20)
        self.assertEqual(done.returncode,23,done.stderr.decode())
        g,st,c=gate(SQLiteRuntimeStore(self.path),clock=[TV]);self.gates.append(g)
        ex=g.get_execution(effect_path.read_text());self.assertEqual(ex['execution_state'],'EXECUTION_UNKNOWN')
        self.assertEqual(len(g.execution_history(ex['execution_id'])),2);self.assertFalse(st.calls)
    def test_08_action_identity_block_survives_restart(self):
        f=self.fresh();m,a,x=self.act(f);recovered=self.reopen(f)
        m2,a2=approved(recovered.g,recovered.c,'act-1');recovered.c[0]=TE
        r=recovered.g.execute(m2['manifest_id'],a2['approval_id']);self.assertEqual(r['decision'],'DENY');self.assertFalse(recovered.s.calls)
    def test_09_approval_consumption_survives_restart(self):
        f=self.fresh();m,a,x=self.act(f);recovered=self.reopen(f)
        self.assertEqual(recovered.g._approvals[a['approval_id']]['consumed_by'],x['execution_id'])
        self.assertEqual(recovered.g.execute(m['manifest_id'],a['approval_id'],TE)['decision'],'DENY')
    def test_10_single_owner_process_lock(self):
        f=self.fresh()
        with self.assertRaises(AuditUnavailable):SQLiteRuntimeStore(self.path)
        with self.assertRaises(StoreConflict):gate(f.store)
    def test_11_wrong_gate_key_on_reopen(self):
        f=self.fresh();f.g.close();store=SQLiteRuntimeStore(self.path)
        try:
            with self.assertRaises(StoreConflict):
                ManagedGate(Live([TP]),b'wrong',runtime_store=store,feedback_policy=POLICY,tenant='ACME',environment='prod',trust_roots=ROOTS)
        finally:store.close()
    def test_12_scope_and_policy_mismatches_refuse_publication(self):
        f=self.fresh();p=profile();p['authority_scope']['tenant']='OTHER'
        self.assertFalse(f.g.publish_profile(p)['published']);p=profile();p['monitoring_policy_ref']['policy_version']='other'
        self.assertFalse(f.g.publish_profile(p)['published'])
    def test_13_policy_change_requires_explicit_migration(self):
        f=self.fresh();f.g.close();pol=copy.deepcopy(POLICY);pol['policy_version']='new';store=SQLiteRuntimeStore(self.path)
        try:
            with self.assertRaises(StoreConflict):gate(store,policy=pol)
        finally:store.close()
    def test_14_snapshot_tampering_detected(self):
        f=self.fresh();self.act(f);f.g.close()
        conn=sqlite3.connect(self.path);raw=json.loads(conn.execute('SELECT state FROM metadata').fetchone()[0]);raw['state']['_dispatches']={}
        conn.execute('UPDATE metadata SET state=?',(json.dumps(raw),));conn.commit();conn.close();store=SQLiteRuntimeStore(self.path)
        try:
            with self.assertRaises(AuditUnavailable):gate(store)
        finally:store.close()
    def test_15_append_only_event_sql_guard(self):
        f=self.fresh()
        with self.assertRaises(sqlite3.IntegrityError):f.store._conn.execute('DELETE FROM events')
        with self.assertRaises(sqlite3.IntegrityError):f.store._conn.execute("UPDATE events SET body='{}'")
    def test_16_unkeyed_chain_corruption_detected(self):
        f=self.fresh();f.g.close();conn=sqlite3.connect(self.path);conn.execute('DROP TRIGGER events_no_update')
        body=json.loads(conn.execute('SELECT body FROM events LIMIT 1').fetchone()[0]);body['result']='DENY'
        conn.execute('UPDATE events SET body=? WHERE seq=1',(json.dumps(body),));conn.commit();conn.close()
        with self.assertRaises(AuditUnavailable):SQLiteRuntimeStore(self.path)
    def test_17_export_retry_does_not_retry_action(self):
        f=self.fresh();self.act(f);received=[]
        def sink(e):received.append(e['event_id']);raise OSError('remote receiver down')
        with self.assertRaises(OSError):f.g.export_audit(sink)
        self.assertEqual(f.store.cursor('primary-audit'),0);self.assertEqual(len(f.s.calls),1)
        f.g.export_audit(lambda e:True);self.assertEqual(f.store.cursor('primary-audit'),f.store.event_count());self.assertEqual(len(f.s.calls),1)
    def test_18_receiver_deduplicates_checkpoint_replay(self):
        f=self.fresh();self.act(f);receiver=SQLiteAuditReceiver(str(Path(self.tmp.name)/'receiver.db'))
        original=f.store.advance;fail=[True]
        def lost(*args):
            if fail[0]:fail[0]=False;raise AuditUnavailable('checkpoint lost')
            return original(*args)
        f.store.advance=lost
        with self.assertRaises(AuditUnavailable):f.g.export_audit(receiver)
        f.g.export_audit(receiver)
        n=receiver.conn.execute('SELECT count(*) FROM received').fetchone()[0];self.assertEqual(n,f.store.event_count());receiver.close()
    def test_19_metrics_observer_failure_does_not_change_authorization(self):
        from telemetry import Metrics
        class Broken(Metrics):
            def observe(self,events):raise RuntimeError('diagnostics failure')
        f=self.fresh(metrics=Broken());m,a,x=self.act(f);self.assertEqual(x['decision'],'ALLOW');self.assertFalse(f.g._runtime_failed)
    def test_20_allowlisted_export_omits_sensitive_bodies(self):
        f=self.fresh();r=copy.deepcopy(REQUEST);r['summary']='SENSITIVE_PROMPT_CANARY'
        m=f.g.propose(BASE['profile_id'],r,TP)['manifest'];f.c[0]=TA;a=f.g.record_approval(m['manifest_id'],JANE)
        def fn(req,ctx):return {'secret_example':'SENSITIVE_RECEIPT_CANARY'}
        f.g.register_executor('email','draft_email',fn,with_context=True)
        # New adapter revision requires a replacement before executing.
        m=f.g.propose(BASE['profile_id'],r,TP)['manifest'];a=f.g.record_approval(m['manifest_id'],JANE,TA);f.g.execute(m['manifest_id'],a['approval_id'],TE)
        exported=canonical(f.store.events());self.assertNotIn('SENSITIVE_',exported);self.assertNotIn('session:jane',exported)
        self.assertIn('SENSITIVE_PROMPT_CANARY',canonical(f.store._state))
    def test_21_unknown_signal_source_rejected(self):
        f=self.fresh();f.c[0]=TV
        r=f.g.ingest_signal(signal(f.p),principal='attacker',auth_ref='any');self.assertFalse(r['accepted']);self.assertFalse(f.g.restrictions())
    def test_22_signal_authentication_failure_rejected(self):
        f=self.fresh();f.s.auth=False;self.assertFalse(self.sig(f)['accepted']);self.assertFalse(f.g.restrictions())
    def test_23_signal_stale_and_future_rejected(self):
        f=self.fresh();f.c[0]=TV
        for at in ('2026-09-07T14:00:00Z','2026-09-07T15:00:00Z','invalid'):
            r=f.g.ingest_signal(signal(f.p,at=at),principal='svc:evaluation',auth_ref='session:evaluation');self.assertFalse(r['accepted'])
    def test_24_signal_wrong_profile_version_rejected(self):
        f=self.fresh();f.c[0]=TV;s=signal(f.p);s['profile_digest']='sha256:'+'0'*64
        self.assertFalse(f.g.ingest_signal(s,principal='svc:evaluation',auth_ref='session:evaluation')['accepted'])
    def test_25_duplicate_signal_never_inflates_threshold(self):
        pol=copy.deepcopy(POLICY);next(r for r in pol['rules'] if r['signal']=='EVALUATION_REGRESSION')['threshold']=2
        f=self.fresh(policy=pol);self.assertTrue(self.sig(f)['accepted']);self.assertTrue(self.sig(f)['duplicate']);self.assertFalse(f.g.restrictions())
        self.sig(f,sid='signal-2');self.assertEqual(len(f.g.restrictions()),1)
    def test_26_signal_id_reuse_with_changed_content_rejected(self):
        f=self.fresh();self.sig(f);s=signal(f.p);s['evidence_ref']='different:evidence'
        self.assertFalse(f.g.ingest_signal(s,principal='svc:evaluation',auth_ref='session:evaluation')['accepted'])
    def test_27_source_cannot_target_another_profile(self):
        f=self.fresh();p=profile();p['profile_id']='aap:acme:other';p=sign_profile_ed25519(p,PRIVATE,'demo-profile-signing-2026');self.assertTrue(f.g.publish_profile(p)['published'])
        f.c[0]=TV;self.assertFalse(f.g.ingest_signal(signal(p),principal='svc:evaluation',auth_ref='session:evaluation')['accepted'])
    def test_28_unknown_action_hold_does_not_block_unrelated_action(self):
        f=self.fresh()
        def unknown(req,ctx):raise TimeoutError('after possible commit')
        f.g.register_executor('email','draft_email',unknown,with_context=True);m,a,x=self.act(f)
        self.assertEqual(x['execution_state'],'EXECUTION_UNKNOWN');self.assertEqual(f.g.restrictions()[0]['mode'],'SUSPENDED')
        p=proposal(f.g,f.c,'independent-action');self.assertEqual(p['decision']['decision'],'ALLOW')
    def test_29_feedback_requires_new_approval_context(self):
        f=self.fresh(autonomous=True);old=proposal(f.g,f.c)['manifest'];self.assertFalse(old['autonomy_approval']['approval_required'])
        self.sig(f);self.assertEqual(f.g.execute(old['manifest_id'],now=TV)['decision'],'DENY')
        new=proposal(f.g,f.c)['manifest'];self.assertTrue(new['autonomy_approval']['approval_required'])
        self.assertEqual(f.g.execute(new['manifest_id'],now=TE)['decision'],'DENY');self.assertFalse(f.s.calls)
    def test_30_extra_approval_never_allows_prohibited_operation(self):
        f=self.fresh();self.sig(f);r=copy.deepcopy(REQUEST);r['operation']='release_payment'
        result=f.g.propose(BASE['profile_id'],r,TV);self.assertEqual(result['decision']['decision'],'DENY')
    def test_31_feedback_never_mutates_standing_profile(self):
        f=self.fresh();before=copy.deepcopy(f.g.profiles.active(BASE['profile_id']));self.sig(f);self.assertEqual(f.g.profiles.active(BASE['profile_id']),before)
    def test_32_holds_survive_restart(self):
        f=self.fresh();self.sig(f);before=f.g.restrictions();r=self.reopen(f);self.assertEqual(r.g.restrictions(),before)
    def test_33_restoration_unauthorized_rejected(self):
        f=self.fresh();self.sig(f);r=f.g.restrictions()[0];self.assertFalse(self.clear(f,r,principal='user:jane',auth_ref='session:jane')['restored'])
    def test_34_restoration_stale_revision_rejected(self):
        f=self.fresh();self.sig(f);r=f.g.restrictions()[0];r['revision']+=1;self.assertFalse(self.clear(f,r)['restored'])
    def test_35_unknown_execution_prevents_restoration(self):
        f=self.fresh();f.g.register_executor('email','draft_email',lambda *_:(_ for _ in ()).throw(TimeoutError()),with_context=True)
        m,a,x=self.act(f);r=f.g.restrictions()[0];self.assertEqual(self.clear(f,r)['reason_code'],'UNRESOLVED_EXECUTION')
        f.c[0]=TV;f.s.disposition='NOT_COMMITTED';self.assertTrue(f.g.reconcile(x['execution_id'])['applied'])
        self.assertTrue(self.clear(f,r)['restored']);self.assertIsNotNone(f.g._approvals[a['approval_id']]['consumed_by'])
        self.assertEqual(f.g.execute(m['manifest_id'],a['approval_id'],TV)['decision'],'DENY')
    def test_36_clear_one_hold_does_not_clear_another(self):
        f=self.fresh();self.sig(f);self.sig(f,'ADAPTER_MISMATCH','signal-2');rs=f.g.restrictions();self.assertEqual(len(rs),2)
        self.assertTrue(self.clear(f,rs[0])['restored']);self.assertEqual(sum(r['active'] for r in f.g.restrictions()),1)
        self.assertEqual(proposal(f.g,f.c,'new')['decision']['decision'],'DENY')
    def test_37_restoration_does_not_revalidate_old_manifest_ABA(self):
        f=self.fresh();old=proposal(f.g,f.c)['manifest'];self.sig(f);self.clear(f,f.g.restrictions()[0])
        self.assertEqual(f.g.execute(old['manifest_id'],now=TV)['decision'],'DENY')
        self.assertEqual(proposal(f.g,f.c,'fresh')['decision']['decision'],'ALLOW')
    def test_38_no_timer_based_automatic_restoration(self):
        f=self.fresh();self.sig(f);f.c[0]='2026-10-07T14:13:00Z';f.g.watchdog();self.assertTrue(f.g.restrictions()[0]['active'])
    def test_39_watchdog_detects_missing_verification_once(self):
        f=self.fresh();self.act(f);f.c[0]='2026-09-07T14:30:00Z'
        self.assertEqual(f.g.watchdog()['signals_created'],1);self.assertEqual(f.g.watchdog()['signals_created'],0)
        self.assertEqual(f.g.restrictions()[0]['signal_code'],'OVERDUE_VERIFICATION')
    def test_40_watchdog_does_not_flag_verified_execution(self):
        f=self.fresh();m,a,x=self.act(f);f.c[0]=TV;f.g.verify_outcome(x['execution_id']);f.c[0]='2026-09-07T14:30:00Z';self.assertEqual(f.g.watchdog()['signals_created'],0)
    def test_41_verification_conflict_immediately_suspends_operation(self):
        f=self.fresh();m,a,x=self.act(f);f.c[0]=TV
        sources=sorted({t['source'] for t in m['outcome_verification']['verification_tests']})
        f.g.register_verifier('reviewer',b'verifier-demo',sources=sources,methods=['read_system_of_record'])
        test=m['outcome_verification']['verification_tests'][0]
        att=seal_attestation(make_observation(x,m,test['test_id'],False,TV,source_version='negative',evidence_ref='demo:negative'),'reviewer',b'verifier-demo')
        result=f.g.verify_outcome(x['execution_id'],attestations=[att]);self.assertFalse(result['verified'])
        self.assertTrue(any(r['signal_code']=='EVIDENCE_CONFLICT' for r in f.g.restrictions()))
        self.assertEqual(proposal(f.g,f.c,'new')['decision']['decision'],'DENY')
        events=f.store.events();source=next(e for e in events if e['event_type']=='OUTCOME_VERIFIED');hold=next(e for e in events if e['event_type']=='RESTRICTION_ACTIVATED');self.assertEqual(source['transaction_revision'],hold['transaction_revision'])
    def test_42_controller_event_replay_does_not_duplicate_holds(self):
        f=self.fresh();self.sig(f);n=len(f.g.restrictions())
        with f.g._lock:f.g._feedback.process(f.g._control,f.store.events(),TV)
        self.assertEqual(len(f.g.restrictions()),n)
    def test_43_repeated_verification_same_incident_not_multiple_samples(self):
        f=self.fresh();m,a,x=self.act(f);f.c[0]=TV;f.s.observed=False
        for _ in range(4):f.g.verify_outcome(x['execution_id'])
        self.assertFalse(f.g.restrictions())
        m2,a2,x2=self.act(f,'act-2');f.c[0]=TV;f.g.verify_outcome(x2['execution_id']);self.assertEqual(len(f.g.restrictions()),1)
    def test_44_executor_can_reenter_read_only_gate(self):
        f=self.fresh();result=[]
        def fn(req,ctx):result.append(f.g.reevaluate(ctx['manifest_id'],TE)['decision']);return {'ok':True}
        f.g.register_executor('email','draft_email',fn,with_context=True)
        th=threading.Thread(target=lambda:self.act(f),daemon=True);th.start();th.join(5)
        self.assertFalse(th.is_alive());self.assertEqual(result,['ALLOW'])
    def test_45_same_manifest_two_approvals_concurrent_single_dispatch(self):
        f=self.fresh();m,a=approved(f.g,f.c);a2=f.g.record_approval(m['manifest_id'],JANE,TA);f.c[0]=TE
        barrier=threading.Barrier(3);results=[]
        def run(approval):barrier.wait();results.append(f.g.execute(m['manifest_id'],approval['approval_id'],TE))
        ts=[threading.Thread(target=run,args=(q,)) for q in (a,a2)]
        for t in ts:t.start()
        barrier.wait()
        for t in ts:t.join(5)
        self.assertEqual(len(f.s.calls),1);self.assertEqual(sum(x['decision']=='ALLOW' for x in results),1)
    def test_46_restriction_before_final_admission_wins_race(self):
        f=self.fresh();m,a=approved(f.g,f.c);f.c[0]=TV;original=f.s.credential_valid;once=[False]
        def credential(identity,at):
            if not once[0]:once[0]=True;self.sig(f,'ADAPTER_MISMATCH')
            return True
        f.s.credential_valid=credential
        x=f.g.execute(m['manifest_id'],a['approval_id'],TV);self.assertEqual(x['decision'],'DENY');self.assertFalse(f.s.calls)
    def test_47_restriction_after_admission_does_not_claim_cancellation(self):
        f=self.fresh()
        def fn(req,ctx):self.sig(f,'ADAPTER_MISMATCH');return {'ok':True}
        f.g.register_executor('email','draft_email',fn,with_context=True);m,a,x=self.act(f)
        self.assertEqual(x['execution_state'],'ACKNOWLEDGED');self.assertTrue(f.g.restrictions())
    def test_48_card_covers_operational_context(self):
        f=self.fresh();self.sig(f);m=proposal(f.g,f.c)['manifest'];self.assertTrue(coverage(m)['complete'],coverage(m));self.assertTrue(check_parity(project(m),m)['ok'])
        c=project(m);c['operational_context']['mode']='NORMAL';self.assertFalse(check_parity(c,m)['ok'])
    def test_49_base_gate_cannot_silently_ignore_managed_policy(self):
        g=Gate(Live([TP]),InMemoryProfileStore(),b'core-demo',trust_roots=ROOTS)
        self.assertFalse(g.publish_profile(profile())['published'])
    def test_50_invalid_feedback_policy_fails_at_configuration(self):
        for field,value in [('mode','EXPAND_PERMISSIONS'),('signal','free text'),('threshold',True),('scope','all_tenants')]:
            p=copy.deepcopy(POLICY);p['rules'][0][field]=value
            with self.assertRaises(Exception):FeedbackController(p)
    def test_51_revocation_survives_restart(self):
        f=self.fresh();f.g.revoke_profile(BASE['profile_id']);r=self.reopen(f);self.assertIsNone(r.g.profiles.active(BASE['profile_id']))
    def test_52_export_checkpoint_persists_restart(self):
        f=self.fresh();self.act(f);f.g.export_audit(lambda e:True);n=f.store.cursor('primary-audit');r=self.reopen(f);self.assertEqual(r.store.cursor('primary-audit'),n)
    def test_53_backlog_limit_holds_new_effects_but_not_recovery(self):
        p=copy.deepcopy(POLICY);p['max_export_backlog']=100;f=self.fresh(policy=p)
        for _ in range(105):f.g.propose(BASE['profile_id'],{'malformed':True},TP)
        self.assertEqual(proposal(f.g,f.c)['decision']['decision'],'DENY');self.assertFalse(f.s.calls)
        f.g.export_audit(lambda e:True);self.assertEqual(proposal(f.g,f.c,'fresh')['decision']['decision'],'ALLOW')
    def test_54_adapter_version_change_invalidates_prior_approval(self):
        f=self.fresh();m,a=approved(f.g,f.c);f.g.register_executor('email','draft_email',f.s.executor,with_context=True,adapter_version='2')
        self.assertEqual(f.g.execute(m['manifest_id'],a['approval_id'],TE)['decision'],'DENY');self.assertFalse(f.s.calls)
    def test_55_manual_restoration_requires_evidence_and_correct_auth(self):
        f=self.fresh();self.sig(f);r=f.g.restrictions()[0]
        self.assertFalse(self.clear(f,r,evidence_ref='')['restored']);self.assertFalse(self.clear(f,r,auth_ref='wrong')['restored'])
    def test_56_two_restorations_cannot_both_clear_same_revision(self):
        f=self.fresh();self.sig(f);r=f.g.restrictions()[0];results=[]
        ts=[threading.Thread(target=lambda:results.append(self.clear(f,r))) for _ in range(2)]
        for t in ts:t.start()
        for t in ts:t.join(5)
        self.assertEqual(sum(x['restored'] for x in results),1)
    def test_57_not_attempted_is_preserved_and_does_not_release_reservation(self):
        f=self.fresh();f.g.register_executor('email','draft_email',lambda *_:(_ for _ in ()).throw(ExecutorNotAttempted()),with_context=True)
        m,a,x=self.act(f);self.assertEqual(x['execution_state'],'NOT_ATTEMPTED');r=self.reopen(f)
        self.assertEqual(r.g.execute(m['manifest_id'],a['approval_id'],TE)['decision'],'DENY');self.assertFalse(r.s.calls)
    def test_58_clock_metrics_do_not_expose_action_ids_in_labels(self):
        f=self.fresh();m,a,x=self.act(f);text=f.g.metrics_text()
        self.assertNotIn(m['manifest_id'],text);self.assertNotIn(x['execution_id'],text);self.assertNotIn('ap@',text)
    def test_59_profile_wide_hold_leaves_other_profile_unaffected(self):
        pol=copy.deepcopy(POLICY);next(r for r in pol['rules'] if r['signal']=='EVALUATION_REGRESSION')['scope']='profile'
        f=self.fresh(policy=pol);p=profile(pol);p['profile_id']='aap:acme:other';p=sign_profile_ed25519(p,PRIVATE,'demo-profile-signing-2026');f.g.publish_profile(p)
        self.sig(f);r=f.g.propose(p['profile_id'],copy.deepcopy(REQUEST),TV);self.assertEqual(r['manifest']['operational_context']['mode'],'NORMAL')
    def test_60_read_methods_do_not_emit_extra_records(self):
        f=self.fresh();n=f.store.event_count();f.g.restrictions();f.g.metrics_text();self.assertEqual(f.store.event_count(),n)

    def test_61_authenticated_person_cannot_claim_unbound_role(self):
        f=self.fresh();m=proposal(f.g,f.c)['manifest'];person=[{'principal':'user:owner','role':'ap_manager','auth_ref':'session:owner'}]
        a=f.g.record_approval(m['manifest_id'],person,TA)
        self.assertEqual(f.g.execute(m['manifest_id'],a['approval_id'],TE)['decision'],'DENY');self.assertFalse(f.s.calls)
    def test_62_feedback_keeps_existing_narrow_approver_roles(self):
        f=self.fresh();p=profile();entry=next(a for a in p['permissions']['allowed'] if a['tool']=='email');entry['approver_roles']=['finance_controller']
        p=sign_profile_ed25519(p,PRIVATE,'demo-profile-signing-2026');f.g.publish_profile(p);f.p=p;self.sig(f)
        m=proposal(f.g,f.c)['manifest'];self.assertEqual(m['autonomy_approval']['approver_roles'],['finance_controller'])
    def test_63_final_emergency_stop_recheck_blocks_late_change(self):
        f=self.fresh();m,a=approved(f.g,f.c);stopped=[False]
        def credential(*args):stopped[0]=True;return True
        f.s.credential_valid=credential;f.s.kill_switch_allows=lambda p:not stopped[0]
        self.assertEqual(f.g.execute(m['manifest_id'],a['approval_id'],TE)['decision'],'DENY');self.assertFalse(f.s.calls)
    def test_64_untrusted_signal_extra_fields_cannot_supply_policy(self):
        f=self.fresh();s=signal(f.p);s['new_permissions']=['release_payment'];f.c[0]=TV
        self.assertFalse(f.g.ingest_signal(s,principal='svc:evaluation',auth_ref='session:evaluation')['accepted']);self.assertFalse(f.g.restrictions())

    def test_65_control_snapshot_schema_active_and_restored(self):
        f=self.fresh();self.sig(f)
        v=Draft202012Validator(json.loads((ROOT/'schemas/runtime-control.schema.json').read_text()),format_checker=strict_format_checker())
        snap=f.g.control_snapshot();v.validate(snap);self.assertTrue(snap['restrictions'][0]['active'])
        self.clear(f,snap['restrictions'][0]);v.validate(f.g.control_snapshot());self.assertFalse(f.g.control_snapshot()['restrictions'][0]['active'])
    def test_66_offline_review_extracts_without_execution(self):
        from audit_review import review_cases
        f=self.fresh();self.act(f);self.sig(f);before=len(f.s.calls)
        r=review_cases(f.store.events());self.assertEqual(r['stream_event_count'],f.store.event_count())
        self.assertEqual(len(f.s.calls),before);self.assertTrue(all(c['review_status']=='UNREVIEWED' and c['proposed_change'] is None for c in r['cases']))
    def test_67_offline_review_rejects_missing_reordered_or_tampered_events(self):
        from audit_review import review_cases
        f=self.fresh();self.act(f);events=f.store.events()
        variants=[events[1:],list(reversed(events)),events+[events[-1]]]
        changed=copy.deepcopy(events);changed[0]['result']='DENY';variants.append(changed)
        for v in variants:
            with self.assertRaises(ValueError):review_cases(v)
    def test_68_resolved_policy_must_match_profile_digest(self):
        from aam import resolved_feedback
        f=self.fresh();path=Path(self.tmp.name)/'policy.json';path.write_text(json.dumps(POLICY))
        self.assertIn('UN',resolved_feedback(f.p,str(path)))
        bad=copy.deepcopy(POLICY);bad['rules'][0]['mode']='REQUIRE_APPROVAL';path.write_text(json.dumps(bad))
        with self.assertRaises(ValueError):resolved_feedback(f.p,str(path))
        with self.assertRaises(ValueError):resolved_feedback(f.p,None)
    def test_69_policy_pin_in_part_a_and_complete_readback(self):
        from aam import product_view,readback_coverage
        p=profile();paths=[k for k,v in product_view(p)]
        self.assertIn('monitoring_policy_ref.policy_digest',paths);self.assertTrue(readback_coverage(p)['complete'])
    def test_70_cli_requires_policy_for_managed_review(self):
        f=self.fresh();path=Path(self.tmp.name)/'profile.json';path.write_text(json.dumps(f.p))
        base=[sys.executable,str(ROOT/'tools/aam.py'),'readback',str(path)]
        a=subprocess.run(base,capture_output=True,text=True,timeout=20);self.assertEqual(a.returncode,2)
        b=subprocess.run(base+['--feedback-policy',str(ROOT/'examples/managed-runtime/feedback-policy.json')],capture_output=True,text=True,timeout=20)
        self.assertEqual(b.returncode,0,b.stderr);self.assertIn('Resolved policy',b.stdout)
    def test_71_runtime_failure_schema_preserves_unknown_not_false_denial(self):
        f=self.fresh(store=FailStore(self.path));m,a=approved(f.g,f.c);f.store.fail=True
        x=f.g.execute(m['manifest_id'],a['approval_id'],TE)
        v=Draft202012Validator(json.loads((ROOT/'schemas/runtime-control.schema.json').read_text()),format_checker=strict_format_checker())
        v.validate(x);x['decision']='DENY';self.assertTrue(list(v.iter_errors(x)))
    def test_72_policy_duplicate_rule_ids_refused(self):
        p=copy.deepcopy(POLICY);p['rules'][1]['rule_id']=p['rules'][0]['rule_id']
        with self.assertRaises(ValueError):FeedbackController(p)

    def test_73_serialized_card_round_trip_keeps_exact_parity(self):
        f=self.fresh();self.sig(f);m=proposal(f.g,f.c)['manifest']
        card=json.loads(json.dumps(project(m)))
        self.assertTrue(check_parity(card,m)['ok'])
        card['all_parameters'][0][1]='tampered';self.assertFalse(check_parity(card,m)['ok'])

class RecordingResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.rows=[]
    def addSuccess(self,test):super().addSuccess(test);self.rows.append({'name':test.id(),'passed':True})
    def addFailure(self,test,err):super().addFailure(test,err);self.rows.append({'name':test.id(),'passed':False,'error':self._exc_info_to_string(err,test)})
    def addError(self,test,err):super().addError(test,err);self.rows.append({'name':test.id(),'passed':False,'error':self._exc_info_to_string(err,test)})

if __name__=='__main__':
    runner=unittest.TextTestRunner(verbosity=2,resultclass=RecordingResult)
    result=runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(AuditFeedbackTests))
    report={'suite':'v0.3.7 audit/feedback regressions','tests_run':result.testsRun,
            'passed':sum(r['passed'] for r in result.rows),'failed':len(result.errors)+len(result.failures),
            'limitations':['synthetic providers','POSIX process exit tested, not hardware power loss','no remote integrations'],
            'cases':result.rows}
    if '--report' in sys.argv:Path(sys.argv[sys.argv.index('--report')+1]).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
    sys.exit(0 if result.wasSuccessful() else 1)
