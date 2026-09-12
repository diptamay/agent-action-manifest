#!/usr/bin/env python3
"""v0.3.6 merge-boundary regressions: synthetic adapters, keys and controlled clocks.

Every named case is independently reported. Counts are scenarios, not security
certifications. These supplement the unchanged core/prior/boundary suites.
"""
from __future__ import annotations
import copy
import json
import subprocess
import sys
import tempfile
import threading
import traceback
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from gate import (Gate, InMemoryProfileStore, ExecutorNotAttempted, sign_profile_ed25519,
                  LIFECYCLE_V, PROFILE_V, schema_errors)
from check_containment import canonical, parse_time, Malformed, digest
from evidence import make_observation, seal_attestation
from reconciliation import make_reconciliation_evidence, RECONCILIATION_BINDINGS
from readback_signoff import (sign_readback, verify_readback_signoff, verify_required_signoffs,
                             review_binding)
from aam import readback, review_digests
from rebuild_examples import ExampleState
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from validation_support import strict_format_checker

EXAMPLE = ROOT / 'examples/business-workflow-agent.invoice-triage'
P0 = json.loads((EXAMPLE / 'profile.json').read_text())
R0 = json.loads((EXAMPLE / 'request.json').read_text())
KEYID = 'demo-profile-signing-2026'
PRIVATE = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.key.hex').read_text().strip())
PUBLIC = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
ROOTS = {KEYID: {'method':'ed25519', 'public_key':PUBLIC}}
TP, TA, TE, TV = '2026-09-05T14:10:00Z', '2026-09-05T14:13:00Z', '2026-09-05T14:14:00Z', '2026-09-05T14:15:00Z'
JANE = [{'role':'ap_manager','principal':'user:jane','auth_ref':'sso:jane:1'}]
VERIFIER_KEY = b'synthetic-merge-verifier-key'
RESULTS, FIXTURES, SIGNOFFS = [], [], []


def require(condition, detail='assertion failed'):
    if not condition:
        raise AssertionError(detail)


def run(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ''))
        print('PASS', name, flush=True)
    except Exception:
        detail = traceback.format_exc()
        RESULTS.append((name, False, detail))
        print('FAIL', name, '\n'+detail, flush=True)


class Live(ExampleState):
    def __init__(self):
        self.observed_at = TV
        self.observed = True
        self.no_reads = False
        self.read_callback = None
        self.reconcile_callback = None
        self.disposition = 'UNKNOWN'
        self.reconcile_calls = 0
    def observe(self, test, manifest, execution):
        if self.read_callback:
            return self.read_callback(test, manifest, execution)
        if self.no_reads:
            return None
        return make_observation(execution, manifest, test['test_id'], self.observed,
                                self.observed_at, source_version='synthetic-revision-1', evidence_ref='test:merge:read')
    def reconcile(self, manifest, execution):
        self.reconcile_calls += 1
        if self.reconcile_callback:
            return self.reconcile_callback(manifest, execution)
        return evidence(execution, manifest, self.disposition)


def evidence(ex, m, disposition='COMMITTED', at=TV):
    return make_reconciliation_evidence(ex, m, disposition, at, final=disposition!='UNKNOWN',
                                       source='test:transaction-store', source_version='txn-revision-1',
                                       evidence_ref='test:terminal-receipt', transaction_ref='txn:synthetic:1')


def fresh(*, unknown=False, dispatched=True, skew=0, kwargs=None):
    state, store, clock = Live(), InMemoryProfileStore(), [TV]
    g = Gate(state, store, b'merge-synthetic-gate-key', trust_roots=ROOTS,
             clock=lambda:clock[0], observation_clock_skew_seconds=skew, **(kwargs or {}))
    require(g.publish_profile(P0)['published'])
    calls=[]
    def executor(request, context):
        calls.append((copy.deepcopy(request),copy.deepcopy(context)))
        if unknown:
            raise TimeoutError('sensitive value must never appear in records')
        return {'accepted':True}
    g.register_executor('email','draft_email',executor,with_context=True)
    proposal=g.propose(P0['profile_id'],copy.deepcopy(R0),TP)
    require(proposal['decision']['decision']=='ALLOW',str(proposal))
    m=proposal['manifest'];approval=g.record_approval(m['manifest_id'],JANE,TA)
    f=SimpleNamespace(g=g,state=state,store=store,m=m,approval=approval,clock=clock,calls=calls,ex=None)
    if dispatched:
        f.ex=g.execute(m['manifest_id'],approval['approval_id'],TE)
        require(f.ex['execution_state']==('EXECUTION_UNKNOWN' if unknown else 'ACKNOWLEDGED'))
    FIXTURES.append(f)
    return f


def regs(f):
    f.g.register_verifier('independent-reviewer',VERIFIER_KEY,
                         sources=sorted({t['source'] for t in f.m['outcome_verification']['verification_tests']}),
                         methods=['read_system_of_record','independent_observation','human_confirmation'])


def atts(f, value=False, at=TV):
    regs(f)
    return [seal_attestation(make_observation(f.ex,f.m,t['test_id'],value,at,
                                            source_version='attested-revision-2',evidence_ref='test:attestation'),
                             'independent-reviewer',VERIFIER_KEY)
            for t in f.m['outcome_verification']['verification_tests'] if t['method']!='tool_return_code']


def remains_unknown(f, record):
    require(not record['applied'],str(record))
    require(f.g.get_execution(f.ex['execution_id'])['execution_state']=='EXECUTION_UNKNOWN')


def unknown_postconditions():
    f=fresh(unknown=True)
    result=f.g.verify_outcome(f.ex['execution_id'],TV)
    require(result['postconditions_verified'] and not result['verified'] and result['reconciliation_required'])
    require(f.g.get_execution(f.ex['execution_id'])['execution_state']=='EXECUTION_UNKNOWN')
run('positive postconditions alone never reconcile an unknown dispatch',unknown_postconditions)


def commit():
    f=fresh(unknown=True);f.state.disposition='COMMITTED'
    r=f.g.reconcile(f.ex['execution_id'],TV)
    require(r['applied'] and r['state_after']=='COMMITTED')
    history=f.g.execution_history(f.ex['execution_id'])
    require([x['execution_state'] for x in history]==['DISPATCHED','EXECUTION_UNKNOWN','COMMITTED'])
    require(history[-1]['receipt']==f.ex['receipt'])
    require(f.g.verify_outcome(f.ex['execution_id'],TV)['verified'])
    require(len(f.calls)==1)
run('terminal transaction evidence reconciles unknown to committed; verification is separate',commit)


def committed_unverified():
    f=fresh(unknown=True);f.state.disposition='COMMITTED';f.state.no_reads=True
    require(f.g.reconcile(f.ex['execution_id'],TV)['applied'])
    o=f.g.verify_outcome(f.ex['execution_id'],TV)
    require(not o['verified'] and not o['reconciliation_required'])
run('committed transaction with unobservable postconditions is not business completion',committed_unverified)


def negative():
    f=fresh(unknown=True);f.state.disposition='NOT_COMMITTED'
    r=f.g.reconcile(f.ex['execution_id'],TV);ex=f.g.get_execution(f.ex['execution_id'])
    require(r['applied'] and ex['execution_state']=='NOT_COMMITTED' and 'not_attempted_at' not in ex)
    require(ex['dispatched_at']==TE and ex['execution_unknown_at']==TE)
    require(not f.g.verify_outcome(f.ex['execution_id'],TV)['verified'])
    denied=f.g.execute(f.m['manifest_id'],f.approval['approval_id'],TV)
    require(denied['authorization_decision']=='DENY' and len(f.calls)==1)
    request=copy.deepcopy(R0)
    p=f.g.propose(P0['profile_id'],request,TV)
    a=f.g.record_approval(p['manifest']['manifest_id'],JANE,TV)
    d=f.g.execute(p['manifest']['manifest_id'],a['approval_id'],TV)
    require(d['execution_state']=='NOT_DISPATCHED' and len(f.calls)==1)
run('not committed preserves attempted history and never restores approval or redispatch',negative)


def no_attempt():
    f=fresh(dispatched=False)
    def preflight(*_):
        raise ExecutorNotAttempted('credentials:super-secret')
    f.g.register_executor('email','draft_email',preflight)
    ex=f.g.execute(f.m['manifest_id'],f.approval['approval_id'],TE)
    require(ex['authorization_decision']=='ALLOW' and ex['execution_state']=='NOT_ATTEMPTED')
    require(not ex['reconciliation_required'] and 'super-secret' not in json.dumps(ex))
    require(not f.g.verify_outcome(ex['execution_id'],TV)['verified'])
    require(not f.g.reconcile(ex['execution_id'],TV)['applied'] and f.state.reconcile_calls==0)
    require(f.g.execute(f.m['manifest_id'],f.approval['approval_id'],TV)['decision']=='DENY')
    require(f.g._approvals[f.approval['approval_id']]['consumed_by']==ex['execution_id'])
run('ExecutorNotAttempted records preflight no-attempt without approval restoration',no_attempt)


def unknown_error():
    f=fresh(unknown=True)
    require(f.ex['decision']=='ALLOW' and f.ex['reconciliation_required'])
    require('sensitive value' not in json.dumps(f.ex))
run('ordinary timeout still means unknown; adapter exception text is not persisted',unknown_error)


def rec_unknown():
    f=fresh(unknown=True)
    remains_unknown(f,f.g.reconcile(f.ex['execution_id'],TV))
    f.state.disposition='COMMITTED'
    require(f.g.reconcile(f.ex['execution_id'],TV)['applied'])
    require(len(f.g.reconciliation_history(f.ex['execution_id']))==2)
run('unresolved reconciliation is recorded and can later be settled',rec_unknown)


def rejection(mut):
    f=fresh(unknown=True)
    f.state.reconcile_callback=lambda m,ex:mut(evidence(ex,m))
    remains_unknown(f,f.g.reconcile(f.ex['execution_id'],TV))
for field in RECONCILIATION_BINDINGS:
    def change(e, field=field):
        e[field]=('sha256:'+'f'*64) if field.endswith('digest') or field=='idempotency_key' else 'wrong-binding'
        return e
    run('reconciliation rejects wrong '+field,lambda change=change:rejection(change))
for name,mut in [
    ('bare status string',lambda e:'COMMITTED'),('bare boolean',lambda e:True),
    ('missing evidence',lambda e:None),('non-JSON evidence',lambda e:object()),
    ('non-final negative',lambda e:{**e,'disposition':'NOT_COMMITTED','final':False}),
    ('unknown marked final',lambda e:{**e,'disposition':'UNKNOWN','final':True}),
    ('observation instead of transaction evidence',lambda e:{**e,'record_type':'ObservationRecord'}),
    ('empty source version',lambda e:{**e,'source_version':''}),
    ('missing transaction reference',lambda e:{k:v for k,v in e.items() if k!='transaction_ref'}),
    ('pre-attempt evidence',lambda e:{**e,'observed_at':'2026-09-05T14:13:59Z'}),
    ('future evidence',lambda e:{**e,'observed_at':'2026-09-05T14:15:01Z'}),
    ('malformed evidence time',lambda e:{**e,'observed_at':'bad'})]:
    run('reconciliation rejects '+name,lambda mut=mut:rejection(mut))


def rec_stale():
    f=fresh(unknown=True)
    f.state.disposition='COMMITTED'
    remains_unknown(f,f.g.reconcile(f.ex['execution_id'],'2026-09-05T14:21:00Z'))
run('reconciliation enforces its configured evidence-age window',rec_stale)


def rec_exception():
    f=fresh(unknown=True)
    def down(*_):raise RuntimeError('sensitive downstream credential')
    f.state.reconcile_callback=down
    r=f.g.reconcile(f.ex['execution_id'],TV);remains_unknown(f,r)
    require('sensitive downstream credential' not in json.dumps(r))
run('reconciliation provider exception produces a sealed unresolved record',rec_exception)


def bad_requests():
    f=fresh(unknown=True)
    require(not f.g.reconcile('missing',TV)['applied'])
    remains_unknown(f,f.g.reconcile(f.ex['execution_id'],'bad-time'))
    require(f.state.reconcile_calls==0)
run('unknown execution id and malformed reconciliation time never call the adapter',bad_requests)


def acknowledged_no_reconcile():
    f=fresh();require(not f.g.reconcile(f.ex['execution_id'],TV)['applied'])
    require(f.state.reconcile_calls==0)
run('acknowledged executions cannot be overwritten by reconciliation',acknowledged_no_reconcile)


def replay_reconcile():
    f=fresh(unknown=True);f.state.disposition='COMMITTED'
    require(f.g.reconcile(f.ex['execution_id'],TV)['applied'])
    require(not f.g.reconcile(f.ex['execution_id'],TV)['applied'] and f.state.reconcile_calls==1)
run('settled execution ignores repeated reconciliation without another provider call',replay_reconcile)


def race(delayed, winner):
    f=fresh(unknown=True);started=threading.Event();release=threading.Event();outputs=[]
    def callback(m,ex):
        if threading.current_thread().name=='delayed-reconcile':
            started.set();require(release.wait(3),'race release timed out')
            return evidence(ex,m,delayed)
        return evidence(ex,m,winner)
    f.state.reconcile_callback=callback
    t=threading.Thread(name='delayed-reconcile',target=lambda:outputs.append(f.g.reconcile(f.ex['execution_id'],TV)),daemon=True)
    t.start();require(started.wait(3),'slow reader did not start')
    settled=f.g.reconcile(f.ex['execution_id'],TV);release.set();t.join(3)
    require(not t.is_alive() and settled['applied'])
    require(len(outputs)==1 and not outputs[0]['applied'])
    require(f.g.get_execution(f.ex['execution_id'])['execution_state']==winner)
    require(len(f.g.execution_history(f.ex['execution_id']))==3)
for delayed,winner in [('NOT_COMMITTED','COMMITTED'),('COMMITTED','NOT_COMMITTED'),('COMMITTED','COMMITTED')]:
    run(f'delayed {delayed} cannot overwrite already settled {winner}',lambda delayed=delayed,winner=winner:race(delayed,winner))


def reconcile_callback_unlocked():
    f=fresh(unknown=True)
    def callback(m,ex):
        require(f.g.get_execution(ex['execution_id']) is not None)
        require(f.g.reevaluate(m['manifest_id'],TV)['decision']=='ALLOW')
        m['action_target']['parameters']['rogue']=True
        # Build evidence against original Manifest, because returned arguments are detached copies.
        return evidence(ex,f.m)
    f.state.reconcile_callback=callback
    result=[];t=threading.Thread(target=lambda:result.append(f.g.reconcile(f.ex['execution_id'],TV)),daemon=True)
    t.start();t.join(3)
    require(not t.is_alive() and result[0]['applied'])
    require('rogue' not in f.g._own_manifest(f.m['manifest_id'])['action_target']['parameters'])
run('reconciliation I/O is outside the gate mutex and receives detached snapshots',reconcile_callback_unlocked)


def original_after_revocation():
    f=fresh(unknown=True);f.store.revoke(P0['profile_id']);f.state.disposition='COMMITTED'
    require(f.g.reconcile(f.ex['execution_id'],TV)['applied'])
    require(f.g.execute(f.m['manifest_id'],f.approval['approval_id'],TV)['decision']=='DENY')
run('reconciliation can inspect historical attempts after revocation but cannot authorize new effects',original_after_revocation)


def history_copies():
    f=fresh(unknown=True);f.state.disposition='COMMITTED'
    record=f.g.reconcile(f.ex['execution_id'],TV);record['applied']=False
    histories=f.g.reconciliation_history(f.ex['execution_id']);histories[0]['state_after']='UNKNOWN'
    require(f.g.reconciliation_history(f.ex['execution_id'])[0]['state_after']=='COMMITTED')
    exs=f.g.execution_history(f.ex['execution_id'])
    require(all(exs[i]['previous_record_seal']==exs[i-1]['seal'] for i in range(1,len(exs))))
run('reconciliation records and sequence-linked execution history are detached copies',history_copies)


def conflict(live,attested):
    f=fresh();f.state.observed=live
    o=f.g.verify_outcome(f.ex['execution_id'],TV,atts(f,attested))
    require(not o['verified'] and not o['postconditions_verified'])
    for result in o['results']:
        if result['required_for_completion']:
            require(result['evidence_conflict'] and result['observed'] is None)
            require({e['observed'] for e in result['admissible_evidence']}=={False,True})
for live,attested in [(True,False),(False,True)]:
    run(f'live {live} versus authenticated {attested} remains unresolved with both evidence records',lambda live=live,attested=attested:conflict(live,attested))


def agreement():
    f=fresh();o=f.g.verify_outcome(f.ex['execution_id'],TV,atts(f,True))
    require(o['verified'])
    require(all(not r['evidence_conflict'] and len(r['admissible_evidence'])==2 for r in o['results'] if r['required_for_completion']))
run('agreeing live and authenticated evidence can establish completion',agreement)


def invalid_negative():
    f=fresh();a=atts(f,False)
    for item in a:item['seal']='f'*64
    require(f.g.verify_outcome(f.ex['execution_id'],TV,a)['verified'])
run('unauthenticated negative input cannot manufacture an evidence conflict',invalid_negative)


def wrong_execution_negative():
    f=fresh();other=fresh();a=atts(other,False);regs(f)
    require(f.g.verify_outcome(f.ex['execution_id'],TV,a)['verified'])
run('authentic evidence for another execution is inadmissible rather than a conflict',wrong_execution_negative)


def verification_race():
    f=fresh(unknown=True);f.state.disposition='COMMITTED'
    first=[True]
    def read(test,m,ex):
        if first[0]:
            first[0]=False;require(f.g.reconcile(ex['execution_id'],TV)['applied'])
        return make_observation(ex,m,test['test_id'],True,TV,source_version='r',evidence_ref='test:race')
    f.state.read_callback=read
    o=f.g.verify_outcome(f.ex['execution_id'],TV)
    require(not o['verified'] and any('changed during verification' in x for x in o['reasons']))
    require(f.g.verify_outcome(f.ex['execution_id'],TV)['verified'])
run('concurrent reconciliation invalidates the old verification snapshot instead of reporting stale completion',verification_race)


def skew_future(seconds,accepted):
    f=fresh(skew=5);f.state.observed_at=f'2026-09-05T14:15:{seconds:02d}Z'
    o=f.g.verify_outcome(f.ex['execution_id'],TV)
    require(o['verified']==accepted,str(o));require(o['observation_clock_skew_seconds']==5)
run('future observation exactly at configured skew boundary passes both freshness checks',lambda:skew_future(5,True))
run('future observation beyond configured skew boundary remains unresolved',lambda:skew_future(6,False))


def skew_prior():
    f=fresh(skew=60);f.state.observed_at='2026-09-05T14:13:59Z'
    require(not f.g.verify_outcome(f.ex['execution_id'],TV)['verified'])
run('clock skew never admits a pre-dispatch-attempt observation',skew_prior)


def skew_age():
    f=fresh(skew=60)
    require(not f.g.verify_outcome(f.ex['execution_id'],'2026-09-05T14:31:00Z')['verified'])
run('clock skew does not extend maximum observation age or test deadline',skew_age)


def skew_attestation():
    f=fresh(skew=5);f.state.no_reads=True
    require(f.g.verify_outcome(f.ex['execution_id'],TV,atts(f,True,'2026-09-05T14:15:05Z'))['verified'])
run('registered attestation uses the same configured clock policy as live reads',skew_attestation)


def skew_reconciliation():
    f=fresh(unknown=True,skew=5)
    f.state.reconcile_callback=lambda m,ex:evidence(ex,m,at='2026-09-05T14:15:05Z')
    require(f.g.reconcile(f.ex['execution_id'],TV)['applied'])
run('reconciliation applies and records bounded future-clock tolerance',skew_reconciliation)


def approval_skew():
    f=fresh(dispatched=False,skew=60)
    a=f.g.record_approval(f.m['manifest_id'],JANE,'2026-09-05T14:14:01Z')
    require(f.g.execute(f.m['manifest_id'],a['approval_id'],TE)['decision']=='DENY')
run('observation clock skew never expands approval validity',approval_skew)
for value in [-1,61,1.5,True,float('nan'),'5']:
    def invalid_skew(value=value):
        try: Gate(Live(),InMemoryProfileStore(),b'k',observation_clock_skew_seconds=value)
        except ValueError:return
        raise AssertionError('invalid skew accepted')
    run(f'invalid trusted clock-skew config rejected: {value!r}',invalid_skew)

# Identity-bound read-back sign-offs.
K_A=Ed25519PrivateKey.generate();K_B=Ed25519PrivateKey.generate()
PRIVATE_A=K_A.private_bytes_raw();PRIVATE_B=K_B.private_bytes_raw()
TRUST={
    'review-a':{'method':'ed25519','public_key':K_A.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
                'principal':'user:product-owner','roles':['product_owner'],'parts':['A','profile']},
    'review-b':{'method':'ed25519','public_key':K_B.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
                'principal':'user:engineer','roles':['engineering'],'parts':['B','profile']},
}


def signoffs():
    a=sign_readback(P0,part='A',principal='user:product-owner',role='product_owner',private_key_bytes=PRIVATE_A,key_id='review-a',signed_at=TA)
    b=sign_readback(P0,part='B',principal='user:engineer',role='engineering',private_key_bytes=PRIVATE_B,key_id='review-b',signed_at=TA)
    SIGNOFFS.extend(copy.deepcopy([a,b]));return a,b


def signature_roundtrip(part):
    a,b=signoffs()
    rec=a if part=='A' else b if part=='B' else sign_readback(P0,part='profile',principal='user:product-owner',role='product_owner',private_key_bytes=PRIVATE_A,key_id='review-a',signed_at=TA)
    key=K_B if part=='B' else K_A
    # Independently verify serialized saved bytes, not merely this module's verifier.
    saved=json.loads(json.dumps(rec));body={k:v for k,v in saved.items() if k!='signature'}
    key.public_key().verify(bytes.fromhex(saved['signature']['value']),canonical(body).encode())
    require(saved['binding']=='identity_bound' and verify_readback_signoff(P0,saved,TRUST,TV)['valid'])
    require(saved['review_digest']==review_digests(P0)[part])
    require(saved['readback_digest']==digest(readback(P0)))
for part in ['A','B','profile']:
    run('serialized '+part+' sign-off independently verifies and binds exact rendered review',lambda part=part:signature_roundtrip(part))

for field in ['binding','principal','role','part','key_id','profile_digest','review_digest','readback_digest','signed_at','signoff_id']:
    def tamper(field=field):
        a,_=signoffs();a[field]='modified'
        require(not verify_readback_signoff(P0,a,TRUST,TV)['valid'])
    run('sign-off rejects tampered '+field,tamper)


def edited_profile():
    a,_=signoffs();p=copy.deepcopy(P0);p['identity']['owner']='someone else'
    require(not verify_readback_signoff(p,a,TRUST,TV)['valid'])
run('old review cannot approve a changed Profile',edited_profile)
for name,mut in [
    ('wrong public key',lambda r:r['review-a'].update(public_key=TRUST['review-b']['public_key'])),
    ('wrong principal mapping',lambda r:r['review-a'].update(principal='user:other')),
    ('wrong role authorization',lambda r:r['review-a'].update(roles=['engineering'])),
    ('wrong part authorization',lambda r:r['review-a'].update(parts=['B'])),
    ('revoked key',lambda r:r['review-a'].update(revoked=True)),
    ('expired key',lambda r:r['review-a'].update(not_after=TE)),
    ('not-yet-valid key',lambda r:r['review-a'].update(not_before=TV)),
    ('unknown key',lambda r:r.pop('review-a'))]:
    def untrusted(mut=mut):
        a,_=signoffs();roots=copy.deepcopy(TRUST);mut(roots)
        require(not verify_readback_signoff(P0,a,roots,TV)['valid'])
    run('sign-off rejects '+name,untrusted)


def future_signoff():
    a,_=signoffs()
    require(not verify_readback_signoff(P0,a,TRUST,TP)['valid'])
run('sign-off verification does not accept future approvals',future_signoff)


def publication_required():
    a,b=signoffs();g=Gate(Live(),InMemoryProfileStore(),b'k',trust_roots=ROOTS,clock=lambda:TV,
        readback_trust_roots=TRUST,require_readback_signoffs=True)
    require(not g.publish_profile(P0)['published'])
    require(not g.publish_profile(P0,readback_signoffs=[a])['published'])
    require(g.publish_profile(P0,readback_signoffs=[a,b])['published'])
    p=copy.deepcopy(P0);p['identity']['owner']='new owner';p=sign_profile_ed25519(p,PRIVATE,KEYID)
    require(not g.publish_profile(p,readback_signoffs=[a,b])['published'])
    FIXTURES.append(SimpleNamespace(g=g))
run('optional publication enforcement requires exact valid Part A and B approvals',publication_required)


def distinct_principals():
    a,b=signoffs();r=copy.deepcopy(TRUST);r['review-b']['principal']='user:product-owner'
    b=sign_readback(P0,part='B',principal='user:product-owner',role='engineering',private_key_bytes=PRIVATE_B,key_id='review-b',signed_at=TA)
    require(not verify_required_signoffs(P0,[a,b],r,TV)['valid'])
run('publication requires different product-owner and engineering principals',distinct_principals)


def whole_not_substitute():
    p=sign_readback(P0,part='profile',principal='user:product-owner',role='product_owner',private_key_bytes=PRIVATE_A,key_id='review-a',signed_at=TA)
    require(verify_readback_signoff(P0,p,TRUST,TV)['valid'])
    require(not verify_required_signoffs(P0,[p],TRUST,TV)['valid'])
run('whole-Profile sign-off cannot silently replace two required Part A/B approvals',whole_not_substitute)


def no_self_asserted_key():
    a,_=signoffs()
    require(not verify_readback_signoff(P0,a,{'review-a':{'method':'ed25519','public_key':TRUST['review-a']['public_key']}},TV)['valid'])
run('a valid signature without trusted principal role and part mapping is insufficient',no_self_asserted_key)

# Explicit format enforcement, including absence of optional dependency.
for text in ['bad-time','2026-09-05','2026-09-05 14:15:00Z','2026-09-05T14:15:00','2026-99-05T14:15:00Z','2026-09-05T14:15:00+0000','2026-09-05T14:15:60Z']:
    def bad_date(text=text):
        require(not strict_format_checker().conforms(text,'date-time'))
        p=copy.deepcopy(P0);p['issued_at']=text;require(schema_errors(PROFILE_V,p))
        try:parse_time(text)
        except Malformed:return
        raise AssertionError('malformed time parsed')
    run('schema and parser reject unsupported timestamp '+text,bad_date)


def valid_offsets():
    for text in ['2026-09-05T14:15:00Z','2026-09-05t14:15:00z','2026-09-05T10:15:00-04:00','2026-09-05T14:15:00.123456Z']:
        require(strict_format_checker().conforms(text,'date-time'));parse_time(text)
run('required format checker and parser agree on supported RFC3339 offsets and fractions',valid_offsets)


def missing_dependency(target):
    code=f'''import sys
sys.path.insert(0, {str(ROOT/'tools')!r})
sys.modules['rfc3339_validator']=None
{target}
'''
    proc=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=15)
    require(proc.returncode!=0 and 'rfc3339-validator' in proc.stderr,proc.stdout+proc.stderr)
run('gate fails closed at import when required timestamp validator is absent',lambda:missing_dependency('import gate'))
run('CLI validation fails closed when required timestamp validator is absent',lambda:missing_dependency(f"import aam; raise SystemExit(aam.main(['validate', {str(EXAMPLE/'profile.json')!r}]))"))


def all_record_schemas():
    for f in FIXTURES:
        g=f.g
        records=list(g._decisions.values())+[a['record'] for a in g._approvals.values()]+g._execution_events+list(g._outcomes.values())+list(g._reconciliations.values())
        for record in records:
            errs=schema_errors(LIFECYCLE_V,record)
            require(not errs,record['record_type']+': '+str(errs))
            require(g._sealed_ok(record),'invalid local record seal')
    for signoff in SIGNOFFS:
        require(not schema_errors(LIFECYCLE_V,signoff))
run('all accumulated success failure conflict and reconciliation records validate and authenticate',all_record_schemas)

failed=[x for x in RESULTS if not x[1]]
print(f'\n{len(RESULTS)-len(failed)}/{len(RESULTS)} v0.3.6 merge regressions passed')
raise SystemExit(1 if failed else 0)
