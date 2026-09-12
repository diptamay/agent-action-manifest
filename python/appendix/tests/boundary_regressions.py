#!/usr/bin/env python3
"""v0.3.6 boundary regressions. All fixtures are synthetic; no live systems are used.

These tests supplement (not replace) the 174 core checks and the ten prior-review
regressions. PASS is evidence for the stated scenario, not a production-safety claim.
"""
import copy
import hashlib
import hmac
import json
import sys
import threading
import traceback
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from gate import (Gate, InMemoryProfileStore, StateProvider, sign_profile_ed25519,
                  sign_profile_hmac, LIFECYCLE_V, schema_errors)
from check_containment import canonical, digest, check
from evidence import make_observation, seal_attestation, BINDING_FIELDS
from render_card import project, render_text, check_parity
from rebuild_examples import ExampleState

KEY_ID = 'demo-profile-signing-2026'
PRIVATE = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.key.hex').read_text().strip())
PUBLIC = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
ROOTS = {KEY_ID: {'method': 'ed25519', 'public_key': PUBLIC}}
P0 = json.loads((ROOT / 'examples/business-workflow-agent.invoice-triage/profile.json').read_text())
R0 = json.loads((ROOT / 'examples/business-workflow-agent.invoice-triage/request.json').read_text())
JANE = [{'role': 'ap_manager', 'principal': 'user:jane', 'auth_ref': 'sso:jane:1'}]
TP, TA, TE, TV = '2026-09-05T14:10:00Z', '2026-09-05T14:13:00Z', '2026-09-05T14:14:00Z', '2026-09-05T14:15:00Z'
VERIFIER_KEY = b'public-synthetic-verifier-test-key'
RESULTS, FIXTURES = [], []


def require(value, detail='assertion failed'):
    if not value:
        raise AssertionError(detail)


def run(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ''))
        print('PASS', name)
    except Exception:
        detail = traceback.format_exc()
        RESULTS.append((name, False, detail))
        print('FAIL', name, '\n' + detail)


class Live(ExampleState):
    def __init__(self):
        self.mode = 'structured'
        self.values = {}
        self.observed_at = TV
        self.callback = None
    def observe(self, test, manifest, execution):
        if self.callback:
            return self.callback(test, manifest, execution)
        if self.mode == 'none':
            return None
        if self.mode == 'raw_bool':
            return True
        return make_observation(execution, manifest, test['test_id'],
                                self.values.get(test['test_id'], True), self.observed_at,
                                source_version='synthetic-revision-1', evidence_ref='testrun:boundary:read')


def sign(profile):
    return sign_profile_ed25519(profile, PRIVATE, KEY_ID)


def fresh(mut=None, dispatch=False):
    profile, request = copy.deepcopy(P0), copy.deepcopy(R0)
    if mut:
        mut(profile)
    profile = sign(profile)
    state, store = Live(), InMemoryProfileStore()
    clock = [TV]
    gate = Gate(state, store, b'synthetic-gate-key', trust_roots=ROOTS, clock=lambda: clock[0])
    published = gate.publish_profile(profile)
    require(published['published'], str(published))
    calls = []
    gate.register_executor('email', 'draft_email', lambda request: (calls.append(copy.deepcopy(request)) or {'accepted': True}))
    proposed = gate.propose(profile['profile_id'], request, TP)
    require(proposed['decision']['decision'] == 'ALLOW', str(proposed['decision']))
    manifest = proposed['manifest']
    approval = gate.record_approval(manifest['manifest_id'], JANE, TA)
    f = SimpleNamespace(p=profile, r=request, state=state, store=store, g=gate, calls=calls,
                        m=manifest, approval=approval, clock=clock, ex=None)
    FIXTURES.append(f)
    if dispatch:
        execute(f)
    return f


def execute(f):
    f.ex = f.g.execute(f.m['manifest_id'], f.approval['approval_id'], TE)
    return f.ex


def operation(profile):
    return next(a for a in profile['permissions']['allowed'] if a['tool'] == 'email' and a['operation'] == 'draft_email')


def register(f, *, sources=None, methods=None):
    tests = f.m['outcome_verification']['verification_tests']
    f.g.register_verifier('verifier-a', VERIFIER_KEY,
                          sources=sources or sorted({t['source'] for t in tests} | {'other-source'}),
                          methods=methods or ['read_system_of_record', 'independent_observation', 'human_confirmation'])


def attestations(f, observed=True, at=TV):
    return [seal_attestation(make_observation(f.ex, f.m, t['test_id'], observed, at,
                        source_version='synthetic-revision-1', evidence_ref='testrun:boundary:attestation'),
                        'verifier-a', VERIFIER_KEY)
            for t in f.m['outcome_verification']['verification_tests'] if t['method'] != 'tool_return_code']


def resign(att):
    body = {k: v for k, v in att.items() if k != 'seal'}
    return {**body, 'seal': hmac.new(VERIFIER_KEY, canonical(body).encode(), hashlib.sha256).hexdigest()}


def proof_fixture():
    f = fresh(dispatch=True)
    f.state.mode = 'none'
    register(f)
    return f


def valid_direct():
    f = fresh(dispatch=True)
    result = f.g.verify_outcome(f.ex['execution_id'], TV)
    require(result['verified'] and len(result['results']) == 3)
run('fresh structured system-of-record evidence completes all three declared AP postconditions', valid_direct)


def valid_proof():
    f = proof_fixture()
    result = f.g.verify_outcome(f.ex['execution_id'], TV, attestations(f))
    require(result['verified'] and all(r['observed_via'] == 'verifier_attestation' for r in result['results']))
    require(not hasattr(f.g, 'attest'), 'gate must not expose an oracle that authenticates proposed booleans')
run('valid execution-bound verifier evidence completes; no gate signing-oracle API', valid_proof)


def legacy_proof():
    f = proof_fixture()
    legacy = [resign({'verifier_id': 'verifier-a', 'assertion': t['assertion'], 'observed': True, 'at': TV})
              for t in f.m['outcome_verification']['verification_tests']]
    require(not f.g.verify_outcome(f.ex['execution_id'], TV, legacy)['verified'])
run('legacy assertion-only attestations are rejected even with a valid old-format HMAC', legacy_proof)


def replay(target_change=False):
    f = proof_fixture()
    old_proofs = attestations(f)
    request = copy.deepcopy(f.r)
    request['action_id'] += ':new-action'
    if target_change:
        request['effect_target']['identifier'] = 'other@northwind-supply.example'
        request['parameters']['recipient'] = 'other@northwind-supply.example'
    out = f.g.propose(f.p['profile_id'], request, TP)
    require(out['decision']['decision'] == 'ALLOW', str(out['decision']))
    if not target_change:
        require([t['assertion'] for t in out['manifest']['outcome_verification']['verification_tests']] ==
                [t['assertion'] for t in f.m['outcome_verification']['verification_tests']])
    approval = f.g.record_approval(out['manifest']['manifest_id'], JANE, TA)
    execution = f.g.execute(out['manifest']['manifest_id'], approval['approval_id'], TE)
    require(execution['execution_state'] == 'ACKNOWLEDGED')
    require(not f.g.verify_outcome(execution['execution_id'], TV, old_proofs)['verified'])
run('proof replay fails across executions with identical rendered assertions', replay)
run('proof replay fails across targets', lambda: replay(True))


def binding(field):
    f = proof_fixture()
    proofs = attestations(f)
    value = (digest('foreign') if field.endswith('_digest') else
             'independent_observation' if field == 'method' else
             'other-source' if field == 'source' else 'foreign-id')
    proofs[0][field] = value
    proofs[0] = resign(proofs[0])
    require(f.g._attestation_ok(proofs[0]), 'test must reach binding validation, not just fail HMAC/schema')
    require(not f.g.verify_outcome(f.ex['execution_id'], TV, proofs)['verified'])
for field in BINDING_FIELDS:
    run('authenticated evidence with wrong ' + field + ' cannot complete', lambda field=field: binding(field))


def evidence_mutation(mutate, verification_time=TV):
    f = proof_fixture()
    proofs = attestations(f)
    for i, proof in enumerate(proofs):
        mutate(proof)
        proofs[i] = resign(proof)
    require(not f.g.verify_outcome(f.ex['execution_id'], verification_time, proofs)['verified'])
for name, mutation, time_ in [
    ('pre-dispatch observation', lambda a: a.update(observed_at=TA), TV),
    ('future observation, including one second of skew', lambda a: a.update(observed_at='2026-09-05T14:15:01Z'), TV),
    ('stale observation', lambda a: None, '2026-09-05T14:22:00Z'),
    ('timezone-less observation', lambda a: a.update(observed_at='2026-09-05T14:15:00'), TV),
    ('malformed observation time', lambda a: a.update(observed_at='yesterday'), TV),
    ('truthy non-boolean observation', lambda a: a.update(observed='true'), TV),
    ('empty source version', lambda a: a.update(source_version=''), TV),
    ('missing evidence reference', lambda a: a.pop('evidence_ref'), TV),
]:
    run(name + ' fails closed', lambda mutation=mutation, time_=time_: evidence_mutation(mutation, time_))


def false_and_conflicting(conflict=False, duplicate=False):
    f = proof_fixture()
    proofs = attestations(f, observed=not (not conflict and not duplicate))
    if conflict:
        proof = copy.deepcopy(proofs[0]); proof['observed'] = False; proofs.append(resign(proof))
    if duplicate:
        proofs.append(copy.deepcopy(proofs[0]))
    require(f.g.verify_outcome(f.ex['execution_id'], TV, proofs)['verified'] is duplicate)
run('authenticated negative observations do not complete', false_and_conflicting)
run('conflicting authenticated evidence is unresolved, not last-write-wins', lambda: false_and_conflicting(conflict=True))
run('identical repeated evidence within the same execution is harmless', lambda: false_and_conflicting(duplicate=True))


def scope(source=False):
    f = proof_fixture()
    register(f, sources=['unrelated-system'] if source else None,
             methods=None if source else ['human_confirmation'])
    require(not f.g.verify_outcome(f.ex['execution_id'], TV, attestations(f))['verified'])
run('registered verifier outside source scope is rejected', lambda: scope(True))
run('registered verifier outside method scope is rejected', scope)


def human():
    def mutate(p):
        for t in operation(p)['verification']['tests']:
            t['method'], t['source'] = 'human_confirmation', 'authenticated-human-service'
    f = fresh(mut=mutate, dispatch=True)
    f.state.callback = lambda *args: (_ for _ in ()).throw(AssertionError('human confirmation must use verifier evidence'))
    register(f, methods=['human_confirmation'])
    result = f.g.verify_outcome(f.ex['execution_id'], TV, attestations(f))
    require(result['verified'] and all(r['observed_via'] == 'human_attestation' for r in result['results']))
run('human confirmations use the same binding and scoped authenticated-verifier path', human)


def raw_observation():
    f = fresh(dispatch=True); f.state.mode = 'raw_bool'
    result = f.g.verify_outcome(f.ex['execution_id'], TV)
    require(not result['verified'] and all(r['observed'] is None for r in result['results']))
run('raw booleans from StateProvider.observe are no longer accepted', raw_observation)


def mismatched_read():
    f = fresh(dispatch=True)
    def read(test, manifest, execution):
        result = make_observation(execution, manifest, test['test_id'], True, TV,
                                  source_version='revision-1', evidence_ref='testrun:wrong-context')
        result['execution_id'] = 'other-execution'
        return result
    f.state.callback = read
    require(not f.g.verify_outcome(f.ex['execution_id'], TV)['verified'])
run('structured direct-read evidence must bind to the exact execution too', mismatched_read)


def observation_exception(fallback=False):
    f = fresh(dispatch=True)
    def fail(*args): raise RuntimeError('sensitive-provider-diagnostic')
    f.state.callback = fail
    register(f)
    result = f.g.verify_outcome(f.ex['execution_id'], TV, attestations(f) if fallback else None)
    require(result['verified'] is fallback)
    require('sensitive-provider-diagnostic' not in canonical(result), 'raw provider exception leaked')
    require(all(r['evidence_errors'] for r in result['results']))
run('observation exception creates an unverified record without escaping or leaking details', observation_exception)
run('valid bound evidence can reconcile an unobservable test, not an ambiguous dispatch', lambda: observation_exception(True))


def designated():
    def mutate(p):
        v = operation(p)['verification']
        v.update(completion_rule='designated_postconditions_verified', designated_test_ids=['postcondition-1'])
    f = fresh(mut=mutate, dispatch=True)
    f.state.values = {'postcondition-2': False, 'postcondition-3': False}
    result = f.g.verify_outcome(f.ex['execution_id'], TV)
    require(result['verified'] and [r['observed'] for r in result['results']] == [True, False, False])
    require([r['test_id'] for r in result['results'] if r['required_for_completion']] == ['postcondition-1'])
    card = project(f.m)
    require(card['designated_test_ids'] == ['postcondition-1'] and check_parity(card, f.m)['ok'])
    require('postcondition-1' in render_text(f.m))
run('designated tests define completion; non-designated failures stay visible on records/Card', designated)


def invalid_plan(mutate):
    profile = copy.deepcopy(P0)
    mutate(operation(profile)['verification'])
    g = Gate(Live(), InMemoryProfileStore(), b'k', trust_roots=ROOTS)
    require(not g.publish_profile(sign(profile))['published'])
for name, mutate in [
    ('missing designated IDs', lambda v: v.update(completion_rule='designated_postconditions_verified')),
    ('unknown designated ID', lambda v: v.update(completion_rule='designated_postconditions_verified', designated_test_ids=['unknown'])),
    ('duplicate designated IDs', lambda v: v.update(completion_rule='designated_postconditions_verified', designated_test_ids=['postcondition-1']*2)),
    ('duplicate test IDs', lambda v: v['tests'][1].update(test_id=v['tests'][0]['test_id'])),
    ('all-mode with designated IDs', lambda v: v.update(designated_test_ids=['postcondition-1'])),
    ('uncovered postcondition in all-mode', lambda v: v['expected_postconditions'].append('not independently tested')),
    ('out-of-range postcondition mapping', lambda v: v['tests'][0].update(postcondition_index=999)),
    ('tool-return-only designation', lambda v: (v['tests'][0].update(method='tool_return_code'), v.update(completion_rule='designated_postconditions_verified', designated_test_ids=['postcondition-1']))),
]:
    run('publication rejects ' + name, lambda mutate=mutate: invalid_plan(mutate))


def plan_drift():
    f = fresh()
    manifest = copy.deepcopy(f.m)
    manifest['outcome_verification'].update(completion_rule='designated_postconditions_verified', designated_test_ids=['postcondition-1'])
    result = check(f.p, manifest, TP)
    require(result['decision'] == 'DENY' and any(v.startswith('C14 verification_binding') for v in result['violations']))
run('containment rejects a well-shaped but weakened Profile-derived completion plan', plan_drift)


def committed_then_raised():
    f = fresh()
    commits = []
    def adapter(request, context):
        commits.append(context)
        raise TimeoutError('the remote effect has already committed')
    f.g.register_executor('email', 'draft_email', adapter, with_context=True)
    execute(f)
    require(f.ex['authorization_decision'] == 'ALLOW' and f.ex['execution_state'] == 'EXECUTION_UNKNOWN')
    require(len(commits) == 1 and commits[0]['idempotency_key'] == f.ex['idempotency_key'])
    history = f.g.execution_history(f.ex['execution_id'])
    require([r['execution_state'] for r in history] == ['DISPATCHED', 'EXECUTION_UNKNOWN'])
    require(history[1]['previous_record_seal'] == history[0]['seal'])
    require(f.g._approvals[f.approval['approval_id']]['consumed_by'] == f.ex['execution_id'])
    result = f.g.verify_outcome(f.ex['execution_id'], TV)
    require(result['postconditions_verified'] and not result['verified'] and result['completion'] == 'escalate' and result['reconciliation_required'])
    retried = f.g.execute(f.m['manifest_id'], f.approval['approval_id'], TE)
    require(retried['execution_state'] == 'NOT_DISPATCHED' and len(commits) == 1)
run('commit-then-timeout remains ALLOW/EXECUTION_UNKNOWN, preserves history, blocks retry and completion', committed_then_raised)


def rebuilt_retry(change=False):
    f = fresh(dispatch=True)
    req = copy.deepcopy(f.r)
    if change:
        req['parameters']['variance_usd'] += 1
    proposed = f.g.propose(f.p['profile_id'], req, TP)
    require(proposed['decision']['decision'] == 'ALLOW')
    a = f.g.record_approval(proposed['manifest']['manifest_id'], JANE, TA)
    execution = f.g.execute(proposed['manifest']['manifest_id'], a['approval_id'], TE)
    require(execution['execution_state'] == 'NOT_DISPATCHED' and execution['duplicate_of_execution_id'] == f.ex['execution_id'] and len(f.calls) == 1)
    require(f.g._approvals[a['approval_id']]['consumed_by'] is None)
run('rebuilt Manifest with the same action_id is not dispatched twice', rebuilt_retry)
run('reusing action_id for different material is also denied, not silently retried', lambda: rebuilt_retry(True))


def autonomous_duplicate():
    directory = ROOT / 'examples/software-agent.repo-maintainer'
    p, r = json.loads((directory/'profile.json').read_text()), json.loads((directory/'request.json').read_text())
    g = Gate(ExampleState(), InMemoryProfileStore(), b'k', trust_roots=ROOTS)
    require(g.publish_profile(p)['published'])
    calls = []
    g.register_executor('github','open_pull_request',lambda request: calls.append(request))
    proposed = g.propose(p['profile_id'],r,'2026-09-05T16:00:00Z')
    require(not proposed['manifest']['autonomy_approval']['approval_required'])
    first = g.execute(proposed['manifest']['manifest_id'],now='2026-09-05T16:01:00Z')
    second = g.execute(proposed['manifest']['manifest_id'],now='2026-09-05T16:01:00Z')
    require(first['execution_state']=='ACKNOWLEDGED' and second['execution_state']=='NOT_DISPATCHED' and len(calls)==1)
run('single-dispatch reservation also protects approval-free autonomous Manifests', autonomous_duplicate)


def concurrent():
    f = fresh(); results=[]
    workers=[threading.Thread(target=lambda: results.append(f.g.execute(f.m['manifest_id'],f.approval['approval_id'],TE)),daemon=True) for _ in range(8)]
    for worker in workers:worker.start()
    for worker in workers:worker.join(3)
    require(not any(worker.is_alive() for worker in workers), 'deadlock')
    require(sum(r['execution_state']=='ACKNOWLEDGED' for r in results)==1 and len(f.calls)==1)
run('eight concurrent dispatch attempts consume one approval and invoke one executor', concurrent)


def reentrant():
    f=fresh(); returned=[]
    f.g.register_executor('email','draft_email',lambda request: f.g.reevaluate(f.m['manifest_id'],TE))
    worker=threading.Thread(target=lambda:returned.append(execute(f)),daemon=True);worker.start();worker.join(3)
    require(not worker.is_alive() and returned[0]['execution_state']=='ACKNOWLEDGED','executor callback deadlocked gate')
run('executor can call a gate read/reevaluation without global-lock deadlock', reentrant)


def unrelated_progress():
    f=fresh(); entered=threading.Event(); release=threading.Event(); completed=[]
    first_id=f.m['action_target']['parameters']['invoice']
    def blocking(request):
        if request['parameters']['variance_usd']==f.r['parameters']['variance_usd']:
            entered.set(); release.wait(3)
        return {'ack':True}
    f.g.register_executor('email','draft_email',blocking)
    first=threading.Thread(target=lambda:completed.append(execute(f)),daemon=True);first.start()
    require(entered.wait(2),'first executor did not start')
    try:
        req=copy.deepcopy(f.r);req['action_id']+=':unrelated';req['parameters']['variance_usd']+=1
        proposed=f.g.propose(f.p['profile_id'],req,TP)
        approval=f.g.record_approval(proposed['manifest']['manifest_id'],JANE,TA)
        second=[]
        worker=threading.Thread(target=lambda:second.append(f.g.execute(proposed['manifest']['manifest_id'],approval['approval_id'],TE)),daemon=True)
        worker.start();worker.join(1)
        require(not worker.is_alive() and second[0]['execution_state']=='ACKNOWLEDGED','unrelated dispatch blocked by executor lock')
        in_progress=f.g.get_execution(f.g._dispatches[f.m['manifest_id']])
        require(in_progress['execution_state']=='DISPATCHED')
        require(not f.g.verify_outcome(in_progress['execution_id'],TV)['verified'])
    finally:
        release.set();first.join(2)
run('slow executor does not hold the ledger lock or permit premature verification', unrelated_progress)


def bad_receipt():
    f=fresh();f.g.register_executor('email','draft_email',lambda request:object())
    execute(f)
    require(f.ex['execution_state']=='EXECUTION_UNKNOWN' and f.ex['authorization_decision']=='ALLOW')
run('non-JSON receipt after dispatch is ambiguous too, never DENY', bad_receipt)


def predicate_failure(method, value='raises'):
    f=fresh()
    def callback(*args):
        if value=='raises':raise RuntimeError('private dependency detail')
        return value
    setattr(f.state,method,callback)
    result=execute(f)
    require(result['execution_state']=='NOT_DISPATCHED' and not f.calls)
    require(result['authorization_decision']==('DENY' if value is False else 'INDETERMINATE'),str(result))
    require('private dependency detail' not in canonical(result))
for method in ['kill_switch_allows','effect_target_in_class','evaluate_rule','evaluate_selector','credential_valid','authenticated']:
    run(method+' exception yields recorded INDETERMINATE without dispatch',lambda method=method:predicate_failure(method))
for value,name in [(None,'None'),('true','truthy string'),(1,'integer one'),(False,'explicit false')]:
    run('credential predicate '+name+' is not silently treated as permission',lambda value=value:predicate_failure('credential_valid',value))


def extra_resolver_failures(kind):
    if kind=='threshold':
        directory=ROOT/'examples/software-agent.repo-maintainer';p=json.loads((directory/'profile.json').read_text());r=json.loads((directory/'request.json').read_text())
        next(a for a in p['permissions']['allowed'] if a['operation']=='open_pull_request')['default_mode']='request_approval'
        state=Live()
        def fail(*args):raise RuntimeError('threshold unavailable')
        state.evaluate_threshold=fail
        g=Gate(state,InMemoryProfileStore(),b'k',trust_roots=ROOTS)
        require(g.publish_profile(sign(p))['published'])
        result=g.propose(p['profile_id'],r,'2026-09-05T16:00:00Z')
    elif kind=='recovery':
        directory=ROOT/'examples/software-agent.repo-maintainer';p=json.loads((directory/'profile.json').read_text());r=json.loads((directory/'request.json').read_text())
        state=Live()
        def fail(*args):raise RuntimeError('recovery unavailable')
        state.recovery_evidence=fail
        g=Gate(state,InMemoryProfileStore(),b'k',trust_roots=ROOTS);require(g.publish_profile(p)['published'])
        result=g.propose(p['profile_id'],r,'2026-09-05T16:00:00Z')
    else:
        def mutate(p):p['data_boundary']['egress_policy']='signed_summary'
        f=fresh(mut=mutate)
        def fail(*args):raise RuntimeError('egress unavailable')
        f.state.egress_policy_permits=fail
        result=f.g.propose(f.p['profile_id'],f.r,TP)
    require(result['decision']['decision']=='INDETERMINATE',str(result))
    require(not schema_errors(LIFECYCLE_V,result['decision']))
for kind in ['threshold','recovery','egress']:
    run(kind+' provider failure cannot escape the decision model',lambda kind=kind:extra_resolver_failures(kind))


def store_failure():
    f=fresh()
    def fail(*args):raise RuntimeError('store unavailable')
    f.store.active=fail
    require(f.g.propose(f.p['profile_id'],f.r,TP)['decision']['decision']=='INDETERMINATE')
    result=execute(f);require(result['authorization_decision']=='INDETERMINATE' and not f.calls)
run('ProfileStore read failure yields non-executable records at propose and execute',store_failure)


def denial_dominates():
    f=fresh();f.state.kill_switch_allows=lambda *args:False
    def fail(*args):raise RuntimeError('credential service unavailable')
    f.state.credential_valid=fail
    result=execute(f);require(result['authorization_decision']=='DENY' and not f.calls)
run('known policy failure remains DENY even when a different dependency is unavailable',denial_dominates)


def slow_authorization():
    f=fresh();f.clock[0]=TE
    def credential(*args):f.clock[0]='2026-09-05T14:25:00Z';return True
    f.state.credential_valid=credential
    result=f.g.execute(f.m['manifest_id'],f.approval['approval_id'])
    require(result['execution_state']=='NOT_DISPATCHED' and any('expired' in x for x in result['reasons']) and not f.calls)
run('clock advances during a provider call: expired authorization is not dispatched',slow_authorization)


def after_read_clock():
    f=fresh(dispatch=True);f.clock[0]='2026-09-05T14:14:59Z'
    def read(test,m,ex):
        f.clock[0]=TV
        return make_observation(ex,m,test['test_id'],True,TV,source_version='revision-2',evidence_ref='testrun:after-read')
    f.state.callback=read
    require(f.g.verify_outcome(f.ex['execution_id'])['verified'])
run('fresh synchronous read after verification starts is not misclassified as future evidence',after_read_clock)


def late_read_stales_earlier():
    f=fresh(dispatch=True);f.clock[0]=TV
    def read(test,m,ex):
        if test['test_id']!='postcondition-1':f.clock[0]='2026-09-05T14:25:00Z'
        return make_observation(ex,m,test['test_id'],True,TV,source_version='revision-1',evidence_ref='testrun:slow-read')
    f.state.callback=read
    result=f.g.verify_outcome(f.ex['execution_id'])
    require(not result['verified'] and result['results'][0]['observed'] is None)
run('earlier observation is rechecked for staleness at final verification time',late_read_stales_earlier)


def copies():
    f=fresh(dispatch=True)
    f.ex['receipt']['accepted']=False
    f.m['action_target']['parameters']['variance_usd']=999999
    actual=f.g.get_execution(f.ex['execution_id'])
    require(actual['receipt']['accepted'] is True)
    require(f.g.verify_outcome(actual['execution_id'],TV)['verified'])
run('returned Manifests and records are detached copies, not mutable ledger references',copies)


def hmac_policy():
    profile=copy.deepcopy(P0);profile['conformance']['level']='L1'
    authenticated=sign_profile_hmac(profile,b'shared','hmac-root')
    g=Gate(Live(),InMemoryProfileStore(),b'k',trust_roots={'hmac-root':{'method':'hmac-sha256','secret':b'shared'}})
    require(g.publish_profile(authenticated)['published'])
    profile['conformance']['level']='L2'
    require(not g.publish_profile(sign_profile_hmac(profile,b'shared','hmac-root'))['published'])
    wrong=Gate(Live(),InMemoryProfileStore(),b'k',trust_roots={'hmac-root':{'method':'hmac-sha256','secret':b'wrong'}})
    require(not wrong.publish_profile(authenticated)['published'])
run('HMAC authenticates an explicitly configured L1 Profile; L2/L3 still require Ed25519',hmac_policy)


def failures_are_records():
    f=fresh()
    f.g.propose(f.p['profile_id'],{'mode':'root'},TP)
    f.g.propose(f.p['profile_id'],f.r,'bad-time')
    f.g.execute('unknown-id',now=TE)
    f.g.execute(f.m['manifest_id'],now='bad-time')
    f.g.record_approval('unknown-id',[],TA)
    f.g.record_approval(f.m['manifest_id'],JANE,'bad-time')
    f.g.verify_outcome('unknown-id',TV)
    f.g.verify_outcome('unknown-id','bad-time')
    f.g.propose(f.p['profile_id'],f.r,TP,manifest_id=f.m['manifest_id'])
    # Completed records should be stored even on error paths.
    require(len(f.g._outcomes)==2)
    for fixture in FIXTURES:
        g=fixture.g
        records=list(g._decisions.values())+[e['record'] for e in g._approvals.values()]+g._execution_events+list(g._outcomes.values())
        for record in records:
            require(not schema_errors(LIFECYCLE_V,record),record['record_type']+': '+str(schema_errors(LIFECYCLE_V,record)))
            require(g._sealed_ok(record),'record seal failed')
run('every accumulated success, denial, unresolved, in-flight and unknown record validates and is sealed',failures_are_records)

failed=[r for r in RESULTS if not r[1]]
print(f'\n{len(RESULTS)-len(failed)}/{len(RESULTS)} boundary regressions passed')
sys.exit(1 if failed else 0)
