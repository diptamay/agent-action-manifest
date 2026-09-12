"""Synthetic fixtures for the managed-runtime demo/tests. Never live integration code."""
import copy
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from managed_gate import ManagedGate
from gate import StateProvider,sign_profile_ed25519
from feedback import policy_ref
from evidence import make_observation
from reconciliation import make_reconciliation_evidence
from check_containment import profile_digest
from rebuild_examples import ExampleState

BASE=json.loads((ROOT/'examples/business-workflow-agent.invoice-triage/profile.json').read_text())
REQUEST=json.loads((ROOT/'examples/business-workflow-agent.invoice-triage/request.json').read_text())
POLICY=json.loads((ROOT/'examples/managed-runtime/feedback-policy.json').read_text())
PRIVATE=bytes.fromhex((ROOT/'examples/trust/demo-profile-signing.key.hex').read_text().strip())
PUBLIC=bytes.fromhex((ROOT/'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
ROOTS={'demo-profile-signing-2026':{'method':'ed25519','public_key':PUBLIC}}
TP='2026-09-07T14:10:00Z';TA='2026-09-07T14:11:00Z';TE='2026-09-07T14:12:00Z';TV='2026-09-07T14:13:00Z'
JANE=[{'principal':'user:jane','role':'ap_manager','auth_ref':'session:jane'}]
SECRET=b'DEMO-ONLY-managed-gate-secret-not-for-production'


class Live(ExampleState):
    def __init__(self,clock):
        self.clock=clock;self.observed=True;self.disposition='UNKNOWN';self.auth=True
        self.calls=[]
    def authenticated(self,principal,auth_ref):
        return self.auth and ((principal,auth_ref) in {
            ('user:jane','session:jane'),('user:owner','session:owner'),('svc:evaluation','session:evaluation')})
    def observe(self,test,manifest,execution):
        if self.observed is None:return None
        return make_observation(execution,manifest,test['test_id'],self.observed,self.clock[0],
                                source_version='demo-observation-1',evidence_ref='demo:retained-observation')
    def reconcile(self,manifest,execution):
        return make_reconciliation_evidence(execution,manifest,self.disposition,self.clock[0],
            final=self.disposition!='UNKNOWN',source='demo:transaction-service',source_version='terminal-v1',
            evidence_ref='demo:transaction-evidence',transaction_ref='demo:transaction-1')
    def executor(self,request,context):
        self.calls.append((copy.deepcopy(request),copy.deepcopy(context)))
        return {'accepted':True,'transaction_ref':'demo:transaction-1'}


def profile(policy=None,autonomous=False):
    p=copy.deepcopy(BASE);p['schema_version']='0.3.7';p['profile_version']='1.0.7'
    p['monitoring_policy_ref']=policy_ref(policy or POLICY)
    if autonomous:
        entry=next(a for a in p['permissions']['allowed'] if a['tool']=='email' and a['operation']=='draft_email')
        entry['default_mode']='execute_allowlisted'
        entry['max_mode']='execute_allowlisted'
        p['autonomy_policy']['max_mode']='execute_allowlisted'
    return sign_profile_ed25519(p,PRIVATE,'demo-profile-signing-2026')


def gate(store,clock=None,policy=None,**kwargs):
    clock=clock or [TP];state=Live(clock);pol=policy or POLICY
    g=ManagedGate(state,SECRET,runtime_store=store,feedback_policy=pol,tenant='ACME',environment='prod',
        clock=lambda:clock[0],trust_roots=ROOTS,restoration_principals=['user:owner'],
        approval_principals={'user:jane':['ap_manager']},
        signal_principals={'svc:evaluation':{'signals':['EVALUATION_REGRESSION','ADAPTER_MISMATCH'],
                           'profile_ids':[BASE['profile_id']]}},**kwargs)
    return g,state,clock


def proposal(g,clock,action_id='logical-action-1'):
    clock[0]=TP;r=copy.deepcopy(REQUEST);r['action_id']=action_id
    result=g.propose(BASE['profile_id'],r)
    return result


def approved(g,clock,action_id='logical-action-1'):
    result=proposal(g,clock,action_id);m=result['manifest'];clock[0]=TA
    return m,g.record_approval(m['manifest_id'],JANE)


def signal(p,code='EVALUATION_REGRESSION',signal_id='signal-1',at=TV):
    return {'signal_id':signal_id,'signal_code':code,'profile_id':p['profile_id'],
            'profile_digest':profile_digest(p),'tool':'email','operation':'draft_email',
            'observed_at':at,'evidence_ref':'demo:reviewed-evidence'}
