#!/usr/bin/env python3
"""Reproduce five boundary failures against an EXTERNAL, unmodified v0.3.4 appendix.

Usage: python tests/reproduce_v034_findings.py /path/to/v0.3.4/repo/appendix
This is an audit helper, not part of the v0.3.6 passing-regression suite. It imports
only the specified v0.3.4 reference and uses synthetic executors; no network calls.
"""
import copy
import json
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit(__doc__)
ROOT = Path(sys.argv[1]).resolve()
if (ROOT.parent / 'VERSION').read_text().strip() != '0.3.4':
    raise SystemExit('Supply the appendix directory of an unmodified v0.3.4 pack.')
sys.path.insert(0, str(ROOT / 'tools'))
from gate import Gate, InMemoryProfileStore, StateProvider, sign_profile_ed25519

P = json.loads((ROOT/'examples/business-workflow-agent.invoice-triage/profile.json').read_text())
R = json.loads((ROOT/'examples/business-workflow-agent.invoice-triage/request.json').read_text())
PUB = bytes.fromhex((ROOT/'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
PRIV = bytes.fromhex((ROOT/'examples/trust/demo-profile-signing.key.hex').read_text().strip())
KEY_ID = 'demo-profile-signing-2026'
JANE = [{'role': 'ap_manager', 'principal': 'user:jane', 'auth_ref': 'sso:jane'}]

class Live(StateProvider):
    def kill_switch_allows(self, *args): return True
    def credential_valid(self, *args): return True
    def effect_target_in_class(self, *args): return True
    def evaluate_rule(self, *args): return True
    def evaluate_selector(self, *args): return True
    def evaluate_threshold(self, *args): return True
    def egress_policy_permits(self, *args): return True
    def authenticated(self, *args): return True
    def observe(self, *args): return None


def fresh(profile=None):
    g = Gate(Live(), InMemoryProfileStore(), b'k', trust_roots={KEY_ID: {'method': 'ed25519', 'public_key': PUB}})
    assert g.publish_profile(profile or P)['published']
    g.register_executor('email', 'draft_email', lambda request: {'ack': True})
    return g


def dispatch(g):
    m = g.propose(P['profile_id'], R, '2026-09-05T14:10:00Z')['manifest']
    a = g.record_approval(m['manifest_id'], JANE, '2026-09-05T14:13:00Z')
    e = g.execute(m['manifest_id'], a['approval_id'], '2026-09-05T14:14:00Z')
    return m, e

reproduced=[]
g=fresh();m,e=dispatch(g);g.register_verifier('v',b'v')
proofs=[g.attest('v',t['assertion'],True,'2026-09-05T14:15:00Z') for t in m['outcome_verification']['verification_tests']]
_,e2=dispatch(g)
reproduced.append(('cross-execution replay accepted',g.verify_outcome(e2['execution_id'],'2026-09-05T14:15:00Z',proofs)['verified']))
future=[g.attest('v',t['assertion'],True,'2026-09-05T15:00:00Z') for t in m['outcome_verification']['verification_tests']]
reproduced.append(('future-dated proof accepted',g.verify_outcome(e['execution_id'],'2026-09-05T14:15:00Z',future)['verified']))
g=fresh();effects=[]
def timeout(request):effects.append(request);raise TimeoutError('effect committed before response failed')
g.register_executor('email','draft_email',timeout);_,e=dispatch(g)
reproduced.append(('committed side effect mislabeled DENY',e['decision']=='DENY' and len(effects)==1))
p=copy.deepcopy(P)
next(x for x in p['permissions']['allowed'] if x['operation']=='draft_email')['verification']['completion_rule']='designated_postconditions_verified'
p=sign_profile_ed25519(p,PRIV,KEY_ID)
g=fresh(p)
reproduced.append(('designated completion accepted without any designation mechanism',g.publish_profile(p)['published']))
g=fresh()
def unavailable(*args):raise RuntimeError('credential service down')
g.state.credential_valid=unavailable
try:
    dispatch(g)
    escaped=False
except RuntimeError:
    escaped=True
reproduced.append(('credential-provider exception escapes the decision model',escaped))
for name,found in reproduced:print(('REPRODUCED ' if found else 'NOT REPRODUCED ')+name)
print(f'\n{sum(found for _,found in reproduced)}/{len(reproduced)} baseline findings reproduced')
sys.exit(0 if all(found for _,found in reproduced) else 1)
