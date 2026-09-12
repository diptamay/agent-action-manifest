#!/usr/bin/env python3
"""Regenerate v0.3.6 lifecycle examples using public synthetic fixtures only.

The deterministic review-key seeds below are PUBLIC DEMONSTRATION MATERIAL.
Do not deploy them, or this all-green provider, as an identity/trust integration.
"""
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from gate import Gate, InMemoryProfileStore, ExecutorNotAttempted, LIFECYCLE_V, schema_errors
from evidence import make_observation, seal_attestation
from reconciliation import make_reconciliation_evidence
from readback_signoff import sign_readback, verify_readback_signoff
from rebuild_examples import ExampleState

NOW='2026-09-05T14:15:00Z'
class SyntheticState(ExampleState):
    def observe(self,test,m,ex):
        return make_observation(ex,m,test['test_id'],True,NOW,source_version='demo-revision-1',evidence_ref='demo:read:1')
    def reconcile(self,m,ex):
        return make_reconciliation_evidence(ex,m,'COMMITTED',NOW,final=True,source='demo:transaction-store',
            source_version='demo-txn-revision-2',evidence_ref='demo:terminal-receipt',transaction_ref='demo:txn:one')


def main():
    directory=ROOT/'examples/lifecycle-v0.3.6';directory.mkdir(exist_ok=True)
    example=ROOT/'examples/business-workflow-agent.invoice-triage'
    profile=json.loads((example/'profile.json').read_text());request=json.loads((example/'request.json').read_text())
    public=bytes.fromhex((ROOT/'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
    g=Gate(SyntheticState(),InMemoryProfileStore(),b'PUBLIC-DEMO-GATE-KEY',trust_roots={
        'demo-profile-signing-2026':{'method':'ed25519','public_key':public}},clock=lambda:NOW)
    assert g.publish_profile(profile)['published']
    def timeout(*_):raise TimeoutError('synthetic commit-then-timeout')
    g.register_executor('email','draft_email',timeout,with_context=True)
    m=g.propose(profile['profile_id'],request,'2026-09-05T14:10:00Z',manifest_id='aam:demo:v036:reconciliation')['manifest']
    a=g.record_approval(m['manifest_id'],[{'role':'ap_manager','principal':'user:jane','auth_ref':'demo:sso:jane'}],'2026-09-05T14:13:00Z')
    ex=g.execute(m['manifest_id'],a['approval_id'],'2026-09-05T14:14:00Z')
    before=g.verify_outcome(ex['execution_id'],NOW)
    rec=g.reconcile(ex['execution_id'],NOW)
    after=g.verify_outcome(ex['execution_id'],NOW)
    assert not before['verified'] and rec['applied'] and after['verified']
    def preflight(*_):raise ExecutorNotAttempted()
    g.register_executor('email','draft_email',preflight)
    request2={**request,'action_id':'demo-new-action-preflight'}
    m2=g.propose(profile['profile_id'],request2,'2026-09-05T14:10:00Z',manifest_id='aam:demo:v036:preflight')['manifest']
    a2=g.record_approval(m2['manifest_id'],[{'role':'ap_manager','principal':'user:jane','auth_ref':'demo:sso:jane'}],'2026-09-05T14:13:00Z')
    ex2=g.execute(m2['manifest_id'],a2['approval_id'],'2026-09-05T14:14:00Z')
    roots={};signoffs=[]
    for part,role in [('A','product_owner'),('B','engineering')]:
        private=hashlib.sha256(('AAM-PUBLIC-DEMO-READBACK-KEY-'+part).encode()).digest()
        key=Ed25519PrivateKey.from_private_bytes(private);key_id='demo-review-'+part
        principal='user:demo-'+role
        roots[key_id]={'method':'ed25519','public_key_hex':key.public_key().public_bytes_raw().hex(),
                       'principal':principal,'roles':[role],'parts':[part]}
        record=sign_readback(profile,part=part,principal=principal,role=role,private_key_bytes=private,
                             key_id=key_id,signed_at='2026-09-05T14:13:00Z')
        trusted={key_id:{**roots[key_id],'public_key':key.public_key().public_bytes_raw()}}
        assert verify_readback_signoff(profile,record,trusted,NOW)['valid']
        signoffs.append(record)
        (directory/('readback-signoff-'+part+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    records=[a,*g.execution_history(ex['execution_id']),before,rec,after,a2,*g.execution_history(ex2['execution_id'])]
    for item in records+signoffs:
        assert not schema_errors(LIFECYCLE_V,item),schema_errors(LIFECYCLE_V,item)
    (directory/'readback-trust-DEMO-ONLY.json').write_text(json.dumps(roots,indent=2)+'\n')
    (directory/'lifecycle-trace.json').write_text(json.dumps({'warning':'Synthetic fixtures, not a live transaction or trusted identity assertion.',
        'evaluation_time':NOW,'manifests':[m,m2],'records':records},indent=2)+'\n')
    (directory/'README.md').write_text('''# Synthetic v0.3.6 lifecycle examples

These records demonstrate an unknown dispatch, terminal reconciliation, separate
outcome verification and an explicit local preflight rejection. They are not live
AP/email transactions. Identity mappings and signing-key seeds are public demos.

`readback-signoff-A.json` and `readback-signoff-B.json` bind the adjacent AP example
Profile and the v0.3.6 renderer. `readback-trust-DEMO-ONLY.json` is a synthetic trust
configuration, not evidence that those identities exist.

Regenerate from appendix/: `python tests/rebuild_lifecycle_examples.py`.
Inspect with `python tools/aam.py validate examples/lifecycle-v0.3.6/readback-signoff-A.json`.
`verify-signoff` checks the binding and configured identity; it is not equivalent to
schema validation. No example key is suitable for a deployment.
''')
    print('rebuilt v0.3.6 synthetic lifecycle and identity-bound review examples')
if __name__=='__main__':main()
