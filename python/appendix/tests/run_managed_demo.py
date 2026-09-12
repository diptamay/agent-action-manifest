#!/usr/bin/env python3
"""Reproducible synthetic AP audit -> signal -> restricted review -> restoration demo.

No external service is contacted and no email is sent. Database files are temporary;
only safe example projections are emitted. Bundled keys are PUBLIC DEMO MATERIAL.
"""
import argparse
import json
import tempfile
from pathlib import Path
from managed_demo_support import *
from runtime_store import SQLiteRuntimeStore
from audit_export import SQLiteAuditReceiver
from audit_review import review_cases
from render_card import project,render_text
from aam import readback,resolved_feedback


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,default=ROOT/'examples/managed-runtime/generated');a=ap.parse_args()
    a.out.mkdir(parents=True,exist_ok=True)
    def save(name,value): (a.out/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
    with tempfile.TemporaryDirectory() as folder:
        store=SQLiteRuntimeStore(Path(folder)/'runtime.db');g,live,clock=gate(store)
        p=profile(autonomous=True);trace=[]
        try:
            trace.append(g.publish_profile(p))
            trace.append(g.register_executor('email','draft_email',live.executor,with_context=True))
            initial=proposal(g,clock,'demo-initial');m=initial['manifest']
            clock[0]=TE;execution=g.execute(m['manifest_id']);trace.append(execution)
            clock[0]=TV;trace.append(g.verify_outcome(execution['execution_id']))
            # Authenticated evaluation evidence can tighten, never broaden the published Profile.
            result=g.ingest_signal(signal(p),principal='svc:evaluation',auth_ref='session:evaluation');trace.append(result)
            clock[0]='2026-09-07T14:13:10Z';req=copy.deepcopy(REQUEST);req['action_id']='demo-after-regression'
            proposed=g.propose(p['profile_id'],req);restricted=proposed['manifest']
            blocked=g.execute(restricted['manifest_id']);trace.append(blocked)
            approval=g.record_approval(restricted['manifest_id'],JANE);trace.append(approval)
            clock[0]='2026-09-07T14:13:20Z';execution2=g.execute(restricted['manifest_id'],approval['approval_id']);trace.append(execution2)
            clock[0]='2026-09-07T14:13:30Z';trace.append(g.verify_outcome(execution2['execution_id']))
            save('restricted-control-snapshot.json',g.control_snapshot())
            hold=next(r for r in g.restrictions() if r['active'])
            trace.append(g.restore_restriction(hold['restriction_id'],hold['revision'],principal='user:owner',
              auth_ref='session:owner',reason='Synthetic owner reviewed evaluator result and corrective test evidence',evidence_ref='demo:review-case-approved'))
            assert restricted['operational_context']['mode']=='REQUIRE_APPROVAL'
            assert blocked['decision']!='ALLOW'
            assert len(live.calls)==2
            assert not any(r['active'] for r in g.restrictions())
            receiver=SQLiteAuditReceiver(Path(folder)/'receiver.db')
            try:trace.append(g.export_audit(receiver))
            finally:receiver.close()
            save('managed-profile.json',p);save('managed-manifest.json',restricted);save('managed-card.json',project(restricted))
            save('demo-results.json',{'synthetic':True,'trace':trace,'adapter_calls':len(live.calls),
                  'assertions':'review required after authenticated signal; approval permits allowed draft only; manual restoration; no execution replay'})
            save('audit-events.json',store.events());save('review-cases.json',review_cases(store.events()))
            save('restored-control-snapshot.json',g.control_snapshot())
            (a.out/'managed-card.md').write_text(render_text(restricted)+'\n')
            (a.out/'managed-readback.md').write_text(readback(p)+'\n\n'+resolved_feedback(p,str(ROOT/'examples/managed-runtime/feedback-policy.json'))+'\n')
            (a.out/'metrics.prom').write_text(g.metrics_text())
            print(json.dumps({'passed':True,'synthetic_adapter_calls':len(live.calls),'audit_events':store.event_count(),'output':str(a.out)},indent=2))
        finally:g.close()

if __name__=='__main__':main()
