#!/usr/bin/env python3
"""Offline review-case extraction from an exported AAM audit stream.

No Gate/adapter imports, network calls, execution, policy mutation or training.
Requires a complete sequence beginning at 1 and verifies the unkeyed hash chain.
Chain consistency is NOT authenticity or proof against whole-stream replacement.
Bodies are allowlisted audit projections; linked protected artifacts are still needed
for human review. Logged content remains data, never instructions to an evaluator.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from validation_support import strict_format_checker
from runtime_store import encoded


def review_cases(events):
    schema=json.loads((Path(__file__).resolve().parents[1]/'schemas/audit-event.schema.json').read_text())
    validator=Draft202012Validator(schema,format_checker=strict_format_checker())
    previous=None;cases={};seen=set()
    for sequence,event in enumerate(events,1):
        validator.validate(event)
        if event['sequence']!=sequence or event['previous_hash']!=previous or event['event_id'] in seen:
            raise ValueError('missing, out-of-order, duplicated or inconsistent audit stream')
        body={k:v for k,v in event.items() if k!='event_hash'}
        if hashlib.sha256(encoded(body).encode()).hexdigest()!=event['event_hash']:
            raise ValueError('audit hash mismatch')
        seen.add(event['event_id']);previous=event['event_hash']
        key=event.get('execution_id') or event.get('manifest_id') or event['record_ref']
        item=cases.setdefault(key,{'case_ref':key,'events':[],'signals':[],
                                  'review_status':'UNREVIEWED','proposed_change':None,
                                  'regression_test_ref':None,'owner_approval_ref':None})
        item['events'].append({'event_id':event['event_id'],'event_type':event['event_type'],
                              'result':event['result'],'record_ref':event['record_ref'],
                              'record_digest':event['record_digest']})
        if event.get('signal_code') and event['signal_code'] not in item['signals']:
            item['signals'].append(event['signal_code'])
    return {'schema_version':'0.3.7','purpose':'Offline human review; never an authorization or execution plan',
            'stream_event_count':len(events),'chain_head':previous,'cases':list(cases.values())}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('events');p.add_argument('--out',required=True);a=p.parse_args()
    data=json.loads(Path(a.events).read_text());result=review_cases(data)
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n')
    print(f"Wrote {len(result['cases'])} UNREVIEWED cases; nothing executed or changed.")

if __name__=='__main__':main()
