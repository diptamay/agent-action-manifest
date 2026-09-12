"""Deterministic protective responses. Never rewrites a Profile or issues approval.

Only typed, gate-owned events and authenticated administrative signals are input.
Historical success never increases authority. Holds compose; restoration is an
independent authenticated command with an expected revision and evidence reference.
"""
from __future__ import annotations
import copy
import json
import uuid
from datetime import timedelta
from check_containment import digest, parse_time
from jsonschema import Draft202012Validator
from validation_support import strict_format_checker
from pathlib import Path

SIGNALS = ('EXECUTION_UNKNOWN','EVIDENCE_CONFLICT','VERIFICATION_FAILED',
           'EVALUATION_REGRESSION','ADAPTER_MISMATCH','OVERDUE_EXECUTION','OVERDUE_VERIFICATION')
MODES = {'NORMAL': 0, 'REQUIRE_APPROVAL': 1, 'SUSPENDED': 2}


def policy_ref(policy):
    return {'policy_id':policy['policy_id'], 'policy_version':policy['policy_version'],
            'policy_digest':digest(policy)}


def scope_key(profile_id, tool='*', operation='*', action_id='*'):
    return json.dumps([profile_id,tool,operation,action_id],separators=(',',':'))


def empty_control():
    return {'restrictions':{},'epochs':{},'seen_signals':{},'windows':{},
            'transitions':{},'external_signals':{},'watchdog_seen':{},'last_processed_at':None}


class FeedbackController:
    def __init__(self, policy):
        schema = json.loads((Path(__file__).resolve().parents[1]/'schemas/feedback-policy.schema.json').read_text())
        Draft202012Validator(schema,format_checker=strict_format_checker()).validate(policy)
        ids = [r['rule_id'] for r in policy['rules']]
        if len(ids) != len(set(ids)):
            raise ValueError('duplicate feedback rule id')
        self._policy = copy.deepcopy(policy)
        self.reference = policy_ref(policy)

    @property
    def policy(self):
        return copy.deepcopy(self._policy)

    def context(self, control, profile_id, tool, operation, action_id):
        keys = [scope_key(profile_id),scope_key(profile_id,tool,operation),
                scope_key(profile_id,tool,operation,action_id)]
        active = sorted((r for r in control['restrictions'].values()
                         if r['active'] and r['scope_key'] in keys),key=lambda r:r['restriction_id'])
        mode = max((r['mode'] for r in active),key=lambda m:MODES[m],default='NORMAL')
        return {**self.reference,'mode':mode,
                'control_revision':digest({k:control['epochs'].get(k,0) for k in keys}),
                'restrictions':[{'restriction_id':r['restriction_id'],'revision':r['revision'],
                                 'rule_id':r['rule_id'],'signal_code':r['signal_code'],'mode':r['mode']}
                                for r in active]}

    def process(self, control, events, at):
        """Runs within the SAME local transaction as the triggering lifecycle event."""
        now = parse_time(at)
        for event in events:
            code = event.get('signal_code')
            if code not in SIGNALS:
                continue
            event_id = event['event_id']
            if event_id in control['seen_signals']:
                continue
            control['seen_signals'][event_id] = event['record_digest']
            scope = event['scope']
            if not scope.get('profile_id'):
                continue
            for rule in self._policy['rules']:
                if rule['signal'] != code:
                    continue
                tool, operation = scope.get('tool'),scope.get('operation')
                if not tool or not operation:
                    continue
                action_id = event.get('action_id') or '*'
                key = (scope_key(scope['profile_id']) if rule['scope']=='profile' else
                       scope_key(scope['profile_id'],tool,operation,action_id if rule['scope']=='action' else '*'))
                window_key = rule['rule_id']+'|'+key
                window = control['windows'].get(window_key,[])
                floor = now-timedelta(seconds=rule['window_seconds'])
                window = [x for x in window if parse_time(x['recorded_at']) >= floor]
                # Re-verifying the same failed execution does not manufacture independent incidents.
                incident_id = event.get('execution_id') or event['record_ref']
                if not any(x['incident_id']==incident_id for x in window):
                    window.append({'event_id':event_id,'recorded_at':at,'incident_id':incident_id})
                control['windows'][window_key] = window
                if len(window) < rule['threshold']:
                    continue
                if any(r['active'] and r['rule_id']==rule['rule_id'] and r['scope_key']==key
                       for r in control['restrictions'].values()):
                    continue
                rid = 'hold:'+uuid.uuid4().hex
                restriction = {'restriction_id':rid,'revision':1,'active':True,
                               'scope_key':key,'profile_id':scope['profile_id'],
                               'rule_id':rule['rule_id'],'policy_ref':copy.deepcopy(self.reference),
                               'signal_code':code,'mode':rule['mode'],'created_at':at,
                               'trigger_event_ids':[x['event_id'] for x in window],
                               'execution_ids':sorted({event['execution_id']} if event.get('execution_id') else set()),
                               'restoration':'authenticated_manual','restored_at':None}
                control['restrictions'][rid]=restriction
                control['epochs'][key]=control['epochs'].get(key,0)+1
                tid='control:'+uuid.uuid4().hex
                control['transitions'][tid]={'transition_id':tid,'restriction_id':rid,
                    'operation':'activate','at':at,'actor':'gate:feedback-controller',
                    'profile_id':scope['profile_id'],'scope_key':key,'rule_id':rule['rule_id'],
                    'from_revision':0,'to_revision':1,'mode':rule['mode'],
                    'trigger_event_ids':restriction['trigger_event_ids']}
            control['last_processed_at']=at

    def restore(self, control, restriction_id, expected_revision, principal, reason, evidence_ref, at):
        """Authentication/ACL and outstanding execution checks are performed by ManagedGate."""
        r=control['restrictions'].get(restriction_id)
        if r is None or not r['active'] or type(expected_revision) is not int or r['revision']!=expected_revision:
            return {'restored':False,'reason_code':'RESTRICTION_REVISION_MISMATCH'}
        r.update(active=False,revision=r['revision']+1,restored_at=at)
        key=r['scope_key'];control['epochs'][key]=control['epochs'].get(key,0)+1
        # A fresh independent incident after restoration must be able to trip the rule again.
        control['windows'].pop(r['rule_id']+'|'+key,None)
        tid='control:'+uuid.uuid4().hex
        control['transitions'][tid]={'transition_id':tid,'restriction_id':restriction_id,
            'operation':'restore','at':at,'actor':principal,'profile_id':r['profile_id'],
            'scope_key':key,'rule_id':r['rule_id'],'from_revision':expected_revision,
            'to_revision':r['revision'],'mode':r['mode'],'reason':reason,'evidence_ref':evidence_ref}
        return {'restored':True,'restriction_id':restriction_id,'revision':r['revision'],
                'reason_code':'RESTORATION_RECORDED','transition_id':tid}
