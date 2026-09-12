#!/usr/bin/env python3
"""Focused AAM v0.4.0 aggregate, context, campaign and delegation regressions."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

from aggregate import AggregateBudgetController, policy_ref, validate_policy
from audit import restore, snapshot
from check_containment import digest, profile_digest
from gate import MANIFEST_V, PROFILE_V, _load, schema_errors, sign_profile_ed25519
from managed_demo_support import BASE, POLICY, PRIVATE, PUBLIC, SECRET, Live
from feedback import policy_ref as feedback_policy_ref
from managed_gate import ManagedGate
from render_card import check_parity, coverage, project
from runtime_store import AuditUnavailable, InMemoryRuntimeStore
from v4 import V4ManagedGate

AGGREGATE = json.loads((ROOT / "examples/managed-runtime/aggregate-policy.json").read_text())
AUDIT_V = _load("audit-event.schema.json")
CONTEXT = {
    "context_id": "context:ap-demo",
    "context_version": "1",
    "context_digest": digest({
        "model_routes": ["provider:model-pinned"],
        "fallbacks": [],
        "instructions": "sha256:demo-instructions",
        "skills": "sha256:demo-skills",
        "memory_policy": "sha256:demo-memory",
        "orchestration": "sha256:demo-orchestration",
        "adapters": "sha256:demo-adapters",
    }),
}


class V4Live(Live):
    def authenticated(self, principal, auth_ref):
        return (principal, auth_ref) in {
            ("svc:caller-a", "session:caller-a"),
            ("svc:caller-b", "session:caller-b"),
            ("svc:context", "session:context"),
            ("svc:delegator", "session:delegator"),
            ("svc:campaign", "session:campaign"),
            ("user:owner", "session:owner"),
        }


def v4_profile(profile_id="aap:acme:invoice-triage-v4", *, child_ids=None, autonomous=True):
    profile = copy.deepcopy(BASE)
    profile.update(schema_version="0.4.0", profile_id=profile_id, profile_version="2.0.0")
    profile["monitoring_policy_ref"] = feedback_policy_ref(POLICY)
    profile["aggregate_execution_policy_ref"] = policy_ref(AGGREGATE)
    profile["execution_context_ref"] = copy.deepcopy(CONTEXT)
    profile["program_context"] = {
        "program_id": "program:invoice-review",
        "accountable_organization": "Synthetic Example Organization",
        "declared_purpose": "Draft bounded invoice-variance review messages for human review.",
        "owner_principal": "user:owner",
    }
    profile["delegation_policy"] = ({"mode": "attenuated", "max_depth": 2,
                                      "allowed_child_profile_ids": child_ids}
                                     if child_ids else {"mode": "forbidden"})
    profile["identity"]["agent_name"] = profile_id.rsplit(":", 1)[-1]
    if autonomous:
        entry = next(x for x in profile["permissions"]["allowed"]
                     if x["tool"] == "email" and x["operation"] == "draft_email")
        entry["default_mode"] = "execute_allowlisted"
        entry["max_mode"] = "execute_allowlisted"
        profile["autonomy_policy"]["max_mode"] = "execute_allowlisted"
    return sign_profile_ed25519(profile, PRIVATE, "demo-profile-signing-2026")


def context_attestation():
    return {**CONTEXT, "principal": "svc:context", "auth_ref": "session:context"}


def actor(principal="svc:caller-a"):
    return {"principal": principal, "auth_ref": "session:" + principal.split(":", 1)[1]}


def make_gate(policy=None):
    clock = ["2026-09-07T14:10:00Z"]
    state = V4Live(clock)
    aggregate = copy.deepcopy(policy or AGGREGATE)
    gate = V4ManagedGate(
        state, SECRET, runtime_store=InMemoryRuntimeStore(), feedback_policy=POLICY,
        aggregate_policy=aggregate, tenant="ACME", environment="prod", clock=lambda: clock[0],
        trust_roots={"demo-profile-signing-2026": {"method": "ed25519", "public_key": PUBLIC}},
        restoration_principals=["user:owner"],
        actor_groups={"svc:caller-a": "actor:ap-team", "svc:caller-b": "actor:ap-team"},
        context_principals={"svc:context": ["aap:acme:invoice-triage-v4", "aap:acme:parent", "aap:acme:child", "aap:acme:broad-child", "aap:acme:contract-child"]},
        delegation_principals={"svc:delegator": ["aap:acme:child", "aap:acme:broad-child", "aap:acme:contract-child"]},
        campaign_principals={"svc:campaign": {"indicators": ["VELOCITY_ANOMALY"],
                                                "profile_ids": ["aap:acme:invoice-triage-v4"]}},
    )
    gate.register_executor("email", "draft_email", state.executor, with_context=True)
    return gate, state, clock


def request(action_id, target="ap@northwind-supply.example"):
    body = copy.deepcopy(json.loads((ROOT / "examples/business-workflow-agent.invoice-triage/request.json").read_text()))
    body["action_id"] = action_id
    body["effect_target"]["identifier"] = target
    body["effect_target"]["display"] = target
    body["parameters"]["recipient"] = target
    return body


def propose(gate, profile_id, action_id, *, principal="svc:caller-a", target="ap@northwind-supply.example", delegation=None):
    return gate.propose(profile_id, request(action_id, target), actor=actor(principal),
                        context_attestation=context_attestation(), delegation_attestation=delegation)


class V4RegressionTests(unittest.TestCase):
    def setUp(self):
        self.gate, self.state, self.clock = make_gate()

    def tearDown(self):
        self.gate.close()

    def publish(self, profile=None):
        profile = profile or v4_profile()
        result = self.gate.publish_profile(profile)
        self.assertTrue(result["published"], result)
        return profile

    def test_01_policy_schema_and_semantics(self):
        self.assertEqual(validate_policy(AGGREGATE), [])
        AggregateBudgetController(AGGREGATE)
        bad = copy.deepcopy(AGGREGATE); bad["budgets"][0]["group_by"] = ["profile"]
        self.assertTrue(validate_policy(bad))

    def test_02_v4_profile_manifest_and_card_parity(self):
        profile = self.publish(); self.assertEqual(schema_errors(PROFILE_V, profile), [])
        result = propose(self.gate, profile["profile_id"], "action-1")
        self.assertEqual(result["decision"]["decision"], "ALLOW", result)
        manifest = result["manifest"]
        self.assertEqual(schema_errors(MANIFEST_V, manifest), [])
        self.assertTrue(coverage(manifest)["complete"], coverage(manifest))
        self.assertTrue(check_parity(project(manifest), manifest)["ok"])
        execution = self.gate.execute(manifest["manifest_id"])
        self.assertEqual(execution["decision"], "ALLOW", execution)
        audit_errors = [error for event in self.gate.runtime_store.events()
                        for error in schema_errors(AUDIT_V, event)]
        self.assertEqual(audit_errors, [])

    def test_03_context_mismatch_is_not_authority(self):
        profile = self.publish(); bad = context_attestation(); bad["context_digest"] = "sha256:" + "0" * 64
        result = self.gate.propose(profile["profile_id"], request("action-1"), actor=actor(), context_attestation=bad)
        self.assertEqual(result["decision"]["decision"], "DENY")
        self.assertNotIn("manifest", result)
        missing_actor = self.gate.propose(profile["profile_id"], request("action-2"), actor=None,
                                          context_attestation=context_attestation())
        self.assertEqual(missing_actor["decision"]["decision"], "DENY")

    def test_04_new_action_ids_share_the_same_budget(self):
        profile = self.publish()
        for number in (1, 2):
            proposed = propose(self.gate, profile["profile_id"], f"action-{number}")
            self.assertEqual(proposed["decision"]["decision"], "ALLOW", proposed)
            executed = self.gate.execute(proposed["manifest"]["manifest_id"])
            self.assertEqual(executed["execution_state"], "ACKNOWLEDGED", executed)
        blocked = propose(self.gate, profile["profile_id"], "action-3")
        self.assertEqual(blocked["decision"]["decision"], "DENY", blocked)
        self.assertEqual(len(self.state.calls), 2)

    def test_05_rotated_principal_in_same_actor_group_cannot_reset_budget(self):
        profile = self.publish()
        for number, principal in ((1, "svc:caller-a"), (2, "svc:caller-b")):
            proposed = propose(self.gate, profile["profile_id"], f"action-{number}", principal=principal)
            self.assertEqual(self.gate.execute(proposed["manifest"]["manifest_id"])["decision"], "ALLOW")
        self.assertEqual(propose(self.gate, profile["profile_id"], "action-3", principal="svc:caller-a")["decision"]["decision"], "DENY")

    def test_06_stale_manifest_cannot_escape_changed_aggregate_context(self):
        profile = self.publish()
        first = propose(self.gate, profile["profile_id"], "action-1")
        stale = propose(self.gate, profile["profile_id"], "action-2")
        self.gate.execute(first["manifest"]["manifest_id"])
        denied = self.gate.execute(stale["manifest"]["manifest_id"])
        self.assertEqual(denied["decision"], "DENY", denied)
        self.assertEqual(len(self.state.calls), 1)

    def test_07_unknown_execution_keeps_in_flight_budget(self):
        policy = copy.deepcopy(AGGREGATE)
        next(b for b in policy["budgets"] if b["measure"] == "in_flight")["limit"] = 1
        self.gate.close(); self.gate, self.state, self.clock = make_gate(policy)
        profile = v4_profile(); profile["aggregate_execution_policy_ref"] = policy_ref(policy)
        profile = sign_profile_ed25519({k: v for k, v in profile.items() if k != "integrity"}, PRIVATE, "demo-profile-signing-2026")
        self.publish(profile)
        self.gate.register_executor("email", "draft_email", lambda request, context: (_ for _ in ()).throw(TimeoutError()), with_context=True)
        proposed = propose(self.gate, profile["profile_id"], "action-1")
        execution = self.gate.execute(proposed["manifest"]["manifest_id"])
        self.assertEqual(execution["execution_state"], "EXECUTION_UNKNOWN")
        self.assertEqual(propose(self.gate, profile["profile_id"], "action-2")["decision"]["decision"], "DENY")

    def test_08_campaign_observations_only_restrict_and_restore_is_explicit(self):
        profile = self.publish()
        prior = propose(self.gate, profile["profile_id"], "action-before")
        for number in (1, 2):
            observation = {
                "observation_id": f"observation-{number}", "indicator": "VELOCITY_ANOMALY",
                "observed_at": self.clock[0], "profile_id": profile["profile_id"],
                "profile_digest": profile_digest(profile), "program_id": profile["program_context"]["program_id"],
                "actor_group_id": "actor:ap-team", "tool": "email", "operation": "draft_email",
                "context_digest": CONTEXT["context_digest"], "evidence_ref": f"demo:evidence:{number}",
            }
            accepted = self.gate.ingest_campaign_observation(observation, principal="svc:campaign", auth_ref="session:campaign")
            self.assertTrue(accepted["accepted"], accepted)
        self.assertEqual(propose(self.gate, profile["profile_id"], "action-after")["decision"]["decision"], "DENY")
        self.assertEqual(self.gate.execute(prior["manifest"]["manifest_id"])["decision"], "DENY")
        hold = next(h for h in self.gate.aggregate_snapshot()["campaign_holds"] if h["active"])
        restored = self.gate.restore_campaign_hold(hold["hold_id"], hold["revision"], principal="user:owner",
                                                   auth_ref="session:owner", reason="reviewed",
                                                   evidence_ref="demo:restoration")
        self.assertTrue(restored["restored"])

    def test_09_valid_delegation_is_attenuated_and_shares_root(self):
        child_id = "aap:acme:child"
        parent = v4_profile("aap:acme:parent", child_ids=[child_id])
        child = v4_profile(child_id)
        self.publish(parent); self.publish(child)
        parent_request = propose(self.gate, parent["profile_id"], "parent-action")
        parent_execution = self.gate.execute(parent_request["manifest"]["manifest_id"])
        self.assertEqual(parent_execution["decision"], "ALLOW", parent_execution)
        attestation = {
            "attestation_id": "delegation-1", "parent_manifest_id": parent_request["manifest"]["manifest_id"],
            "parent_profile_id": parent["profile_id"], "parent_action_id": "parent-action",
            "child_profile_id": child["profile_id"], "child_action_id": "child-action", "delegation_depth": 1,
            "child_profile_digest": profile_digest(child), "issued_at": self.clock[0],
            "expires_at": "2026-09-07T14:20:00Z", "principal": "svc:delegator", "auth_ref": "session:delegator",
        }
        result = propose(self.gate, child["profile_id"], "child-action", delegation=attestation)
        self.assertEqual(result["decision"]["decision"], "ALLOW", result)
        self.assertEqual(result["manifest"]["delegation"]["root_profile_id"], parent["profile_id"])
        self.assertEqual(result["manifest"]["delegation"]["depth"], 1)

    def test_10_broader_child_and_agent_supplied_delegation_are_rejected(self):
        child_id = "aap:acme:broad-child"
        parent = v4_profile("aap:acme:parent", child_ids=[child_id])
        child = v4_profile(child_id)
        child["authority_scope"]["systems"].append("unapproved-system")
        child = sign_profile_ed25519({k: v for k, v in child.items() if k != "integrity"}, PRIVATE, "demo-profile-signing-2026")
        self.publish(parent); self.publish(child)
        parent_request = propose(self.gate, parent["profile_id"], "parent-action")
        self.gate.execute(parent_request["manifest"]["manifest_id"])
        attestation = {
            "attestation_id": "delegation-broad", "parent_manifest_id": parent_request["manifest"]["manifest_id"],
            "parent_profile_id": parent["profile_id"], "parent_action_id": "parent-action",
            "child_profile_id": child["profile_id"], "child_action_id": "child-action", "delegation_depth": 1,
            "child_profile_digest": profile_digest(child), "issued_at": self.clock[0],
            "expires_at": "2026-09-07T14:20:00Z", "principal": "svc:delegator", "auth_ref": "session:delegator",
        }
        result = propose(self.gate, child["profile_id"], "child-action", delegation=attestation)
        self.assertEqual(result["decision"]["decision"], "DENY")
        forged = request("child-action"); forged["delegation"] = attestation
        denied = self.gate.propose(child["profile_id"], forged, actor=actor(), context_attestation=context_attestation())
        self.assertEqual(denied["decision"]["decision"], "DENY")

    def test_11_child_cannot_broaden_an_existing_operation_contract(self):
        child_id = "aap:acme:contract-child"
        parent = v4_profile("aap:acme:parent", child_ids=[child_id])
        child = v4_profile(child_id)
        operation = next(x for x in child["permissions"]["allowed"]
                         if x["tool"] == "email" and x["operation"] == "draft_email")
        operation["constraints"]["max_recipients"] = 2
        child = sign_profile_ed25519({k: v for k, v in child.items() if k != "integrity"}, PRIVATE,
                                     "demo-profile-signing-2026")
        self.publish(parent); self.publish(child)
        parent_request = propose(self.gate, parent["profile_id"], "parent-action")
        self.gate.execute(parent_request["manifest"]["manifest_id"])
        attestation = {
            "attestation_id": "delegation-contract", "parent_manifest_id": parent_request["manifest"]["manifest_id"],
            "parent_profile_id": parent["profile_id"], "parent_action_id": "parent-action",
            "child_profile_id": child["profile_id"], "child_action_id": "child-action", "delegation_depth": 1,
            "child_profile_digest": profile_digest(child), "issued_at": self.clock[0],
            "expires_at": "2026-09-07T14:20:00Z", "principal": "svc:delegator", "auth_ref": "session:delegator",
        }
        result = propose(self.gate, child["profile_id"], "child-action", delegation=attestation)
        self.assertEqual(result["decision"]["decision"], "DENY", result)

    def test_12_base_managed_gate_cannot_silently_accept_v4_profile(self):
        state = V4Live(["2026-09-07T14:10:00Z"])
        gate = ManagedGate(state, SECRET, runtime_store=InMemoryRuntimeStore(), feedback_policy=POLICY,
                           tenant="ACME", environment="prod",
                           trust_roots={"demo-profile-signing-2026": {"method": "ed25519", "public_key": PUBLIC}})
        try:
            result = gate.publish_profile(v4_profile())
            self.assertFalse(result["published"], result)
            legacy = snapshot(gate)
            for key in ("_aggregate_state", "_campaign_observations", "_campaign_holds"):
                legacy.pop(key)
            restore(gate, legacy)
            self.assertEqual(gate._aggregate_state, {"reservations": {}})
        finally:
            gate.close()

    def test_13_v4_requires_state_migration_for_a_legacy_snapshot(self):
        legacy = snapshot(self.gate)
        for key in ("_aggregate_state", "_campaign_observations", "_campaign_holds"):
            legacy.pop(key)
        with self.assertRaises(AuditUnavailable):
            restore(self.gate, legacy)

    def test_14_egress_budget_measures_canonical_value_not_client_cost(self):
        policy = copy.deepcopy(AGGREGATE)
        policy["budgets"].append({
            "budget_id": "program-subject-bytes", "selector": {"tool": "email", "operation": "draft_email"},
            "measure": "egress_bytes", "window": {"kind": "rolling", "seconds": 3600},
            "limit": 10000, "group_by": ["program"], "on_exhaustion": "DENY",
            "parameter": "subject_line", "maximum_per_action": 1000,
        })
        self.gate.close(); self.gate, self.state, self.clock = make_gate(policy)
        profile = v4_profile(); profile["aggregate_execution_policy_ref"] = policy_ref(policy)
        profile = sign_profile_ed25519({k: v for k, v in profile.items() if k != "integrity"}, PRIVATE,
                                       "demo-profile-signing-2026")
        self.publish(profile)
        proposed = propose(self.gate, profile["profile_id"], "action-egress")
        self.assertEqual(proposed["decision"]["decision"], "ALLOW", proposed)
        claim = next(x for x in proposed["manifest"]["aggregate_execution"]["claims"]
                     if x["budget_id"] == "program-subject-bytes")
        value = proposed["manifest"]["action_target"]["parameters"]["subject_line"]
        expected = len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                  allow_nan=False).encode("utf-8"))
        self.assertEqual(claim["amount"], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
