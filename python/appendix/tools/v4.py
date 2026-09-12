"""AAM v0.4.0 managed gate extensions.

V4ManagedGate adds domain-neutral aggregate budgets, pinned execution-context
attestations, attenuated delegation, and restrictive campaign observations. Agents
still submit Action Requests, never authority. All new context is supplied and
authenticated by the trusted host service.
"""
from __future__ import annotations

import copy
import json
import threading
import uuid
from datetime import timedelta

from aggregate import AggregateBudgetController, empty_state
from check_containment import canonical, digest, parse_time, profile_digest, Malformed
from gate import DependencyUnavailable
from managed_gate import ManagedGate, guarded

MODE_RANK = {"recommend": 0, "request_approval": 1, "execute_allowlisted": 2, "conditional_autonomy": 3}
SEVERITY_RANK = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


class V4ManagedGate(ManagedGate):
    """Trusted v0.4.0 API. Transport authentication remains a host responsibility."""

    _managed_profile_versions = ("0.4.0",)

    def __init__(self, state, secret, *, aggregate_policy, actor_groups,
                 context_principals, delegation_principals=None,
                 campaign_principals=None, **kwargs):
        self._aggregate = AggregateBudgetController(aggregate_policy)
        self._actor_groups = copy.deepcopy(actor_groups)
        self._context_principals = copy.deepcopy(context_principals)
        self._delegation_principals = copy.deepcopy(delegation_principals or {})
        self._campaign_principals = copy.deepcopy(campaign_principals or {})
        self._proposal_local = threading.local()
        for principal, group in self._actor_groups.items():
            if not isinstance(principal, str) or not principal or not isinstance(group, str) or not group:
                raise ValueError("actor_groups must map non-empty principals to non-empty accountable actor groups")
        for mapping, label in ((self._context_principals, "context"),
                               (self._delegation_principals, "delegation")):
            for principal, profiles in mapping.items():
                if not isinstance(principal, str) or not principal or not isinstance(profiles, list) or any(not isinstance(p, str) or not p for p in profiles):
                    raise ValueError(f"invalid {label} principal ACL")
        for principal, acl in self._campaign_principals.items():
            if (not isinstance(principal, str) or not principal or not isinstance(acl, dict)
                or set(acl) != {"indicators", "profile_ids"}
                or not isinstance(acl["indicators"], list) or not acl["indicators"]
                or not isinstance(acl["profile_ids"], list) or not acl["profile_ids"]):
                raise ValueError("invalid campaign principal ACL")
        self._v4_binding = {
            "aggregate_policy": self._aggregate.reference,
            "actor_groups": self._actor_groups,
            "context_principals": self._context_principals,
            "delegation_principals": self._delegation_principals,
            "campaign_principals": self._campaign_principals,
        }
        kwargs.setdefault("gate_id", "managed-gate/0.4.0")
        super().__init__(state, secret, **kwargs)
        if not self._aggregate_state:
            self._aggregate_state = empty_state()

    @guarded
    def publish_profile(self, profile, *, readback_signoffs=None):
        reasons = []
        if not isinstance(profile, dict) or profile.get("schema_version") != "0.4.0":
            reasons.append("V4ManagedGate requires a v0.4.0 Profile")
        elif profile.get("aggregate_execution_policy_ref") != self._aggregate.reference:
            reasons.append("Profile aggregate policy reference does not match the configured policy")
        elif profile.get("delegation_policy", {}).get("mode") == "attenuated" and not any(
            "delegation_root" in b["group_by"] for b in self._aggregate.policy["budgets"]
        ):
            reasons.append("delegation requires at least one shared delegation_root budget")
        if reasons:
            self._admin_record("PROFILE_PUBLICATION_REJECTED", profile.get("profile_id") if isinstance(profile, dict) else None)
            return {"published": False, "reasons": reasons}
        return super().publish_profile(profile, readback_signoffs=readback_signoffs)

    def _authenticated(self, principal, auth_ref):
        if not isinstance(principal, str) or not principal or not isinstance(auth_ref, str) or not auth_ref:
            raise DependencyUnavailable("authenticated host principal is required")
        if self._require_state_bool("authenticated", principal, auth_ref) is not True:
            raise DependencyUnavailable("host principal authentication failed")

    def _validate_context(self, profile, attestation):
        fields = {"context_id", "context_version", "context_digest", "principal", "auth_ref"}
        if not isinstance(attestation, dict) or set(attestation) != fields:
            raise ValueError("exact execution-context attestation is required")
        principal = attestation["principal"]
        if profile["profile_id"] not in self._context_principals.get(principal, []):
            raise ValueError("execution-context attestor is not authorized for this Profile")
        self._authenticated(principal, attestation["auth_ref"])
        expected = profile["execution_context_ref"]
        actual = {k: attestation[k] for k in ("context_id", "context_version", "context_digest")}
        if actual != expected:
            raise ValueError("execution context differs from the reviewed Profile")
        return {**actual, "attested_by": principal}

    @staticmethod
    def _attenuation_errors(parent, child):
        errors = []
        ps, cs = parent["authority_scope"], child["authority_scope"]
        if ps.get("tenant") != cs.get("tenant") or ps["environment"] != cs["environment"]:
            errors.append("child tenant/environment differs from parent")
        if not set(cs["systems"]) <= set(ps["systems"]):
            errors.append("child systems are not a subset of parent systems")
        if cs.get("selector") != ps.get("selector"):
            errors.append("reference attenuation requires the child scope selector to equal the parent selector")
        p_targets = {canonical(x) for x in ps["targets"]}
        if not {canonical(x) for x in cs["targets"]} <= p_targets:
            errors.append("child authority targets are not an exact structural subset of parent targets")
        parent_ops = {(x["tool"], x["operation"]): canonical(x) for x in parent["permissions"]["allowed"]}
        child_ops = {(x["tool"], x["operation"]): canonical(x) for x in child["permissions"]["allowed"]}
        if not set(child_ops) <= set(parent_ops):
            errors.append("child operations are not a subset of parent operations")
        elif any(value != parent_ops[key] for key, value in child_ops.items()):
            errors.append("child operation contracts differ from the reviewed parent contracts")
        if MODE_RANK[child["autonomy_policy"]["max_mode"]] > MODE_RANK[parent["autonomy_policy"]["max_mode"]]:
            errors.append("child autonomy exceeds parent autonomy")
        if MODE_RANK[child["autonomy_policy"]["default_mode"]] > MODE_RANK[parent["autonomy_policy"]["default_mode"]]:
            errors.append("child default autonomy exceeds parent default autonomy")
        if not {canonical(x) for x in child["autonomy_policy"].get("thresholds", [])} <= {
            canonical(x) for x in parent["autonomy_policy"].get("thresholds", [])
        }:
            errors.append("child autonomy thresholds are not an exact structural subset of parent thresholds")
        if not set(parent["autonomy_policy"].get("downgrade_on", [])) <= set(child["autonomy_policy"].get("downgrade_on", [])):
            errors.append("child drops a parent autonomy downgrade trigger")
        if cs["max_execution_authority_seconds"] > ps["max_execution_authority_seconds"] or cs["max_review_window_minutes"] > ps["max_review_window_minutes"]:
            errors.append("child authority or review lifetime exceeds parent")
        pi, ci = parent["impact_envelope"], child["impact_envelope"]
        if SEVERITY_RANK[ci["max_severity"]] > SEVERITY_RANK[pi["max_severity"]] or ci["max_affected_objects"] > pi["max_affected_objects"]:
            errors.append("child impact envelope exceeds parent")
        if not set(ci["allowed_domains"]) <= set(pi["allowed_domains"]):
            errors.append("child impact domains exceed parent domains")
        if ci["irreversible_allowed"] and not pi["irreversible_allowed"]:
            errors.append("child permits irreversible impact that the parent forbids")
        p_never = {canonical(x) for x in parent["permissions"]["prohibited"]}
        c_never = {canonical(x) for x in child["permissions"]["prohibited"]}
        if not p_never <= c_never:
            errors.append("child drops a parent prohibition")
        if child["aggregate_execution_policy_ref"] != parent["aggregate_execution_policy_ref"]:
            errors.append("child does not share the parent's aggregate policy")
        for field in ("program_context", "execution_context_ref", "monitoring_policy_ref",
                      "approval_policy", "input_trust", "data_boundary", "audit_policy",
                      "recovery_policy", "emergency_disable", "conformance"):
            if canonical(child[field]) != canonical(parent[field]):
                errors.append(f"child {field} differs from the parent reviewed boundary")
        pc, cc = parent["credentials_policy"], child["credentials_policy"]
        if (not set(cc["privileges"]) <= set(pc["privileges"])
            or cc["max_ttl_minutes"] > pc["max_ttl_minutes"]
            or (pc["fail_closed_on_expiry"] and not cc["fail_closed_on_expiry"])):
            errors.append("child credential authority exceeds parent credentials")
        return errors

    def _validate_delegation(self, profile, request, attestation, now):
        if attestation is None:
            return {"mode": "root", "root_profile_id": profile["profile_id"], "depth": 0}
        fields = {"attestation_id", "parent_manifest_id", "parent_profile_id", "parent_action_id",
                  "child_profile_id", "child_action_id", "delegation_depth", "child_profile_digest",
                  "issued_at", "expires_at", "principal", "auth_ref"}
        if not isinstance(attestation, dict) or set(attestation) != fields:
            raise ValueError("delegation attestation has an invalid shape")
        principal = attestation["principal"]
        if profile["profile_id"] not in self._delegation_principals.get(principal, []):
            raise ValueError("delegation attestor is not authorized for this child Profile")
        self._authenticated(principal, attestation["auth_ref"])
        if attestation["child_profile_id"] != profile["profile_id"] or attestation["child_profile_digest"] != profile_digest(profile):
            raise ValueError("delegation is not bound to this child Profile")
        if not request.get("action_id") or attestation["child_action_id"] != request["action_id"]:
            raise ValueError("delegation must bind the exact child action_id")
        instant = parse_time(now)
        if not (parse_time(attestation["issued_at"]) <= instant < parse_time(attestation["expires_at"])):
            raise ValueError("delegation attestation is not currently valid")
        with self._lock:
            parent_manifest = copy.deepcopy(self._manifests.get(attestation["parent_manifest_id"]))
            parent_execution_id = self._dispatches.get(attestation["parent_manifest_id"])
            parent_execution = copy.deepcopy(self._executions.get(parent_execution_id))
            parent_profile = copy.deepcopy(self._runtime_profiles.get(
                parent_manifest["profile_ref"]["profile_id"] if parent_manifest else None))
        if not parent_manifest or not self._manifest_ok(parent_manifest):
            raise ValueError("parent Manifest is unknown or invalid")
        parent_action = parent_manifest["action_target"]
        if (attestation["parent_profile_id"] != parent_manifest["profile_ref"]["profile_id"]
            or attestation["parent_action_id"] != parent_action["action_id"]):
            raise ValueError("delegation parent binding differs from the parent Manifest")
        if not parent_execution or parent_execution["execution_state"] not in {"DISPATCHED", "ACKNOWLEDGED", "COMMITTED"}:
            raise ValueError("parent action has not been admitted or is execution-unknown/terminally refused")
        policy = parent_profile.get("delegation_policy", {}) if parent_profile else {}
        if policy.get("mode") != "attenuated" or profile["profile_id"] not in policy.get("allowed_child_profile_ids", []):
            raise ValueError("parent Profile does not permit this child")
        expected_depth = parent_manifest["delegation"]["depth"] + 1
        if attestation["delegation_depth"] != expected_depth or expected_depth > policy["max_depth"]:
            raise ValueError("delegation depth is invalid")
        errors = self._attenuation_errors(parent_profile, profile)
        if errors:
            raise ValueError("; ".join(errors))
        return {
            "mode": "attenuated",
            "attestation_id": attestation["attestation_id"],
            "parent_manifest_id": parent_manifest["manifest_id"],
            "parent_action_id": parent_action["action_id"],
            "root_profile_id": parent_manifest["delegation"]["root_profile_id"],
            "depth": expected_depth,
            "attested_by": principal,
            "expires_at": attestation["expires_at"],
        }

    def _campaign_context(self, manifest):
        agg = manifest["aggregate_execution"]
        action = manifest["action_target"]
        values = {"actor": agg["actor_group_id"], "program": agg["program_id"],
                  "profile": manifest["profile_ref"]["profile_id"],
                  "operation": action["tool"] + "." + action["operation"]}
        holds = [copy.deepcopy(h) for h in self._campaign_holds.values()
                 if h["active"] and values[h["scope"]] == h["scope_value"]]
        holds.sort(key=lambda h: h["hold_id"])
        mode = "SUSPENDED" if any(h["mode"] == "SUSPENDED" for h in holds) else (
            "REQUIRE_APPROVAL" if holds else "NORMAL")
        public = [{k: h[k] for k in ("hold_id", "revision", "rule_id", "indicator", "mode", "scope", "scope_value")} for h in holds]
        return {"mode": mode, "holds": public, "revision": digest(public)}

    def _force_approval(self, profile, manifest):
        if manifest["autonomy_approval"]["mode"] == "recommend" or manifest["autonomy_approval"]["approval_required"]:
            return
        action = manifest["action_target"]
        entry = next(x for x in profile["permissions"]["allowed"] if x["tool"] == action["tool"] and x["operation"] == action["operation"])
        policy = profile["approval_policy"]
        manifest["autonomy_approval"].update(
            mode="request_approval", approval_required=True,
            approver_roles=list(entry.get("approver_roles") or policy["approver_roles"]),
            required_evidence=list(policy.get("required_evidence", [])),
            dual_approval_required=(action["tool"] + "." + action["operation"]) in policy.get("dual_approval_for", []),
            approval_timeout_minutes=policy.get("approval_timeout_minutes", profile["authority_scope"]["max_review_window_minutes"]),
        )

    def _prepare_manifest_context(self, profile, manifest):
        super()._prepare_manifest_context(profile, manifest)
        context = getattr(self._proposal_local, "value", None)
        if not context:
            raise ValueError("trusted v0.4 proposal context is missing")
        manifest["program_context"] = copy.deepcopy(profile["program_context"])
        manifest["execution_context_binding"] = copy.deepcopy(context["execution_context"])
        manifest["delegation"] = copy.deepcopy(context["delegation"])
        manifest["aggregate_execution"] = self._aggregate.build_claim(
            profile, manifest, context["actor_group"], context["delegation"]["root_profile_id"])
        with self._lock:
            aggregate_snapshot = self._aggregate.review_snapshot(
                self._aggregate_state, manifest, manifest["issued_at"], active_execution=self._active_execution)
            aggregate_issues = aggregate_snapshot["issues"]
            manifest["aggregate_execution"]["review_snapshot"] = aggregate_snapshot
            manifest["campaign_context"] = self._campaign_context(manifest)
        if any(x.startswith("AGGREGATE_BUDGET_REQUIRE_APPROVAL:") for x in aggregate_issues) or manifest["campaign_context"]["mode"] == "REQUIRE_APPROVAL":
            self._force_approval(profile, manifest)

    @guarded
    def propose(self, profile_id, request, now=None, manifest_id=None, *, actor, context_attestation,
                delegation_attestation=None):
        now = now or self._clock()
        try:
            profile = self._runtime_profiles.get(profile_id)
            if not profile:
                return super().propose(profile_id, request, now, manifest_id)
            if not isinstance(actor, dict) or set(actor) != {"principal", "auth_ref"}:
                raise ValueError("exact authenticated actor context is required")
            self._authenticated(actor.get("principal"), actor.get("auth_ref"))
            actor_group = self._actor_groups.get(actor["principal"])
            if not actor_group:
                raise ValueError("requester has no gate-owned accountable actor group")
            execution_context = self._validate_context(profile, context_attestation)
            delegation = self._validate_delegation(profile, request, delegation_attestation, now)
            self._proposal_local.value = {"actor_group": actor_group,
                                          "execution_context": execution_context,
                                          "delegation": delegation}
            return super().propose(profile_id, request, now, manifest_id)
        except (ValueError, TypeError, KeyError, Malformed, DependencyUnavailable) as exc:
            return {"decision": self._deny_record(None, ["trusted v0.4 proposal context: " + str(exc)], now,
                                                   "INDETERMINATE" if isinstance(exc, DependencyUnavailable) else "DENY")}
        finally:
            self._proposal_local.value = None

    def _active_execution(self, execution_id):
        if not execution_id:
            return False
        execution = self._executions.get(execution_id)
        if not execution or execution["execution_state"] not in {"DISPATCHED", "EXECUTION_UNKNOWN", "ACKNOWLEDGED", "COMMITTED"}:
            return False
        return not any(outcome.get("execution_id") == execution_id and outcome.get("verified") for outcome in self._outcomes.values())

    def _aggregate_current_issues(self, manifest):
        return self._aggregate.evaluate(self._aggregate_state, manifest, self._clock(), active_execution=self._active_execution)

    def _aggregate_current_snapshot(self, manifest):
        return self._aggregate.review_snapshot(
            self._aggregate_state, manifest, self._clock(), active_execution=self._active_execution)

    def _campaign_issues(self, manifest):
        current = self._campaign_context(manifest)
        if manifest.get("campaign_context") != current:
            return ["CAMPAIGN_CONTEXT_CHANGED: build a replacement and obtain any newly required approval"]
        if current["mode"] == "SUSPENDED":
            return ["CAMPAIGN_SUSPENDED: a reviewed restrictive campaign hold is active"]
        if current["mode"] == "REQUIRE_APPROVAL" and not manifest["autonomy_approval"]["approval_required"]:
            return ["CAMPAIGN_APPROVAL_REQUIRED"]
        return []

    def _runtime_issues(self, manifest):
        with self._lock:
            errors = ManagedGate._admission_issues(self, manifest)
            current_snapshot = self._aggregate_current_snapshot(manifest)
            current = current_snapshot["issues"]
            if manifest["aggregate_execution"]["review_snapshot"] != current_snapshot:
                errors.append("AGGREGATE_CONTEXT_CHANGED: build a replacement and obtain any newly required approval")
            errors.extend(x for x in current if not (x.startswith("AGGREGATE_BUDGET_REQUIRE_APPROVAL:") and manifest["autonomy_approval"]["approval_required"]))
            errors.extend(self._campaign_issues(manifest))
            return errors

    def _admission_issues(self, manifest):
        errors = ManagedGate._admission_issues(self, manifest)
        current_snapshot = self._aggregate_current_snapshot(manifest)
        current = current_snapshot["issues"]
        if manifest["aggregate_execution"]["review_snapshot"] != current_snapshot:
            errors.append("AGGREGATE_CONTEXT_CHANGED: build a replacement and obtain any newly required approval")
        errors.extend(self._campaign_issues(manifest))
        if not errors:
            errors.extend(self._aggregate.evaluate(
                self._aggregate_state, manifest, self._clock(), active_execution=self._active_execution,
                reserve=True, allow_reviewed=manifest["autonomy_approval"]["approval_required"]))
        return errors

    def _finalize_transaction_state(self):
        reservations = self._aggregate_state.setdefault("reservations", {})
        for manifest_id in list(reservations):
            execution_id = self._dispatches.get(manifest_id)
            if not execution_id:
                reservations.pop(manifest_id, None)
            else:
                reservations[manifest_id]["execution_id"] = execution_id

    @guarded
    def ingest_campaign_observation(self, observation, *, principal, auth_ref):
        reason = "INVALID_CAMPAIGN_OBSERVATION"
        try:
            fields = {"observation_id", "indicator", "observed_at", "profile_id", "profile_digest",
                      "program_id", "actor_group_id", "tool", "operation", "context_digest", "evidence_ref"}
            if not isinstance(observation, dict) or set(observation) != fields or any(not isinstance(v, str) or not v or len(v) > 512 for v in observation.values()):
                raise ValueError(reason)
            acl = self._campaign_principals.get(principal)
            if not acl or observation["indicator"] not in acl["indicators"] or observation["profile_id"] not in acl["profile_ids"]:
                reason = "CAMPAIGN_SOURCE_NOT_AUTHORIZED"; raise ValueError(reason)
            self._authenticated(principal, auth_ref)
            now = parse_time(self._clock()); observed = parse_time(observation["observed_at"])
            max_window = max((r["window_seconds"] for r in self._aggregate.policy["campaign_rules"]), default=1)
            if observed > now or (now - observed).total_seconds() > max_window:
                reason = "CAMPAIGN_OBSERVATION_STALE_OR_FUTURE"; raise ValueError(reason)
            with self._lock:
                profile = self._runtime_profiles.get(observation["profile_id"])
                if not profile or profile_digest(profile) != observation["profile_digest"]:
                    reason = "CAMPAIGN_PROFILE_VERSION_MISMATCH"; raise ValueError(reason)
                if profile["program_context"]["program_id"] != observation["program_id"] or profile["execution_context_ref"]["context_digest"] != observation["context_digest"]:
                    reason = "CAMPAIGN_CONTEXT_MISMATCH"; raise ValueError(reason)
                allowed = {(entry["tool"], entry["operation"]) for entry in profile["permissions"]["allowed"]}
                if (observation["tool"], observation["operation"]) not in allowed:
                    reason = "CAMPAIGN_OPERATION_OUTSIDE_PROFILE"; raise ValueError(reason)
                if observation["actor_group_id"] not in set(self._actor_groups.values()):
                    reason = "CAMPAIGN_ACTOR_GROUP_UNKNOWN"; raise ValueError(reason)
                key = digest({"principal": principal, "observation_id": observation["observation_id"]})
                prior = self._campaign_observations.get(key)
                body = {**copy.deepcopy(observation), "source_principal": principal, "accepted_at": self._clock()}
                if prior:
                    if {k: v for k, v in prior.items() if k != "accepted_at"} != {k: v for k, v in body.items() if k != "accepted_at"}:
                        reason = "CAMPAIGN_OBSERVATION_ID_CONFLICT"; raise ValueError(reason)
                    return {"accepted": True, "duplicate": True, "observation_id": observation["observation_id"]}
                self._campaign_observations[key] = body
                self._apply_campaign_rules(body)
            return {"accepted": True, "duplicate": False, "observation_id": observation["observation_id"]}
        except (ValueError, TypeError, KeyError, Malformed, DependencyUnavailable):
            self._admin_record("CAMPAIGN_OBSERVATION_REJECTED", observation.get("profile_id") if isinstance(observation, dict) else None,
                               actor=principal, reason_code=reason)
            return {"accepted": False, "reason_code": reason}

    def _apply_campaign_rules(self, observation):
        now = parse_time(self._clock())
        values = {"actor": observation["actor_group_id"], "program": observation["program_id"],
                  "profile": observation["profile_id"],
                  "operation": observation["tool"] + "." + observation["operation"]}
        for rule in self._aggregate.policy["campaign_rules"]:
            if rule["indicator"] != observation["indicator"]:
                continue
            value = values[rule["scope"]]
            incidents = {item["observation_id"] for item in self._campaign_observations.values()
                         if item["indicator"] == rule["indicator"]
                         and ({"actor": item["actor_group_id"], "program": item["program_id"],
                               "profile": item["profile_id"], "operation": item["tool"] + "." + item["operation"]}[rule["scope"]] == value)
                         and 0 <= (now - parse_time(item["observed_at"])).total_seconds() <= rule["window_seconds"]}
            if len(incidents) < rule["threshold"]:
                continue
            hold_id = "campaign:" + digest({"rule_id": rule["rule_id"], "scope": rule["scope"], "value": value})[7:31]
            old = self._campaign_holds.get(hold_id)
            if old and old["active"]:
                continue
            self._campaign_holds[hold_id] = {
                "hold_id": hold_id, "revision": (old["revision"] + 1 if old else 1),
                "rule_id": rule["rule_id"], "indicator": rule["indicator"], "mode": rule["mode"],
                "scope": rule["scope"], "scope_value": value, "active": True,
                "activated_at": self._clock(), "incident_count": len(incidents),
            }

    @guarded
    def restore_campaign_hold(self, hold_id, expected_revision, *, principal, auth_ref, reason, evidence_ref):
        if principal not in self._restoration_principals or not all(isinstance(x, str) and x for x in (reason, evidence_ref)):
            return {"restored": False, "reason_code": "RESTORATION_NOT_AUTHORIZED_OR_INCOMPLETE"}
        try:
            self._authenticated(principal, auth_ref)
        except DependencyUnavailable:
            return {"restored": False, "reason_code": "RESTORATION_AUTHENTICATION_FAILED"}
        with self._lock:
            hold = self._campaign_holds.get(hold_id)
            if not hold or not hold["active"] or hold["revision"] != expected_revision:
                return {"restored": False, "reason_code": "HOLD_MISSING_INACTIVE_OR_CHANGED"}
            hold.update(active=False, restored_at=self._clock(), restored_by=principal,
                        restoration_reason_digest=digest(reason), restoration_evidence_ref=evidence_ref)
            return {"restored": True, "hold_id": hold_id, "revision": hold["revision"]}

    def aggregate_snapshot(self):
        with self._lock:
            return {"record_type": "AggregateRuntimeSnapshot", "schema_version": "0.4.0",
                    "policy_ref": copy.deepcopy(self._aggregate.reference),
                    "reservations": copy.deepcopy(list(self._aggregate_state["reservations"].values())),
                    "campaign_holds": copy.deepcopy(list(self._campaign_holds.values()))}
