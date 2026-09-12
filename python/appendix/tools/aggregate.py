"""Domain-neutral aggregate admission budgets for AAM v0.4.0.

The controller consumes only gate-derived Manifest claims. It never grants authority:
an action must already pass Profile containment, live checks and approval. Reservations
are committed with the local dispatch reservation by V4ManagedGate. Remote effects
remain outside that transaction.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from check_containment import canonical, digest, parse_time

MEASURES = {"admissions", "in_flight", "objects", "distinct_targets", "egress_bytes"}
DIMENSIONS = {
    "tenant", "environment", "accountable_actor", "profile", "program",
    "operation", "target_class", "delegation_root",
}
RESPONSES = {"DENY", "REQUIRE_APPROVAL", "SUSPENDED"}
WINDOWS = {"rolling", "fixed", "lifetime"}


def policy_ref(policy: dict) -> dict:
    body = {k: v for k, v in policy.items() if k != "integrity"}
    return {
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_digest": digest(body),
    }


def validate_policy(policy: dict) -> list[str]:
    errors = []
    if not isinstance(policy, dict):
        return ["aggregate policy must be an object"]
    required = {"schema_version", "policy_id", "policy_version", "budgets", "campaign_rules"}
    if set(policy) != required:
        errors.append("aggregate policy fields must be exactly " + ", ".join(sorted(required)))
    if policy.get("schema_version") != "0.4.0":
        errors.append("aggregate policy schema_version must be 0.4.0")
    for name in ("policy_id", "policy_version"):
        if not isinstance(policy.get(name), str) or not policy[name]:
            errors.append(name + " must be a non-empty string")
    budgets = policy.get("budgets")
    if not isinstance(budgets, list) or not budgets:
        errors.append("budgets must be a non-empty list")
        budgets = []
    ids = set()
    for index, budget in enumerate(budgets):
        prefix = f"budget[{index}]"
        allowed = {"budget_id", "selector", "measure", "window", "limit", "group_by", "on_exhaustion", "parameter", "maximum_per_action"}
        if not isinstance(budget, dict) or not set(budget) <= allowed:
            errors.append(prefix + " has an invalid shape")
            continue
        bid = budget.get("budget_id")
        if not isinstance(bid, str) or not bid or bid in ids:
            errors.append(prefix + " budget_id must be unique and non-empty")
        ids.add(bid)
        if budget.get("measure") not in MEASURES:
            errors.append(prefix + " measure is invalid")
        if type(budget.get("limit")) is not int or budget["limit"] < 1:
            errors.append(prefix + " limit must be a positive integer")
        if budget.get("on_exhaustion") not in RESPONSES:
            errors.append(prefix + " on_exhaustion is invalid")
        group = budget.get("group_by")
        if not isinstance(group, list) or not group or len(group) != len(set(group)) or not set(group) <= DIMENSIONS:
            errors.append(prefix + " group_by is invalid")
        elif not set(group) & {"accountable_actor", "program", "delegation_root"}:
            errors.append(prefix + " must aggregate by accountable_actor, program or delegation_root")
        selector = budget.get("selector", {})
        if not isinstance(selector, dict) or not set(selector) <= {"tool", "operation", "target_class"} or any(not isinstance(v, str) or not v for v in selector.values()):
            errors.append(prefix + " selector is invalid")
        window = budget.get("window")
        if not isinstance(window, dict) or window.get("kind") not in WINDOWS or not set(window) <= {"kind", "seconds"}:
            errors.append(prefix + " window is invalid")
        elif window["kind"] != "lifetime" and (type(window.get("seconds")) is not int or window["seconds"] < 1):
            errors.append(prefix + " rolling/fixed windows require positive seconds")
        elif window["kind"] == "lifetime" and "seconds" in window:
            errors.append(prefix + " lifetime window cannot have seconds")
        if budget.get("measure") == "egress_bytes":
            if not isinstance(budget.get("parameter"), str) or not budget["parameter"]:
                errors.append(prefix + " egress_bytes requires the name of a request parameter to measure")
            if type(budget.get("maximum_per_action")) is not int or budget["maximum_per_action"] < 0:
                errors.append(prefix + " egress_bytes requires maximum_per_action")
        elif "parameter" in budget or "maximum_per_action" in budget:
            errors.append(prefix + " parameter cost fields are only valid for egress_bytes")
    rules = policy.get("campaign_rules")
    if not isinstance(rules, list):
        errors.append("campaign_rules must be a list")
        rules = []
    rule_ids = set()
    for index, rule in enumerate(rules):
        prefix = f"campaign_rule[{index}]"
        fields = {"rule_id", "indicator", "threshold", "window_seconds", "scope", "mode"}
        if not isinstance(rule, dict) or set(rule) != fields:
            errors.append(prefix + " has an invalid shape")
            continue
        if not isinstance(rule["rule_id"], str) or not rule["rule_id"] or rule["rule_id"] in rule_ids:
            errors.append(prefix + " rule_id must be unique and non-empty")
        rule_ids.add(rule["rule_id"])
        if not isinstance(rule["indicator"], str) or not rule["indicator"]:
            errors.append(prefix + " indicator must be a non-empty typed identifier")
        if type(rule["threshold"]) is not int or rule["threshold"] < 1:
            errors.append(prefix + " threshold must be positive")
        if type(rule["window_seconds"]) is not int or rule["window_seconds"] < 1:
            errors.append(prefix + " window_seconds must be positive")
        if rule["scope"] not in {"actor", "program", "profile", "operation"}:
            errors.append(prefix + " scope is invalid")
        if rule["mode"] not in {"REQUIRE_APPROVAL", "SUSPENDED"}:
            errors.append(prefix + " mode may only restrict")
    try:
        canonical(policy)
    except (TypeError, ValueError):
        errors.append("aggregate policy must be canonical JSON")
    return errors


def empty_state() -> dict:
    return {"reservations": {}}


class AggregateBudgetController:
    def __init__(self, policy: dict):
        errors = validate_policy(policy)
        if errors:
            raise ValueError("; ".join(errors))
        self.policy = copy.deepcopy(policy)
        self.reference = policy_ref(policy)

    @staticmethod
    def _matches(selector: dict, manifest: dict) -> bool:
        action = manifest["action_target"]
        values = {
            "tool": action["tool"],
            "operation": action["operation"],
            "target_class": action["effect_target"].get("class", ""),
        }
        return all(values.get(k) == v for k, v in selector.items())

    def build_claim(self, profile: dict, manifest: dict, actor_group: str, delegation_root: str) -> dict:
        action = manifest["action_target"]
        grouping = {
            "tenant": profile["authority_scope"].get("tenant", ""),
            "environment": profile["authority_scope"]["environment"],
            "accountable_actor": actor_group,
            "profile": profile["profile_id"],
            "program": profile["program_context"]["program_id"],
            "operation": action["tool"] + "." + action["operation"],
            "target_class": action["effect_target"].get("class", ""),
            "delegation_root": delegation_root,
        }
        target_digest = digest({
            "type": action["effect_target"]["type"],
            "identifier": action["effect_target"]["identifier"],
            "system": action["effect_target"].get("system"),
        })
        claims = []
        for budget in self.policy["budgets"]:
            if not self._matches(budget.get("selector", {}), manifest):
                continue
            measure = budget["measure"]
            if measure in {"admissions", "in_flight", "distinct_targets"}:
                amount = 1
            elif measure == "objects":
                amount = manifest["impact"].get("max_affected_objects", 1)
            else:
                parameters = action.get("parameters", {})
                if budget["parameter"] not in parameters:
                    raise ValueError("egress measurement parameter is absent")
                amount = len(canonical(parameters[budget["parameter"]]).encode("utf-8"))
                if amount > budget["maximum_per_action"]:
                    raise ValueError("canonical egress parameter is above the policy maximum")
            group = {name: grouping[name] for name in budget["group_by"]}
            claims.append({
                "budget_id": budget["budget_id"],
                "measure": measure,
                "window": copy.deepcopy(budget["window"]),
                "limit": budget["limit"],
                "on_exhaustion": budget["on_exhaustion"],
                "group": group,
                "group_digest": digest(group),
                "amount": amount,
            })
        return {
            "policy_ref": copy.deepcopy(self.reference),
            "actor_group_id": actor_group,
            "delegation_root_profile_id": delegation_root,
            "program_id": profile["program_context"]["program_id"],
            "target_digest": target_digest,
            "claims": claims,
        }

    @staticmethod
    def _in_window(reservation: dict, window: dict, now) -> bool:
        if window["kind"] == "lifetime":
            return True
        at = parse_time(reservation["reserved_at"])
        seconds = window["seconds"]
        if window["kind"] == "rolling":
            return 0 <= (now - at).total_seconds() < seconds
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        return int((now - epoch).total_seconds()) // seconds == int((at - epoch).total_seconds()) // seconds

    def evaluate(self, state: dict, manifest: dict, now: str, *, active_execution,
                 reserve: bool = False, allow_reviewed: bool = False) -> list[str]:
        claim_set = manifest["aggregate_execution"]
        if claim_set["policy_ref"] != self.reference:
            return ["AGGREGATE_POLICY_CHANGED"]
        instant = parse_time(now)
        errors = []
        reservations = state["reservations"]
        for claim in claim_set["claims"]:
            relevant = [r for r in reservations.values()
                        if self._in_window(r, claim["window"], instant)
                        for c in r["claims"]
                        if c["budget_id"] == claim["budget_id"] and c["group_digest"] == claim["group_digest"]]
            if claim["measure"] == "distinct_targets":
                current = len({r["target_digest"] for r in relevant})
                projected = current + (0 if claim_set["target_digest"] in {r["target_digest"] for r in relevant} else 1)
            elif claim["measure"] == "in_flight":
                current = sum(1 for r in relevant if active_execution(r.get("execution_id")))
                projected = current + 1
            else:
                current = sum(next(c["amount"] for c in r["claims"] if c["budget_id"] == claim["budget_id"] and c["group_digest"] == claim["group_digest"]) for r in relevant)
                projected = current + claim["amount"]
            if projected > claim["limit"]:
                errors.append(f"AGGREGATE_BUDGET_{claim['on_exhaustion']}: {claim['budget_id']} would be {projected}/{claim['limit']}")
        blocking = [e for e in errors if not (allow_reviewed and e.startswith("AGGREGATE_BUDGET_REQUIRE_APPROVAL:"))]
        if reserve and not blocking:
            mid = manifest["manifest_id"]
            if mid in reservations:
                return ["AGGREGATE_RESERVATION_ALREADY_EXISTS"]
            reservations[mid] = {
                "manifest_id": mid,
                "execution_id": None,
                "reserved_at": now,
                "target_digest": claim_set["target_digest"],
                "claims": copy.deepcopy(claim_set["claims"]),
            }
        return blocking if allow_reviewed else errors

    def review_snapshot(self, state: dict, manifest: dict, now: str, *, active_execution) -> dict:
        """Bind a proposal to the relevant aggregate ledger view.

        A violations-only snapshot is insufficient: usage may change while still
        below a limit. Include every currently relevant reservation so a Manifest
        proposed against an older ledger view cannot be dispatched unchanged.
        """
        claim_set = manifest["aggregate_execution"]
        instant = parse_time(now)
        relevant = []
        reservations = state.setdefault("reservations", {})
        for reservation in reservations.values():
            matching_claims = []
            for claim in claim_set["claims"]:
                if not self._in_window(reservation, claim["window"], instant):
                    continue
                for reserved_claim in reservation["claims"]:
                    if (reserved_claim["budget_id"] == claim["budget_id"]
                            and reserved_claim["group_digest"] == claim["group_digest"]):
                        matching_claims.append({
                            "budget_id": reserved_claim["budget_id"],
                            "amount": reserved_claim["amount"],
                            "active": active_execution(reservation.get("execution_id")),
                        })
                        break
            if matching_claims:
                relevant.append({
                    "manifest_id": reservation["manifest_id"],
                    "execution_id": reservation.get("execution_id"),
                    "reserved_at": reservation["reserved_at"],
                    "target_digest": reservation["target_digest"],
                    "claims": matching_claims,
                })
        relevant.sort(key=lambda item: item["manifest_id"])
        issues = self.evaluate(state, manifest, now, active_execution=active_execution)
        return {"issues": issues, "revision": digest(relevant)}
