#!/usr/bin/env python3
"""
render_card.py — generate the Action Assurance Card from an Action Manifest, and check
parity. AAM v0.4.0.

The Card is a projection of the Manifest (plus the profile prohibitions the Manifest
carries verbatim in `not_permitted_summary`). Rendering adds labels and order only. The
approver sees what will happen, the exact effect target and material parameters, the
evidence and uncertainty, blast radius, what the agent cannot do, recovery, and how success
will be verified — without reading technical identifiers.
"""
import json
import copy
import sys

# Normative authority-relevant projection: card_key -> extractor
def _params(m):
    return [[p["label"], p["value"]] for p in m["action_target"].get("material_parameters", [])]

PROJECTION = [
    ("operational_context", lambda m: m.get("operational_context")),
    ("program_context", lambda m: m.get("program_context")),
    ("execution_context_binding", lambda m: m.get("execution_context_binding")),
    ("delegation", lambda m: m.get("delegation")),
    ("aggregate_execution", lambda m: m.get("aggregate_execution")),
    ("campaign_context", lambda m: m.get("campaign_context")),
    ("what_will_happen",      lambda m: m["action_target"]["summary"]),
    ("effect_target",         lambda m: (m["action_target"]["effect_target"].get("display") + f' [{m["action_target"]["effect_target"]["identifier"]}]') if m["action_target"]["effect_target"].get("display") else m["action_target"]["effect_target"]["identifier"]),
    ("effect_target_kind",    lambda m: m["action_target"]["effect_target"]["type"]),
    ("about",                 lambda m: ((m["action_target"].get("subject") or {}).get("display", "") + f' [{(m["action_target"].get("subject") or {}).get("identifier", "")}]').strip(" []") if m["action_target"].get("subject") else None),
    ("material_parameters",   _params),
    ("operation",             lambda m: f'{m["action_target"]["tool"]}.{m["action_target"]["operation"]}'),
    ("why_evidence",          lambda m: m["evidence"]["evidence_refs"]),
    ("uncertainty",           lambda m: m["evidence"].get("unresolved_conflicts", [])),
    ("untrusted_inputs_used", lambda m: m["evidence"].get("untrusted_sources_present", [])),
    ("blast_radius",          lambda m: m["impact"]["blast_radius"]),
    ("severity",              lambda m: m["impact"]["severity"]),
    ("reversible",            lambda m: m["impact"]["reversible"]),
    ("cannot_do",             lambda m: m.get("not_permitted_summary", [])),
    ("stated_not_enforced",   lambda m: m.get("documented_not_enforced", [])),
    ("built_by",              lambda m: m.get("built_by")),
    ("mode",                  lambda m: m["autonomy_approval"]["mode"]),
    ("approval_required",     lambda m: m["autonomy_approval"]["approval_required"]),
    ("approver_roles",        lambda m: m["autonomy_approval"].get("approver_roles", [])),
    ("dual_approval",         lambda m: m["autonomy_approval"].get("dual_approval_required", False)),
    ("success_means",         lambda m: m["outcome_verification"]["expected_postconditions"]),
    ("verified_by",           lambda m: [f'{t.get("test_id")}: {t.get("method")} via {t.get("source", "?")}: {t.get("assertion")} [postcondition index {t.get("postcondition_index", "n/a")}]' for t in m["outcome_verification"].get("verification_tests", [])]),
    ("if_verification_fails", lambda m: m["outcome_verification"]["on_failure"]),
    ("recovery",              lambda m: m["recovery"]["method"]),
    ("recovery_tested",       lambda m: bool(m["recovery"].get("tested")) and bool(m["recovery"].get("tested_evidence_ref"))),
    ("recovery_owner",        lambda m: m["recovery"]["owner"]),
    ("acting_as",             lambda m: m["credentials"]["identity"]),
    ("credential_ttl_minutes",lambda m: m["credentials"]["ttl_minutes"]),
    ("data_leaving_boundary", lambda m: m["data_boundary_claim"].get("egress_fields", [])),
    ("inference_location",    lambda m: m["data_boundary_claim"]["model_hosting"]),
    ("agent_and_profile",     lambda m: f'{m["identity"]["agent_name"]} {m["identity"]["agent_version"]} · profile {m["profile_ref"]["profile_id"]} v{m["profile_ref"]["profile_version"]} ({m["profile_ref"]["conformance_level"]})'),
    ("review_until",          lambda m: m["review_expires_at"]),
    ("manifest_id",           lambda m: m["manifest_id"]),
    ("all_parameters",        lambda m: sorted([k, v] for k, v in (m["action_target"].get("parameters") or {}).items())),
    ("scope",                 lambda m: f'{m["scope_claim"].get("tenant", "-")} · {m["scope_claim"]["environment"]} · systems {", ".join(m["scope_claim"]["systems"])}' + (f' · assets {", ".join(m["scope_claim"]["assets"])}' if m["scope_claim"].get("assets") else "") + (f' · {m["scope_claim"]["selector"]}' if m["scope_claim"].get("selector") else "") + (f' · window: {m["scope_claim"]["operating_window"]}' if m["scope_claim"].get("operating_window") else "")),
    ("subject_kind",          lambda m: (m["action_target"].get("subject") or {}).get("type")),
    ("effect_target_class",   lambda m: m["action_target"]["effect_target"].get("class")),
    ("evidence_provenance",   lambda m: m["evidence"].get("provenance", [])),
    ("impact_domains",        lambda m: m["impact"]["domains"]),
    ("bounded_by",            lambda m: m["impact"].get("bounded_by", [])),
    ("max_affected_objects",  lambda m: m["impact"].get("max_affected_objects")),
    ("approval_timeout_min",  lambda m: m["autonomy_approval"].get("approval_timeout_minutes")),
    ("required_evidence",     lambda m: m["autonomy_approval"].get("required_evidence", [])),
    ("privileges_used",       lambda m: m["credentials"]["privileges"]),
    ("audit_records",         lambda m: m["audit"]["records"]),
    ("completion_rule",       lambda m: m["outcome_verification"]["completion_rule"]),
    ("designated_test_ids",   lambda m: m["outcome_verification"].get("designated_test_ids", [])),
    ("max_observation_age_seconds", lambda m: m["outcome_verification"]["max_observation_age_seconds"]),
    ("recovery_evidence",     lambda m: m["recovery"].get("tested_evidence_ref")),
    ("recovery_last_tested",  lambda m: m["recovery"].get("last_tested")),
    ("recovery_minutes",      lambda m: m["recovery"].get("time_to_recover_minutes")),
    ("request_digest",        lambda m: m["request_digest"]),
    ("profile_digest",        lambda m: m["profile_ref"].get("profile_digest")),
    ("issued_at",             lambda m: m["issued_at"]),
    ("versions",              lambda m: f'manifest {m["manifest_version"]} · model {m["identity"]["model"]["provider"]} {m["identity"]["model"]["identifier"]} · prompt v{m["identity"]["prompt"]["version"]}' + (f' ({m["identity"]["prompt"]["hash"]})' if m["identity"]["prompt"].get("hash") else "") + f' · policy v{m["identity"]["policy"]["version"]}' + (f' ({m["identity"]["policy"]["hash"]})' if m["identity"]["policy"].get("hash") else "")),
    ("parameters_summary",    lambda m: m["action_target"].get("parameters_summary")),
    ("action_id",             lambda m: m["action_target"]["action_id"]),
    ("requested_at",          lambda m: m["action_target"].get("requested_at")),
    ("subject_system",        lambda m: (m["action_target"].get("subject") or {}).get("system")),
    ("effect_target_system",  lambda m: m["action_target"]["effect_target"].get("system")),
]

V4_KEYS = {"program_context", "execution_context_binding", "delegation",
           "aggregate_execution", "campaign_context"}

LABELS = {
    "operational_context": "Operational restrictions (review snapshot)",
    "program_context": "Accountable program",
    "execution_context_binding": "Execution context binding",
    "delegation": "Delegation chain",
    "aggregate_execution": "Aggregate budget claims",
    "campaign_context": "Campaign restrictions (review snapshot)",
    "what_will_happen": "What will happen", "effect_target": "To / on", "effect_target_kind": "Target kind", "about": "About",
    "material_parameters": "Details", "operation": "Operation", "why_evidence": "Why (evidence)", "uncertainty": "Uncertainty / open conflicts",
    "untrusted_inputs_used": "Untrusted inputs consulted", "blast_radius": "Worst case if wrong", "severity": "Severity", "reversible": "Reversible",
    "cannot_do": "This agent can never (enforced by the gate)", "stated_not_enforced": "Stated in the Profile but NOT enforced by the gate", "built_by": "Manifest built by", "mode": "Autonomy", "approval_required": "Needs your approval", "approver_roles": "Approver role(s)",
    "dual_approval": "Two approvers required", "success_means": "Success means", "verified_by": "Verified by", "if_verification_fails": "If verification fails",
    "recovery": "Way back", "recovery_tested": "Way back tested (evidenced)", "recovery_owner": "Recovery owner", "acting_as": "Acting as",
    "credential_ttl_minutes": "Credential expires (min)", "data_leaving_boundary": "Data leaving boundary", "inference_location": "Inference runs",
    "agent_and_profile": "Agent / authority profile", "review_until": "Review window ends", "manifest_id": "Manifest id",
    "impact_domains": "Impact domains", "all_parameters": "All parameters (as they will execute)", "scope": "Scope claimed", "subject_kind": "Subject kind", "effect_target_class": "Target class",
    "evidence_provenance": "Evidence provenance", "bounded_by": "Bounded by", "max_affected_objects": "Max objects affected",
    "approval_timeout_min": "Approval valid for (min)", "required_evidence": "Evidence you must be shown", "privileges_used": "Privileges used",
    "audit_records": "Will be recorded", "completion_rule": "Completion rule", "designated_test_ids": "Designated required tests", "max_observation_age_seconds": "Maximum evidence age (s)", "recovery_evidence": "Recovery test evidence", "recovery_last_tested": "Recovery last tested",
    "recovery_minutes": "Time to recover (min)", "request_digest": "Request digest (binding)", "profile_digest": "Profile digest", "issued_at": "Issued at",
    "versions": "Versions", "parameters_summary": "Parameters summary", "action_id": "Action id", "requested_at": "Requested at",
    "subject_system": "Subject system", "effect_target_system": "Target system",
}


def project(manifest: dict) -> dict:
    return copy.deepcopy({k: fn(manifest) for k, fn in PROJECTION
                          if k not in V4_KEYS or k in manifest})


def render_text(manifest: dict) -> str:
    c = project(manifest)
    out = ["ACTION ASSURANCE CARD", "=" * 22]
    for k in c:
        val = c[k]
        if k in ("material_parameters", "all_parameters"):
            val = "; ".join(f"{lab}: {v}" for lab, v in val) if val else "(none)"
        elif isinstance(val, list):
            val = "\n" + "\n".join(f"{'':<30}- {x}" for x in val) if val else "(none)"
        out.append(f"{LABELS.get(k, k):<30} {val}")
    out += ["", "Approve [ ]   Reject [ ]   Request more evidence [ ]",
            "Generated from the exact Manifest the gate checked. Tool success is not outcome success. Transport failure is not proof that no action occurred."]
    return "\n".join(out)


def leaf_values(doc, path="", exclude=("integrity", "schema_version")):
    """All scalar leaf values of a document with their paths, skipping excluded top-level keys."""
    out = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if not path and k in exclude:
                continue
            out += leaf_values(v, f"{path}.{k}" if path else k, exclude)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            out += leaf_values(v, f"{path}[{i}]", exclude)
    else:
        out.append((path, doc))
    return out


def coverage(manifest: dict) -> dict:
    """Every authority-bearing / execution-material leaf of the Manifest must appear in the Card projection.
    Returns the leaves that are missing. Empty means the approver is shown everything in the digest."""
    text = json.dumps(project(manifest), default=str, ensure_ascii=False)
    missing = []
    for path, val in leaf_values(manifest):
        needle = json.dumps(val, ensure_ascii=False) if isinstance(val, (bool, int, float)) or val is None else str(val)
        if isinstance(val, (bool, int, float)) or val is None:
            if str(val) not in text and needle not in text:
                missing.append(path)
        elif needle not in text:
            missing.append(path)
    return {"complete": not missing, "missing": missing}


def check_parity(card: dict, manifest: dict) -> dict:
    expected = project(manifest)
    missing = [k for k in expected if k not in card]
    extra = [k for k in card if k not in expected]
    differing = [k for k in expected if k in card and card[k] != expected[k]]
    return {"ok": not (missing or extra or differing), "missing": missing, "extra": extra, "differing": differing}


def main(argv):
    if len(argv) < 2:
        print("usage: render_card.py <manifest.json> [--json]")
        return 2
    m = json.load(open(argv[1]))
    if "--coverage" in argv:
        print(json.dumps(coverage(m), indent=2))
        return 0 if coverage(m)["complete"] else 1
    print(json.dumps(project(m), indent=2, default=str) if "--json" in argv else render_text(m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
