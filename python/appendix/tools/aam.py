#!/usr/bin/env python3
"""
aam.py — Agent Action Manifest command line, v0.4.0.

  aam init      Ask the product owner the worksheet questions (or read an answers file), then write
                profile.json and profile.readback.md. The PM never edits JSON.
  aam readback  Render an existing Profile back into plain English for sign-off.
  aam validate  Structural validation of a Profile or Manifest against the schemas.
  aam check     Containment check of a Manifest against a Profile (ALLOW / DENY / INDETERMINATE).
  aam card      Render the Action Assurance Card for a Manifest.

Answers files are JSON with the same keys the interactive prompts use; see examples/answers/.
The read-back partitions the Profile into product and engineering review views, with separate
digests. Use aam signoff and verify-signoff for identity-bound approval records. Read-back text
alone is not approval. Signing the whole Profile remains a separate publication operation.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_containment import check, profile_digest  # noqa: E402
from render_card import render_text, leaf_values  # noqa: E402

DOMAINS = ["operational", "physical", "safety", "financial", "legal", "privacy", "security", "external_communication", "code_or_data_integrity", "other"]
MODES = ["recommend", "request_approval", "execute_allowlisted", "conditional_autonomy"]


# ---------------------------------------------------------------------------
# Question plan: (key, prompt, kind, who, default)
# kind: str | int | bool | list | choice:<a,b,c> | ops | nevers | targets
# ---------------------------------------------------------------------------
PLAN = [
    ("0. Which agent is this?", [
        ("agent_name", "Agent name", "str", "Product", "invoice-triage"),
        ("agent_version", "Agent version", "str", "Product", "1.4"),
        ("owner", "Who owns this Profile (a person or role)?", "str", "Product", "AP Platform Lead"),
        ("tenant", "Tenant or organisation this applies to", "str", "Product", "ACME"),
        ("environment", "Environment", "choice:prod,staging,dev", "Engineering", "prod"),
        ("model_provider", "Model provider (pinned)", "str", "Engineering", "<provider>"),
        ("model_identifier", "Model identifier / version (pinned, not 'latest')", "str", "Engineering", "<model@2026-05>"),
        ("prompt_version", "Prompt version", "str", "Engineering", "9"),
        ("policy_version", "Policy version", "str", "Engineering", "3"),
    ]),
    ("1. What may the agent read?", [
        ("systems", "Systems it may look at (comma-separated)", "list", "Product", "erp.ap, ticketing, email"),
        ("targets", "Kinds of records it may act on or about", "targets", "Product", None),
        ("untrusted_sources", "Inputs that could contain hidden instructions (comma-separated)", "list", "Product", "invoice_pdfs, vendor_emails, ocr_output"),
    ]),
    ("2. What may the agent do?", [
        ("operations", "Operations, one at a time", "ops", "Product", None),
    ]),
    ("3. What must the agent never do?", [
        ("nevers", "Never-list, one at a time", "nevers", "Product", None),
    ]),
    ("4. What is the biggest thing a single action may affect?", [
        ("allowed_domains", f"Kinds of consequence allowed (comma-separated from: {', '.join(DOMAINS)})", "list", "Product", "financial, external_communication, operational"),
        ("max_severity", "Highest severity any one action may carry", "choice:low,moderate,high,critical", "Product", "moderate"),
        ("max_affected_objects", "Most objects one action may affect", "int", "Product", "2"),
        ("irreversible_allowed", "May any action be irreversible?", "bool", "Product", "no"),
        ("worst_case", "Worst case for one action, in one sentence", "str", "Product", "One draft to one vendor about one invoice; no money movement."),
    ]),
    ("5. When must a human approve, and who?", [
        ("approver_roles", "Roles that may approve (comma-separated)", "list", "Product", "ap_manager, finance_controller"),
        ("required_evidence", "What the approver must be shown (comma-separated)", "list", "Product", "invoice_image, po_match_evidence, variance, draft_text"),
        ("dual_approval_for", "Operations needing two approvers (tool.operation, comma-separated; blank for none)", "list", "Product", ""),
        ("approval_timeout_minutes", "How long may an approval wait (minutes)", "int", "Product", "1440"),
        ("max_review_window_minutes", "How long may a request wait for review before it expires (minutes)", "int", "Product", "1440"),
        ("default_mode", "Default behaviour when unsure", "choice:" + ",".join(MODES), "Product", "request_approval"),
        ("max_mode", "Most autonomy any operation may ever have", "choice:" + ",".join(MODES), "Product", "execute_allowlisted"),
        ("thresholds", "Plain-English rules for when something may run without approval (comma-separated; blank for none)", "list", "Product", "variance <= 2000 USD and PO exists -> execute_allowlisted"),
    ]),
    ("6. What data may leave, and where does inference run?", [
        ("model_hosting", "Where the model runs", "choice:customer_boundary,regional,hosted,other", "Engineering", "customer_boundary"),
        ("egress_policy", "What may leave the boundary", "choice:none,allowlisted_fields,signed_summary,unrestricted", "Product", "none"),
        ("egress_allowlist", "If allowlisted: fields that may leave (comma-separated)", "list", "Product", ""),
        ("never_egress", "What may never leave (comma-separated)", "list", "Product", "bank_details, personal_data"),
        ("log_retention_days", "How long prompts and logs are kept (days)", "int", "Product", "30"),
    ]),
    ("7. Credential boundaries", [
        ("credential_identity", "The agent's own identity (never a person's login)", "str", "Engineering", "svc:ap-agent"),
        ("privileges", "What that identity may do (comma-separated)", "list", "Engineering", "erp.ap:read, erp.ap:status_write, ticketing:write, email:draft"),
        ("max_ttl_minutes", "How long a credential lasts (minutes); it stops the agent when it expires", "int", "Engineering", "240"),
    ]),
    ("8. Logging and accountability", [
        ("records", "What is recorded for every action (comma-separated)", "list", "Engineering", "tool_calls, evidence_refs, gate_decision, approvals, denials, outcome"),
        ("readers", "Who may read the log (comma-separated)", "list", "Product", "ap_platform_lead, finance_controller, security"),
        ("alert_on", "What triggers an alert (comma-separated)", "list", "Product", "release_payment_attempt, bank_detail_edit_attempt, email_to_unlisted_domain"),
    ]),
    ("9. Emergency stop", [
        ("kill_mechanism", "How the agent is stopped", "str", "Engineering", "feature flag ap-agent.enabled"),
        ("kill_state_source", "Where the gate reads the live state", "str", "Engineering", "flags://acme/ap-agent.enabled"),
        ("kill_operators", "Who can flip it (comma-separated; people outside engineering count)", "list", "Product", "ap_platform_lead, finance_controller"),
    ]),
    ("10. Who owns recovery?", [
        ("recovery_owner", "Who is responsible when an action must be undone", "str", "Product", "ap_platform_lead"),
        ("max_execution_authority_seconds", "After the gate says yes, how many seconds may the action wait before it must be re-checked", "int", "Engineering", "300"),
        ("conformance_level", "Conformance level you are claiming today", "choice:L0,L1,L2,L3", "Engineering", "L0"),
    ]),
]


def _parse(kind, raw, default):
    raw = (raw if raw is not None else "").strip()
    if raw == "" and default is not None:
        raw = default if isinstance(default, str) else json.dumps(default)
    if kind == "str":
        return raw
    if kind == "int":
        return int(raw)
    if kind == "bool":
        return raw.lower() in ("y", "yes", "true", "1")
    if kind == "list":
        return [x.strip() for x in raw.split(",") if x.strip()]
    if kind.startswith("choice:"):
        opts = kind.split(":", 1)[1].split(",")
        if raw not in opts:
            raise ValueError(f"must be one of {opts}")
        return raw
    return raw


class Console:
    """Interactive asker. Any object with .ask(key, prompt, kind, who, default) works (tests use a dict)."""

    def ask(self, key, prompt, kind, who, default):
        while True:
            hint = f" [{default}]" if default not in (None, "") else ""
            raw = input(f"  ({who}) {prompt}{hint}: ")
            try:
                return _parse(kind, raw, default)
            except ValueError as e:
                print(f"    ! {e}")

    def ask_ops(self):
        ops = []
        print("  (Product) Operations. Enter a blank operation name to finish.")
        while True:
            name = input("    operation as tool.operation (e.g. email.draft_email): ").strip()
            if not name:
                break
            tool, op = name.split(".", 1) if "." in name else ("tool", name)
            ops.append({
                "tool": tool, "operation": op,
                "effect_type": input("      what does it affect (kind: email_address, ticket, invoice, branch, work_order...): ").strip(),
                "effect_classes": [x.strip() for x in input("      allowed classes of that thing (comma-separated; blank if any): ").split(",") if x.strip()],
                "material_parameters": [x.strip() for x in input("      details the approver must see (comma-separated parameter names): ").split(",") if x.strip()],
                "allowed_parameters": [x.strip() for x in input("      all parameters this operation accepts (comma-separated): ").split(",") if x.strip()],
                "max_mode": _parse("choice:" + ",".join(MODES), input("      most autonomy allowed for this operation [request_approval]: "), "request_approval"),
                "reversible": _parse("bool", input("      can it be undone? [yes]: "), "yes"),
            })
        return ops

    def ask_nevers(self):
        nevers = []
        print("  (Product) Never-list. Enter a blank description to finish.")
        while True:
            d = input("    never: ").strip()
            if not d:
                break
            to = input("      tool.operation it corresponds to, '*' allowed (blank if not a single operation): ").strip()
            item = {"description": d}
            if to:
                t, o = to.split(".", 1) if "." in to else (to, "*")
                item.update({"tool": t, "operation": o})
            nevers.append(item)
        return nevers

    def ask_targets(self):
        targets = []
        print("  (Product) Kinds of records the agent may act on or about. Blank kind to finish.")
        while True:
            t = input("    kind (invoice, email_address, ticket, branch, industrial_asset...): ").strip()
            if not t:
                break
            ids = [x.strip() for x in input("      exact identifiers if you can list them (comma-separated; blank to describe instead): ").split(",") if x.strip()]
            entry = {"type": t}
            if ids:
                entry["identifiers"] = ids
            else:
                entry["selector"] = input("      describe which ones (e.g. 'invoices in review'): ").strip()
            targets.append(entry)
        return targets


class AnswerFile:
    """Non-interactive asker backed by a dict (answers.json)."""

    def __init__(self, answers):
        self.a = answers

    def ask(self, key, prompt, kind, who, default):
        if key not in self.a:
            return _parse(kind, "", default)
        v = self.a[key]
        return _parse(kind, v, default) if isinstance(v, str) else v

    def ask_ops(self):
        return self.a.get("operations", [])

    def ask_nevers(self):
        return self.a.get("nevers", [])

    def ask_targets(self):
        return self.a.get("targets", [])


def collect(asker) -> dict:
    a = {}
    for section, questions in PLAN:
        if asker.__class__ is Console:
            print(f"\n{section}")
        for key, prompt, kind, who, default in questions:
            if kind == "ops":
                a[key] = asker.ask_ops()
            elif kind == "nevers":
                a[key] = asker.ask_nevers()
            elif kind == "targets":
                a[key] = asker.ask_targets()
            else:
                a[key] = asker.ask(key, prompt, kind, who, default)
    return a


def build_profile(a: dict, profile_id: str | None = None, version: str = "1.0.0") -> dict:
    """Deterministic translation of worksheet answers into a Profile."""
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    allowed = []
    for op in a["operations"]:
        e = {"tool": op["tool"], "operation": op["operation"], "effect_target": {"type": op["effect_type"]}}
        if op.get("effect_classes"):
            e["effect_target"]["classes"] = op["effect_classes"]
        if op.get("allowed_parameters"):
            e["allowed_parameters"] = op["allowed_parameters"]
        if op.get("material_parameters"):
            e["material_parameters"] = op["material_parameters"]
        if op.get("constraints"):
            e["constraints"] = op["constraints"]
        e["max_mode"] = op.get("max_mode", "request_approval")
        e["default_mode"] = op.get("default_mode", "request_approval")
        e["reversible"] = bool(op.get("reversible", True))
        # engineering bindings (Part B); defaults are deliberately conservative
        e["impact"] = op.get("impact") or {"domains": [d for d in a["allowed_domains"] if d in DOMAINS] or ["other"], "severity": a["max_severity"], "blast_radius": op.get("blast_radius") or a["worst_case"], "reversible": bool(op.get("reversible", True)), "max_affected_objects": int(op.get("max_affected_objects", a["max_affected_objects"]))}
        e["privileges_required"] = op.get("privileges_required") or a["privileges"]
        if op.get("egress_fields") is not None: e["egress_fields"] = op["egress_fields"]
        if op.get("systems"): e["systems"] = op["systems"]
        e["verification"] = op.get("verification") or {"expected_postconditions": [f"{op['tool']}.{op['operation']} completed as declared (engineering to replace)"], "tests": [{"method": "human_confirmation", "source": "approver", "assertion": f"human confirms {op['tool']}.{op['operation']} outcome (engineering to replace with a system-of-record read)"}], "on_failure": "escalate"}
        # Default templates are explicit placeholders, not verified engineering evidence.
        e["verification"] = __import__("copy").deepcopy(e["verification"])
        e["verification"].setdefault("completion_rule", "all_postconditions_verified")
        e["verification"].setdefault("max_observation_age_seconds", 300)
        for i, test in enumerate(e["verification"]["tests"]):
            test.setdefault("test_id", f"postcondition-{i + 1}")
            if test["method"] != "tool_return_code":
                test.setdefault("postcondition_index", i)
        if op.get("summary_template"): e["summary_template"] = op["summary_template"]
        allowed.append(e)
    prohibited = a["nevers"] or [{"description": "No prohibitions declared (fill this in)"}]
    for pr in prohibited:                       # free-text rules must declare how they are enforced
        if pr.get("rule") and not pr.get("enforcement"):
            pr["enforcement"] = "documentation_only"
    for t in a["targets"]:
        if t.get("selector") and not t.get("enforcement"):
            t["enforcement"] = "documentation_only"
    prof = {
        "schema_version": "0.3.7",
        "profile_id": profile_id or f"aap:{a['tenant'].lower()}:{a['agent_name']}",
        "profile_version": version,
        "issued_at": now,
        "identity": {
            "agent_name": a["agent_name"], "agent_version": a["agent_version"],
            "model": {"provider": a["model_provider"], "identifier": a["model_identifier"]},
            "prompt": {"version": a["prompt_version"]}, "policy": {"version": a["policy_version"]},
            "owner": a["owner"],
        },
        "authority_scope": {
            "tenant": a["tenant"], "environment": a["environment"], "systems": a["systems"],
            "targets": a["targets"] or [{"type": "unspecified", "selector": "fill this in"}],
            "max_review_window_minutes": a["max_review_window_minutes"],
            "max_execution_authority_seconds": a["max_execution_authority_seconds"],
        },
        "permissions": {"default_deny": True, "allowed": allowed, "prohibited": prohibited},
        "impact_envelope": {
            "allowed_domains": [d for d in a["allowed_domains"] if d in DOMAINS] or ["other"], "max_severity": a["max_severity"],
            "max_affected_objects": int(a["max_affected_objects"]), "irreversible_allowed": a["irreversible_allowed"],
            "notes": a["worst_case"],
        },
        "autonomy_policy": {"default_mode": a["default_mode"], "max_mode": a["max_mode"],
                            "thresholds": [t if isinstance(t, dict) else {"description": t, "enforcement": "documentation_only", "mode": a["default_mode"]} for t in a["thresholds"]],
                            "downgrade_on": ["evaluation_regression", "anomaly_alert"]},
        "approval_policy": {"approver_roles": a["approver_roles"], "required_evidence": a["required_evidence"],
                            "one_approval_one_action": True, "dual_approval_for": a["dual_approval_for"],
                            "approval_timeout_minutes": a["approval_timeout_minutes"],
                            "distinct_principals_required": True, "principal_authentication_required": True},
        "input_trust": {"untrusted_sources": a["untrusted_sources"], "content_is_data_not_instructions": True},
        "credentials_policy": {"identity": a["credential_identity"], "privileges": a["privileges"],
                               "max_ttl_minutes": a["max_ttl_minutes"], "fail_closed_on_expiry": True},
        "data_boundary": {"model_hosting": a["model_hosting"], "egress_policy": a["egress_policy"],
                          "egress_allowlist": a["egress_allowlist"], "never_egress": a["never_egress"],
                          "log_retention_days": a["log_retention_days"]},
        "audit_policy": {"records": a["records"], "readers": a["readers"], "alert_on": a["alert_on"], "append_only": True},
        "recovery_policy": {"owner": a["recovery_owner"], "requires_tested_recovery_for_execution": True,
                            "test_evidence_required": True, "test_max_age_days": 90,
                            "templates": [{"tool": op["tool"], "operation": op["operation"], "method": op.get("recovery_method") or "engineering to fill", "tested": bool(op.get("recovery_tested", False)),
                                           "tested_evidence_ref": op.get("recovery_evidence_ref") or "unset:not-yet-tested", "owner": a["recovery_owner"], "irreversible": not bool(op.get("reversible", True)),
                                           **({"last_tested": op["recovery_last_tested"]} if op.get("recovery_last_tested") else {})} for op in a["operations"]]},
        "emergency_disable": {"mechanism": a["kill_mechanism"], "execution_state": "allowed", "state_source": a["kill_state_source"],
                              "operators": a["kill_operators"], "checked_at_gate": True, "halts_pending": True,
                              "halts_in_flight_where_possible": True},
        "conformance": {"level": a["conformance_level"], "assessed_at": now[:10], "assessor": a["owner"]},
    }
    if a["conformance_level"] != "L0":
        prof["conformance"]["enforcement"] = {"gate_id": "fill-in", "outside_model": True, "checks_action_target": True,
                                              "checks_manifest_within_profile": True, "checks_scope_permissions_credentials_stop": True}
    return prof


PRODUCT_PATHS = [  # Part A: product decisions. Everything else is Part B: engineering binding.
    "identity.agent_name", "identity.agent_version", "identity.owner",
    "authority_scope.tenant", "authority_scope.environment", "authority_scope.systems", "authority_scope.targets[*].type", "authority_scope.targets[*].selector", "authority_scope.targets[*].identifiers", "authority_scope.operating_window", "authority_scope.max_review_window_minutes",
    "permissions.default_deny", "permissions.allowed[*].tool", "permissions.allowed[*].operation", "permissions.allowed[*].effect_target", "permissions.allowed[*].material_parameters", "permissions.allowed[*].default_mode", "permissions.allowed[*].max_mode", "permissions.allowed[*].reversible", "permissions.allowed[*].impact", "permissions.allowed[*].summary_template", "permissions.allowed[*].approver_roles",
    "permissions.prohibited[*].description", "permissions.prohibited[*].enforcement",
    "impact_envelope", "autonomy_policy.default_mode", "autonomy_policy.max_mode", "autonomy_policy.thresholds[*].description", "autonomy_policy.thresholds[*].enforcement", "autonomy_policy.thresholds[*].mode", "autonomy_policy.thresholds[*].operations",
    "approval_policy", "input_trust.untrusted_sources", "data_boundary.egress_policy", "data_boundary.never_egress", "data_boundary.log_retention_days",
    "monitoring_policy_ref", "audit_policy.readers", "audit_policy.alert_on", "emergency_disable.operators", "emergency_disable.halts_pending", "recovery_policy.owner", "conformance.level",
]


def _is_product(path: str) -> bool:
    import re
    norm = re.sub(r"\[\d+\]", "[*]", path)
    return any(norm == p or norm.startswith(p + ".") or norm.startswith(p + "[") for p in PRODUCT_PATHS)


def product_view(prof: dict) -> list:
    return [(p, v) for p, v in leaf_values(prof) if _is_product(p)]


def engineering_view(prof: dict) -> list:
    return [(p, v) for p, v in leaf_values(prof) if not _is_product(p)]


def review_digests(prof: dict) -> dict:
    """Exact digests displayed in read-back and bound by ReadbackSignoff."""
    import hashlib
    def view_digest(view):
        return "sha256:" + hashlib.sha256(json.dumps(view, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return {"A": view_digest(product_view(prof)), "B": view_digest(engineering_view(prof)), "profile": profile_digest(prof)}


def readback(prof: dict) -> str:
    """Plain-English projection with review digests; does not authenticate human sign-offs."""
    I, S, P, E, A, D, C, L, K, R = (prof[k] for k in ("identity", "authority_scope", "permissions", "impact_envelope", "approval_policy",
                                                        "data_boundary", "credentials_policy", "audit_policy", "emergency_disable", "recovery_policy"))
    ap = prof["autonomy_policy"]
    lines = [f"# Read-back: {I['agent_name']} v{I['agent_version']}  (profile {prof['profile_id']} v{prof['profile_version']})",
             f"Owner: {I['owner']} · Tenant {S.get('tenant', '-')} · {S['environment']} · Model {I['model']['identifier']} · prompt v{I['prompt']['version']} · policy v{I['policy']['version']}",
             f"Conformance claimed: {prof['conformance']['level']}", "",
             "Review digests alone are not authenticated approvals. Use signoff to sign the exact Part A/B content and verify-signoff to verify the saved signature against trusted principal/role keys. Whole-Profile integrity is a separate check.", "",
             "## 1. What it may read",
             f"Systems: {', '.join(S['systems'])}",
             "Records: " + "; ".join((f"{t['type']}: {', '.join(t['identifiers'])}" if "identifiers" in t else f"{t['type']}: {t.get('selector', '?')}") for t in S["targets"]),
             f"Inputs treated as untrusted: {', '.join(prof['input_trust']['untrusted_sources'])}", "",
             "## 2. What it may do"]
    for e in P["allowed"]:
        et = e.get("effect_target", {})
        lines.append(f"- {e['tool']}.{e['operation']} → affects {et.get('type', '?')}" + (f" ({', '.join(et['classes'])})" if et.get("classes") else "")
                     + (f"; approver sees: {', '.join(e['material_parameters'])}" if e.get("material_parameters") else "")
                     + f"; up to: {e.get('max_mode', ap['max_mode'])}" + ("" if e.get("reversible", True) else "; NOT reversible"))
    lines += [f"Default when unsure: {ap['default_mode']} · Never more than: {ap['max_mode']}"]
    if ap.get("thresholds"):
        lines.append("May run at a higher autonomy when: " + "; ".join(
            (f"{t['description']} -> {t['mode']} [{'ENFORCED typed check ' + t.get('threshold_id', '') if t.get('enforcement') == 'typed' else 'documentation only, NOT enforced'}]" if isinstance(t, dict) else str(t)) for t in ap["thresholds"]))
    lines += ["", "## 3. What it must never do"] + [f"- {x['description']}" + (f"  [{x.get('tool', '*')}.{x.get('operation', '*')}]" if x.get("tool") or x.get("operation") else "") for x in P["prohibited"]]
    lines += ["", "## 4. Biggest thing one action may affect",
              f"Kinds: {', '.join(E['allowed_domains'])} · max severity {E['max_severity']} · at most {E.get('max_affected_objects', '?')} object(s) · irreversible allowed: {'yes' if E['irreversible_allowed'] else 'no'}",
              f"Worst case: {E.get('notes', '-')}", "",
              "## 5. Approval",
              f"Roles: {', '.join(A['approver_roles'])} · must be shown: {', '.join(A.get('required_evidence', []))} · two approvers for: {', '.join(A.get('dual_approval_for', [])) or 'none'} · approval may wait {A.get('approval_timeout_minutes', '?')} min · requests expire after {S['max_review_window_minutes']} min of review",
              "", "## 6. Data",
              f"Model runs: {D['model_hosting']} · may leave: {D['egress_policy']}" + (f" ({', '.join(D.get('egress_allowlist', []))})" if D.get("egress_allowlist") else "") + f" · never leaves: {', '.join(D.get('never_egress', [])) or 'none listed'} · logs kept {D['log_retention_days']} days",
              "", "## 7. Credentials",
              f"Acts as {C['identity']} · may: {', '.join(C['privileges'])} · credential lasts {C['max_ttl_minutes']} min and stops the agent when it expires",
              "", "## 8. Logging",
              f"Recorded: {', '.join(L['records'])} · readable by: {', '.join(L.get('readers', []))} · alerts on: {', '.join(L['alert_on'])}",
              "", "## 9. Emergency stop",
              f"{K['mechanism']} · live state at {K.get('state_source', '?')} · operated by: {', '.join(K['operators'])} · stops pending actions: {'yes' if K.get('halts_pending') else 'no'}",
              "", "## 10. Recovery",
              f"Owner: {R['owner']} · executing operations need an exercised way back with evidence, no older than {R.get('test_max_age_days', '?')} days",
              f"After the gate says yes, an action must run within {S['max_execution_authority_seconds']} seconds or be re-checked.",
              ]
    if prof.get("monitoring_policy_ref"):
        ref = prof["monitoring_policy_ref"]
        lines += ["", "## 11. Audit and governed response",
                  f"Reviewed feedback policy: {ref['policy_id']} v{ref['policy_version']} ({ref['policy_digest']})",
                  "Resolve this exact policy with --feedback-policy before approving it. ManagedGate applies its typed rules; ordinary Gate refuses this policy-bearing Profile.",
                  "Runtime feedback can require review or suspend new dispatches, never expand standing authority. Restoration is authenticated, separately recorded, and never retries an action."]
    else:
        lines += ["", "No executable feedback policy is pinned. Legacy alert_on / downgrade_on strings are declarations, not activated controllers."]
    pv, ev = product_view(prof), engineering_view(prof)
    digests = review_digests(prof)
    pa_digest, pb_digest = digests["A"], digests["B"]
    lines += ["", "# PART A — Product decisions (product owner reviews; approve the exact digest with aam signoff)",
              "Every product-owned setting, exactly as it will be enforced. Rules, selectors, or thresholds marked documentation_only are shown to you but are NOT enforced by the gate."]
    for path, val in pv:
        lines.append(f"- {path} = {val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)}")
    lines += ["", f"Part A review digest (identity-bound sign-off supported): {pa_digest}", "",
              "# PART B — Engineering binding (engineering reviews; approve the exact digest with aam signoff)",
              "Model/prompt/policy pins, credentials, selectors and rule ids, constraints, parameters, verification templates, recovery evidence, kill-switch mechanism, execution authority."]
    for path, val in ev:
        lines.append(f"- {path} = {val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)}")
    lines += ["", f"Part B review digest (identity-bound sign-off supported): {pb_digest}", "",
              f"Profile digest (binds Part A and Part B; this is what the gate enforces): {profile_digest(prof)}",
              "The Profile digest is what the gate enforces. It covers both parts; neither part can change without the digest changing."]
    return "\n".join(lines)


def readback_coverage(prof: dict) -> dict:
    """Every leaf of the Profile (except the integrity block) must appear in the read-back text."""
    text = readback(prof)
    missing = [p for p, v in leaf_values(prof) if (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)) not in text]
    return {"complete": not missing, "missing": missing}


# ---------------------------------------------------------------------------
def cmd_init(args):
    if args.answers:
        asker = AnswerFile(json.load(open(args.answers)))
    else:
        print("Agent Authority Profile — answer the worksheet. Defaults in [brackets] are from the AP invoice example.")
        asker = Console()
    answers = collect(asker)
    prof = build_profile(answers, args.profile_id, args.version)
    out = args.out or "profile.json"
    json.dump(prof, open(out, "w"), indent=2)
    rb = os.path.splitext(out)[0] + ".readback.md"
    open(rb, "w").write(readback(prof))
    print(f"\nwrote {out}\nwrote {rb}  <- review, then use aam signoff and verify-signoff with trusted principal keys")
    return 0


def resolved_feedback(profile, path):
    """Resolve the policy whose digest is covered by Profile and Part A review."""
    if not profile.get('monitoring_policy_ref'):
        if path:
            raise ValueError('Profile does not pin a feedback policy')
        return ''
    if not path:
        raise ValueError('Policy-bearing Profile requires --feedback-policy for review/signoff')
    from feedback import FeedbackController, policy_ref
    policy = json.load(open(path, encoding='utf-8'))
    FeedbackController(policy)
    if policy_ref(policy) != profile['monitoring_policy_ref']:
        raise ValueError('feedback policy does not match the signed Profile reference')
    lines = ['# Resolved policy (content bound by the Profile policy digest)',
             'This view does not grant authority and never executes an operation.']
    for rule in policy['rules']:
        lines.append(f"- {rule['rule_id']}: {rule['threshold']} distinct {rule['signal']} incident(s) within {rule['window_seconds']} seconds -> {rule['mode']} at {rule['scope']} scope.")
    lines += [f"Signal maximum age: {policy['signal_max_age_seconds']} seconds.",
              f"Overdue execution / verification: {policy['overdue_execution_seconds']} / {policy['overdue_verification_seconds']} seconds.",
              f"Export backlog admission limit: {policy['max_export_backlog']} events; consumer {policy['audit_consumer']}.",
              'Only authenticated manual restoration is implemented. Principal/role bindings are separately trusted deployment configuration.',
              'Exact resolved JSON (engineering review):', json.dumps(policy, indent=2, ensure_ascii=False)]
    return '\n'.join(lines)


def cmd_readback(args):
    prof = json.load(open(args.profile))
    resolved = resolved_feedback(prof, getattr(args, "feedback_policy", None))
    print(readback(prof))
    if resolved: print("\n" + resolved)
    cov = readback_coverage(prof)
    if not cov["complete"]:
        print(f"\n! read-back incomplete; not shown: {cov['missing']}", file=sys.stderr)
        return 1
    return 0


def cmd_validate(args):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        print("pip install jsonschema"); return 2
    doc = json.load(open(args.file))
    name = ("audit-event.schema.json" if doc.get("record_type") == "AuditEvent" else
            "runtime-control.schema.json" if doc.get("record_type") in ("RuntimeFailure", "RuntimeControlSnapshot") else
            "campaign-observation.schema.json" if "observation_id" in doc and "indicator" in doc else
            "delegation-attestation.schema.json" if "attestation_id" in doc and "parent_manifest_id" in doc else
            "execution-context-attestation.schema.json" if "context_id" in doc and "principal" in doc else
            "lifecycle-records.schema.json" if "record_type" in doc else
            "aggregate-execution-policy.schema.json" if "budgets" in doc else
            "feedback-policy.schema.json" if "policy_id" in doc else
            "agent-authority-profile.schema.json" if "profile_id" in doc else
            "action-manifest.schema.json" if "manifest_id" in doc else "action-request.schema.json")
    schema = json.load(open(os.path.join(HERE, "..", "schemas", name)))
    from validation_support import strict_format_checker
    errs = [e.message for e in Draft202012Validator(schema, format_checker=strict_format_checker()).iter_errors(doc)]
    if not errs:
        from verification import verification_errors
        if "record_type" in doc:
            pass  # structural validation is not signature/identity verification
        elif "budgets" in doc:
            from aggregate import validate_policy
            errs.extend(validate_policy(doc))
        elif "policy_id" in doc:
            from feedback import FeedbackController
            try: FeedbackController(doc)
            except ValueError as exc: errs.append(str(exc))
        elif "profile_id" in doc:
            for operation in doc["permissions"]["allowed"]:
                errs.extend(f"{operation['tool']}.{operation['operation']}: {e}"
                            for e in verification_errors(operation["verification"]))
        elif "manifest_id" in doc:
            errs.extend(verification_errors(doc["outcome_verification"], "verification_tests"))
    print("VALID" if not errs else "INVALID\n- " + "\n- ".join(errs))
    return 0 if not errs else 1


def cmd_check(args):
    r = check(json.load(open(args.profile)), json.load(open(args.manifest)), args.now)
    print(json.dumps(r, indent=2))
    return {"ALLOW": 0, "INDETERMINATE": 3, "DENY": 1}[r["decision"]]


def cmd_propose(args):
    """Build a Manifest through the gate's trusted builder from a request (no authority claims in the request)."""
    from gate import Gate, InMemoryProfileStore, StateProvider
    class _NoLive(StateProvider):
        # Authoring preview only: no live integration and no executor is registered.
        def kill_switch_allows(self, p): return None
        def credential_valid(self, i, at): return None
        def effect_target_in_class(self, et, c): return None
    prof = json.load(open(args.profile)); req = json.load(open(args.request))
    store = InMemoryProfileStore(); roots = {}
    if args.trust_pub:
        roots[args.key_id] = {"method": "ed25519", "public_key": bytes.fromhex(open(args.trust_pub).read().strip())}
    g = Gate(_NoLive(), store, secret=b"aam-cli", trust_roots=roots)
    pub = g.publish_profile(prof)
    if not pub["published"]:
        print("profile refused: " + "; ".join(pub["reasons"])); return 1
    out = g.propose(prof["profile_id"], req, args.now)
    if "manifest" in out:
        json.dump(out["manifest"], open(args.out, "w"), indent=2); print(f"wrote {args.out}")
    print(json.dumps({k: out["decision"].get(k) for k in ("decision", "violations", "unresolved_delegations", "reasons")}, indent=2))
    return 0


def cmd_keygen(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    open(args.out + ".key.hex", "w").write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
    open(args.out + ".pub.hex", "w").write(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    print(f"wrote {args.out}.key.hex (private, protect it) and {args.out}.pub.hex (trust root)")
    return 0


def cmd_sign(args):
    from gate import sign_profile_ed25519
    prof = json.load(open(args.profile))
    signed = sign_profile_ed25519(prof, bytes.fromhex(open(args.key).read().strip()), args.key_id)
    json.dump(signed, open(args.out or args.profile, "w"), indent=2)
    print(f"signed with {args.key_id}; profile digest {profile_digest(signed)}")
    return 0


def cmd_card(args):
    print(render_text(json.load(open(args.manifest))))
    return 0


def cmd_signoff(args):
    from readback_signoff import sign_readback
    profile = json.load(open(args.profile, encoding="utf-8"))
    resolved_feedback(profile, getattr(args, "feedback_policy", None))
    record = sign_readback(profile, part=args.part, principal=args.principal, role=args.role,
                          private_key_bytes=bytes.fromhex(open(args.key).read().strip()), key_id=args.key_id)
    with open(args.out, "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(f"wrote {args.out}; signature created, identity/role trust must be checked with verify-signoff")
    return 0


def cmd_verify_signoff(args):
    from readback_signoff import verify_readback_signoff, load_readback_trust_roots
    result = verify_readback_signoff(json.load(open(args.profile)), json.load(open(args.signoff)),
                                    load_readback_trust_roots(args.trust_roots))
    print(json.dumps(result, indent=2))
    return 0 if result['valid'] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aam")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init"); s.add_argument("--answers"); s.add_argument("--out"); s.add_argument("--profile-id"); s.add_argument("--version", default="1.0.0"); s.set_defaults(fn=cmd_init)
    s = sub.add_parser("readback"); s.add_argument("profile"); s.add_argument("--feedback-policy"); s.set_defaults(fn=cmd_readback)
    s = sub.add_parser("validate"); s.add_argument("file"); s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("check"); s.add_argument("profile"); s.add_argument("manifest"); s.add_argument("--now"); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("card"); s.add_argument("manifest"); s.set_defaults(fn=cmd_card)
    s = sub.add_parser("propose"); s.add_argument("profile"); s.add_argument("request"); s.add_argument("--out", default="manifest.json"); s.add_argument("--now"); s.add_argument("--trust-pub"); s.add_argument("--key-id", default="demo-profile-signing-2026"); s.set_defaults(fn=cmd_propose)
    s = sub.add_parser("keygen"); s.add_argument("--out", default="profile-signing"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("sign"); s.add_argument("profile"); s.add_argument("--key", required=True); s.add_argument("--key-id", required=True); s.add_argument("--out"); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("signoff"); s.add_argument("profile"); s.add_argument("--part", choices=["A", "B", "profile"], required=True); s.add_argument("--principal", required=True); s.add_argument("--role", choices=["product_owner", "engineering"], required=True); s.add_argument("--key", required=True); s.add_argument("--key-id", required=True); s.add_argument("--out", default="signoff.json"); s.add_argument("--feedback-policy"); s.set_defaults(fn=cmd_signoff)
    s = sub.add_parser("verify-signoff"); s.add_argument("profile"); s.add_argument("signoff"); s.add_argument("--trust-roots", required=True); s.set_defaults(fn=cmd_verify_signoff)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
