#!/usr/bin/env python3
"""
check_containment.py — deterministic policy check that an Action Manifest is contained
within an Agent Authority Profile. Draft 0.3.6.

Decision model (fail closed):
  ALLOW          every rule evaluated and passed; every delegated check resolved as passed
  DENY           at least one rule failed, or a delegated check was resolved as failed,
                 or an input was malformed
  INDETERMINATE  no rule failed, but at least one delegated check is unresolved
`executable` is True only for ALLOW. INDETERMINATE is never executable.

JSON Schema validates each document's shape. This module checks the cross-document
relationship. Checks it cannot evaluate structurally are returned in `delegated` with a
stable id; the caller (the gate) resolves them via `resolved_delegations={id: bool}`.
No external dependencies.
"""
import hashlib
import re
import json
import sys
from verification import verification_errors, render_verification_plan
from datetime import datetime, timezone

SEVERITY = ["low", "moderate", "high", "critical"]
MODES = ["recommend", "request_approval", "execute_allowlisted", "conditional_autonomy"]
VERIFICATION_INDEPENDENT = {"read_system_of_record", "independent_observation", "human_confirmation"}


class Malformed(Exception):
    pass


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def profile_digest(profile: dict) -> str:
    return digest({k: v for k, v in profile.items() if k != "integrity"})


def manifest_digest(manifest: dict) -> str:
    return digest({k: v for k, v in manifest.items() if k != "integrity"})


def request_digest(tool: str, operation: str, effect_target: dict, parameters: dict) -> str:
    """Digest of the material request; the executed request must reproduce it exactly."""
    return digest({"tool": tool, "operation": operation, "effect_target": effect_target, "parameters": parameters or {}})


def parse_time(s):
    if not isinstance(s, str) or not s:
        raise Malformed(f"timestamp missing or not a string: {s!r}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", s):
        raise Malformed(f"timestamp is not supported RFC3339: {s!r}")
    try:
        d = datetime.fromisoformat(s.upper().replace("Z", "+00:00"))
    except ValueError as e:
        raise Malformed(f"timestamp malformed: {s!r}") from e
    if d.tzinfo is None:
        raise Malformed(f"timestamp lacks timezone: {s!r}")
    return d.astimezone(timezone.utc)


def _rank(seq, v):
    """Rank in an ordered enum. Unknown values raise; they must never be treated as 'safer'."""
    if v not in seq:
        raise Malformed(f"unknown enum value {v!r}; expected one of {seq}")
    return seq.index(v)


def _wild(pattern, value):
    return pattern == "*" or pattern == value


def _constraint(key, cval, params):
    """Return (evaluated, ok, note)."""
    if key not in params:
        return True, False, f"parameter '{key}' required by constraint is absent"
    pval = params[key]
    if isinstance(cval, list):
        if isinstance(pval, list):
            return True, set(map(str, pval)).issubset(set(map(str, cval))), f"{key} ⊆ {cval}"
        return True, pval in cval, f"{key} ∈ {cval}"
    if isinstance(cval, bool) or isinstance(pval, bool):
        return True, pval == cval, f"{key} == {cval!r}"
    if isinstance(cval, (int, float)):
        if key.startswith("max_"):
            return True, isinstance(pval, (int, float)) and pval <= cval, f"{key} ≤ {cval}"
        return True, pval == cval, f"{key} == {cval}"
    if isinstance(cval, str):
        return True, pval == cval, f"{key} == {cval!r}"
    return False, True, f"constraint '{key}' has an opaque shape"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def check(profile: dict, manifest: dict, now: str | None = None, resolved_delegations: dict | None = None) -> dict:
    """Evaluate Manifest ⊆ Profile at time `now` (defaults to the real current UTC time, so an
    expired Manifest fails by default). Returns decision, violations, delegated, checks_passed."""
    v, delegated, passed = [], [], []
    resolved = resolved_delegations or {}
    level = profile.get("conformance", {}).get("level", "L0")
    enforcing = level in ("L1", "L2", "L3")

    def rule(name, cond, msg):
        (passed.append(name) if cond else v.append(f"{name}: {msg}"))

    def delegate(did, note):
        if did in resolved:
            (passed.append(f"{did} (resolved by gate)") if resolved[did] else v.append(f"{did}: resolved by gate as FAILED ({note})"))
        else:
            delegated.append({"id": did, "note": note})

    try:
        at = parse_time(now) if now else parse_time(utc_now_iso())
        pr = manifest["profile_ref"]
        at_ = manifest["action_target"]

        # C1 — profile reference, level, digest
        rule("C1 profile_id", pr["profile_id"] == profile["profile_id"], "references a different profile_id")
        rule("C1 profile_version", pr["profile_version"] == profile["profile_version"], "references a different profile_version")
        rule("C1 conformance_level", pr["conformance_level"] == profile["conformance"]["level"], "claims a level the profile does not declare")
        if "profile_digest" in pr:
            rule("C1 profile_digest", pr["profile_digest"] == profile_digest(profile), "profile_digest does not match canonical profile body")
        else:
            delegate("C1.profile_integrity", "no profile_digest supplied; gate must verify profile integrity by another means")

        # C2 — review window and profile expiry (execution authority is separate; see gate)
        issued, rev_exp = parse_time(manifest["issued_at"]), parse_time(manifest["review_expires_at"])
        rule("C2 review_window", rev_exp > issued, "review_expires_at must be after issued_at")
        max_rev = profile["authority_scope"]["max_review_window_minutes"]
        rule("C2 max_review_window", (rev_exp - issued).total_seconds() / 60 <= max_rev, f"review window exceeds profile max of {max_rev} minutes")
        rule("C2 within_review_window", issued <= at < rev_exp, "manifest is outside its review window at evaluation time")
        if "expires_at" in profile:
            rule("C2 profile_not_expired", at < parse_time(profile["expires_at"]), "profile has expired")
        else:
            passed.append("C2 profile_not_expired")

        # C3 — identity equality
        pi, mi = profile["identity"], manifest["identity"]
        rule("C3 agent", (pi["agent_name"], pi["agent_version"]) == (mi["agent_name"], mi["agent_version"]), "agent name/version differs")
        rule("C3 model", pi["model"] == mi["model"], "model differs from profile")
        rule("C3 prompt.version", pi["prompt"]["version"] == mi["prompt"]["version"], "prompt version differs")
        rule("C3 policy.version", pi["policy"]["version"] == mi["policy"]["version"], "policy version differs")
        if "hash" in pi["prompt"]:
            rule("C3 prompt.hash", mi["prompt"].get("hash") == pi["prompt"]["hash"], "prompt hash differs or missing")
        if "hash" in pi["policy"]:
            rule("C3 policy.hash", mi["policy"].get("hash") == pi["policy"]["hash"], "policy hash differs or missing (pinned in profile)")

        # C4 — scope, subject, and effect target within profile
        ps, ms = profile["authority_scope"], manifest["scope_claim"]
        rule("C4 tenant", ps.get("tenant") == ms.get("tenant"), "tenant differs")
        rule("C4 environment", ps["environment"] == ms["environment"], "environment differs")
        rule("C4 systems", set(ms["systems"]).issubset(set(ps["systems"])), f"systems {sorted(set(ms['systems']) - set(ps['systems']))} outside profile")
        for label, tgt in (("subject", at_.get("subject")), ("effect_target", at_["effect_target"])):
            if not tgt:
                continue
            if tgt.get("system"):
                rule(f"C4 {label}.system", tgt["system"] in ps["systems"], f"{label} system '{tgt['system']}' outside profile systems")
            specs = [t for t in ps["targets"] if t["type"] == tgt["type"]]
            rule(f"C4 {label}.type", bool(specs), f"{label} type '{tgt['type']}' not declared in profile targets")
            if specs:
                spec = specs[0]
                if "identifiers" in spec:
                    rule(f"C4 {label}.identifier", tgt["identifier"] in spec["identifiers"], f"{label} '{tgt['identifier']}' not in profile enumeration for type '{tgt['type']}'")
                elif "selector" in spec:
                    enf = spec.get("enforcement")
                    if enforcing and enf != "typed":
                        rule(f"C4 {label}.selector_enforcement", False, f"at {level} a target selector must be typed (selector_id) or the targets enumerated; '{spec['selector']}' is {enf or 'undeclared'}")
                    elif enf == "typed":
                        delegate(f"C4.{label}.selector:{spec.get('selector_id', '?')}", f"evaluate '{tgt['identifier']}' against typed selector '{spec.get('selector_id')}'")
                    else:
                        delegate(f"C4.{label}.selector", f"evaluate '{tgt['identifier']}' against free-text selector '{spec['selector']}' (L0: not enforced)")
                else:
                    rule(f"C4 {label}.identifier", False, "profile target spec has neither identifiers nor selector")

        # C5 — allowlisted operation, parameters, constraints, effect-target class, material parameters
        allowed = [a for a in profile["permissions"]["allowed"] if a["tool"] == at_["tool"] and a["operation"] == at_["operation"]]
        rule("C5 operation_allowed", bool(allowed), f"{at_['tool']}.{at_['operation']} is not allowlisted (default deny)")
        if allowed:
            entry = allowed[0]
            params = at_.get("parameters") or {}
            known = set(entry.get("allowed_parameters") or []) | set((entry.get("constraints") or {}).keys())
            unknown = sorted(set(params.keys()) - known)
            rule("C5 unknown_parameters", not unknown, f"parameters {unknown} not declared for this operation (default deny)")
            for key, cval in (entry.get("constraints") or {}).items():
                evaluated, ok, note = _constraint(key, cval, params)
                if evaluated:
                    rule(f"C5 constraint {key}", ok, f"not satisfied ({note})")
                else:
                    delegate(f"C5.constraint.{key}", note)
            if "max_mode" in entry:
                rule("C5 operation_max_mode", _rank(MODES, manifest["autonomy_approval"]["mode"]) <= _rank(MODES, entry["max_mode"]), f"mode exceeds operation max_mode {entry['max_mode']}")
            et_spec, et = entry.get("effect_target"), at_["effect_target"]
            if et_spec:
                rule("C5 effect_target.type", et["type"] == et_spec["type"], f"effect target type '{et['type']}' differs from operation's declared type '{et_spec['type']}'")
                if "identifiers" in et_spec:
                    rule("C5 effect_target.identifier", et["identifier"] in et_spec["identifiers"], "effect target not in operation's identifier list")
                if "classes" in et_spec:
                    rule("C5 effect_target.class", et.get("class") in et_spec["classes"], f"effect target class '{et.get('class')}' not permitted for this operation")
                    delegate("C5.effect_target.class_membership", f"verify that '{et['identifier']}' is actually a member of class '{et.get('class')}' at execution time")
            if entry.get("privileges_required"):
                rule("C5 privileges_required", set(entry["privileges_required"]).issubset(set(manifest["credentials"]["privileges"])) and set(manifest["credentials"]["privileges"]).issubset(set(entry["privileges_required"])), "manifest privileges must equal the operation's declared least-privilege set")
            mat_names = entry.get("material_parameters") or []
            mp = {m["name"]: m["value"] for m in manifest["action_target"].get("material_parameters", [])}
            for name in mat_names:
                rule(f"C5 material {name}", name in mp and mp[name] == params.get(name), f"material parameter '{name}' missing from Card data or differs from parameters")
            for name in mp:
                rule(f"C5 material_known {name}", name in known, f"material parameter '{name}' is not a declared parameter")

        # C6 — prohibitions (wildcards on tool/operation; rules delegated); Card summary parity
        for i, pro in enumerate(profile["permissions"]["prohibited"]):
            if pro.get("tool") or pro.get("operation"):
                t_ok, o_ok = _wild(pro.get("tool", "*"), at_["tool"]), _wild(pro.get("operation", "*"), at_["operation"])
                rule(f"C6 prohibited[{i}]", not (t_ok and o_ok), f"operation matches prohibition: {pro['description']}")
            elif pro.get("rule"):
                enf = pro.get("enforcement")
                if enf == "typed":
                    delegate(f"C6.rule:{pro.get('rule_id', i)}", f"evaluate typed rule '{pro.get('rule_id')}' ({pro['description']})")
                elif enf == "documentation_only":
                    passed.append(f"C6 rule[{i}] documentation_only (NOT enforced by the gate): {pro['description']}")
                elif enforcing:
                    rule(f"C6 rule_enforcement[{i}]", False, f"at {level} a rule must declare enforcement typed (with rule_id) or documentation_only: {pro['description']}")
                else:
                    delegate(f"C6.rule[{i}]", f"evaluate free-text rule '{pro['rule']}' (L0)")
            else:
                if enforcing:
                    passed.append(f"C6 prohibited[{i}] descriptive only (NOT enforced by the gate): {pro['description']}")
                else:
                    delegate(f"C6.descriptive[{i}]", f"map descriptive prohibition to a machine check: {pro['description']}")
        def _enforced(p):
            return bool(p.get("tool") or p.get("operation")) or (bool(p.get("rule")) and p.get("enforcement") == "typed")
        enforced = [p["description"] for p in profile["permissions"]["prohibited"] if _enforced(p)]
        documented = [p["description"] for p in profile["permissions"]["prohibited"] if not _enforced(p)]
        rule("C6 not_permitted_summary", manifest.get("not_permitted_summary") == enforced, "Card's 'can never' list must equal exactly the ENFORCED prohibitions")
        rule("C6 documented_not_enforced", manifest.get("documented_not_enforced") == documented, "Card's 'stated, not enforced' list must equal exactly the unenforced prohibitions")

        # C7 — impact within envelope
        pe, mimp = profile["impact_envelope"], manifest["impact"]
        rule("C7 domains", set(mimp["domains"]).issubset(set(pe["allowed_domains"])), "impact domains outside envelope")
        rule("C7 severity", _rank(SEVERITY, mimp["severity"]) <= _rank(SEVERITY, pe["max_severity"]), f"severity {mimp['severity']} exceeds {pe['max_severity']}")
        rule("C7 max_affected_objects_present", "max_affected_objects" in mimp and "max_affected_objects" in pe, "object count missing from manifest impact or profile envelope; missing data is not zero")
        if "max_affected_objects" in mimp and "max_affected_objects" in pe:
            rule("C7 max_affected_objects", mimp["max_affected_objects"] <= pe["max_affected_objects"], "affected objects exceed envelope")
        rule("C7 blast_radius_present", bool(mimp.get("blast_radius")), "blast radius statement missing")
        rule("C7 irreversible", mimp["reversible"] or pe["irreversible_allowed"], "irreversible action but profile forbids irreversible actions")

        # C8 — autonomy and approval policy
        ap, aa, pap = profile["autonomy_policy"], manifest["autonomy_approval"], profile["approval_policy"]
        rule("C8 mode_le_max", _rank(MODES, aa["mode"]) <= _rank(MODES, ap["max_mode"]), f"mode {aa['mode']} exceeds profile max_mode")
        if aa["mode"] == "request_approval":
            rule("C8 approval_required", aa["approval_required"] is True, "request_approval mode requires approval_required=true")
        if aa.get("approver_roles"):
            rule("C8 approver_roles", set(aa["approver_roles"]).issubset(set(pap["approver_roles"])), "approver role outside policy")
        if f"{at_['tool']}.{at_['operation']}" in pap.get("dual_approval_for", []):
            rule("C8 dual_approval", aa.get("dual_approval_required") is True, "profile requires dual approval for this operation")
        if aa["approval_required"]:
            rule("C8 required_evidence", set(pap.get("required_evidence", [])).issubset(set(aa.get("required_evidence", []))), "manifest omits evidence classes the approver must see")
        if aa["mode"] in ("execute_allowlisted", "conditional_autonomy") and not aa["approval_required"]:
            op_name = f"{at_['tool']}.{at_['operation']}"
            entry_default = (allowed[0].get("default_mode") if allowed else None)
            if entry_default and _rank(MODES, aa["mode"]) <= _rank(MODES, entry_default):
                passed.append("C8 mode_at_or_below_operation_default")
            else:
                typed = [t for t in (ap.get("thresholds") or []) if isinstance(t, dict) and t.get("enforcement") == "typed" and _rank(MODES, t["mode"]) >= _rank(MODES, aa["mode"]) and (not t.get("operations") or op_name in t["operations"])]
                doc_only = [t for t in (ap.get("thresholds") or []) if isinstance(t, dict) and t.get("enforcement") != "typed"]
                if typed:
                    for t in typed:
                        delegate(f"C8.threshold:{t.get('threshold_id', '?')}", f"typed threshold '{t.get('threshold_id')}' must hold for {op_name} to run at {aa['mode']} without approval")
                elif enforcing:
                    rule("C8 typed_threshold_required", False, f"at {level} running {op_name} at {aa['mode']} above its default needs a typed threshold; {len(doc_only)} documentation_only threshold(s) cannot elevate autonomy")
                else:
                    delegate("C8.thresholds", "executing above the operation default without a typed threshold (L0)")

        # C9 — credentials
        pc, mc = profile["credentials_policy"], manifest["credentials"]
        rule("C9 identity", pc["identity"] == mc["identity"], "execution identity differs")
        rule("C9 privileges", set(mc["privileges"]).issubset(set(pc["privileges"])), "privileges exceed policy")
        rule("C9 ttl", mc["ttl_minutes"] <= pc["max_ttl_minutes"], "ttl exceeds policy")

        # C10 — data boundary
        pdb, mdb = profile["data_boundary"], manifest["data_boundary_claim"]
        rule("C10 model_hosting", pdb["model_hosting"] == mdb["model_hosting"], "inference location differs")
        eg = set(mdb.get("egress_fields", []))
        if pdb["egress_policy"] == "none":
            rule("C10 egress_none", not eg, "profile egress is none but manifest egresses fields")
        elif pdb["egress_policy"] == "allowlisted_fields":
            rule("C10 egress_allowlist", eg.issubset(set(pdb.get("egress_allowlist", []))), "egress fields not in allowlist")
        else:
            delegate(f"C10.egress_policy:{pdb['egress_policy']}", f"egress policy '{pdb['egress_policy']}' must be evaluated by the gate's StateProvider for fields {sorted(eg)}")
        rule("C10 never_egress", not (eg & set(pdb.get("never_egress", []))), "manifest egresses a never_egress field")

        # C11 — audit minimum
        rule("C11 records", set(profile["audit_policy"]["records"]).issubset(set(manifest["audit"]["records"])), "manifest omits required audit records")

        # C12 — emergency stop: snapshot must be allowed AND live state must be read by the gate
        ed = profile["emergency_disable"]
        rule("C12 snapshot_allowed", ed["execution_state"] == "allowed", "profile snapshot shows execution blocked")
        delegate("C12.live_state", f"read live state from '{ed.get('state_source', ed['mechanism'])}'")

        # C13 — recovery: executing modes need a tested path; 'tested' must be evidenced, not self-attested
        rp, mr = profile["recovery_policy"], manifest["recovery"]
        executing = aa["mode"] in ("execute_allowlisted", "conditional_autonomy")
        if rp["requires_tested_recovery_for_execution"] and executing:
            ref = mr.get("tested_evidence_ref") or ""
            evidenced = bool(mr.get("tested")) and ":" in ref and len(ref) > 8
            rule("C13 tested_recovery_evidenced", evidenced, "executing mode requires tested recovery with a resolvable evidence reference (scheme:identifier); self-attested tested=true is not accepted")
            if evidenced:
                if mr.get("last_tested"):
                    age = (at - parse_time(mr["last_tested"] + "T00:00:00Z")).days
                    rule("C13 recovery_test_not_future", age >= 0, f"recovery test date {mr['last_tested']} is in the future")
                    if rp.get("test_max_age_days") is not None:
                        rule("C13 recovery_test_age", 0 <= age <= rp["test_max_age_days"], f"recovery test is {age} days old, exceeds {rp['test_max_age_days']}")
                delegate("C13.recovery_evidence", f"resolve '{ref}': must exist, be a passed test of {at_['tool']}.{at_['operation']} recovery, and be within {rp.get('test_max_age_days', '?')} days")
        else:
            passed.append("C13 tested_recovery_evidenced")
        rule("C13 irreversible_consistent", mr["irreversible"] == (not mimp["reversible"]), "recovery.irreversible inconsistent with impact.reversible")
        rule("C13 owner", bool(mr.get("owner")), "recovery owner missing")

        # C14 — outcome verification must be independent of the tool's own return code
        tests = manifest["outcome_verification"].get("verification_tests", [])
        independent = [t for t in tests if t.get("method") in VERIFICATION_INDEPENDENT and t.get("assertion")]
        if pr["conformance_level"] in ("L2", "L3") or executing:
            rule("C14 independent_verification", bool(independent), "requires at least one verification test with an independent method and a concrete assertion; a tool return code is not outcome verification")
        else:
            passed.append("C14 independent_verification")

        plan_errors = verification_errors(manifest["outcome_verification"], "verification_tests")
        rule("C14 verification_plan", not plan_errors, "; ".join(plan_errors))
        if allowed and allowed[0].get("verification"):
            expected_plan = render_verification_plan(allowed[0]["verification"], at_)
            rule("C14 verification_binding", manifest["outcome_verification"] == expected_plan,
                 "verification plan, completion selection, or freshness differs from the Profile-derived plan")

        # C15 — untrusted sources declared
        ms_ = set(manifest["evidence"].get("untrusted_sources_present", []))
        rule("C15 untrusted_sources", ms_.issubset(set(profile["input_trust"]["untrusted_sources"])), "untrusted source not declared in profile")

        # C17 — built by a gate (callers never author authority)
        rule("C17 built_by", bool(manifest.get("built_by")), "manifest carries no builder identity; caller-authored manifests are not accepted")

        # C16 — request binding digest present and correct
        rd = request_digest(at_["tool"], at_["operation"], at_["effect_target"], at_.get("parameters") or {})
        rule("C16 request_digest", manifest.get("request_digest") == rd, "request_digest missing or does not match tool/operation/effect_target/parameters")

    except Malformed as e:
        v.append(f"C0 malformed: {e}")
    except (KeyError, TypeError) as e:
        v.append(f"C0 malformed: missing or mistyped field {e!r}")

    if v:
        decision = "DENY"
    elif delegated:
        decision = "INDETERMINATE"
    else:
        decision = "ALLOW"
    return {
        "decision": decision,
        "executable": decision == "ALLOW",
        "profile_digest": profile_digest(profile) if isinstance(profile, dict) else None,
        "manifest_digest": manifest_digest(manifest) if isinstance(manifest, dict) else None,
        "violations": v,
        "delegated": delegated,
        "checks_passed": passed,
    }


def main(argv):
    if len(argv) < 3:
        print("usage: check_containment.py <profile.json> <manifest.json> [now-iso8601]")
        return 2
    r = check(json.load(open(argv[1])), json.load(open(argv[2])), argv[3] if len(argv) > 3 else None)
    print(json.dumps(r, indent=2))
    return {"ALLOW": 0, "INDETERMINATE": 3, "DENY": 1}[r["decision"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
