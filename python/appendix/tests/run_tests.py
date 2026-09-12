#!/usr/bin/env python3
"""
run_tests.py — Agent Action Manifest reference implementation tests, draft 0.3.6.

Sections:
  1  Schemas (profiles, requests, gate-built manifests, lifecycle records) and ingress rejection
  2  Trusted builder: callers cannot author authority; manifests are reproducible from request + profile
  3  Containment tri-state and hardening negatives (C0–C17)
  4  Gate lifecycle: publish (signature) -> propose -> approve -> execute (adapter) -> verify (trusted)
  5  Attacks: replay, concurrency, mutation, expiry, revocation, forged/tampered records, principals, live races
  6  Adversarial regressions converted from the v0.3.3 external review (10 findings)
  7  Card and read-back: parity, tamper detection, completeness; Part A / Part B split
  8  Authoring CLI; determinism; conformance vectors

Run from appendix/: python tests/run_tests.py   (requires jsonschema; cryptography for ed25519)
"""
import copy, glob, json, os, sys, threading
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from check_containment import check, manifest_digest, profile_digest, request_digest, parse_time  # noqa: E402
from render_card import project, render_text, check_parity, coverage as card_coverage  # noqa: E402
from gate import StateProvider, Gate, InMemoryProfileStore, sign_profile_ed25519, sign_profile_hmac, schema_errors, PROFILE_V, MANIFEST_V, REQUEST_V, HAVE_ED25519  # noqa: E402
from evidence import make_observation, seal_attestation
from jsonschema import Draft202012Validator  # noqa: E402

LV = Draft202012Validator(json.load(open(os.path.join(ROOT, "schemas", "lifecycle-records.schema.json"))))
results = []
def ok(name, cond, detail=""): results.append((name, bool(cond), detail))

# ---------- fixtures
KEY_ID = "demo-profile-signing-2026"
PUB = bytes.fromhex(open(os.path.join(ROOT, "examples", "trust", "demo-profile-signing.pub.hex")).read().strip())
PRIV = bytes.fromhex(open(os.path.join(ROOT, "examples", "trust", "demo-profile-signing.key.hex")).read().strip())
ROOTS = {KEY_ID: {"method": "ed25519", "public_key": PUB}}
T = {"software": "2026-09-05T16:00:00Z", "business": "2026-09-05T14:10:00Z", "plant": "2026-09-05T16:20:00Z"}

def load_examples():
    out = {}
    for d in sorted(glob.glob(os.path.join(ROOT, "examples", "*"))):
        if not os.path.exists(os.path.join(d, "profile.json")):
            continue
        key = "software" if "software" in d else "business" if "business" in d else "plant"
        out[key] = (json.load(open(os.path.join(d, "profile.json"))), json.load(open(os.path.join(d, "request.json"))), json.load(open(os.path.join(d, "manifest.json"))))
    return out
X = load_examples()
ok("examples present", set(X) == {"software", "business", "plant"})

class Live(StateProvider):
    """A deployment that implements every predicate and can read every system of record. All green unless flipped."""
    def __init__(self):
        self.kill = self.cred = self.cls = self.rules = self.selectors = self.thresholds = self.auth = True
        self.evidence_ok = True; self.evidence_at = "2026-09-01T00:00:00Z"; self.egress = True
        self.observations = {}   # assertion -> bool ; None means unobservable
    def kill_switch_allows(self, p): return self.kill
    def credential_valid(self, i, at): return self.cred
    def effect_target_in_class(self, et, c): return self.cls
    def evaluate_rule(self, rid, p, m): return self.rules
    def evaluate_selector(self, sid, t, p): return self.selectors
    def evaluate_threshold(self, tid, p, m): return self.thresholds
    def egress_policy_permits(self, policy, fields, p): return self.egress
    def recovery_evidence(self, ref):
        if not self.evidence_ok or not ref.startswith("testrun:"): return None
        for k, (t, o) in {"repo-maintainer:2026-08-28#41": ("github", "open_pull_request"), "ap-agent:2026-08-30#7": ("email", "draft_email"), "ap-agent:2026-08-30#9": ("ticketing", "create_ticket"),
                          "change-response:2026-09-01#3": ("maintenance", "draft_work_order"), "change-response:2026-09-01#4": ("access_management", "request_access_revocation")}.items():
            if k in ref: return {"passed": True, "tool": t, "operation": o, "tested_at": self.evidence_at}
        return None
    def authenticated(self, p, a): return self.auth and bool(a)
    def observe(self, test, m, execution):
        value = self.observations.get(test["assertion"])
        return None if value is None else make_observation(execution, m, test["test_id"], value,
            "2026-09-05T14:15:00Z", source_version="synthetic-revision-1", evidence_ref="testrun:core:observation")

def mkgate(P, live=None, secret=b"test-secret"):
    store = InMemoryProfileStore(); g = Gate(live or Live(), store, secret=secret, trust_roots=ROOTS)
    pub = g.publish_profile(P)
    assert pub["published"], pub
    return g, store
JANE = [{"role": "ap_manager", "principal": "user:jane", "auth_ref": "sso:jane:1"}]
def with_executor(g, key):
    calls = []
    t, o = {"software": ("github", "open_pull_request"), "business": ("email", "draft_email"), "plant": ("maintenance", "draft_work_order")}[key]
    g.register_executor(t, o, lambda req: (calls.append(copy.deepcopy(req)) or {"status": "ok", "id": "x-1"}))
    return calls

# ============================================================ 1. schemas + ingress
for k, (P, R, M) in X.items():
    ok(f"schema profile   {k}", not schema_errors(PROFILE_V, P), "; ".join(schema_errors(PROFILE_V, P))[:200])
    ok(f"schema request   {k}", not schema_errors(REQUEST_V, R), "; ".join(schema_errors(REQUEST_V, R))[:200])
    ok(f"schema manifest  {k} (gate-built)", not schema_errors(MANIFEST_V, M), "; ".join(schema_errors(MANIFEST_V, M))[:200])
P0, R0, M0 = X["business"]
def profile_rejected(mut, name):
    d = copy.deepcopy(P0); mut(d)
    g = Gate(Live(), InMemoryProfileStore(), b"k", trust_roots=ROOTS)
    ok(f"ingress rejects  {name}", not g.publish_profile(d)["published"])
profile_rejected(lambda d: d["permissions"].__setitem__("default_deny", False), "profile default_deny=false")
profile_rejected(lambda d: d["autonomy_policy"].__setitem__("max_mode", "root"), "profile unknown autonomy enum")
profile_rejected(lambda d: d["impact_envelope"].pop("max_affected_objects"), "profile envelope without object count")
profile_rejected(lambda d: d["permissions"]["allowed"][2].pop("impact"), "profile operation without impact binding")
profile_rejected(lambda d: d["permissions"]["allowed"][2].pop("verification"), "profile operation without verification binding")
profile_rejected(lambda d: d.pop("integrity"), "L2 profile without signature")
profile_rejected(lambda d: d["approval_policy"].__setitem__("approver_roles", ["ap_manager", "cfo"]), "L2 profile edited after signing (signature invalid)")
profile_rejected(lambda d: d["integrity"].__setitem__("key_id", "unknown-key"), "L2 profile signed by unknown key")
ok("ingress accepts  L0 profile without signature", Gate(Live(), InMemoryProfileStore(), b"k").publish_profile({**{k: v for k, v in P0.items() if k != "integrity"}, "conformance": {"level": "L0"}})["published"])
hm = sign_profile_hmac({k: v for k, v in P0.items() if k != "integrity"}, b"shared-root", "hmac-root")
ok("ingress rejects  HMAC-authenticated L2 Profile (Ed25519 required)", not Gate(Live(), InMemoryProfileStore(), b"k", trust_roots={"hmac-root": {"method": "hmac-sha256", "secret": b"shared-root"}}).publish_profile(hm)["published"])
ok("ingress rejects  hmac profile with wrong shared secret", not Gate(Live(), InMemoryProfileStore(), b"k", trust_roots={"hmac-root": {"method": "hmac-sha256", "secret": b"other"}}).publish_profile(hm)["published"])

# ============================================================ 2. trusted builder
for k, (P, R, M) in X.items():
    g, _ = mkgate(P)
    out = g.propose(P["profile_id"], R, T[k], manifest_id=M["manifest_id"])
    ok(f"builder          {k} reproduces the example Manifest from request + profile", manifest_digest(out["manifest"]) == manifest_digest(M), str(out["decision"].get("violations"))[:200])
    ok(f"builder          {k} decision ALLOW with full live provider", out["decision"]["decision"] == "ALLOW", str(out["decision"].get("violations") or out["decision"].get("unresolved_delegations"))[:200])
g, _ = mkgate(P0)
bad = dict(R0); bad["mode"] = "conditional_autonomy"; bad["credentials"] = {"identity": "root"}
ok("builder          request with authority claims is rejected at ingress", g.propose(P0["profile_id"], bad, T["business"])["decision"]["decision"] == "DENY")
narr = dict(R0); narr["summary"] = "Send payment to vendor now"
outn = g.propose(P0["profile_id"], narr, T["business"])
ok("builder          caller narrative cannot replace the operation summary; recorded as a conflict", outn["manifest"]["action_target"]["summary"].startswith("Draft (not send)") and any("agent narrative" in c for c in outn["manifest"]["evidence"]["unresolved_conflicts"]))
unk = dict(R0); unk["operation"] = "release_payment"
outu = g.propose(P0["profile_id"], unk, T["business"])
ok("builder          unknown operation is denied without publishing an invalid Manifest", outu["decision"]["decision"] == "DENY" and "manifest" not in outu)
outm = g.propose(P0["profile_id"], R0, T["business"])
ok("builder          Manifest carries built_by, gate seal, enforced/documented split", outm["manifest"]["built_by"] == g.gate_id and outm["manifest"]["integrity"]["method"] == "gate-hmac-sha256" and outm["manifest"]["not_permitted_summary"] and "documented_not_enforced" in outm["manifest"])

# ============================================================ 3. containment tri-state + negatives
for k, (P, R, M) in X.items():
    r = check(P, M, T[k]); ids = [d["id"] for d in r["delegated"]]
    ok(f"containment      {k} pure check is INDETERMINATE and not executable", r["decision"] == "INDETERMINATE" and not r["executable"] and not r["violations"], str(r["violations"])[:200])
    ok(f"containment      {k} ALLOW when all delegations resolved", check(P, M, T[k], resolved_delegations={i: True for i in ids})["decision"] == "ALLOW")
    ok(f"containment      {k} DENY when a delegation resolves failed", check(P, M, T[k], resolved_delegations={**{i: True for i in ids}, "C12.live_state": False})["decision"] == "DENY")
ok("containment      expired Manifest fails by default (real current time)", check(P0, M0)["decision"] == "DENY")
NEG = []
def neg(label, key, mut, expect):
    NEG.append((label, key, mut, expect))
    P, R, M = copy.deepcopy(X[key][0]), X[key][1], copy.deepcopy(X[key][2]); mut(P, M)
    r = check(P, M, T[key]); hit = any(v.startswith(expect) for v in r["violations"])
    ok(f"rejects          {label}", r["decision"] == "DENY" and hit, f"expected '{expect}'; got {r['violations'][:3]}")
def rebind(M):
    a = M["action_target"]; M["request_digest"] = request_digest(a["tool"], a["operation"], a["effect_target"], a.get("parameters") or {})
neg("unknown autonomy mode fails closed", "business", lambda p, m: m["autonomy_approval"].__setitem__("mode", "root"), "C0 malformed")
neg("unknown severity fails closed", "business", lambda p, m: m["impact"].__setitem__("severity", "none"), "C0 malformed")
neg("policy hash drift", "business", lambda p, m: m["identity"]["policy"].__setitem__("hash", "sha256:policy-B"), "C3 policy.hash")
neg("prompt hash drift", "business", lambda p, m: m["identity"]["prompt"].__setitem__("hash", "sha256:x"), "C3 prompt.hash")
neg("model drift", "business", lambda p, m: m["identity"]["model"].__setitem__("identifier", "<model@2026-07>"), "C3 model")
neg("missing object count is not zero", "business", lambda p, m: m["impact"].pop("max_affected_objects"), "C7 max_affected_objects_present")
neg("missing blast radius", "business", lambda p, m: m["impact"].__setitem__("blast_radius", ""), "C7 blast_radius_present")
neg("object count above envelope", "plant", lambda p, m: m["impact"].__setitem__("max_affected_objects", 5), "C7 max_affected_objects")
neg("severity above envelope", "software", lambda p, m: m["impact"].__setitem__("severity", "critical"), "C7 severity")
neg("domain outside envelope", "software", lambda p, m: m["impact"]["domains"].append("financial"), "C7 domains")
neg("irreversible not allowed", "software", lambda p, m: (m["impact"].update({"reversible": False, "irreversibility_notes": "n/a"}), m["recovery"].__setitem__("irreversible", True)), "C7 irreversible")
neg("effect target type not in profile targets", "business", lambda p, m: (m["action_target"]["effect_target"].update({"type": "phone_number"}), rebind(m)), "C4 effect_target.type")
neg("asset outside enumeration", "plant", lambda p, m: (m["action_target"]["subject"].update({"identifier": "Asset-99"}), m["scope_claim"].__setitem__("assets", ["Asset-99"])), "C4 subject.identifier")
neg("system outside scope", "business", lambda p, m: m["scope_claim"]["systems"].append("payments"), "C4 systems")
neg("operation not allowlisted", "software", lambda p, m: (m["action_target"].__setitem__("operation", "close_repo"), rebind(m)), "C5 operation_allowed")
neg("unknown parameter", "business", lambda p, m: (m["action_target"]["parameters"].__setitem__("cc", "cfo@acme.example"), rebind(m)), "C5 unknown_parameters")
neg("constraint violated", "business", lambda p, m: (m["action_target"]["parameters"].__setitem__("max_recipients", 4), rebind(m)), "C5 constraint max_recipients")
neg("effect target class not permitted", "business", lambda p, m: (m["action_target"]["effect_target"].update({"class": "any_external"}), rebind(m)), "C5 effect_target.class")
neg("privileges beyond operation's least-privilege set", "business", lambda p, m: m["credentials"]["privileges"].append("erp.ap:status_write"), "C5 privileges_required")
neg("material parameter differs from actual", "business", lambda p, m: m["action_target"]["material_parameters"][3].__setitem__("value", 3), "C5 material variance_usd")
neg("wildcard prohibition control_system.*", "plant", lambda p, m: (m["action_target"].update({"tool": "control_system", "operation": "write_setpoint"}), p["permissions"]["allowed"].append({"tool": "control_system", "operation": "write_setpoint"}), rebind(m)), "C6 prohibited")
neg("prohibition wins over allowlist", "business", lambda p, m: (p["permissions"]["allowed"].append({"tool": "erp.ap", "operation": "release_payment"}), m["action_target"].update({"tool": "erp.ap", "operation": "release_payment"}), rebind(m)), "C6 prohibited")
neg("'can never' list includes an unenforced rule", "business", lambda p, m: (p["permissions"]["prohibited"][3].__setitem__("enforcement", "documentation_only"),), "C6 not_permitted_summary")
neg("'stated, not enforced' list drifted", "business", lambda p, m: m["documented_not_enforced"].append("Never use subject URGENT"), "C6 documented_not_enforced")
neg("L1+ rule without enforcement kind", "business", lambda p, m: p["permissions"]["prohibited"][3].pop("enforcement"), "C6 rule_enforcement")
neg("L1+ selector without enforcement kind", "business", lambda p, m: p["authority_scope"]["targets"][1].pop("enforcement"), "C4 effect_target.selector_enforcement")
neg("executing above default without typed threshold", "business", lambda p, m: (p["autonomy_policy"].__setitem__("thresholds", [{"description": "free text", "enforcement": "documentation_only", "mode": "execute_allowlisted"}]), m["autonomy_approval"].update({"mode": "execute_allowlisted", "approval_required": False}), [m["autonomy_approval"].pop(k, None) for k in ("approver_roles", "required_evidence", "dual_approval_required", "approval_timeout_minutes")]), "C8 typed_threshold_required")
neg("mode above profile max", "plant", lambda p, m: (m["autonomy_approval"].update({"mode": "execute_allowlisted", "approval_required": False}), [m["autonomy_approval"].pop(k, None) for k in ("approver_roles", "required_evidence", "dual_approval_required", "approval_timeout_minutes")]), "C5 operation_max_mode")
neg("dual approval omitted for revocation", "plant", lambda p, m: (m["action_target"].update({"tool": "access_management", "operation": "request_access_revocation", "effect_target": {"type": "vendor_session", "identifier": "VS-8831", "system": "access_management"}, "parameters": {"session": "VS-8831", "reason": "x"}, "material_parameters": [{"name": "session", "value": "VS-8831", "label": "Session"}, {"name": "reason", "value": "x", "label": "Reason"}]}), m["scope_claim"]["systems"].append("access_management"), m["credentials"].__setitem__("privileges", ["access_management:request"]), rebind(m)), "C8 dual_approval")
neg("ttl exceeds policy", "software", lambda p, m: m["credentials"].__setitem__("ttl_minutes", 600), "C9 ttl")
neg("identity mismatch", "business", lambda p, m: m["credentials"].__setitem__("identity", "human:jane"), "C9 identity")
neg("never-egress field", "plant", lambda p, m: m["data_boundary_claim"]["egress_fields"].append("raw_process_values"), "C10 never_egress")
neg("egress under policy none", "business", lambda p, m: m["data_boundary_claim"]["egress_fields"].append("invoice_text"), "C10 egress_none")
neg("inference location drift", "business", lambda p, m: m["data_boundary_claim"].__setitem__("model_hosting", "hosted"), "C10 model_hosting")
neg("audit below minimum", "software", lambda p, m: m["audit"].__setitem__("records", ["tool_calls"]), "C11 records")
neg("kill switch snapshot blocked", "business", lambda p, m: p["emergency_disable"].__setitem__("execution_state", "blocked"), "C12 snapshot_allowed")
neg("self-attested recovery in executing mode", "software", lambda p, m: m["recovery"].pop("tested_evidence_ref"), "C13 tested_recovery_evidenced")
neg("evidence ref is arbitrary text", "software", lambda p, m: m["recovery"].__setitem__("tested_evidence_ref", "yes we tested it"), "C13 tested_recovery_evidenced")
neg("future-dated recovery test date", "software", lambda p, m: m["recovery"].__setitem__("last_tested", "2026-10-01"), "C13 recovery_test_not_future")
neg("stale recovery test", "software", lambda p, m: m["recovery"].__setitem__("last_tested", "2025-01-01"), "C13 recovery_test_age")
neg("only tool return code as verification", "business", lambda p, m: m["outcome_verification"].__setitem__("verification_tests", [{"method": "tool_return_code", "source": "email", "assertion": "HTTP 200"}]), "C14 independent_verification")
neg("undeclared untrusted source", "business", lambda p, m: m["evidence"]["untrusted_sources_present"].append("chat_transcript"), "C15 untrusted_sources")
neg("stale request digest", "business", lambda p, m: m["action_target"]["parameters"].__setitem__("variance_usd", 31200), "C16 request_digest")
neg("no builder identity", "business", lambda p, m: m.pop("built_by"), "C17 built_by")
neg("review window exceeds profile max", "plant", lambda p, m: m.__setitem__("review_expires_at", "2026-09-06T16:20:00Z"), "C2 max_review_window")
neg("malformed issued_at", "business", lambda p, m: m.__setitem__("issued_at", "yesterday"), "C0 malformed")
neg("timestamp without timezone", "business", lambda p, m: m.__setitem__("review_expires_at", "2026-09-05T14:35:00"), "C0 malformed")
Pd, Md = copy.deepcopy(P0), copy.deepcopy(M0); Pd["permissions"]["prohibited"][3]["enforcement"] = "documentation_only"
Md["not_permitted_summary"] = [x["description"] for x in Pd["permissions"]["prohibited"] if x is not Pd["permissions"]["prohibited"][3]]
Md["documented_not_enforced"] = [Pd["permissions"]["prohibited"][3]["description"]]
Md["profile_ref"]["profile_digest"] = profile_digest(Pd)
rd = check(Pd, Md, T["business"])
ok("rules            documentation_only rule accepted only when listed as NOT enforced", rd["decision"] != "DENY" and any("NOT enforced" in c for c in rd["checks_passed"]), str(rd["violations"])[:200])
ok("rules            documentation_only prohibition never appears under 'can never' on the Card", "Never use subject" not in "".join(project(Md)["cannot_do"]) and (render_text(Md).find("Stated in the Profile but NOT enforced") > 0))

# ============================================================ 4. gate lifecycle (AP)
P, R, M = X["business"]
g, store = mkgate(P); calls = with_executor(g, "business")
out = g.propose(P["profile_id"], R, "2026-09-05T14:10:00Z"); m, d = out["manifest"], out["decision"]
ok("gate             propose -> ALLOW, execution window, bound to Profile digest", d["decision"] == "ALLOW" and "execution_valid_until" in d and d["profile_digest"] == profile_digest(P), str(d.get("violations") or d.get("unresolved_delegations"))[:200])
ok("schema record    GateDecision", not list(LV.iter_errors(d)), "; ".join(e.message for e in LV.iter_errors(d))[:200])
apr = g.record_approval(m["manifest_id"], JANE, "2026-09-05T14:13:00Z")
ok("schema record    ApprovalRecord", not list(LV.iter_errors(apr)), "; ".join(e.message for e in LV.iter_errors(apr))[:200])
ex = g.execute(m["manifest_id"], apr["approval_id"], "2026-09-05T14:14:00Z")
ok("gate             execute -> ALLOW; executor called once with the canonical material request", ex["decision"] == "ALLOW" and len(calls) == 1 and request_digest(calls[0]["tool"], calls[0]["operation"], calls[0]["effect_target"], calls[0]["parameters"]) == m["request_digest"] and ex["executed_request_digest"] == m["request_digest"], str(ex["reasons"]))
ok("schema record    ExecutionRecord", not list(LV.iter_errors(ex)), "; ".join(e.message for e in LV.iter_errors(ex))[:200])
ok("gate             receipt recorded from executor", ex["receipt"] == {"status": "ok", "id": "x-1"})
g.state.observations = {t["assertion"]: True for t in m["outcome_verification"]["verification_tests"]}
ov = g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z")
ok("gate             outcome verified from system-of-record reads", ov["verified"] and ov["completion"] == "complete" and all(r["observed_via"] == "system_of_record_read" for r in ov["results"]))
ok("schema record    OutcomeVerificationRecord", not list(LV.iter_errors(ov)), "; ".join(e.message for e in LV.iter_errors(ov))[:200])
g.state.observations = {m["outcome_verification"]["verification_tests"][0]["assertion"]: True, m["outcome_verification"]["verification_tests"][1]["assertion"]: False}
ov2 = g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z")
ok("gate             tool success is not outcome success (one post-condition false -> reopen)", not ov2["verified"] and ov2["completion"] == "reopen")
g.state.observations = {}
ov3 = g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z")
ok("gate             unobservable post-conditions do not verify", not ov3["verified"] and all(r["observed_via"] == "unobserved" for r in ov3["results"]))
g.register_verifier("verifier-a", b"verifier-secret", sources=[t["source"] for t in m["outcome_verification"]["verification_tests"]], methods=["read_system_of_record"])
atts = [seal_attestation(make_observation(ex, m, t["test_id"], True, "2026-09-05T14:15:00Z", source_version="synthetic-revision-1", evidence_ref="testrun:core:attestation"), "verifier-a", b"verifier-secret") for t in m["outcome_verification"]["verification_tests"]]
ov4 = g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z", attestations=atts)
ok("gate             sealed verifier attestations accepted when the gate cannot observe", ov4["verified"] and all(r["observed_via"] == "verifier_attestation" for r in ov4["results"]))
forged = [dict(a, observed=True, seal="00" * 32) for a in atts]
ok("gate             unsealed/forged attestations ignored", not g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z", attestations=forged)["verified"])
ok("gate             verify_outcome for a forged execution id is not verified", not g.verify_outcome("made-up", "2026-09-05T14:15:00Z")["verified"])

class Mute(StateProvider):
    def kill_switch_allows(self, p): return True
    def credential_valid(self, i, at): return True
    def effect_target_in_class(self, et, c): return True
    def authenticated(self, p, a): return True
gm, _ = mkgate(P, Mute()); outm = gm.propose(P["profile_id"], R, "2026-09-05T14:10:00Z")
ok("gate             unresolved typed selector/rule -> INDETERMINATE, no execution window", outm["decision"]["decision"] == "INDETERMINATE" and "execution_valid_until" not in outm["decision"])
am = gm.record_approval(outm["manifest"]["manifest_id"], JANE, "2026-09-05T14:13:00Z"); with_executor(gm, "business")
ok("gate             INDETERMINATE cannot be executed", gm.execute(outm["manifest"]["manifest_id"], am["approval_id"], "2026-09-05T14:14:00Z")["decision"] == "INDETERMINATE")

# executing mode without approval (software)
Ps, Rs, Ms = X["software"]; gs, _ = mkgate(Ps); cs = with_executor(gs, "software")
os_ = gs.propose(Ps["profile_id"], Rs, "2026-09-05T16:00:00Z")
ok("gate             execute_allowlisted via typed threshold -> ALLOW, no approval needed", os_["decision"]["decision"] == "ALLOW" and gs.execute(os_["manifest"]["manifest_id"], None, "2026-09-05T16:02:00Z")["decision"] == "ALLOW" and len(cs) == 1, str(os_["decision"].get("violations") or os_["decision"].get("unresolved_delegations")))
Pq = copy.deepcopy({k: v for k, v in Ps.items() if k != "integrity"})
next(a for a in Pq["permissions"]["allowed"] if a["operation"] == "open_pull_request")["default_mode"] = "request_approval"
Pq = sign_profile_ed25519(Pq, PRIV, KEY_ID)
gq, _ = mkgate(Pq); oq = gq.propose(Pq["profile_id"], Rs, "2026-09-05T16:00:00Z")
ok("gate             typed threshold true elevates default request_approval to execute_allowlisted", oq["manifest"]["autonomy_approval"]["mode"] == "execute_allowlisted" and not oq["manifest"]["autonomy_approval"]["approval_required"])
gq2, _ = mkgate(Pq); gq2.state.thresholds = False; oq2 = gq2.propose(Pq["profile_id"], Rs, "2026-09-05T16:00:00Z")
ok("gate             threshold false -> builder keeps request_approval", oq2["manifest"]["autonomy_approval"]["mode"] == "request_approval" and oq2["manifest"]["autonomy_approval"]["approval_required"])
Pq3 = copy.deepcopy({k: v for k, v in Pq.items() if k != "integrity"}); Pq3["autonomy_policy"]["thresholds"][0]["enforcement"] = "documentation_only"; Pq3 = sign_profile_ed25519(Pq3, PRIV, KEY_ID)
gq3, _ = mkgate(Pq3); oq3 = gq3.propose(Pq3["profile_id"], Rs, "2026-09-05T16:00:00Z")
ok("gate             documentation_only threshold never elevates autonomy", oq3["manifest"]["autonomy_approval"]["mode"] == "request_approval")

# ============================================================ 5. attacks
def fresh(live=None):
    P, R, M = X["business"]; g, st = mkgate(P, live); calls = with_executor(g, "business")
    out = g.propose(P["profile_id"], R, "2026-09-05T14:10:00Z"); a = g.record_approval(out["manifest"]["manifest_id"], JANE, "2026-09-05T14:13:00Z")
    return P, out["manifest"], g, st, a, calls
NOW = "2026-09-05T14:14:00Z"

P, m, g, st, a, calls = fresh()
e1 = g.execute(m["manifest_id"], a["approval_id"], NOW); e2 = g.execute(m["manifest_id"], a["approval_id"], "2026-09-05T14:14:30Z")
ok("attack           approval replay denied; executor called once", e1["decision"] == "ALLOW" and e2["decision"] == "DENY" and any("replay" in x for x in e2["reasons"]) and len(calls) == 1)

P, m, g, st, a, calls = fresh(); outcomes = []
ts = [threading.Thread(target=lambda: outcomes.append(g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"])) for _ in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
ok("attack           concurrent execute -> exactly one ALLOW, one executor call", outcomes.count("ALLOW") == 1 and len(calls) == 1, str(outcomes))

P, m, g, st, a, calls = fresh()
g._manifests[m["manifest_id"]]["action_target"]["parameters"]["variance_usd"] = 31200      # tamper with the gate's stored manifest
ok("attack           tampered stored Manifest fails its gate seal", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY" and len(calls) == 0)

P, m, g, st, a, calls = fresh()
ok("attack           execution after review window denied", g.execute(m["manifest_id"], a["approval_id"], "2026-09-06T15:00:00Z")["decision"] == "DENY")

P, m, g, st, a, calls = fresh(); g.state.kill = False
ok("attack           kill switch flipped before execution denied", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY" and not calls)
P, m, g, st, a, calls = fresh(); g.state.rules = False
ok("attack           typed rule flipped before execution denied", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY")
P, m, g, st, a, calls = fresh(); g.state.selectors = False
ok("attack           typed selector flipped before execution denied", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY")
P, m, g, st, a, calls = fresh(); g.state.cls = False
ok("attack           effect target left class before execution denied", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY")
P, m, g, st, a, calls = fresh(); g.state.cred = False
ok("attack           credential invalid at execution denied", g.execute(m["manifest_id"], a["approval_id"], NOW)["decision"] == "DENY")
P, m, g, st, a, calls = fresh(); st.revoke(P["profile_id"])
ok("attack           Profile revoked after approval -> denied", any("not active" in x for x in g.execute(m["manifest_id"], a["approval_id"], NOW)["reasons"]))
P, m, g, st, a, calls = fresh(); P2 = copy.deepcopy(P); P2["approval_policy"]["approval_timeout_minutes"] = 5; st.publish(P2)   # bypass ingress on purpose
ok("attack           Profile body changed after approval -> denied", any("digest" in x for x in g.execute(m["manifest_id"], a["approval_id"], NOW)["reasons"]))
P, m, g, st, a, calls = fresh()
ok("attack           unknown approval id denied", g.execute(m["manifest_id"], "approval-i-made-up", NOW)["decision"] == "DENY")
g._approvals[a["approval_id"]]["record"]["approved_by"] = [{"role": "ap_manager", "principal": "user:mallory", "auth_ref": "x"}]
ok("attack           tampered stored approval fails seal", any("seal invalid" in x for x in g.execute(m["manifest_id"], a["approval_id"], NOW)["reasons"]))
P, m, g, st, a, calls = fresh()
a2 = g.record_approval(m["manifest_id"], [{"role": "ap_manager", "principal": "svc:ap-agent", "auth_ref": "sso:x"}], "2026-09-05T14:13:00Z")
ok("attack           agent approving itself denied", any("own execution identity" in x for x in g.execute(m["manifest_id"], a2["approval_id"], NOW)["reasons"]))
a3 = g.record_approval(m["manifest_id"], [{"role": "finance_controller", "principal": "user:cfo", "auth_ref": "sso:cfo:1"}], "2026-09-05T14:13:00Z")
ok("attack           role allowed by Profile but not by Manifest's narrowed set denied", any("required set" in x for x in g.execute(m["manifest_id"], a3["approval_id"], NOW)["reasons"]))
a4 = g.record_approval(m["manifest_id"], [{"role": "ap_manager", "principal": "user:jane"}], "2026-09-05T14:13:00Z")
ok("attack           unauthenticated approver denied", any("not an authenticated principal" in x for x in g.execute(m["manifest_id"], a4["approval_id"], NOW)["reasons"]))
a5 = g.record_approval(m["manifest_id"], JANE, "2026-09-04T09:00:00Z")
ok("attack           approval outside review window denied", g.execute(m["manifest_id"], a5["approval_id"], NOW)["decision"] == "DENY")
ok("attack           approval required but missing denied", g.execute(m["manifest_id"], None, NOW)["decision"] == "DENY")
ok("attack           malformed now fails closed", g.execute(m["manifest_id"], a["approval_id"], "soon")["decision"] == "DENY")
ok("attack           propose with malformed now fails closed", g.propose(P["profile_id"], R0, "soon")["decision"]["decision"] == "DENY")
ok("attack           execute of a Manifest not built by this gate denied", g.execute("aam:acme:invoice-triage:someone-elses", a["approval_id"], NOW)["decision"] == "DENY")
g2 = Gate(Live(), st, b"other-gate-secret", gate_id="reference-gate/0.3.6", trust_roots=ROOTS); g2._manifests[m["manifest_id"]] = copy.deepcopy(m)
ok("attack           Manifest imported into another gate fails that gate's seal", g2.execute(m["manifest_id"], None, NOW)["decision"] == "DENY")
P, m, g, st, a, calls = fresh()
g._executors.clear()
ok("attack           no registered executor -> DENY (gate never hands out authorization)", any("no executor" in x for x in g.execute(m["manifest_id"], a["approval_id"], NOW)["reasons"]))
P, m, g, st, a, calls = fresh()
g.register_executor("email", "draft_email", lambda r: (_ for _ in ()).throw(RuntimeError("smtp down")))
exf = g.execute(m["manifest_id"], a["approval_id"], NOW)
ok("attack           executor exception preserves authorization and records EXECUTION_UNKNOWN", exf["authorization_decision"] == "ALLOW" and exf["execution_state"] == "EXECUTION_UNKNOWN" and exf["reconciliation_required"])

# dual approval (plant revocation)
Pp, Rp, Mp = X["plant"]
Rrev = {"action_id": "vs8831-hold", "tool": "access_management", "operation": "request_access_revocation", "effect_target": {"type": "vendor_session", "identifier": "VS-8831", "system": "access_management", "display": "vendor session VS-8831"},
        "parameters": {"session": "VS-8831", "reason": "anomalous post-change vibration"}, "evidence_refs": ["pam_session:VS-8831", "historian:Asset-12:vibration-window"], "untrusted_sources_present": ["session_metadata_free_text"]}
gp, _ = mkgate(Pp); gp.register_executor("access_management", "request_access_revocation", lambda r: {"held": r["parameters"]["session"]})
op = gp.propose(Pp["profile_id"], Rrev, "2026-09-05T16:21:00Z"); mp = op["manifest"]
ok("dual             revocation Manifest requires dual approval and evaluates ALLOW", mp["autonomy_approval"]["dual_approval_required"] and op["decision"]["decision"] == "ALLOW", str(op["decision"].get("violations") or op["decision"].get("unresolved_delegations")))
same = gp.record_approval(mp["manifest_id"], [{"role": "plant_owner", "principal": "user:sam", "auth_ref": "sso:sam:1"}, {"role": "controls_owner", "principal": "user:sam", "auth_ref": "sso:sam:2"}], "2026-09-05T16:22:00Z")
ok("dual             two roles, same principal -> denied", any("distinct authenticated principals" in x for x in gp.execute(mp["manifest_id"], same["approval_id"], "2026-09-05T16:23:00Z")["reasons"]))
two = gp.record_approval(mp["manifest_id"], [{"role": "plant_owner", "principal": "user:sam", "auth_ref": "sso:sam:1"}, {"role": "controls_owner", "principal": "user:lee", "auth_ref": "sso:lee:1"}], "2026-09-05T16:22:00Z")
ok("dual             two distinct authenticated principals -> ALLOW", gp.execute(mp["manifest_id"], two["approval_id"], "2026-09-05T16:23:00Z")["decision"] == "ALLOW")

# ============================================================ 6. adversarial regressions (v0.3.3 external review)
P, m, g, st, a, calls = fresh()
bad_req = dict(R0); bad_req["parameters"] = dict(R0["parameters"]); bad_req["mode"] = "root"
ok("adv-1            unknown autonomy mode cannot be injected (request schema rejects; checker fails closed)", g.propose(P["profile_id"], bad_req, "2026-09-05T14:10:00Z")["decision"]["decision"] == "DENY")
a_future = g.record_approval(m["manifest_id"], JANE, "2026-09-05T14:20:00:00Z"[:20] + "Z")
ok("adv-2            future-dated approval rejected", any("future" in x for x in g.execute(m["manifest_id"], a_future["approval_id"], NOW)["reasons"]))
ok("adv-3            policy hash drift rejected (see 'rejects policy hash drift')", any(n == "rejects          policy hash drift" and p for n, p, _ in results))
ok("adv-4            documentation_only prohibition is never rendered as 'can never'", any(n.startswith("rules            documentation_only prohibition never appears") and p for n, p, _ in results))
P, m, g, st, a, calls = fresh(); ex = g.execute(m["manifest_id"], a["approval_id"], NOW)
ov = g.verify_outcome(ex["execution_id"], "2026-09-05T14:15:00Z", attestations=[{"assertion": t["assertion"], "observed": True} for t in m["outcome_verification"]["verification_tests"]])
ok("adv-5            caller-supplied booleans do not verify an outcome", not ov["verified"])
ok("adv-6            unsigned L2 Profile refused at ingress (see 'ingress rejects L2 profile without signature')", any(n == "ingress rejects  L2 profile without signature" and p for n, p, _ in results))
Ps, Rs, Ms = X["software"]; g7, _ = mkgate(Ps); g7.state.evidence_at = "2026-10-01T00:00:00Z"; with_executor(g7, "software")
o7 = g7.propose(Ps["profile_id"], Rs, "2026-09-05T16:00:00Z")
ok("adv-7            future-dated recovery evidence rejected", o7["decision"]["decision"] == "DENY" and any("C13.recovery_evidence" in v for v in o7["decision"]["violations"]))
import subprocess
cp = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "render_card.py"), os.path.join(ROOT, "examples", "business-workflow-agent.invoice-triage", "manifest.json")], capture_output=True, text=True)
ok("adv-8            render_card.py CLI prints the Card", cp.returncode == 0 and "ACTION ASSURANCE CARD" in cp.stdout)
ok("adv-9            omitted object count is a violation, not zero (see 'rejects missing object count')", any(n == "rejects          missing object count is not zero" and p for n, p, _ in results))
P10 = copy.deepcopy({k: v for k, v in P0.items() if k != "integrity"}); P10["data_boundary"]["egress_policy"] = "signed_summary"; P10["permissions"]["allowed"][2]["egress_fields"] = ["invoice_number"]
P10 = sign_profile_ed25519(P10, PRIV, KEY_ID); g10, _ = mkgate(P10); o10 = g10.propose(P10["profile_id"], R0, "2026-09-05T14:10:00Z")
ok("adv-10           signed_summary egress policy resolves through the StateProvider", o10["decision"]["decision"] == "ALLOW", str(o10["decision"].get("unresolved_delegations") or o10["decision"].get("violations")))
g10.state.egress = False
ok("adv-10b          egress policy resolver can deny", g10.propose(P10["profile_id"], R0, "2026-09-05T14:10:00Z")["decision"]["decision"] == "DENY")

# ============================================================ 7. Card + read-back
from aam import readback, readback_coverage, product_view, engineering_view, build_profile, AnswerFile, collect  # noqa: E402
for k, (P, R, M) in X.items():
    ok(f"card parity      {k}", check_parity(project(M), M)["ok"])
    ok(f"card coverage    {k}: every Manifest leaf appears on the Card", card_coverage(M)["complete"], str(card_coverage(M)["missing"])[:200])
    ok(f"readback coverage {k}", readback_coverage(P)["complete"], str(readback_coverage(P)["missing"])[:200])
    pv, ev = product_view(P), engineering_view(P)
    ok(f"readback split   {k}: Part A ∪ Part B = whole Profile", len(pv) + len(ev) == len([1 for _ in __import__('render_card').leaf_values(P)]) and pv and ev)
    ok(f"readback split   {k}: model pins and credentials are engineering, never-list and approvers are product", any(p.startswith("identity.model") for p, _ in ev) and any(p.startswith("credentials_policy") for p, _ in ev) and any(p.startswith("permissions.prohibited") for p, _ in pv) and any(p.startswith("approval_policy.approver_roles") for p, _ in pv))
Mb = X["business"][2]
c = project(Mb); c["blast_radius"] = "Minimal."; ok("card tamper      softened blast radius detected", check_parity(c, Mb)["differing"] == ["blast_radius"])
c = project(Mb); del c["uncertainty"]; ok("card tamper      omitted uncertainty detected", check_parity(c, Mb)["missing"] == ["uncertainty"])
c = project(Mb); c["reassurance"] = "Safe."; ok("card tamper      added narrative detected", check_parity(c, Mb)["extra"] == ["reassurance"])
ok("card content     AP card shows recipient address and material details", "ap@northwind-supply.example" in render_text(Mb) and "Variance usd: 312" in render_text(Mb))

# ============================================================ 8. authoring, determinism, vectors
answers = json.load(open(os.path.join(ROOT, "examples", "answers", "ap-invoice-agent.answers.json")))
gen = build_profile(collect(AnswerFile(answers)), version="1.4.0")
ok("authoring        generated Profile validates (L1 without signature)", not schema_errors(PROFILE_V, gen), "; ".join(schema_errors(PROFILE_V, gen))[:200])
ok("authoring        generated Profile publishes and builds a Manifest from the AP request", (lambda gg: gg.publish_profile(gen)["published"] and gg.propose(gen["profile_id"], R0, "2026-09-05T14:10:00Z")["manifest"]["action_target"]["operation"] == "draft_email")(Gate(Live(), InMemoryProfileStore(), b"k")))
ok("authoring        read-back complete and split into Part A / Part B with three digests", readback_coverage(gen)["complete"] and "PART A" in readback(gen) and "PART B" in readback(gen) and "Profile digest (binds" in readback(gen))
ok("authoring        untyped thresholds default to documentation_only and cannot elevate", all(t["enforcement"] == "documentation_only" for t in gen["autonomy_policy"]["thresholds"] if isinstance(t, dict)))
for k, (P, R, M) in X.items():
    ok(f"deterministic    {k}", check(P, M, T[k]) == check(P, M, T[k]))
vectors = []
for k, (P, R, M) in X.items():
    ids = [d["id"] for d in check(P, M, T[k])["delegated"]]
    vectors += [{"name": f"positive-{k}-unresolved", "now": T[k], "profile": P, "manifest": M, "resolved_delegations": {}, "expect": "INDETERMINATE"},
                {"name": f"positive-{k}-resolved", "now": T[k], "profile": P, "manifest": M, "resolved_delegations": {i: True for i in ids}, "expect": "ALLOW"},
                {"name": f"positive-{k}-killswitch-failed", "now": T[k], "profile": P, "manifest": M, "resolved_delegations": {**{i: True for i in ids}, "C12.live_state": False}, "expect": "DENY"},
                {"name": f"positive-{k}-expired", "now": "2026-09-07T00:00:00Z", "profile": P, "manifest": M, "resolved_delegations": {i: True for i in ids}, "expect": "DENY"}]
for label, key, mut, expect in NEG:
    P, M = copy.deepcopy(X[key][0]), copy.deepcopy(X[key][2]); mut(P, M)
    vectors.append({"name": "negative-" + label.replace(" ", "-"), "now": T[key], "profile": P, "manifest": M, "resolved_delegations": {}, "expect": "DENY", "expect_rule_prefix": expect})
os.makedirs(os.path.join(ROOT, "tests", "vectors"), exist_ok=True)
json.dump({"schema_version": "0.3.6", "vectors": vectors}, open(os.path.join(ROOT, "tests", "vectors", "containment-vectors.json"), "w"), indent=1)
ok("vectors          exported", len(vectors) >= 50, str(len(vectors)))

fails = [r for r in results if not r[1]]
for name, passed, detail in results:
    print(("PASS " if passed else "FAIL ") + name + (f"  -- {detail}" if (detail and not passed) else ""))
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
