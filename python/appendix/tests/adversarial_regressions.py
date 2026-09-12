#!/usr/bin/env python3
"""
adversarial_regressions.py — the ten findings from the external v0.3.3 adversarial review, ported to the
v0.3.6 gate API. Each case attempts the original bypass; PASS means the framework now resists it.
The same cases are also folded into tests/run_tests.py (section 6). Run from appendix/.
"""
import copy, json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from gate import Gate, InMemoryProfileStore, StateProvider, sign_profile_ed25519
from check_containment import check
from render_card import render_text

E = os.path.join(ROOT, "examples")
P0 = json.load(open(f"{E}/business-workflow-agent.invoice-triage/profile.json"))
R0 = json.load(open(f"{E}/business-workflow-agent.invoice-triage/request.json"))
M0 = json.load(open(f"{E}/business-workflow-agent.invoice-triage/manifest.json"))
PS = json.load(open(f"{E}/software-agent.repo-maintainer/profile.json")); RS = json.load(open(f"{E}/software-agent.repo-maintainer/request.json"))
KEY_ID = "demo-profile-signing-2026"
PUB = bytes.fromhex(open(f"{E}/trust/demo-profile-signing.pub.hex").read().strip()); PRIV = bytes.fromhex(open(f"{E}/trust/demo-profile-signing.key.hex").read().strip())
ROOTS = {KEY_ID: {"method": "ed25519", "public_key": PUB}}

class Live(StateProvider):
    def __init__(self): self.recovery_tested_at = "2026-09-01T00:00:00Z"; self.obs = {}
    def kill_switch_allows(self, p): return True
    def credential_valid(self, i, at): return True
    def effect_target_in_class(self, et, c): return True
    def evaluate_rule(self, *a): return True
    def evaluate_selector(self, *a): return True
    def evaluate_threshold(self, *a): return True
    def egress_policy_permits(self, *a): return True
    def recovery_evidence(self, ref): return {"passed": True, "tool": "github" if "repo" in ref else "email", "operation": "open_pull_request" if "repo" in ref else "draft_email", "tested_at": self.recovery_tested_at}
    def authenticated(self, p, a): return True
    def observe(self, test, m, execution): return None  # this suite tests forged evidence, not successful reads

def gate_for(P, live=None):
    s = InMemoryProfileStore(); g = Gate(live or Live(), s, b"adversarial-secret", trust_roots=ROOTS)
    pub = g.publish_profile(P); return g, s, pub
JANE = [{"role": "ap_manager", "principal": "user:jane", "auth_ref": "sso:jane"}]

def case(name, resisted, detail=""):
    print(("PASS" if resisted else "FAIL"), name, ("-- " + detail if detail else ""))
    return resisted

allok = True
# 1. unknown autonomy enum: caller cannot set mode at all; a checker fed an unknown enum fails closed
g, _, _ = gate_for(P0); bad = dict(R0); bad["mode"] = "root"
r1 = g.propose(P0["profile_id"], bad, "2026-09-05T14:10:00Z")["decision"]
m1 = copy.deepcopy(M0); m1["autonomy_approval"]["mode"] = "root"
allok &= case("1 unknown autonomy mode", r1["decision"] == "DENY" and check(P0, m1, "2026-09-05T14:10:00Z")["decision"] == "DENY", f"propose={r1['decision']}")

# 2. future-dated approval
g, _, _ = gate_for(P0); g.register_executor("email", "draft_email", lambda r: {"ok": True})
o = g.propose(P0["profile_id"], R0, "2026-09-05T14:10:00Z"); m = o["manifest"]
a = g.record_approval(m["manifest_id"], JANE, "2026-09-05T14:20:00Z")
e = g.execute(m["manifest_id"], a["approval_id"], "2026-09-05T14:14:00Z")
allok &= case("2 future-dated approval", e["decision"] == "DENY" and any("future" in x for x in e["reasons"]), str(e["reasons"])[:120])

# 3. policy hash drift: builder copies pins, so drift can only be injected by editing the manifest -> seal + C3 both catch it
m3 = copy.deepcopy(M0); m3["identity"]["policy"]["hash"] = "sha256:policy-B"
allok &= case("3 policy hash drift", any(v.startswith("C3 policy.hash") for v in check(P0, m3, "2026-09-05T14:10:00Z")["violations"]))

# 4. documentation_only prohibition must not be shown as 'can never'
P4 = copy.deepcopy({k: v for k, v in P0.items() if k != "integrity"})
P4["permissions"]["prohibited"].append({"description": "Never use subject line URGENT", "rule": "subject_line != URGENT", "enforcement": "documentation_only"})
P4 = sign_profile_ed25519(P4, PRIV, KEY_ID); g, _, pub = gate_for(P4)
o4 = g.propose(P4["profile_id"], R0, "2026-09-05T14:10:00Z"); card = render_text(o4["manifest"])
never_block = card.split("This agent can never")[1].split("Stated in the Profile")[0]
allok &= case("4 unenforced never-list not shown as promise", "Never use subject line URGENT" not in never_block and "Never use subject line URGENT" in card.split("Stated in the Profile")[1], "")

# 5. caller-supplied booleans for outcome verification
g, _, _ = gate_for(P0); g.register_executor("email", "draft_email", lambda r: {"ok": True})
o = g.propose(P0["profile_id"], R0, "2026-09-05T14:10:00Z"); m = o["manifest"]; a = g.record_approval(m["manifest_id"], JANE, "2026-09-05T14:13:00Z")
e = g.execute(m["manifest_id"], a["approval_id"], "2026-09-05T14:14:00Z")
ov = g.verify_outcome(e["execution_id"], "2026-09-05T14:15:00Z", attestations=[{"assertion": t["assertion"], "observed": True} for t in m["outcome_verification"]["verification_tests"]])
allok &= case("5 caller cannot self-attest outcome", ov["verified"] is False, f"verified={ov['verified']}")

# 6. unsigned L2 profile
P6 = {k: v for k, v in P0.items() if k != "integrity"}
_, _, pub6 = gate_for(P6)
allok &= case("6 unsigned L2 profile refused at ingress", not pub6["published"], str(pub6.get("reasons"))[:100])

# 7. future-dated recovery evidence (executing mode: software open_pull_request)
live = Live(); live.recovery_tested_at = "2026-10-01T00:00:00Z"; g, _, _ = gate_for(PS, live)
o7 = g.propose(PS["profile_id"], RS, "2026-09-05T16:00:00Z")["decision"]
allok &= case("7 future-dated recovery evidence", o7["decision"] == "DENY" and any("C13.recovery_evidence" in v for v in o7.get("violations", [])), str(o7.get("violations"))[:120])

# 8. render_card CLI
cp = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "render_card.py"), f"{E}/business-workflow-agent.invoice-triage/manifest.json"], capture_output=True, text=True)
allok &= case("8 render_card.py CLI prints", cp.returncode == 0 and "ACTION ASSURANCE CARD" in cp.stdout)

# 9. omitted max_affected_objects
m9 = copy.deepcopy(M0); m9["impact"].pop("max_affected_objects")
allok &= case("9 omitted object count is a violation", any(v.startswith("C7 max_affected_objects_present") for v in check(P0, m9, "2026-09-05T14:10:00Z")["violations"]))

# 10. signed_summary egress policy resolvable
P10 = copy.deepcopy({k: v for k, v in P0.items() if k != "integrity"}); P10["data_boundary"]["egress_policy"] = "signed_summary"
P10["permissions"]["allowed"][2]["egress_fields"] = ["invoice_number"]; P10 = sign_profile_ed25519(P10, PRIV, KEY_ID)
g, _, _ = gate_for(P10); o10 = g.propose(P10["profile_id"], R0, "2026-09-05T14:10:00Z")["decision"]
allok &= case("10 signed_summary egress resolves via StateProvider", o10["decision"] == "ALLOW", str(o10.get("unresolved_delegations"))[:100])

print("\nall findings resisted" if allok else "\nSOME FINDINGS STILL REPRODUCE")
sys.exit(0 if allok else 1)
