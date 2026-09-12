#!/usr/bin/env python3
"""Volatile conformance engine, AAM v0.4.0; use managed_gate.ManagedGate for persistence and feedback.

request -> trusted Manifest -> containment/live checks -> approval -> atomic local
reservation/single-use dispatch -> structured, execution-bound outcome verification.

The local reservation is NOT a transaction with the downstream effect. Transport or
adapter failure after dispatch is EXECUTION_UNKNOWN, never authorization DENY. Local
ledgers are in memory: no crash recovery or cross-process exactly-once claim is made.
Explicit `now` arguments are for trusted deterministic tests, not a client wire API.
"""
import copy
import hashlib
import hmac
import json
import os
import threading
import uuid
from datetime import timedelta

from check_containment import (check, canonical, digest, manifest_digest, profile_digest,
                               request_digest, parse_time, utc_now_iso, Malformed, MODES)
from verification import INDEPENDENT, verification_errors, required_test_ids, render_template, render_verification_plan
from evidence import BINDING_FIELDS, observation_context
from reconciliation import reconciliation_context
from validation_support import strict_format_checker

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as e:
    raise SystemExit("gate.py requires jsonschema (pip install jsonschema)") from e
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    HAVE_ED25519 = True
except ImportError:  # pragma: no cover
    HAVE_ED25519 = False

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMAS = os.path.join(HERE, "..", "schemas")


def _load(name):
    with open(os.path.join(SCHEMAS, name), encoding="utf-8") as stream:
        return Draft202012Validator(json.load(stream), format_checker=strict_format_checker())


PROFILE_V = _load("agent-authority-profile.schema.json")
MANIFEST_V = _load("action-manifest.schema.json")
REQUEST_V = _load("action-request.schema.json")
LIFECYCLE_V = _load("lifecycle-records.schema.json")


def schema_errors(validator, doc):
    return [e.message for e in validator.iter_errors(doc)]


class DependencyUnavailable(RuntimeError):
    """A trusted dependency did not produce a usable answer; never permission to act."""


class ExecutorNotAttempted(Exception):
    """Trusted adapter assertion: no downstream attempt was made.

    Only for local preflight rejection before any remote call/queueing. Never use for
    timeouts, connection loss, uncertain SDK failures or a possibly committed effect.
    Exception text is not persisted, because it may contain secrets. Approval and
    duplicate-dispatch reservations remain consumed; there is no automatic retry.
    """


class StateProvider:
    """Deployment-owned trusted adapters. Boolean predicates must return bool or None.

    None/exception/non-boolean is unresolved, never truthy permission. Implementations
    need their own timeouts. The reference cannot interrupt a permanently hung call.
    """
    def kill_switch_allows(self, profile: dict) -> bool | None: raise NotImplementedError
    def credential_valid(self, identity: str, at) -> bool | None: raise NotImplementedError
    def effect_target_in_class(self, effect_target: dict, cls: str) -> bool | None: raise NotImplementedError
    def evaluate_rule(self, rule_id: str, profile: dict, manifest: dict) -> bool | None: return None
    def evaluate_selector(self, selector_id: str, target: dict, profile: dict) -> bool | None: return None
    def evaluate_threshold(self, threshold_id: str, profile: dict, manifest: dict) -> bool | None: return None
    def egress_policy_permits(self, policy: str, fields: list, profile: dict) -> bool | None: return None
    def recovery_evidence(self, ref: str) -> dict | None: return None
    def authenticated(self, principal: str, auth_ref: str) -> bool | None: return False
    def observe(self, test: dict, manifest: dict, execution: dict) -> dict | None:
        """Fresh read -> ObservationRecord (see evidence.make_observation), or None.

        A raw boolean is deliberately rejected. This interface provides provenance
        fields and binding; it does not prove that an adapter actually read its source.
        """
        return None

    def reconcile(self, manifest: dict, execution: dict) -> dict | None:
        """Read transaction/idempotency status -> ReconciliationEvidence, or None.

        A definitive negative requires final evidence that this exact attempt cannot
        commit later (for example a terminal cancellation/fence), not a missing read.
        This callback must be read-only: it neither retries nor cancels an operation.
        Use reconciliation.make_reconciliation_evidence AFTER reading a trusted source.
        """
        return None


class ProfileStore:
    """Trusted administrative dependency; never give the agent direct write access."""
    def publish(self, profile: dict): raise NotImplementedError
    def active(self, profile_id: str) -> dict | None: raise NotImplementedError


class InMemoryProfileStore(ProfileStore):
    def __init__(self):
        self._p = {}
        self._lock = threading.Lock()
    def publish(self, profile: dict):
        with self._lock:
            self._p[profile["profile_id"]] = copy.deepcopy(profile)
    def revoke(self, profile_id: str):
        with self._lock:
            self._p.pop(profile_id, None)
    def active(self, profile_id: str):
        with self._lock:
            return copy.deepcopy(self._p.get(profile_id))


def sign_profile_ed25519(profile: dict, private_key_bytes: bytes, key_id: str) -> dict:
    if not HAVE_ED25519:
        raise RuntimeError("cryptography not available")
    body = {k: v for k, v in profile.items() if k != "integrity"}
    sig = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical(body).encode())
    out = copy.deepcopy(profile)
    out["integrity"] = {"method": "ed25519", "key_id": key_id, "value": sig.hex()}
    return out


def sign_profile_hmac(profile: dict, secret: bytes, key_id: str) -> dict:
    """Legacy name: symmetric authentication, NOT a signature. L0/L1 only in v0.3.6."""
    body = {k: v for k, v in profile.items() if k != "integrity"}
    out = copy.deepcopy(profile)
    out["integrity"] = {"method": "hmac-sha256", "key_id": key_id,
                        "value": hmac.new(secret, canonical(body).encode(), hashlib.sha256).hexdigest()}
    return out


class Gate:
    def __init__(self, state: StateProvider, profiles: ProfileStore, secret: bytes,
                 gate_id: str = "reference-gate/0.3.7", trust_roots: dict | None = None,
                 clock=None, *, observation_clock_skew_seconds: int = 0,
                 reconciliation_max_age_seconds: int = 300,
                 readback_trust_roots: dict | None = None,
                 require_readback_signoffs: bool = False):
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("a non-empty gate HMAC key is required")
        if type(observation_clock_skew_seconds) is not int or not 0 <= observation_clock_skew_seconds <= 60:
            raise ValueError("observation_clock_skew_seconds must be an integer from 0 to 60")
        if type(reconciliation_max_age_seconds) is not int or not 1 <= reconciliation_max_age_seconds <= 86400:
            raise ValueError("reconciliation_max_age_seconds must be an integer from 1 to 86400")
        if type(require_readback_signoffs) is not bool:
            raise ValueError("require_readback_signoffs must be a boolean")
        self.observation_clock_skew_seconds = observation_clock_skew_seconds
        self.reconciliation_max_age_seconds = reconciliation_max_age_seconds
        self.readback_trust_roots = copy.deepcopy(readback_trust_roots or {})
        self.require_readback_signoffs = require_readback_signoffs
        self.state, self.profiles, self._secret, self.gate_id = state, profiles, secret, gate_id
        self.trust_roots = copy.deepcopy(trust_roots or {})
        self._clock = clock or utc_now_iso
        self._manifests, self._decisions, self._approvals, self._executions, self._outcomes = {}, {}, {}, {}, {}
        self._executors, self._verifiers = {}, {}
        self._dispatches, self._action_dispatches = {}, {}
        self._execution_events = []
        self._reconciliations, self._publication_signoffs = {}, {}
        self._lock = threading.Lock()

    def _seal(self, rec: dict) -> dict:
        body = {k: v for k, v in rec.items() if k != "seal"}
        rec["seal"] = hmac.new(self._secret, canonical(body).encode(), hashlib.sha256).hexdigest()
        return rec

    def _sealed_ok(self, rec: dict) -> bool:
        if not isinstance(rec, dict) or not isinstance(rec.get("seal"), str):
            return False
        try:
            expected = self._seal({k: v for k, v in rec.items() if k != "seal"})["seal"]
            return hmac.compare_digest(rec["seal"], expected)
        except (TypeError, ValueError):
            return False

    def _state_call(self, method, *args):
        try:
            return getattr(self.state, method)(*copy.deepcopy(args))
        except Exception as exc:
            # Do not leak provider exception text, which can contain credentials.
            raise DependencyUnavailable(f"StateProvider.{method} unavailable ({type(exc).__name__})") from exc

    def _state_bool(self, method, *args):
        result = self._state_call(method, *args)
        if result is None or type(result) is bool:
            return result
        raise DependencyUnavailable(f"StateProvider.{method} returned a non-boolean predicate")

    def _require_state_bool(self, method, *args):
        result = self._state_bool(method, *args)
        if result is None:
            raise DependencyUnavailable(f"StateProvider.{method} is unresolved")
        return result

    def _active(self, profile_id):
        try:
            return copy.deepcopy(self.profiles.active(profile_id))
        except Exception as exc:
            raise DependencyUnavailable(f"ProfileStore.active unavailable ({type(exc).__name__})") from exc

    # Trusted administration only: not exposed to the proposing agent.
    def register_executor(self, tool: str, operation: str, fn, *, with_context: bool = False):
        """fn(request) or fn(request, context) -> JSON receipt.

        Context carries execution_id and a stable idempotency_key separately from
        the canonical material request. The adapter must forward the key to a
        downstream system that actually enforces it; registration alone does not.
        """
        if not callable(fn):
            raise TypeError("executor must be callable")
        with self._lock:
            self._executors[(tool, operation)] = (fn, with_context)

    def register_verifier(self, verifier_id: str, secret: bytes, *, sources: list[str], methods: list[str]):
        if not verifier_id or not isinstance(secret, bytes) or not secret or not sources or not methods:
            raise ValueError("verifier needs an identity, key, sources and methods")
        if not set(methods).issubset(INDEPENDENT):
            raise ValueError("verifier methods must be independent observation methods")
        with self._lock:
            self._verifiers[verifier_id] = {"secret": secret, "sources": set(sources), "methods": set(methods)}

    def publish_profile(self, profile: dict, *, readback_signoffs: list | None = None) -> dict:
        profile = copy.deepcopy(profile)
        if isinstance(profile, dict) and profile.get("monitoring_policy_ref") and not getattr(self, "_managed_runtime", False):
            return {"published": False, "reasons": ["monitoring_policy_ref requires ManagedGate; volatile Gate cannot silently ignore runtime controls"]}
        errs = schema_errors(PROFILE_V, profile)
        if not errs:
            for operation in profile["permissions"]["allowed"]:
                errs.extend(f"{operation['tool']}.{operation['operation']}: {e}"
                            for e in verification_errors(operation["verification"]))
        if errs:
            return {"published": False, "reasons": ["schema/semantics: " + e for e in errs[:5]]}
        level = profile["conformance"]["level"]
        if level in ("L2", "L3") or "integrity" in profile:
            ok, why = self._verify_profile_signature(profile)
            if not ok:
                return {"published": False, "reasons": [why]}
        if self.require_readback_signoffs:
            from readback_signoff import verify_required_signoffs
            review = verify_required_signoffs(profile, readback_signoffs, self.readback_trust_roots, self._clock())
            if not review["valid"]:
                return {"published": False, "reasons": review["reasons"]}
        try:
            self.profiles.publish(profile)
        except Exception as exc:
            return {"published": False, "reasons": [f"ProfileStore.publish unavailable ({type(exc).__name__})"]}
        if self.require_readback_signoffs:
            with self._lock:
                self._publication_signoffs[profile_digest(profile)] = copy.deepcopy(readback_signoffs)
        return {"published": True, "profile_id": profile["profile_id"],
                "profile_version": profile["profile_version"], "profile_digest": profile_digest(profile)}

    def _verify_profile_signature(self, profile: dict):
        integ = profile.get("integrity")
        if not integ:
            return False, "L2+ profile has no integrity block"
        if profile["conformance"]["level"] in ("L2", "L3") and integ.get("method") != "ed25519":
            return False, "L2/L3 require Ed25519; HMAC is symmetric authentication, not a signature"
        root = self.trust_roots.get(integ.get("key_id"))
        if not root or root.get("method") != integ.get("method"):
            return False, f"no trust root for key_id {integ.get('key_id')!r} with method {integ.get('method')!r}"
        body = canonical({k: v for k, v in profile.items() if k != "integrity"}).encode()
        try:
            if integ["method"] == "ed25519":
                if not HAVE_ED25519:
                    return False, "ed25519 verification unavailable (cryptography not installed)"
                Ed25519PublicKey.from_public_bytes(root["public_key"]).verify(bytes.fromhex(integ["value"]), body)
                return True, ""
            if integ["method"] == "hmac-sha256":
                expect = hmac.new(root["secret"], body, hashlib.sha256).hexdigest()
                return (True, "") if hmac.compare_digest(expect, integ["value"]) else (False, "profile HMAC invalid")
        except (ValueError, TypeError, KeyError):
            return False, "profile integrity material invalid"
        except Exception as exc:
            return False, f"profile signature verification failed ({type(exc).__name__})"
        return False, "unknown integrity method"

    def _fill(self, template: str, req: dict) -> str:
        return render_template(template, req)

    def build_manifest(self, profile: dict, request: dict, now: str, manifest_id: str | None = None) -> dict:
        """Derive every authority-bearing field from the Profile. The request contributes only what/where/why."""
        at_ = copy.deepcopy(request)
        entry = next((a for a in profile["permissions"]["allowed"] if a["tool"] == at_["tool"] and a["operation"] == at_["operation"]), None)
        pol = profile["approval_policy"]
        op_name = f"{at_['tool']}.{at_['operation']}"
        # mode: operation default; elevated only by a typed threshold that holds now (checked again by containment/live)
        mode = entry["default_mode"] if entry else "recommend"
        if entry and _rank(entry["max_mode"]) > _rank(mode):
            for t in profile["autonomy_policy"].get("thresholds") or []:
                if t.get("enforcement") == "typed" and (not t.get("operations") or op_name in t["operations"]) and _rank(t["mode"]) > _rank(mode) and _rank(t["mode"]) <= _rank(entry["max_mode"]):
                    if self._state_bool("evaluate_threshold", t.get("threshold_id", ""), profile, {"action_target": at_}) is True:
                        mode = t["mode"]
        approval_required = mode in ("recommend", "request_approval")
        params = at_.get("parameters") or {}
        material = [{"name": n, "value": params.get(n), "label": n.replace("_", " ").capitalize()} for n in (entry.get("material_parameters") if entry else [])]
        review_min = min(profile["authority_scope"]["max_review_window_minutes"], (entry or {}).get("review_window_minutes", profile["authority_scope"]["max_review_window_minutes"]))
        issued = parse_time(now)
        rec_t = next((t for t in profile["recovery_policy"].get("templates", []) if t["tool"] == at_["tool"] and t["operation"] == at_["operation"]), None)
        imp = (entry or {}).get("impact") or {}
        ver = (entry or {}).get("verification") or {}
        enforced = [p["description"] for p in profile["permissions"]["prohibited"] if (p.get("tool") or p.get("operation")) or (p.get("rule") and p.get("enforcement") == "typed")]
        documented = [p["description"] for p in profile["permissions"]["prohibited"] if not ((p.get("tool") or p.get("operation")) or (p.get("rule") and p.get("enforcement") == "typed"))]
        systems = sorted({s for s in [(at_.get("subject") or {}).get("system"), at_["effect_target"].get("system")] if s} | set((entry or {}).get("systems") or []))
        m = {
            "schema_version": "0.4.0" if profile.get("schema_version") == "0.4.0" else "0.3.7",
            "manifest_id": manifest_id or f"aam:{profile['profile_id'].split(':', 1)[-1]}:{uuid.uuid4().hex[:12]}",
            "manifest_version": "1.1.0" if profile.get("schema_version") == "0.4.0" else "1.0.0",
            "issued_at": now,
            "review_expires_at": (issued + timedelta(minutes=review_min)).isoformat().replace("+00:00", "Z"),
            "built_by": self.gate_id,
            "profile_ref": {"profile_id": profile["profile_id"], "profile_version": profile["profile_version"], "profile_digest": profile_digest(profile), "conformance_level": profile["conformance"]["level"]},
            "identity": {"agent_name": profile["identity"]["agent_name"], "agent_version": profile["identity"]["agent_version"], "model": dict(profile["identity"]["model"]),
                         "prompt": dict(profile["identity"]["prompt"]), "policy": dict(profile["identity"]["policy"])},
            "action_target": {
                "action_id": at_.get("action_id") or f"act-{uuid.uuid4().hex[:10]}",
                "requested_at": now,
                "summary": self._fill(entry["summary_template"], at_) if entry and entry.get("summary_template") else (at_.get("summary") or f"{op_name} on {at_['effect_target'].get('display') or at_['effect_target']['identifier']}"),
                "tool": at_["tool"], "operation": at_["operation"],
                **({"subject": dict(at_["subject"])} if at_.get("subject") else {}),
                "effect_target": dict(at_["effect_target"]),
                "parameters": dict(params),
                "material_parameters": material,
                "parameters_summary": "; ".join(f"{k}={v}" for k, v in params.items()),
            },
            "scope_claim": {**({"tenant": profile["authority_scope"]["tenant"]} if profile["authority_scope"].get("tenant") else {}), "environment": profile["authority_scope"]["environment"], "systems": systems or list(profile["authority_scope"]["systems"][:1]),
                            **({"assets": [at_["subject"]["identifier"]]} if at_.get("subject") and at_["subject"]["type"] in {t["type"] for t in profile["authority_scope"]["targets"] if "identifiers" in t} else {}),
                            **({"operating_window": profile["authority_scope"]["operating_window"]} if profile["authority_scope"].get("operating_window") else {})},
            "impact": {"domains": list(imp.get("domains", [])), "severity": imp.get("severity", "critical"), "blast_radius": self._fill(imp.get("blast_radius", ""), at_) if imp.get("blast_radius") else "",
                       "bounded_by": [self._fill(b, at_) for b in imp.get("bounded_by", [])], "reversible": imp.get("reversible", False),
                       **({"max_affected_objects": imp["max_affected_objects"]} if "max_affected_objects" in imp else {}),
                       **({"irreversibility_notes": imp["irreversibility_notes"]} if imp.get("irreversibility_notes") else {})},
            "autonomy_approval": {"mode": mode, "approval_required": approval_required, "one_approval_one_action": True,
                                  **({"approver_roles": list((entry or {}).get("approver_roles") or pol["approver_roles"]), "required_evidence": list(pol.get("required_evidence", [])),
                                      "dual_approval_required": op_name in pol.get("dual_approval_for", []), "approval_timeout_minutes": pol.get("approval_timeout_minutes", review_min)} if approval_required else {})},
            "evidence": {"evidence_refs": list(at_["evidence_refs"]), **({"provenance": list(at_["provenance"])} if at_.get("provenance") else {}),
                         "unresolved_conflicts": list(at_.get("unresolved_conflicts") or []), "untrusted_sources_present": list(at_.get("untrusted_sources_present") or []),
                         "content_is_data_not_instructions": True},
            "credentials": {"identity": profile["credentials_policy"]["identity"], "privileges": list((entry or {}).get("privileges_required") or []),
                            "ttl_minutes": min(profile["credentials_policy"]["max_ttl_minutes"], (entry or {}).get("ttl_minutes", profile["credentials_policy"]["max_ttl_minutes"])), "fail_closed_on_expiry": True},
            "data_boundary_claim": {"model_hosting": profile["data_boundary"]["model_hosting"], "egress_fields": list((entry or {}).get("egress_fields") or [])},
            "audit": {"records": list(profile["audit_policy"]["records"])},
            "outcome_verification": render_verification_plan(ver, at_),
            "recovery": {"method": rec_t["method"] if rec_t else "", "tested": bool(rec_t and rec_t.get("tested")), **({"last_tested": rec_t["last_tested"]} if rec_t and rec_t.get("last_tested") else {}),
                         **({"time_to_recover_minutes": rec_t["time_to_recover_minutes"]} if rec_t and "time_to_recover_minutes" in rec_t else {}),
                         "irreversible": (rec_t or {}).get("irreversible", not imp.get("reversible", False)), "owner": (rec_t or {}).get("owner") or profile["recovery_policy"]["owner"],
                         **({"tested_evidence_ref": rec_t["tested_evidence_ref"]} if rec_t and rec_t.get("tested_evidence_ref") else {})},
            "not_permitted_summary": enforced,
            "documented_not_enforced": documented,
            "request_digest": request_digest(at_["tool"], at_["operation"], at_["effect_target"], params),
        }
        if at_.get("summary") and m["action_target"]["summary"] != at_["summary"]:
            m["evidence"]["unresolved_conflicts"] = m["evidence"]["unresolved_conflicts"] + [f"agent narrative differs from operation summary: {at_['summary']}"]
        self._prepare_manifest_context(profile, m)
        # gate seal on the Manifest body
        body = {k: v for k, v in m.items() if k != "integrity"}
        m["integrity"] = {"method": "gate-hmac-sha256", "key_id": self.gate_id, "value": hmac.new(self._secret, canonical(body).encode(), hashlib.sha256).hexdigest()}
        return m

    def _prepare_manifest_context(self, profile, manifest):
        """ManagedGate adds a trusted operational-context snapshot before sealing."""
        if profile.get("monitoring_policy_ref"):
            raise ValueError("monitoring policy requires ManagedGate")

    def _runtime_issues(self, manifest):
        """ManagedGate's restrictions augment, never replace, static containment."""
        return []

    def _admission_issues(self, manifest):
        """Runs inside the local reservation lock; no external callbacks allowed."""
        return []

    # request -> trusted construction -> schema/semantic validation -> live decision
    def propose(self, profile_id: str, request: dict, now: str | None = None,
                manifest_id: str | None = None) -> dict:
        now = now or self._clock()
        try:
            parse_time(now)
            canonical(request)  # reject non-JSON/NaN payloads before construction
        except (Malformed, TypeError, ValueError) as exc:
            return {"decision": self._deny_record(None, [f"malformed request/time ({type(exc).__name__})"], now)}
        errs = schema_errors(REQUEST_V, request)
        if errs:
            return {"decision": self._deny_record(None, ["request schema: " + e for e in errs[:5]], now)}
        try:
            prof = self._active(profile_id)
            if prof is None:
                return {"decision": self._deny_record(None, ["Profile is not active (revoked or unknown)"], now)}
            manifest = self.build_manifest(prof, request, now, manifest_id)
        except DependencyUnavailable as exc:
            return {"decision": self._deny_record(None, [str(exc)], now, "INDETERMINATE")}
        except (KeyError, TypeError, ValueError) as exc:
            return {"decision": self._deny_record(None, [f"Manifest construction failed ({type(exc).__name__})"], now)}
        errors = schema_errors(MANIFEST_V, manifest)
        errors += verification_errors(manifest["outcome_verification"], "verification_tests")
        if errors:
            return {"decision": self._deny_record(manifest, ["manifest schema/semantics: " + e for e in errors[:5]], now)}
        with self._lock:
            collision = manifest["manifest_id"] in self._manifests
            if not collision:
                self._manifests[manifest["manifest_id"]] = copy.deepcopy(manifest)
        if collision:
            return {"decision": self._deny_record(manifest, ["manifest_id already exists; immutable manifests cannot be overwritten"], now)}
        return {"manifest": copy.deepcopy(manifest), "decision": self._decide(manifest, now)}

    def reevaluate(self, manifest_id: str, now: str | None = None) -> dict:
        now = now or self._clock()
        try:
            parse_time(now)
        except Malformed as exc:
            return self._deny_record(None, [str(exc)], now)
        m = self._own_manifest(manifest_id)
        if m is None:
            return self._deny_record(None, ["manifest not built by this gate or seal invalid"], now)
        return self._decide(m, now)

    def _manifest_ok(self, m):
        if not isinstance(m, dict) or m.get("built_by") != self.gate_id:
            return False
        try:
            value = m["integrity"]["value"]
            body = {k: v for k, v in m.items() if k != "integrity"}
            expected = hmac.new(self._secret, canonical(body).encode(), hashlib.sha256).hexdigest()
            return isinstance(value, str) and hmac.compare_digest(value, expected)
        except (KeyError, ValueError, TypeError):
            return False

    def _own_manifest(self, manifest_id):
        with self._lock:
            m = copy.deepcopy(self._manifests.get(manifest_id))
        return m if self._manifest_ok(m) else None

    def _record_time(self, now):
        try:
            parse_time(now)
            return now
        except Malformed:
            return self._clock()

    def _deny_record(self, manifest, reasons, now, decision="DENY"):
        rec = {"record_type": "GateDecision", "decision_id": str(uuid.uuid4()), "gate_id": self.gate_id,
               "manifest_id": manifest.get("manifest_id") if manifest else None,
               "manifest_digest": manifest_digest(manifest) if manifest else None,
               "decision": decision, "decided_at": self._record_time(now), "reasons": reasons}
        return self._store_decision(rec)

    def _store_decision(self, rec):
        self._seal(rec)
        with self._lock:
            self._decisions[rec["decision_id"]] = copy.deepcopy(rec)
        return copy.deepcopy(rec)

    def _active_profile_for(self, manifest):
        pr = manifest["profile_ref"]
        prof = self._active(pr["profile_id"])
        if prof is None:
            return None, "Profile is not active (revoked or unknown)"
        if prof["profile_version"] != pr["profile_version"]:
            return None, f"active Profile version {prof['profile_version']} differs from Manifest's {pr['profile_version']}"
        if pr["profile_digest"] != profile_digest(prof):
            return None, "active Profile digest differs from the one the Manifest was built under"
        return prof, None

    def _resolve(self, profile, manifest, delegated, at):
        resolutions, errors = {}, []
        et = manifest["action_target"]["effect_target"]
        for delegation in delegated:
            did = delegation["id"]
            try:
                result = None
                if did == "C12.live_state":
                    result = self._state_bool("kill_switch_allows", profile)
                elif did == "C5.effect_target.class_membership":
                    result = self._state_bool("effect_target_in_class", et, et.get("class"))
                elif did.startswith("C8.threshold:"):
                    result = self._state_bool("evaluate_threshold", did.split(":", 1)[1], profile, manifest)
                elif did == "C13.recovery_evidence":
                    evidence = self._state_call("recovery_evidence", manifest["recovery"].get("tested_evidence_ref", ""))
                    if evidence is None:
                        result = None
                    elif not isinstance(evidence, dict):
                        raise DependencyUnavailable("StateProvider.recovery_evidence returned a non-object")
                    else:
                        result = (evidence.get("passed") is True
                                  and evidence.get("tool") == manifest["action_target"]["tool"]
                                  and evidence.get("operation") == manifest["action_target"]["operation"])
                        if result:
                            try:
                                age = (at - parse_time(evidence["tested_at"])).total_seconds() / 86400
                                max_age = profile["recovery_policy"].get("test_max_age_days")
                                result = age >= 0 and (max_age is None or age <= max_age)
                            except (Malformed, KeyError):
                                result = False
                elif did.startswith("C6.rule:"):
                    result = self._state_bool("evaluate_rule", did.split(":", 1)[1], profile, manifest)
                elif did.startswith("C4.") and ".selector:" in did:
                    label = did.split(".")[1]
                    target = manifest["action_target"].get(label) if label != "effect_target" else et
                    result = self._state_bool("evaluate_selector", did.split(":", 1)[1], target, profile)
                elif did.startswith("C10.egress_policy:"):
                    result = self._state_bool("egress_policy_permits", did.split(":", 1)[1],
                                              manifest["data_boundary_claim"].get("egress_fields", []), profile)
                if result is not None:
                    resolutions[did] = result
            except DependencyUnavailable as exc:
                errors.append(f"{did}: {exc}")
        return resolutions, errors

    def _full_check(self, profile, manifest, now):
        first = check(profile, manifest, now)
        if first["decision"] == "DENY":
            return first
        resolved, errors = self._resolve(profile, manifest, first["delegated"], parse_time(now))
        result = check(profile, manifest, now, resolved_delegations=resolved)
        result["dependency_errors"] = errors
        return result

    def _decide(self, manifest, now):
        rec = {"record_type": "GateDecision", "decision_id": str(uuid.uuid4()), "gate_id": self.gate_id,
               "manifest_id": manifest["manifest_id"], "manifest_digest": manifest_digest(manifest), "decided_at": now}
        try:
            prof, err = self._active_profile_for(manifest)
        except DependencyUnavailable as exc:
            return self._deny_record(manifest, [str(exc)], now, "INDETERMINATE")
        if err:
            return self._deny_record(manifest, [err], now)
        result = self._full_check(prof, manifest, now)
        runtime_issues = self._runtime_issues(manifest)
        if runtime_issues:
            return self._deny_record(manifest, runtime_issues, now)
        rec.update({"profile_id": prof["profile_id"], "profile_version": prof["profile_version"],
                    "profile_digest": profile_digest(prof), "decision": result["decision"],
                    "checks_passed": result["checks_passed"], "violations": result["violations"],
                    "unresolved_delegations": [d["id"] for d in result["delegated"]],
                    "dependency_errors": result.get("dependency_errors", [])})
        if result["decision"] == "ALLOW":
            until = min(parse_time(manifest["review_expires_at"]),
                        parse_time(now) + timedelta(seconds=prof["authority_scope"]["max_execution_authority_seconds"]))
            rec["execution_valid_until"] = until.isoformat().replace("+00:00", "Z")
        return self._store_decision(rec)

    def record_approval(self, manifest_id: str, approved_by: list, approved_at: str | None = None,
                        decision: str = "approved") -> dict:
        m = self._own_manifest(manifest_id)
        approved_at = approved_at or self._clock()
        reasons = []
        try:
            parse_time(approved_at)
        except Malformed:
            reasons.append("malformed approval timestamp")
            approved_at = self._clock()
        if decision not in ("approved", "rejected", "more_evidence"):
            reasons.append("unknown approval decision")
        valid_people = (isinstance(approved_by, list) and bool(approved_by)
                        and all(isinstance(a, dict) and isinstance(a.get("role"), str) and a["role"]
                                and set(a).issubset({"role", "principal", "auth_ref"})
                                and all(isinstance(v, str) for v in a.values()) for a in approved_by))
        if not valid_people:
            reasons.append("malformed approver list")
            approved_by = []
        if m is None:
            reasons.append("manifest not built by this gate or seal invalid")
        rec = {"record_type": "ApprovalRecord", "approval_id": str(uuid.uuid4()), "manifest_id": manifest_id,
               "manifest_digest": manifest_digest(m) if m else None,
               "action_id": m["action_target"]["action_id"] if m else None,
               "profile_digest": m["profile_ref"]["profile_digest"] if m else None,
               "approved_by": copy.deepcopy(approved_by), "approved_at": approved_at,
               "decision": "rejected" if reasons else decision, "reasons": reasons}
        self._seal(rec)
        with self._lock:
            self._approvals[rec["approval_id"]] = {"record": copy.deepcopy(rec), "consumed_by": None}
        return copy.deepcopy(rec)

    def _validate_approval(self, profile, manifest, approval, at) -> list:
        reasons = []
        aa = manifest["autonomy_approval"]
        if approval.get("decision") != "approved":
            reasons.append("approval decision is not 'approved'")
        if approval.get("manifest_digest") != manifest_digest(manifest) or approval.get("manifest_id") != manifest["manifest_id"] or approval.get("action_id") != manifest["action_target"]["action_id"]:
            reasons.append("approval is bound to a different Manifest")
        if approval.get("profile_digest") != profile_digest(profile):
            reasons.append("approval was given under a different Profile version")
        try:
            approved_at = parse_time(approval.get("approved_at"))
            if approved_at > at:
                reasons.append("approval is dated in the future")
            if not (parse_time(manifest["issued_at"]) <= approved_at <= parse_time(manifest["review_expires_at"])):
                reasons.append("approval was given outside the Manifest's review window")
            t = aa.get("approval_timeout_minutes")
            if t is not None and at > approved_at + timedelta(minutes=t):
                reasons.append("approval has timed out")
        except Malformed as e:
            reasons.append(f"malformed approval timestamp: {e}")
        approvers = approval.get("approved_by", [])
        roles = [a.get("role") for a in approvers]
        required_roles = set(aa.get("approver_roles") or profile["approval_policy"]["approver_roles"])
        if not roles or not set(roles).issubset(required_roles):
            reasons.append(f"approver role(s) {roles} not within the required set {sorted(required_roles)}")
        pol = profile["approval_policy"]
        principals = []
        for a in approvers:
            pr = a.get("principal")
            if pol.get("principal_authentication_required", True) and (not pr or not a.get("auth_ref") or not self._require_state_bool("authenticated", pr, a["auth_ref"])):
                reasons.append(f"approver '{pr or '?'}' is not an authenticated principal")
            if pr:
                principals.append(pr)
        if manifest["credentials"]["identity"] in principals:
            reasons.append("agent's own execution identity appears as an approver")
        if aa.get("dual_approval_required"):
            if pol.get("distinct_principals_required", True) and len(set(principals)) < 2:
                reasons.append("dual approval requires two distinct authenticated principals")
            elif not pol.get("distinct_principals_required", True) and len(set(roles)) < 2:
                reasons.append("dual approval requires two distinct approver roles")
        return reasons

    # Atomic LOCAL reservation, then dispatch OUTSIDE the ledger lock.
    def execute(self, manifest_id: str, approval_id: str | None = None, now: str | None = None) -> dict:
        override = now  # trusted test override; a production HTTP handler must not accept this from an agent
        now = now or self._clock()
        m = self._own_manifest(manifest_id)
        rec = {"record_type": "ExecutionRecord", "execution_id": str(uuid.uuid4()),
               "manifest_id": manifest_id, "manifest_digest": manifest_digest(m) if m else None,
               "gate_decision_id": None, "approval_id": approval_id,
               "request_digest": m.get("request_digest") if m else None,
               "requested_at": self._record_time(now), "authorized_at": None,
               "execution_state": "NOT_DISPATCHED", "reconciliation_required": False}
        if m is None:
            return self._finish(rec, "DENY", ["manifest not built by this gate or seal invalid"])
        try:
            at = parse_time(now)
        except Malformed as exc:
            return self._finish(rec, "DENY", [str(exc)])
        try:
            prof, err = self._active_profile_for(m)
        except DependencyUnavailable as exc:
            return self._finish(rec, "INDETERMINATE", [str(exc)])
        if err:
            return self._finish(rec, "DENY", [err])
        denied, unresolved = [], []
        if m["autonomy_approval"]["mode"] == "recommend":
            denied.append("recommend-only Manifests are never executed")
        if at >= parse_time(m["review_expires_at"]):
            denied.append("Manifest review window has expired")
        dec = self._decide(m, now)
        rec["gate_decision_id"] = dec["decision_id"]
        if dec["decision"] != "ALLOW":
            message = f"pre-execution evaluation is {dec['decision']}: {dec.get('violations') or dec.get('unresolved_delegations') or dec.get('reasons')}"
            (denied if dec["decision"] == "DENY" else unresolved).append(message)
            unresolved.extend(dec.get("dependency_errors", []))
        with self._lock:
            executor = self._executors.get((m["action_target"]["tool"], m["action_target"]["operation"]))
            approval_entry = copy.deepcopy(self._approvals.get(approval_id)) if approval_id else None
        if executor is None:
            denied.append("no executor registered for this operation; the gate does not hand out authorization for another component to execute")
        if m["autonomy_approval"]["approval_required"]:
            if not approval_id:
                denied.append("approval required but none supplied")
            elif approval_entry is None or not self._sealed_ok(approval_entry["record"]):
                denied.append("approval unknown or seal invalid (caller-supplied records are not trusted)")
            else:
                try:
                    denied.extend(self._validate_approval(prof, m, approval_entry["record"], at))
                except DependencyUnavailable as exc:
                    unresolved.append(str(exc))
                if approval_entry["consumed_by"] is not None:
                    denied.append("approval already consumed (replay)")
        action = m["action_target"]
        request = {"tool": action["tool"], "operation": action["operation"],
                   "effect_target": copy.deepcopy(action["effect_target"]),
                   "parameters": copy.deepcopy(action.get("parameters") or {})}
        material_digest = request_digest(request["tool"], request["operation"], request["effect_target"], request["parameters"])
        if material_digest != m["request_digest"]:
            denied.append("canonical material execution request does not match the checked Manifest")
        # Time and active Profile are checked again after potentially slow dependency calls.
        try:
            credential_time = parse_time(override or self._clock())
            if not self._require_state_bool("credential_valid", m["credentials"]["identity"], credential_time):
                denied.append("execution credential not valid (live state)")
        except DependencyUnavailable as exc:
            unresolved.append(str(exc))
        except Malformed as exc:
            denied.append(str(exc))
        try:
            _, changed = self._active_profile_for(m)
            if changed:
                denied.append(changed)
        except DependencyUnavailable as exc:
            unresolved.append(str(exc))
        # Re-read the independent stop after other potentially slow provider calls.
        # This remains an external observation, not a transaction with the remote effect.
        try:
            if not self._require_state_bool("kill_switch_allows", prof):
                denied.append("emergency stop is active (final live check)")
        except DependencyUnavailable as exc:
            unresolved.append(str(exc))
        dispatch_time = override or self._clock()
        try:
            dispatch_at = parse_time(dispatch_time)
            if dispatch_at < at:
                unresolved.append("gate clock moved backwards during authorization")
            if dispatch_at >= parse_time(m["review_expires_at"]):
                denied.append("Manifest review window expired while evaluating dependencies")
            if dec.get("execution_valid_until") and dispatch_at >= parse_time(dec["execution_valid_until"]):
                denied.append("fresh authorization window expired while evaluating dependencies")
            if approval_entry is not None and self._sealed_ok(approval_entry["record"]):
                approved_time = parse_time(approval_entry["record"]["approved_at"])
                timeout = m["autonomy_approval"].get("approval_timeout_minutes")
                if timeout is not None and dispatch_at > approved_time + timedelta(minutes=timeout):
                    denied.append("approval timed out while evaluating dependencies")
        except Malformed as exc:
            denied.append(str(exc))
        if denied or unresolved:
            return self._finish(rec, "DENY" if denied else "INDETERMINATE", denied + unresolved)
        action_key = (prof["profile_id"], action["action_id"])
        rec["idempotency_key"] = digest({"namespace": "aam-action-v1", "profile_id": action_key[0], "action_id": action_key[1]})
        # No executor, StateProvider, or identity-provider call runs inside this lock.
        with self._lock:
            current = self._manifests.get(manifest_id)
            if not self._manifest_ok(current) or manifest_digest(current) != manifest_digest(m):
                return self._finish(rec, "DENY", ["Manifest changed before dispatch reservation"], locked=True)
            admission_issues = self._admission_issues(m)
            if admission_issues:
                return self._finish(rec, "DENY", admission_issues, locked=True)
            prior_id = self._dispatches.get(manifest_id) or self._action_dispatches.get(action_key)
            if prior_id:
                rec["duplicate_of_execution_id"] = prior_id
                return self._finish(rec, "DENY", ["Manifest or action_id already dispatched; reconcile the original execution, do not retry with a new ID"], locked=True)
            if m["autonomy_approval"]["approval_required"]:
                entry = self._approvals.get(approval_id)
                if (entry is None or not self._sealed_ok(entry["record"])
                        or entry["record"]["seal"] != approval_entry["record"]["seal"]):
                    return self._finish(rec, "DENY", ["approval changed or seal invalid before dispatch"], locked=True)
                if entry["consumed_by"] is not None:
                    return self._finish(rec, "DENY", ["approval already consumed (replay)"], locked=True)
                entry["consumed_by"] = rec["execution_id"]
            self._dispatches[manifest_id] = rec["execution_id"]
            self._action_dispatches[action_key] = rec["execution_id"]
            rec.update({"authorized_at": dispatch_time, "dispatched_at": dispatch_time,
                        "execution_state": "DISPATCHED", "executed_request_digest": material_digest,
                        "reconciliation_required": True})
            self._finish(rec, "ALLOW", [], locked=True)
        context = {"execution_id": rec["execution_id"], "manifest_id": manifest_id,
                   "manifest_digest": rec["manifest_digest"], "request_digest": material_digest,
                   "idempotency_key": rec["idempotency_key"]}
        fn, with_context = executor
        try:
            receipt = fn(copy.deepcopy(request), copy.deepcopy(context)) if with_context else fn(copy.deepcopy(request))
            canonical(receipt)  # invalid receipts are ambiguous failures after dispatch too
            rec["receipt"] = copy.deepcopy(receipt)
        except ExecutorNotAttempted:
            rec.update({"execution_state": "NOT_ATTEMPTED", "not_attempted_at": override or self._clock(),
                        "reconciliation_required": False, "receipt": {"error_type": "ExecutorNotAttempted"}})
            return self._finish(rec, "ALLOW", ["trusted adapter asserts no downstream attempt; approval and dispatch reservations remain consumed"])
        except Exception as exc:
            rec.update({"execution_state": "EXECUTION_UNKNOWN", "execution_unknown_at": override or self._clock(),
                        "reconciliation_required": True, "receipt": {"error_type": type(exc).__name__}})
            return self._finish(rec, "ALLOW", [f"executor/receipt failure after dispatch ({type(exc).__name__}); effect may have committed; reconciliation required; no automatic retry"])
        rec.update({"execution_state": "ACKNOWLEDGED", "acknowledged_at": override or self._clock(),
                    "reconciliation_required": False})
        return self._finish(rec, "ALLOW", [])

    def _finish(self, rec, decision, reasons, locked=False):
        # `decision` is a compatibility alias for AUTHORIZATION, not an outcome.
        rec.update({"decision": decision, "authorization_decision": decision, "reasons": list(reasons)})
        rec.setdefault("receipt", None)
        def store():
            previous = self._executions.get(rec["execution_id"])
            rec["record_sequence"] = previous["record_sequence"] + 1 if previous else 0
            rec["previous_record_seal"] = previous["seal"] if previous else None
            self._seal(rec)
            snapshot = copy.deepcopy(rec)
            self._executions[rec["execution_id"]] = snapshot
            self._execution_events.append(copy.deepcopy(snapshot))
            return copy.deepcopy(snapshot)
        if locked:
            return store()
        with self._lock:
            return store()

    def get_execution(self, execution_id: str) -> dict | None:
        with self._lock:
            record = copy.deepcopy(self._executions.get(execution_id))
        return record if record is not None and self._sealed_ok(record) else None

    def execution_history(self, execution_id: str) -> list[dict]:
        with self._lock:
            return copy.deepcopy([e for e in self._execution_events if e["execution_id"] == execution_id])

    def reconciliation_history(self, execution_id: str) -> list[dict]:
        """Detached snapshots of every reconciliation attempt, including rejected races."""
        with self._lock:
            return copy.deepcopy([r for r in self._reconciliations.values() if r['execution_id'] == execution_id])

    def reconcile(self, execution_id: str, now: str | None = None) -> dict:
        """Read-only reconciliation of EXECUTION_UNKNOWN; no retry/approval restoration.

        Provider I/O is outside the ledger lock. The final transition compares the
        exact execution seal/version examined before the read. A delayed result never
        overwrites a newer settlement; every attempt gets a sealed record. A positive
        settlement establishes COMMITTED, not verified business postconditions.
        """
        override = now
        now = now or self._clock()
        ex = self.get_execution(execution_id)
        record = {
            'record_type': 'ReconciliationRecord', 'reconciliation_id': str(uuid.uuid4()),
            'execution_id': execution_id, 'manifest_id': ex['manifest_id'] if ex else None,
            'manifest_digest': ex['manifest_digest'] if ex else None,
            'idempotency_key': ex.get('idempotency_key') if ex else None,
            'requested_at': self._record_time(now), 'reconciled_at': self._record_time(now),
            'expected_record_sequence': ex['record_sequence'] if ex else None,
            'examined_execution_seal': ex['seal'] if ex else None,
            'state_before': ex['execution_state'] if ex else None,
            'state_after': ex['execution_state'] if ex else None,
            'applied': False, 'disposition': 'UNKNOWN', 'evidence': None, 'reasons': [],
            'observation_clock_skew_seconds': self.observation_clock_skew_seconds,
            'max_evidence_age_seconds': self.reconciliation_max_age_seconds,
        }

        def store_locked():
            self._seal(record)
            self._reconciliations[record['reconciliation_id']] = copy.deepcopy(record)
            return copy.deepcopy(record)

        def reject(reason):
            record['reasons'].append(reason)
            with self._lock:
                current = self._executions.get(execution_id)
                if current is not None and self._sealed_ok(current):
                    record['state_after'] = current['execution_state']
                return store_locked()

        try:
            started_at = parse_time(now)
        except Malformed:
            return reject('malformed reconciliation timestamp')
        if ex is None or ex['execution_state'] != 'EXECUTION_UNKNOWN' or ex['authorization_decision'] != 'ALLOW':
            return reject('only a sealed, authorized EXECUTION_UNKNOWN may be reconciled')
        manifest = self._own_manifest(ex['manifest_id'])
        if manifest is None or manifest_digest(manifest) != ex['manifest_digest']:
            return reject('immutable Manifest unavailable or invalid')
        try:
            evidence = self._state_call('reconcile', manifest, ex)
        except DependencyUnavailable as exc:
            return reject(str(exc))
        try:
            completed_time = override or self._clock()
            completed_at = parse_time(completed_time)
            record['reconciled_at'] = completed_time
            if completed_at < started_at:
                return reject('gate clock moved backwards during reconciliation')
            canonical(evidence)  # reject objects which cannot be captured in an audit record
            if not isinstance(evidence, dict) or evidence.get('record_type') != 'ReconciliationEvidence' or schema_errors(LIFECYCLE_V, evidence):
                return reject('unresolved or malformed reconciliation evidence; no state transition')
            record['evidence'] = copy.deepcopy(evidence)
            record['disposition'] = evidence['disposition']
            context = reconciliation_context(ex, manifest)
            if any(evidence[k] != value for k, value in context.items()):
                return reject('reconciliation evidence binding mismatch')
            observed_at = parse_time(evidence['observed_at'])
            # Clock skew never admits a timestamp predating the completed dispatch attempt.
            if observed_at < parse_time(ex['execution_unknown_at']):
                return reject('reconciliation evidence predates the completed dispatch attempt')
            if observed_at > completed_at + timedelta(seconds=self.observation_clock_skew_seconds):
                return reject('reconciliation evidence future-dated beyond clock-skew tolerance')
            if (completed_at - observed_at).total_seconds() > self.reconciliation_max_age_seconds:
                return reject('reconciliation evidence is stale')
            if evidence['disposition'] == 'UNKNOWN':
                return reject('transaction status remains unknown; no state transition')
            if evidence['final'] is not True:
                return reject('definitive reconciliation requires terminal downstream evidence')
        except (Malformed, TypeError, ValueError, KeyError):
            return reject('invalid reconciliation evidence/time; no state transition')
        with self._lock:
            current = self._executions.get(execution_id)
            if (current is None or not self._sealed_ok(current) or current['seal'] != ex['seal']
                    or current['record_sequence'] != ex['record_sequence']
                    or current['execution_state'] != 'EXECUTION_UNKNOWN'):
                record['state_after'] = current['execution_state'] if current and self._sealed_ok(current) else None
                record['reasons'].append('execution changed during reconciliation; stale result rejected without overwrite')
                return store_locked()
            updated = copy.deepcopy(current)
            updated.update({'execution_state': evidence['disposition'], 'reconciliation_required': False,
                            'reconciled_at': record['reconciled_at'],
                            'last_reconciliation_id': record['reconciliation_id']})
            self._finish(updated, 'ALLOW', ['execution reconciled from terminal transaction evidence; outcome verification remains separate; no retry authorized'], locked=True)
            record.update({'applied': True, 'state_after': evidence['disposition']})
            return store_locked()

    def attestation_context(self, execution_id: str, test_id: str) -> dict:
        """Return binding/challenge data, never sign a caller's proposed observation."""
        execution = self.get_execution(execution_id)
        if execution is None or execution["execution_state"] not in ("ACKNOWLEDGED", "EXECUTION_UNKNOWN", "COMMITTED"):
            raise ValueError("execution must have a completed dispatch attempt")
        manifest = self._own_manifest(execution["manifest_id"])
        if manifest is None:
            raise ValueError("Manifest unavailable or invalid")
        return observation_context(execution, manifest, test_id)

    def _attestation_ok(self, att: dict) -> bool:
        if not isinstance(att, dict) or att.get("record_type") != "VerifierAttestation" or schema_errors(LIFECYCLE_V, att):
            return False
        with self._lock:
            verifier = self._verifiers.get(att["verifier_id"])
        if not verifier or att["source"] not in verifier["sources"] or att["method"] not in verifier["methods"]:
            return False
        body = {k: v for k, v in att.items() if k != "seal"}
        expected = hmac.new(verifier["secret"], canonical(body).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(att["seal"], expected)

    def _observation_errors(self, observation, context, ex, plan, test, at):
        if not isinstance(observation, dict) or observation.get("record_type") not in ("ObservationRecord", "VerifierAttestation"):
            return ["structured observation required; raw booleans are not evidence"]
        if schema_errors(LIFECYCLE_V, observation):
            return ["observation schema invalid"]
        errors = [f"observation binding mismatch: {k}" for k in BINDING_FIELDS if observation.get(k) != context[k]]
        try:
            observed_at = parse_time(observation["observed_at"])
            floor = parse_time(ex.get("acknowledged_at") or ex.get("execution_unknown_at") or ex["dispatched_at"])
            if observed_at < floor:
                errors.append("observation predates completion of the dispatch attempt")
            if observed_at > at + timedelta(seconds=self.observation_clock_skew_seconds):
                errors.append("observation is future-dated beyond configured clock-skew tolerance")
            if (at - observed_at).total_seconds() > plan["max_observation_age_seconds"]:
                errors.append("observation is stale")
            if "timeout_minutes" in test and observed_at > parse_time(ex["dispatched_at"]) + timedelta(minutes=test["timeout_minutes"]):
                errors.append("observation is after the test's post-dispatch deadline")
        except (Malformed, KeyError):
            errors.append("observation/execution timestamp invalid")
        return errors

    def _store_outcome(self, rec):
        self._seal(rec)
        with self._lock:
            self._outcomes[rec["verification_id"]] = copy.deepcopy(rec)
        return copy.deepcopy(rec)

    def verify_outcome(self, execution_id: str, now: str | None = None, attestations: list | None = None) -> dict:
        override = now
        now = now or self._clock()
        ex = self.get_execution(execution_id)
        base = {"record_type": "OutcomeVerificationRecord", "verification_id": str(uuid.uuid4()),
                "execution_id": execution_id, "verified_at": self._record_time(now),
                "manifest_id": ex["manifest_id"] if ex else None,
                "manifest_digest": ex["manifest_digest"] if ex else None,
                "results": [], "verified": False, "postconditions_verified": False,
                "observation_clock_skew_seconds": self.observation_clock_skew_seconds,
                "completion": "escalate", "reconciliation_required": bool(ex and ex["reconciliation_required"]), "reasons": []}
        try:
            at = parse_time(now)
        except Malformed as exc:
            base["reasons"] = [str(exc)]
            return self._store_outcome(base)
        if ex is None or ex["authorization_decision"] != "ALLOW" or ex["execution_state"] not in ("ACKNOWLEDGED", "EXECUTION_UNKNOWN", "COMMITTED"):
            base["reasons"] = ["execution unknown, unsealed, not authorized, or dispatch still in progress"]
            return self._store_outcome(base)
        m = self._own_manifest(ex["manifest_id"])
        if m is None or manifest_digest(m) != ex["manifest_digest"]:
            base["reasons"] = ["execution's immutable Manifest unavailable or invalid"]
            return self._store_outcome(base)
        plan = m["outcome_verification"]
        errors = verification_errors(plan, "verification_tests")
        if errors:
            base["reasons"] = errors
            return self._store_outcome(base)
        required = required_test_ids(plan)
        valid_atts = []
        if attestations is not None and not isinstance(attestations, list):
            base["reasons"].append("attestations must be a list; ignored")
        else:
            for att in attestations or []:
                if self._attestation_ok(att):
                    valid_atts.append(copy.deepcopy(att))
                else:
                    base["reasons"].append("invalid, unauthenticated or out-of-scope attestation ignored")
        for test in plan["verification_tests"]:
            result = {"test_id": test["test_id"], "assertion": test["assertion"], "method": test["method"],
                      "source": test["source"], "observed": None, "observed_via": "unobserved",
                      "required_for_completion": test["test_id"] in required, "evidence_errors": []}
            if "postcondition_index" in test:
                result["postcondition_index"] = test["postcondition_index"]
            if test["method"] not in INDEPENDENT:
                base["results"].append(result)  # tool receipts never count as observations
                continue
            context = observation_context(ex, m, test["test_id"])
            observation, via = None, None
            candidates = []
            if test["method"] in ("read_system_of_record", "independent_observation"):
                try:
                    candidate = self._state_call("observe", test, m, ex)
                    at = parse_time(override or self._clock())
                    if candidate is not None:
                        errs = self._observation_errors(candidate, context, ex, plan, test, at)
                        # An attestation is accepted only via the registered-verifier path.
                        if isinstance(candidate, dict) and candidate.get("record_type") != "ObservationRecord":
                            errs.append("StateProvider.observe must return an ObservationRecord")
                        result["evidence_errors"].extend(errs)
                        if not errs:
                            candidates.append((candidate, "system_of_record_read"))
                except DependencyUnavailable as exc:
                    result["evidence_errors"].append(str(exc))
            for att in valid_atts:
                if att["test_id"] != test["test_id"]:
                    continue
                errs = self._observation_errors(att, context, ex, plan, test, at)
                result["evidence_errors"].extend(errs)
                if not errs:
                    via = "human_attestation" if test["method"] == "human_confirmation" else "verifier_attestation"
                    candidates.append((att, via))
            # Store exact accepted evidence (including negative/conflicting evidence), not
            # just a winning boolean. Sources are trusted but neither silently overrides another.
            result["admissible_evidence"] = [copy.deepcopy(item) for item, _ in candidates]
            result["evidence_conflict"] = len({item["observed"] for item, _ in candidates}) > 1
            if result["evidence_conflict"]:
                result["evidence_errors"].append("conflicting admissible observations for this test; no source takes implicit priority")
            elif candidates:
                observation, via = max(candidates, key=lambda pair: parse_time(pair[0]["observed_at"]))
            if observation is not None:
                result.update({"observed": observation["observed"], "observed_via": via,
                               "observed_at": observation["observed_at"], "source_version": observation["source_version"],
                               "evidence_ref": observation["evidence_ref"]})
                if "verifier_id" in observation:
                    result["attested_by"] = observation["verifier_id"]
            base["results"].append(result)
        # An earlier read may have become stale while a later adapter was running.
        final_time = override or self._clock()
        final_at = parse_time(final_time)
        base["verified_at"] = final_time
        for result in base["results"]:
            if result["observed"] is not None:
                observed_at = parse_time(result["observed_at"])
                if observed_at > final_at + timedelta(seconds=self.observation_clock_skew_seconds) or (final_at - observed_at).total_seconds() > plan["max_observation_age_seconds"]:
                    result["observed"] = None
                    result["observed_via"] = "unobserved"
                    result["evidence_errors"].append("observation outside freshness window at final verification time")
        current = self.get_execution(execution_id)
        if current is None or current["seal"] != ex["seal"]:
            base["reasons"].append("execution changed during verification; repeat verification against the new snapshot")
            base["reconciliation_required"] = bool(current and current["reconciliation_required"])
            return self._store_outcome(base)
        base["postconditions_verified"] = bool(required) and all(
            r["observed"] is True for r in base["results"] if r["required_for_completion"])
        base["verified"] = base["postconditions_verified"] and ex["execution_state"] in ("ACKNOWLEDGED", "COMMITTED")
        base["completion"] = "complete" if base["verified"] else plan["on_failure"]
        if ex["execution_state"] == "EXECUTION_UNKNOWN":
            base["completion"] = "escalate"
            base["reconciliation_required"] = True
            base["reasons"].append("dispatch outcome is unknown; observations do not authorize retry or settle downstream reconciliation")
        elif not base["postconditions_verified"]:
            base["reasons"].append("required postconditions are false, unobservable, stale, or invalid")
        return self._store_outcome(base)


def _rank(mode):
    return MODES.index(mode)
