"""Helpers for trusted observation adapters and independent verifier components.

These functions DO NOT perform a read or authenticate a human. Call them only after
an actual observation. The gate never exposes a 'sign my boolean' endpoint. Keys and
these helpers belong to the verifier service, not the agent runtime.
"""
import copy
import hashlib
import hmac

from check_containment import canonical, digest, manifest_digest, parse_time

BINDING_FIELDS = (
    "execution_id", "manifest_digest", "request_digest", "test_id",
    "assertion_digest", "postcondition_digest", "effect_target_digest", "method", "source",
)


def observation_context(execution: dict, manifest: dict, test_id: str) -> dict:
    """Public challenge data only; contains neither credentials nor a signing key."""
    test = next((t for t in manifest["outcome_verification"]["verification_tests"]
                 if t["test_id"] == test_id), None)
    if test is None or "postcondition_index" not in test:
        raise ValueError("test_id must identify an independent postcondition test")
    if execution["manifest_digest"] != manifest_digest(manifest):
        raise ValueError("execution and Manifest do not match")
    return {
        "execution_id": execution["execution_id"],
        "manifest_digest": manifest_digest(manifest),
        "request_digest": manifest["request_digest"],
        "test_id": test_id,
        "assertion_digest": digest(test["assertion"]),
        "postcondition_digest": digest(manifest["outcome_verification"]["expected_postconditions"][test["postcondition_index"]]),
        "effect_target_digest": digest(manifest["action_target"]["effect_target"]),
        "method": test["method"], "source": test["source"],
    }


def make_observation(execution: dict, manifest: dict, test_id: str, observed: bool,
                     observed_at: str, *, source_version: str, evidence_ref: str) -> dict:
    """Build a structured result AFTER a trusted adapter has made a fresh read.

    source_version is the system's revision/version/cursor, not the gate's timestamp.
    evidence_ref should identify the read receipt or auditable evidence. Their truth
    remains the adapter's responsibility; the gate validates presence and binding.
    """
    if type(observed) is not bool:
        raise ValueError("observed must be a boolean, not a truthy substitute")
    parse_time(observed_at)
    if not isinstance(source_version, str) or not source_version or not isinstance(evidence_ref, str) or not evidence_ref:
        raise ValueError("source_version and evidence_ref must be non-empty strings")
    return {"record_type": "ObservationRecord", **observation_context(execution, manifest, test_id),
            "observed": observed, "observed_at": observed_at,
            "source_version": source_version, "evidence_ref": evidence_ref}


def seal_attestation(observation: dict, verifier_id: str, secret: bytes) -> dict:
    """Run in a trusted verifier component; HMAC authentication is not a signature.

    Gate registration restricts this verifier to declared sources and methods.
    """
    if observation.get("record_type") != "ObservationRecord" or type(observation.get("observed")) is not bool:
        raise ValueError("expected a structured ObservationRecord")
    if not verifier_id or not secret:
        raise ValueError("verifier identity and key are required")
    body = {**copy.deepcopy(observation), "record_type": "VerifierAttestation", "verifier_id": verifier_id}
    body.pop("seal", None)
    body["seal"] = hmac.new(secret, canonical(body).encode(), hashlib.sha256).hexdigest()
    return body
