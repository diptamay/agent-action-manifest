"""Identity-bound Part A/B read-back approval, separate from Profile publication keys.

A signature authenticates a key. A deployment-owned trust root binds that key to a
principal, permitted roles and parts. Neither a principal string nor an uploaded
public key establishes identity by itself. No online identity/key service is included.
"""
from __future__ import annotations
import copy
import json
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from check_containment import canonical, digest, profile_digest, parse_time, utc_now_iso, Malformed
from validation_support import strict_format_checker

SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'
LIFECYCLE_V = Draft202012Validator(json.loads((SCHEMAS / 'lifecycle-records.schema.json').read_text()), format_checker=strict_format_checker())
PROFILE_V = Draft202012Validator(json.loads((SCHEMAS / 'agent-authority-profile.schema.json').read_text()), format_checker=strict_format_checker())
READBACK_VERSION = 'aam-readback/0.3.6'
PART_ROLES = {'A': {'product_owner'}, 'B': {'engineering'}, 'profile': {'product_owner', 'engineering'}}


def review_binding(profile: dict, part: str) -> dict:
    # Lazy import avoids a CLI/module import cycle; the CLI and signer use one renderer.
    from aam import readback, review_digests
    if part not in PART_ROLES:
        raise ValueError('part must be A, B or profile')
    if list(PROFILE_V.iter_errors(profile)):
        raise ValueError('Profile schema invalid')
    from verification import verification_errors
    if any(verification_errors(op['verification']) for op in profile['permissions']['allowed']):
        raise ValueError('Profile verification plan invalid')
    return {'profile_id': profile['profile_id'], 'profile_version': profile['profile_version'],
            'profile_digest': profile_digest(profile), 'part': part,
            'review_digest': review_digests(profile)[part],
            'readback_digest': digest(readback(profile)), 'readback_version': READBACK_VERSION}


def sign_readback(profile: dict, *, part: str, principal: str, role: str,
                  private_key_bytes: bytes, key_id: str, signed_at: str | None = None) -> dict:
    if any(not isinstance(value, str) or not value.strip() for value in (principal, role, key_id)):
        raise ValueError('principal, role and key_id are required')
    if role not in PART_ROLES.get(part, set()):
        raise ValueError('role does not match the reviewed part')
    signed_at = signed_at or utc_now_iso()
    parse_time(signed_at)
    body = {'record_type': 'ReadbackSignoff', 'schema_version': '0.3.6',
            'signoff_id': str(uuid.uuid4()), **review_binding(profile, part),
            'principal': principal, 'role': role, 'signed_at': signed_at,
            'binding': 'identity_bound', 'key_id': key_id}
    # Finalize every field BEFORE signing. No signed field changes afterwards.
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical(body).encode('utf-8'))
    record = {**body, 'signature': {'method': 'ed25519', 'value': signature.hex()}}
    if list(LIFECYCLE_V.iter_errors(record)):
        raise ValueError('constructed sign-off does not match its schema')
    return record


def verify_readback_signoff(profile: dict, record: dict, trust_roots: dict,
                            now: str | None = None) -> dict:
    """Verify exact rendered review, Profile binding, signature and authorized identity."""
    reasons = []
    try:
        if not isinstance(record, dict) or record.get('record_type') != 'ReadbackSignoff' or list(LIFECYCLE_V.iter_errors(record)):
            return {'valid': False, 'reasons': ['invalid ReadbackSignoff schema']}
        expected = review_binding(profile, record['part'])
        if any(record[key] != value for key, value in expected.items()):
            reasons.append('sign-off is bound to a different Profile or read-back')
        at, signed = parse_time(now or utc_now_iso()), parse_time(record['signed_at'])
        if signed > at or signed < parse_time(profile['issued_at']):
            reasons.append('sign-off is future-dated or predates the Profile')
        if profile.get('expires_at') and signed >= parse_time(profile['expires_at']):
            reasons.append('sign-off was made after Profile expiry')
        root = trust_roots.get(record['key_id'])
        if not isinstance(root, dict) or root.get('method') != 'ed25519':
            return {'valid': False, 'reasons': reasons + ['no trusted Ed25519 principal binding for this key']}
        if root.get('revoked', False) is not False:
            reasons.append('signing key is revoked or has invalid revocation state')
        if root.get('principal') != record['principal']:
            reasons.append('key is not bound to the claimed principal')
        if (not isinstance(root.get('roles'), list) or record['role'] not in root['roles']
                or record['role'] not in PART_ROLES[record['part']]):
            reasons.append('key/principal is not authorized for the claimed role')
        if not isinstance(root.get('parts'), list) or record['part'] not in root['parts']:
            reasons.append('key/principal is not authorized for this part')
        if root.get('not_before') and signed < parse_time(root['not_before']):
            reasons.append('sign-off predates key validity')
        if root.get('not_before') and at < parse_time(root['not_before']):
            reasons.append('key is not yet valid')
        if root.get('not_after') and (signed >= parse_time(root['not_after']) or at >= parse_time(root['not_after'])):
            reasons.append('key validity has expired')
        body = {key: value for key, value in record.items() if key != 'signature'}
        Ed25519PublicKey.from_public_bytes(root['public_key']).verify(
            bytes.fromhex(record['signature']['value']), canonical(body).encode('utf-8'))
    except InvalidSignature:
        reasons.append('sign-off signature does not verify')
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        reasons.append('invalid Profile, sign-off, trust material or verification time')
    return {'valid': not reasons, 'reasons': reasons}


def verify_required_signoffs(profile: dict, records: list | None, trust_roots: dict, now: str) -> dict:
    """Publication policy: valid A/product-owner and B/engineering, distinct principals.

    Whole-Profile sign-offs are supported as audit records but do not replace the two
    independently attributed Part A/B approvals. Supplied invalid records fail closed.
    """
    if not isinstance(records, list) or not records:
        return {'valid': False, 'reasons': ['publication requires identity-bound Part A and Part B sign-offs']}
    reasons, principals = [], {'A': set(), 'B': set()}
    for record in records:
        result = verify_readback_signoff(profile, record, trust_roots, now)
        reasons.extend(result['reasons'])
        if result['valid'] and record['part'] in principals:
            principals[record['part']].add(record['principal'])
    if not principals['A'] or not principals['B']:
        reasons.append('both authorized Part A and Part B sign-offs are required')
    elif not any(a != b for a in principals['A'] for b in principals['B']):
        reasons.append('Part A and Part B must be approved by distinct principals')
    return {'valid': not reasons, 'reasons': reasons}


def load_readback_trust_roots(path: str) -> dict:
    """Read deployment-controlled JSON; never trust a roots file supplied by an agent.

    Each root uses public_key_hex on disk, principal, roles and parts. Key material is
    converted to bytes for the verifier. This file is configuration, not self-certified identity.
    """
    roots = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(roots, dict):
        raise ValueError('read-back trust roots must be an object')
    result = copy.deepcopy(roots)
    for key_id, root in result.items():
        if not isinstance(root, dict) or not isinstance(key_id, str):
            raise ValueError('malformed trust root')
        root['public_key'] = bytes.fromhex(root.pop('public_key_hex'))
    return result
