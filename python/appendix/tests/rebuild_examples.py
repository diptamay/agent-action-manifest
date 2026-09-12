#!/usr/bin/env python3
"""Re-sign bundled DEMO Profiles and rebuild their gate-sealed Manifests.

Only bundled public demonstration keys are used. No live systems are contacted.
Do not use these keys, the fixed clock, or this all-green provider in production.
"""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from gate import Gate, InMemoryProfileStore, StateProvider, sign_profile_ed25519


class ExampleState(StateProvider):
    def kill_switch_allows(self, p): return True
    def credential_valid(self, i, at): return True
    def effect_target_in_class(self, et, c): return True
    def evaluate_rule(self, *args): return True
    def evaluate_selector(self, *args): return True
    def evaluate_threshold(self, *args): return True
    def egress_policy_permits(self, *args): return True
    def recovery_evidence(self, ref):
        tool, operation = ('github', 'open_pull_request') if 'repo' in ref else (('email', 'draft_email') if 'ap-agent' in ref else ('maintenance', 'draft_work_order'))
        return {'passed': True, 'tool': tool, 'operation': operation, 'tested_at': '2026-09-01T00:00:00Z'}
    def authenticated(self, *args): return True


def main():
    key_id = 'demo-profile-signing-2026'
    private = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.key.hex').read_text().strip())
    public = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
    for p in sorted((ROOT / 'examples').glob('*/profile.json')):
        profile = sign_profile_ed25519(json.loads(p.read_text()), private, key_id)
        p.write_text(json.dumps(profile, indent=2) + '\n')
        request = json.loads(p.with_name('request.json').read_text())
        previous = json.loads(p.with_name('manifest.json').read_text())
        gate = Gate(ExampleState(), InMemoryProfileStore(), b'test-secret', trust_roots={key_id: {'method': 'ed25519', 'public_key': public}})
        published = gate.publish_profile(profile)
        if not published['published']:
            raise RuntimeError(published)
        result = gate.propose(profile['profile_id'], request, previous['issued_at'], manifest_id=previous['manifest_id'])
        if result['decision']['decision'] != 'ALLOW':
            raise RuntimeError(result['decision'])
        p.with_name('manifest.json').write_text(json.dumps(result['manifest'], indent=2) + '\n')
        print('rebuilt', p.parent.name)


if __name__ == '__main__':
    main()
