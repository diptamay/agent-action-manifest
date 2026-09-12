#!/usr/bin/env python3
"""Run the reference suites and offline release-integration checks.

No live integrations or network calls. Fixed times and bundled public demo keys are
used only for fixtures. Core tests regenerate the containment-vector JSON file.
Optional --report writes the exact command results and environment used for this run.
"""
from __future__ import annotations
import argparse
import ast
import copy
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / 'tools'))
from jsonschema import Draft202012Validator
from check_containment import check
from gate import Gate, InMemoryProfileStore, StateProvider, PROFILE_V, MANIFEST_V, REQUEST_V, LIFECYCLE_V, schema_errors
from render_card import project, check_parity, coverage
from verification import verification_errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--report', type=Path)
    args = ap.parse_args()
    report = {
        'release': (REPO / 'VERSION').read_text().strip(),
        'run_at_utc': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(),
        'platform': platform.platform(),
        'dependencies': {p: importlib.metadata.version(p) for p in ('jsonschema', 'cryptography', 'rfc3339-validator')},
        'scope': 'Offline synthetic reference checks; not live integration, independent certification or production-safety proof.',
        'suites': [], 'integration_checks': [],
    }
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}

    def command(name, argv, expected=(0,), suite=False):
        proc = subprocess.run([sys.executable, *map(str, argv)], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=180)
        item = {'name': name, 'command': [sys.executable, *map(str, argv)],
                'returncode': proc.returncode, 'passed': proc.returncode in expected,
                'stdout': proc.stdout, 'stderr': proc.stderr}
        report['suites' if suite else 'integration_checks'].append(item)
        print(('PASS ' if item['passed'] else 'FAIL ') + name, flush=True)
        if not item['passed']:
            print(proc.stdout + proc.stderr, flush=True)
        return proc

    def assertion(name, value, detail=''):
        report['integration_checks'].append({'name': name, 'passed': bool(value), 'detail': detail})
        print(('PASS ' if value else 'FAIL ') + name, flush=True)

    command('core suite (174 checks)', ['tests/run_tests.py'], suite=True)
    command('prior-review regressions (10 cases; overlap core)', ['tests/adversarial_regressions.py'], suite=True)
    command('v0.3.5 boundary regressions retained (71 cases)', ['tests/boundary_regressions.py'], suite=True)
    command('v0.3.6 merge regressions (95 cases)', ['tests/merge_regressions.py'], suite=True)

    command('v0.3.7 audit and governed feedback (73 tests)', ['tests/audit_feedback_regressions.py'], suite=True)
    command('v0.4.0 aggregate/context/campaign/delegation (14 tests)', ['tests/v4_regressions.py'], suite=True)
    command('publication metadata and documentation regressions', ['tests/publication_regressions.py'], suite=True)

    syntax_errors = []
    for path in sorted(ROOT.rglob('*.py')):
        try:
            ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except SyntaxError as exc:
            syntax_errors.append(f'{path.relative_to(ROOT)}: {exc}')
    assertion('all Python files parse', not syntax_errors, '; '.join(syntax_errors))

    for path in sorted((ROOT / 'schemas').glob('*.json')):
        try:
            Draft202012Validator.check_schema(json.loads(path.read_text()))
            assertion('schema meta-validation: ' + path.name, True)
        except Exception as exc:
            assertion('schema meta-validation: ' + path.name, False, str(exc))

    vectors = json.loads((ROOT / 'tests/vectors/containment-vectors.json').read_text())['vectors']
    bad = []
    for v in vectors:
        result = check(v['profile'], v['manifest'], v['now'], resolved_delegations=v['resolved_delegations'])
        if result['decision'] != v['expect']:
            bad.append(v['name'])
        if v.get('expect_rule_prefix') and not any(x.startswith(v['expect_rule_prefix']) for x in result['violations']):
            bad.append(v['name'] + ': missing expected rule')
    assertion('59 exported containment vectors replay', len(vectors) == 59 and not bad, '; '.join(bad))

    public = bytes.fromhex((ROOT / 'examples/trust/demo-profile-signing.pub.hex').read_text().strip())
    for directory in sorted((ROOT / 'examples').glob('*-agent.*')):
        profile = json.loads((directory / 'profile.json').read_text())
        manifest = json.loads((directory / 'manifest.json').read_text())
        request = json.loads((directory / 'request.json').read_text())
        errs = schema_errors(PROFILE_V, profile) + schema_errors(MANIFEST_V, manifest) + schema_errors(REQUEST_V, request)
        for operation in profile['permissions']['allowed']:
            errs += verification_errors(operation['verification'])
        errs += verification_errors(manifest['outcome_verification'], 'verification_tests')
        assertion(directory.name + ': schema and verification plan', not errs, '; '.join(errs))
        gate = Gate(StateProvider(), InMemoryProfileStore(), b'release-synthetic-local-key',
                    trust_roots={'demo-profile-signing-2026': {'method': 'ed25519', 'public_key': public}})
        assertion(directory.name + ': demo Ed25519 verifies', gate.publish_profile(profile)['published'])
        card = project(manifest)
        assertion(directory.name + ': complete Card coverage/parity', coverage(manifest)['complete'] and check_parity(card, manifest)['ok'])

    example = ROOT / 'examples/business-workflow-agent.invoice-triage'
    lifecycle = ROOT / 'examples/lifecycle-v0.3.6'
    trace = json.loads((lifecycle / 'lifecycle-trace.json').read_text())
    record_errors = [error for record in trace['records'] for error in schema_errors(LIFECYCLE_V, record)]
    assertion('bundled synthetic lifecycle trace validates', not record_errors, '; '.join(record_errors))
    from readback_signoff import verify_readback_signoff, load_readback_trust_roots
    review_roots = load_readback_trust_roots(str(lifecycle / 'readback-trust-DEMO-ONLY.json'))
    review_profile = json.loads((example / 'profile.json').read_text())
    for part in ('A', 'B'):
        review_record = json.loads((lifecycle / ('readback-signoff-' + part + '.json')).read_text())
        review_result = verify_readback_signoff(review_profile, review_record, review_roots, trace['evaluation_time'])
        assertion('bundled Part ' + part + ' identity-bound demo signoff verifies', review_result['valid'], '; '.join(review_result['reasons']))
    with tempfile.TemporaryDirectory(prefix='aam-release-') as td:
        temp = Path(td)
        v4_out = temp / 'v4-demo'
        command('v0.4 synthetic quickstart', ['tests/run_v4_demo.py', '--out', v4_out])
        command('CLI validates v0.4 demo Profile', ['tools/aam.py', 'validate', v4_out / 'profile.json'])
        command('CLI validates v0.4 demo Manifest', ['tools/aam.py', 'validate', v4_out / 'manifest.json'])
        profile = temp / 'profile.json'
        command('CLI worksheet init', ['tools/aam.py', 'init', '--answers', 'examples/answers/ap-invoice-agent.answers.json', '--out', profile, '--version', '1.4.0'])
        command('CLI validate generated Profile', ['tools/aam.py', 'validate', profile])
        command('CLI complete Part A/B read-back', ['tools/aam.py', 'readback', profile])
        command('CLI keygen (temporary demo key)', ['tools/aam.py', 'keygen', '--out', temp / 'root'])
        command('CLI sign whole Profile', ['tools/aam.py', 'sign', profile, '--key', temp / 'root.key.hex', '--key-id', 'temporary-test-root'])
        signed = json.loads(profile.read_text())
        gate = Gate(StateProvider(), InMemoryProfileStore(), b'cli-test-key', trust_roots={
            'temporary-test-root': {'method': 'ed25519', 'public_key': bytes.fromhex((temp / 'root.pub.hex').read_text().strip())}})
        assertion('CLI signature accepted by configured trust root', gate.publish_profile(signed)['published'])
        roots_file = temp / 'readback-trust.json'
        roots_file.write_text(json.dumps({'temporary-test-root': {
            'method':'ed25519', 'public_key_hex':(temp / 'root.pub.hex').read_text().strip(),
            'principal':'user:test-product-owner', 'roles':['product_owner'], 'parts':['A','profile']}}))
        review_file = temp / 'review-a.json'
        command('CLI signoff: finalized identity-bound Part A record', ['tools/aam.py', 'signoff', profile,
                '--part','A','--principal','user:test-product-owner','--role','product_owner',
                '--key',temp / 'root.key.hex','--key-id','temporary-test-root','--out',review_file])
        command('CLI validates ReadbackSignoff structure', ['tools/aam.py','validate',review_file])
        command('CLI verifies saved signoff against trusted principal role and part',
                ['tools/aam.py','verify-signoff',profile,review_file,'--trust-roots',roots_file])
        review_record = json.loads(review_file.read_text())
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from check_containment import canonical
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex((temp/'root.pub.hex').read_text().strip())).verify(
                bytes.fromhex(review_record['signature']['value']),
                canonical({k:v for k,v in review_record.items() if k != 'signature'}).encode())
            signature_ok = True
        except Exception:
            signature_ok = False
        assertion('independent Ed25519 verifies exact saved signoff body', signature_ok)
        changed = copy.deepcopy(review_record); changed['binding'] = 'workflow'
        tampered = temp / 'tampered-review.json'; tampered.write_text(json.dumps(changed))
        command('CLI rejects post-signing mutation', ['tools/aam.py','verify-signoff',profile,tampered,'--trust-roots',roots_file],expected=(1,))
        untrusted = temp/'untrusted.json'; untrusted.write_text('{}')
        command('CLI rejects unknown signoff principal key', ['tools/aam.py','verify-signoff',profile,review_file,'--trust-roots',untrusted],expected=(1,))
        command('CLI signoff requires an explicit private key', ['tools/aam.py','signoff',profile,'--part','A',
                '--principal','user:test-product-owner','--role','product_owner','--key-id','test'],expected=(2,))
        invalid = copy.deepcopy(signed)
        plan = invalid['permissions']['allowed'][0]['verification']
        plan['completion_rule'] = 'designated_postconditions_verified'
        plan['designated_test_ids'] = ['not-a-real-test']
        (temp / 'invalid.json').write_text(json.dumps(invalid))
        command('CLI rejects unknown designated id semantically', ['tools/aam.py', 'validate', temp / 'invalid.json'], expected=(1,))
        invalid = copy.deepcopy(signed)
        invalid['issued_at'] = 'not-a-timestamp'
        (temp / 'invalid-date.json').write_text(json.dumps(invalid))
        command('CLI rejects malformed date-time', ['tools/aam.py', 'validate', temp / 'invalid-date.json'], expected=(1,))
        preview = temp / 'preview.json'
        command('CLI authoring-only proposal preview', ['tools/aam.py', 'propose', example / 'profile.json', example / 'request.json',
                '--trust-pub', ROOT / 'examples/trust/demo-profile-signing.pub.hex', '--now', '2026-09-05T14:10:00Z', '--out', preview])
        command('CLI validates preview Manifest', ['tools/aam.py', 'validate', preview])
        command('CLI renders complete Card', ['tools/render_card.py', preview])
        command('CLI unresolved historical check is non-executable', ['tools/aam.py', 'check', example / 'profile.json', example / 'manifest.json', '--now', '2026-09-05T14:10:00Z'], expected=(3,))
        command('CLI expired check denies', ['tools/aam.py', 'check', example / 'profile.json', example / 'manifest.json', '--now', '2026-09-07T00:00:00Z'], expected=(1,))

    managed = ROOT / 'examples/managed-runtime'
    generated = managed / 'generated'
    command('CLI validates feedback policy', ['tools/aam.py','validate',managed/'feedback-policy.json'])
    command('CLI validates policy-bearing Profile', ['tools/aam.py','validate',generated/'managed-profile.json'])
    command('CLI validates managed Manifest', ['tools/aam.py','validate',generated/'managed-manifest.json'])
    command('CLI validates active runtime controls', ['tools/aam.py','validate',generated/'restricted-control-snapshot.json'])
    command('CLI resolves exact policy in readback', ['tools/aam.py','readback',generated/'managed-profile.json','--feedback-policy',managed/'feedback-policy.json'])
    command('CLI refuses managed readback without policy', ['tools/aam.py','readback',generated/'managed-profile.json'],expected=(2,))
    from audit_review import review_cases
    audit_events=json.loads((generated/'audit-events.json').read_text())
    cases=review_cases(audit_events)
    assertion('bundled audit chain and offline review cases', cases['stream_event_count']==len(audit_events) and bool(cases['cases']))
    from feedback import policy_ref
    policy=json.loads((managed/'feedback-policy.json').read_text())
    managed_profile=json.loads((generated/'managed-profile.json').read_text())
    assertion('managed Profile pins exact feedback policy',managed_profile['monitoring_policy_ref']==policy_ref(policy))
    managed_manifest=json.loads((generated/'managed-manifest.json').read_text())
    assertion('managed Card preserves mode and complete parity',check_parity(json.loads((generated/'managed-card.json').read_text()),managed_manifest)['ok'] and coverage(managed_manifest)['complete'])
    assertion('bundled audit includes recorded control transitions', any(e['event_type']=='RESTRICTION_ACTIVATED' for e in audit_events))
    with tempfile.TemporaryDirectory(prefix='aam-managed-release-') as td:
        command('synthetic managed end-to-end scenario', ['tests/run_managed_demo.py','--out',td])
        command('offline audit review CLI never executes', ['tools/audit_review.py',generated/'audit-events.json','--out',Path(td)/'review.json'])

    all_items = report['suites'] + report['integration_checks']
    report['passed'] = all(x['passed'] for x in all_items)
    report['summary'] = {'suites_passed': sum(x['passed'] for x in report['suites']), 'suites_total': len(report['suites']),
                         'integration_checks_passed': sum(x['passed'] for x in report['integration_checks']),
                         'integration_checks_total': len(report['integration_checks']), 'containment_vectors': len(vectors)}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('Report: ' + str(args.report))
    print(json.dumps(report['summary'], indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
