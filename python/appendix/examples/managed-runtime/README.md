# Managed AP demo — synthetic v0.3.7 compatibility path

Run `python appendix/tests/run_managed_demo.py` from repo root to regenerate `generated/`. All actions, evidence, times and principals are synthetic; no email or network call occurs. The temporary local databases are deleted after the run; exportable example artifacts remain.

Unlike the main illustrative Card (emails always reviewed), this demo intentionally signs a different autonomous-draft Profile so an authenticated evaluation regression can tighten operation to REQUIRE_APPROVAL. The test first shows refusal without approval, then an approved allowed draft, verification and authenticated manual restoration. It never permits sending or payment.

`generated/audit-events.json` contains 21 linked events for this scenario. Random identifiers/hashes may change on regeneration; count and semantics are asserted. `managed-readback.md` resolves the exact feedback policy. `metrics.prom` is an example text snapshot, not a running endpoint. `review-cases.json` is UNREVIEWED input for an owner-led correction/test workflow, not a generated policy.

Use protected external sources and trustworthy principal/role configuration in a real host. Demo keys and synthetic source assertions provide no production assurance.

`aggregate-policy.json` is the domain-neutral aggregate-policy fixture used by the extended regression suite. The retained managed demo itself continues to exercise the backwards-compatible Profile path.
