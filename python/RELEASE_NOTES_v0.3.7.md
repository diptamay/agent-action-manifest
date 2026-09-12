# v0.3.7 — audit and governed feedback (Python)

Date: 7 September 2026. Base: completed Python v0.3.6. The attempted Java build is not used. Both historical archives remain unchanged.

## Added

- ManagedGate wraps the existing lifecycle rather than replacing it.
- Single-owner SQLite WAL/FULL and explicitly volatile in-memory runtime stores. Audit events, approval consumption, reservations, full lifecycle state and restrictions checkpoint together.
- Restart recovery preserves admitted unknown actions and duplicate blocks. Persistence failure returns an explicit non-durable RuntimeFailure and latches further admission.
- Typed feedback policy, digest-bound to Profile; distinct-incident count/windows; action/operation/Profile scoped REQUIRE_APPROVAL or SUSPENDED holds; no authority expansion.
- Authenticated external evaluation/adapter signals with ACL, Profile/operation version, timestamp and replay/content checks.
- Authenticated manual restoration with revision and unresolved-execution checks, composable causes and no restored approvals/retries.
- At-least-once export with persistent cursor, example idempotent local receiver, metrics text and an explicitly scheduled watchdog.
- Offline review-case extraction with no executor, training or policy-write path.
- Schema/CLI support for new contracts; resolved policy review; operational-context Card disclosure; all seven Word documents updated.

## Additional fixes while integrating

- A Card's JSON projection now preserves parity after serialization (parameter pairs are JSON lists, not Python-only tuples).
- Projection data is copied; editing a Card cannot mutate its source Manifest through aliases.
- Managed approvals check an explicit principal-to-role configuration as well as authentication and declared roles.
- Feedback preserves an already narrower approver role set.
- Core execute performs a final independent emergency-stop read after other slow checks.
- The read-back text no longer incorrectly claims the CLI cannot verify Part A/B sign-offs.

## Validation

The release runner includes retained 174 core checks, 10 prior-review regressions, 71 v0.3.5 boundary cases, 95 v0.3.6 merge cases, 73 audit/feedback unittest cases, 53 release-integration checks and replay of 59 exported containment vectors. **These groups overlap**; use the recorded reports for actual pass/fail and environment, not an additive security score.

Tests use fixed synthetic sources and demo keys. The new suite includes actual POSIX child-process termination after a fsynced synthetic effect. It does not simulate hardware power loss, prove storage behavior under every filesystem failure, exercise real industrial APIs or constitute independent assessment.

The publication package retains two core reader documents. Implementation detail remains with the code documentation.

## Intentional limits

This is a bounded reference library, not an installed production proxy or monitoring service. Callbacks and sources remain trusted; transport auth, no-bypass isolation, scheduler, storage encryption/retention and authentic monitoring are host responsibilities. Full-state checkpointing limits scale. No replicas, automatic retry/resume, automatic restoration, self-modifying policy or model retraining. SQLite/SQL triggers/hash chains do not prove privileged rollback resistance or remote exactly-once effects.

## Compatibility

Legacy schema0.3.6 Profiles/Manifests remain structurally readable by the core tools. ManagedGate requires a schema0.3.7 Profile with exact monitoring_policy_ref and configured scope. That field must not be silently dropped. See MIGRATION_v0.3.7.md before integrating.
