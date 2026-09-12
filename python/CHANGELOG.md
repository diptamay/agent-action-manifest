# Changelog

## 0.4.0 — aggregate execution and trusted orchestration context

Incorporates the backwards-compatible v0.3.8 reader clarifications and adds an opt-in `V4ManagedGate`. New v0.4 Profiles pin a reviewed aggregate-execution policy, program context, execution-context reference, and delegation policy. The trusted host authenticates accountable actor groups and context/delegation/campaign sources. Gate-derived aggregate claims cover admissions, in-flight work, objects, distinct targets, and bounded egress; reservations are made with local dispatch admission. Relevant aggregate-ledger changes invalidate unexecuted proposals. Execution-unknown work retains in-flight capacity until verified settlement.

Delegation is bound to an admitted parent action, must attenuate the parent Profile, and shares a delegation-root budget. Authenticated campaign observations can only require approval or suspend new dispatch; restoration is explicit and recorded. Agents still submit requests and cannot supply authority, reset limits with new identifiers, widen a child Profile, create campaign observations, or expand authority through feedback.

This release preserves the v0.3.7 `Gate` and `ManagedGate` paths for compatibility. It does not add a hosted authentication service, detector fleet, distributed quota coordinator, automatic retry, or production-readiness claim. See `MIGRATION_v0.4.0.md`, `RELEASE_NOTES_v0.4.0.md`, and the recorded validation report.

The public repository uses the conventional lowercase `python/` directory for the reference implementation; documentation, CI, validation records, checksums, and release packaging use the same path.

Reader-facing README and Word content is release-number neutral. Personal maintainer/contact details and organization references were removed from the public package; citation and document properties use neutral project-contributor attribution. Publication regressions enforce both rules.

## 0.3.7 publication preparation

Added repository overview, Apache-2.0 licensing and coverage notice, citation metadata, and GitHub Actions CI. Corrected the validation-report link, a non-installable dependency pin, and residual event-specific branding; removed the redundant package-start file and decorative dates from reader materials; refreshed document pagination and renders; added publication regression checks; and regenerated validation evidence and checksums. Runtime authority and execution semantics are unchanged.

## 0.3.7 — Python audit and governed feedback

Managed persistent runtime, transactional audit/reservation/feedback, typed scoped holds, authenticated restoration, metrics/export, watchdog and offline review cases. Policy pin/read-back/Card integration. All seven documents updated. Additional serialized Card parity, principal-role and final-stop fixes. See release notes, migration guide and recorded validation.

The unfinished Java attempt was not shipped and is not a source for this release.

## Earlier releases

Historical behavior is summarized in the migration guide and retained regression suites. Current evidence is under `validation/` for the version in `VERSION`.
