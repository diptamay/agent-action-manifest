# Migration to AAM v0.4.0

v0.4.0 incorporates the documentation clarifications planned for v0.3.8 and adds optional runtime controls. Existing v0.3.7 Profiles and callers may continue using `Gate` or `ManagedGate`; they are not silently upgraded to v0.4 semantics.

## When to migrate

Use `V4ManagedGate` when one-action limits are insufficient and the host needs shared execution budgets, authenticated program/execution context, attenuated delegation, or campaign-level restrictive holds. Staying on the compatible v0.3.7 path is valid when those controls are not claimed.

## Profile changes

A v0.4 Profile sets `schema_version` to `0.4.0` and adds:

- `program_context`, with a stable host-owned `program_id`;
- `execution_context_ref`, pinning a reviewed context identifier, version, and digest;
- `aggregate_execution_policy_ref`, pinning the exact aggregate policy;
- `delegation_policy`, set to `forbidden` or an allowlist-based attenuated policy;
- the existing `monitoring_policy_ref`, because V4ManagedGate builds on the managed runtime.

Do not let an agent populate these fields. Product and engineering owners review them, and the trusted host resolves their exact referenced policies and authenticated identities.

## Host configuration changes

Construct `V4ManagedGate` with the exact aggregate policy and host-owned mappings for accountable actor groups, context attestors, delegation attestors and campaign-observation sources. Include this configuration in durable runtime binding. Principal rotation should retain the same accountable actor group when it represents the same controlled actor.

Proposals now require an authenticated caller record and execution-context attestation. Delegated proposals additionally require an attestation bound to the admitted parent Manifest and exact child action. Campaign observations enter through their separate authenticated ingestion method, never through an Action Request.

## State migration

There is no automatic database migration. Before enabling v0.4, create and review a state-preserving migration that retains all v0.3.7 dispatch reservations, approvals, unresolved executions, audit history, feedback holds and export cursors, then initializes aggregate reservations and campaign state under the new runtime binding. Do not point the new gate at an empty database to evade existing reservations or holds.

Select stable aggregation dimensions before cutover. Accountable-actor, program and delegation-root identities are security-relevant host data. If multiple gate instances enforce the same limits, they require a shared, serializable admission authority; the bundled SQLite store is single-owner and does not provide distributed coordination.

## Approval, execution and reconciliation

Approval remains bound to the exact Manifest. Aggregate or campaign context changes make an unexecuted Manifest stale; build a replacement and obtain any newly required approval. Budget reservation occurs in the same local critical section as dispatch admission, before the remote adapter call.

An `EXECUTION_UNKNOWN` record remains in flight until trustworthy reconciliation and verified outcome evidence settle it. Reconciliation records what happened and does not automatically redispatch. Campaign holds and ordinary governed feedback may only preserve or reduce authority; restoration is explicit and does not release an action reservation or schedule work.

## Verification checklist

1. Validate all new policies and v0.4 Profiles with `aam.py validate`.
2. Run `python appendix/tests/verify_release.py` and record the report.
3. Test concurrent admissions at every aggregate boundary using the intended production store.
4. Test process loss after local reservation and before/after remote acknowledgement.
5. Test principal rotation, actor-group mapping changes, stale Manifest rejection and delegation-root sharing.
6. Test source authentication, stale/mismatched campaign observations, multiple holds and explicit restoration.
7. Independently test adapters, evidence freshness, authorization routing, key protection, storage recovery and reconciliation operations.

Passing the bundled tests is reference evidence only; it does not establish production readiness or the correctness of a deployment migration.
