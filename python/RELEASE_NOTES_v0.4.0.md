# AAM v0.4.0 release notes

This release incorporates the backwards-compatible v0.3.8 documentation clarifications and implements a domain-neutral v0.4 extension for aggregate execution control and trusted orchestration context.

## Added

- `V4ManagedGate`, layered on the v0.3.7 managed lifecycle.
- Exact aggregate-policy pinning and gate-derived claims for admissions, in-flight executions, affected objects, distinct targets and bounded egress.
- Fixed, rolling and lifetime windows grouped by trusted tenant, environment, accountable actor, Profile, program, operation, target class or delegation root.
- Atomic local aggregate reservation at dispatch admission and stale-proposal detection when the relevant ledger view changes.
- Authenticated execution-context attestations and gate-owned accountable actor mappings.
- Delegation attestations bound to an admitted parent action, exact child action and structurally attenuated child Profile.
- Authenticated campaign observations whose reviewed rules can only require approval or suspend new dispatches.
- Explicit campaign-hold restoration, audit projections, Card parity fields, four JSON Schemas and fourteen focused regression tests.

## Preserved

- Authority comes from an approved Profile; an agent supplies an Action Request, not authority.
- Scope, expiry, live predicates, credential validity, approval binding and Card parity remain enforced.
- Adapter acknowledgement is not verified outcome.
- Execution-unknown state requires reconciliation and never triggers automatic redispatch.
- Feedback and campaign controls can restrict authority but cannot expand it.
- v0.3.7 Profiles remain usable through the existing `Gate` and `ManagedGate` entry points.

## Deliberately not included

No Anthropic-specific taxonomy, policy, actor class or domain prohibition is part of the AAM core. The release also does not include a hosted service, identity provider, detector fleet, semantic campaign classifier, distributed budget coordinator, remote transaction manager, automatic retry, independent security assessment, certification or safety guarantee.

The new logic validates authenticated references and deterministic policy rules. A production host remains responsible for identity, source trust, durable multi-instance coordination, key and credential protection, adapter correctness, evidence quality, monitoring, retention, incident review and state-preserving migration.
