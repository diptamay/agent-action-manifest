# Agent Action Manifest — Python reference

**Aggregate execution, trusted orchestration context, audit, and governed restriction. Discussion/reference release, not a standard, certification, independent security audit or production service.**

Product-owned **Agent Authority Profile → agent Action Request → gate-built Action Manifest → Action Assurance Card → dispatch → verified outcome/reconciliation** remains the framework. The optional extended path adds aggregate budgets, authenticated execution context, attenuated delegation, and campaign-level restrictive holds. These controls constrain already-approved authority; they never create authority or weaken verification. Restoration is separately authenticated and recorded. Historical success does not create permission.

## Start here

The reader-facing set is exactly two documents at the package root:
`../01_AAM_Workflow_and_Definition.docx` and
`../02_AAM_Authority_and_Readiness_Worksheet.docx`.
The first contains the simplified workflow, illustrative Card, proxy result handling and governed feedback. The second includes readiness checks and sign-off.

The optional editable source is in `../Diagram_Source/` (three tabs: overview, results, aggregate/campaign controls).
Developer-only detail from the former engineering appendix is preserved in `docs/implementation.md`; it is not a separate required publication document.

The `Gate` and `ManagedGate` paths remain for compatibility. The extended managed gate is opt-in and uses additional schema fields and trusted-host inputs. Superseded handouts, duplicate checklists, nested release archives and historical review bundles remain intentionally omitted.

The accounts-payable example drafts an email about a $312 variance; it does not send email or move money. The supplementary managed demo deliberately uses a separately signed, synthetic autonomous-draft variant so a regression can visibly tighten it to human approval. This is not an undisclosed relaxation of the illustrative Card's approval rule.

## Run the release (Python)

From this `python/` directory, Python 3.10+ with the pinned dependencies is intended. The exact Python/SQLite/platform used in the package validation is recorded in `validation/final-package-test-report.json`; other interpreter/platform combinations were not covered by that run.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python appendix/tests/verify_release.py --report validation/my-local-test-report.json
python appendix/tests/run_managed_demo.py --out /tmp/aam-managed-demo
python appendix/tests/run_managed_demo.py --out /tmp/aam-managed-demo
```

The managed demo creates temporary SQLite databases, calls **synthetic** adapters and emits example artifacts. No network request, email or industrial action occurs. The production persistence reference requires POSIX advisory locks and a local filesystem; the memory implementation is explicitly volatile.

```bash
python appendix/tools/aam.py validate appendix/examples/managed-runtime/feedback-policy.json
python appendix/tools/aam.py readback   appendix/examples/managed-runtime/generated/managed-profile.json   --feedback-policy appendix/examples/managed-runtime/feedback-policy.json
python appendix/tools/audit_review.py   appendix/examples/managed-runtime/generated/audit-events.json   --out /tmp/aam-review-cases.json
```

For a policy-bearing Profile, `readback` and `signoff` require the exact referenced policy file. Its digest is included in Part A and the Profile. `verify-signoff` still requires a trusted key-to-principal/role/part map. Whole-Profile Ed25519 verification remains separate. Optional publication enforcement of distinct Part A/B reviews is **off by default** and must be enabled explicitly.

**Bundled keys are public DEMO MATERIAL. Never deploy them.** Supply protected persistent gate keys, trusted Profile/reviewer keys, real identity verification and principal-role bindings in a trusted service boundary.

## Three deliberately different entry points

| Component | Purpose |
|---|---|
| `gate.Gate` | Retained volatile conformance engine and lifecycle reference. No durability or active audit-feedback claim. Refuses a Profile containing `monitoring_policy_ref`. |
| `managed_gate.ManagedGate` | Reuses the core lifecycle with synchronous state/audit transactions, restrictions, restart handling, metrics and export. Requires a runtime store and an exact feedback policy. |
| Extended managed gate | Adds pinned aggregate budgets, gate-owned accountable actor groups, authenticated context and delegation attestations, and restrictive campaign observations. Requires an extended Profile and an exact aggregate policy. |
| `InMemoryRuntimeStore` | Same transaction behavior for tests/demo, but no survival across process loss. |
| `SQLiteRuntimeStore` | Single-owner POSIX/local-disk persistence reference using WAL/FULL, complete JSON checkpoints, event chain and export cursor. Not a scalable or replicated event store. |

The managed gate APIs are **trusted Python service APIs, not HTTP/MCP servers**. The agent must not share their process, credentials, internal objects, raw stores or admin methods. The host supplies authenticated caller/tenant routing, bypass prevention, scheduler, storage protections and real integrations. Passing an agent name, actor group, context, delegation, observation, or principal string alone does not authenticate it.

## Behavioral contract

**Admission:** current Profile, live predicates, approved material request, scoped restrictions, approval and logical-action reservation must all permit dispatch. Approval consumption, reservation and audit are committed locally before the callback. A restriction committed before admission blocks it; a later restriction cannot recall an already-admitted remote action.

**Aggregate execution:** the gate derives budget groupings from the active Profile plus authenticated host context. Supported reference measures are admissions, in-flight executions, maximum affected objects, distinct targets and the canonical JSON byte length of a named material parameter over fixed, rolling or lifetime windows. The adapter must ensure that measured parameter is the actual egress payload. A new action ID or rotated principal does not reset an accountable-actor, program or delegation-root budget. An unexecuted Manifest is stale when its relevant aggregate ledger view changes. A production host needs durable, correctly scoped aggregate state; this repository supplies only a single-owner local reference.

**Execution context and delegation:** Extended Profiles pin a program and execution-context digest. Agents cannot declare these values. Delegation requires an authenticated attestation bound to a previously admitted parent Manifest and the exact child action. The child must remain within the parent boundary and preserve its prohibitions. The reference requires exact inherited operation contracts and reviewed security boundaries because it does not claim general semantic subset reasoning; a changed parameter or constraint is rejected even if a reviewer might consider it narrower. This is structural attenuation, not proof that the parent intended every semantic detail of a child request.

**Campaign restriction:** authenticated, version-bound observations feed reviewed count/window rules. A rule may require approval or suspend new dispatches and never expands standing authority. The reference validates shape, source ACL, freshness and binding; it does not detect campaigns, assess evidence truth or infer intent. Restoring a hold is explicit and never retries an action.

**Audit failure:** required transaction failure returns `RuntimeFailure` with `audit_persisted=false`, latches the runtime unavailable and never automatically retries. A prior admission/effect may exist. After a crash, a persisted DISPATCHED reservation without a final disposition becomes EXECUTION_UNKNOWN. The same logical action remains blocked; reconciliation does not authorize redispatch.

**Feedback:** gate-owned unknown/conflict/verification events and authenticated, version-bound regression/mismatch signals feed typed count/window rules in the same state transaction. Modes are NORMAL, REQUIRE_APPROVAL and SUSPENDED. Multiple holds compose. Stale contexts, including restored-then-restricted ABA changes and adapter registration changes, invalidate old proposals.

**Restoration:** an allowed authenticated principal supplies the exact hold revision, reason and reviewed evidence reference. Matching unresolved executions prevent restoration. One hold's restoration does not clear another hold, release a reservation, restore approval or schedule a retry. No automatic restoration is implemented. The reviewer must actually assess the evidence; the code does not establish repair truth from a reference string.

**Export/metrics:** export delivers committed events at least once with stable event IDs and a persistent cursor. Retrying delivery never retries an action. A backlog limit gates new admission. Metrics use bounded event/result labels and are diagnostic, not authority. Their observer failures do not undo committed control state. The host must schedule `watchdog()` and export work outside admission; no daemon or hosted monitoring endpoint is included.

**Improvement:** `audit_review.py` validates stream structure and unkeyed chain consistency and groups UNREVIEWED cases. It neither executes nor learns policies. Humans review linked evidence, propose a fix, add regressions and approve a versioned release. Untrusted logged content remains data.

## Source map

| File | Responsibility |
|---|---|
| `appendix/tools/gate.py` | Existing trusted builder, containment/live checks, approval, execution, verification and reconciliation hooks |
| `appendix/tools/managed_gate.py` | Managed service wrapper, scoped admission, source/role ACLs, restart recovery, watchdog and restoration |
| `appendix/tools/runtime_store.py` | Atomic checkpoint/events, single-owner SQLite, volatile memory store, sequence/hash chain and export cursors |
| `appendix/tools/audit.py` | Allowlisted event projection and synchronous transaction/feedback integration |
| `appendix/tools/feedback.py` | Reviewed typed response policy, distinct-incident windows, composable holds, scope epochs |
| `appendix/tools/aggregate.py` | Aggregate policy validation, gate-derived budget claims, relevant-ledger snapshots and atomic reservations |
| Extended managed-gate module | Trusted context, actor grouping, delegation attenuation, campaign holds and aggregate admission |
| `appendix/tools/audit_export.py` | At-least-once worker function and idempotent local receiver example |
| `appendix/tools/telemetry.py` | Bounded-label counters, timing and runtime health text |
| `appendix/tools/audit_review.py` | Non-executing offline improvement-case extraction |
| `appendix/tools/aam.py` | Authoring, complete read-back, resolved policy review, Profile and read-back signing/verification |
| `appendix/tools/render_card.py` | Full Card projection, operational-context disclosure, JSON-round-trip parity |
| `appendix/tools/evidence.py`, `reconciliation.py`, `verification.py` | Bound evidence, terminal transaction settlement and verification-plan semantics |
| `appendix/schemas/` | Compatible core contracts plus aggregate policy, context/delegation attestations, campaign observations, audit events and runtime outputs |
| `appendix/tests/` | Retained suites, focused extension regressions, example/demo generators and release runner |

## Storage, privacy and deployment limits

A complete sensitive state checkpoint is written on each mutation and retained event/history data is loaded into memory. This intentionally simple reference is **bounded, not high-volume production architecture**. It includes no compaction or retention enforcement. Preserve reservation tombstones when designing archival/retention; deleting audit history cannot safely turn an old action into a new one.

Events omit raw prompts, parameters, receipts, evidence bodies and authentication handles. Protected state can contain those details or their references: deploy encryption, filesystem permissions, backups and retention controls separately; use opaque non-secret auth handles. A digest without retrievable underlying evidence is insufficient. SQL append-only triggers and an unkeyed event hash chain are not WORM storage or protection against a privileged administrator restoring an old valid database. Checkpoint HMAC depends on key protection.

The store binding fixes tenant, environment, policies, keys/trust settings, actor/context mappings and administrative ACLs. Reopening with another configuration fails. Reviewed, state-preserving migration/key rotation is a deployment task; **do not start an empty store to bypass holds or duplicate reservations**. No automatic migration is shipped.

No replicas, remote aggregate-budget coordinator, remote transaction coordinator, exactly-once remote effects, automatic action retries/resume, model training, policy self-modification, real detector fleet, general identity server, standalone proxy daemon or independent safety proof are supplied. Trusted adapters must enforce idempotency, timeouts, actual-effect binding, independent/fresh observations and transaction finality. Aggregate dimensions reduce ID-reset evasion, but the gate does not infer semantic duplicates or common control beyond its authenticated actor-group mapping.

For industrial settings, restricting agent dispatch is not authority to stop machinery or defeat a separate safety mechanism.

## License and release evidence

First-party release content is provided under Apache License 2.0. See the repository-root `LICENSE` and `NOTICE` for coverage and third-party treatment. The license does not imply that any outside organization owns or endorses the work.

The original compatibility test report is retained as historical evidence for the base implementation, not a current package test result. `validation/final-package-test-report.json` records the actual package run when present. The top-level `SHA256SUMS.txt` verifies the delivered file set.

Counts overlap and are not independent safety guarantees. All tests use synthetic adapters and fixtures, not live payment, email, industrial, or external audit services. Neither compilation nor passing reference tests establishes production safety.
