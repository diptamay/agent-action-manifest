# Implementation reference — AAM v0.4.0

> Developer reference only. Sections A1–A12 retain the v0.3.7 engineering material. A13 defines the opt-in v0.4 extension. The two documents at the package root are the publication/adoption set.

Lifecycle records, gate contract, containment rules, hardening changes, worksheet-to-schema mapping, worked examples across three domains, effort, and known limitations.

AAM v0.4.0 · reference implementation in appendix/tools, tests in appendix/tests · complements IAM, OAuth, policy engines, and runtime controls; does not replace them · language-neutral

Legacy worksheet section numbers in this developer reference describe the source release authoring format; they are not section numbers in the condensed worksheet at the package root. Use the field names when mapping to the condensed form.

## A1. Lifecycle and records

Manifests remain immutable. Gate retains the volatile conformance model. ManagedGate adds complete JSON checkpoints and linked audit events through InMemoryRuntimeStore or a single-owner SQLiteRuntimeStore. The latter persists approval consumption, action reservations and lifecycle/control state before an adapter runs. It is a bounded local reference, not a production audit service or remote transaction coordinator.

| Record | Produced by | Binds to | Carries |
| --- | --- | --- | --- |
| Agent Authority Profile | Product owner (worksheet) + engineering | agent version | Standing authority; integrity at L2+ |
| Action request | The caller (agent runtime or tool proxy) | — | Operation, subject, effect target, parameters, evidence. No authority claims; schema-validated at ingress |
| Action Manifest | The gate’s trusted builder, per request | profile id + version + digest; sealed by the gate | Every authority-bearing field derived from the Profile’s per-operation binding; request digest; enforced never-list and separate stated-not-enforced list |
| GateDecision | The gate | manifest digest | ALLOW / DENY / INDETERMINATE; checks passed; violations; unresolved delegations; execution_valid_until (ALLOW only) |
| ApprovalRecord | Approval UI | manifest digest + action id | Approver roles/principals; time; single-use consumption marker |
| ExecutionRecord | The gate, which performs the call itself | manifest digest + gate decision + approval + request digest + executed request digest | Authorization (ALLOW / DENY / INDETERMINATE); dispatch state; idempotency key; receipt or uncertainty; linked state snapshots |
| OutcomeVerificationRecord | The gate, after the call | execution id | Required tests, observations and evidence errors; postconditions_verified separate from verified; completion routing and reconciliation_required |
| ObservationRecord | Trusted StateProvider adapter | Execution + Manifest/request + test + assertion/postcondition + target + source/method | Boolean observation; observed_at; source_version; evidence_ref. Structured metadata is validated, not proof of source truth |
| VerifierAttestation | Independent registered verifier | All ObservationRecord bindings | Scoped verifier id plus HMAC seal. Not an agent-facing “sign my success” API or a transferable digital signature |
| ReconciliationEvidence | Trusted transaction-status adapter | Execution, Manifest/request, Profile, action, target and idempotency key | Final disposition plus source/version, time and transaction/evidence references; no postcondition-only settlement |
| ReconciliationRecord | The gate | Execution snapshot seal/sequence + transaction evidence | Applied or rejected transition, reasons, before/after states and clock policy; stale readers cannot overwrite settlement |
| ReadbackSignoff | Authorized product/engineering reviewer | Exact Profile + part digest + rendered read-back digest | Finalized identity/role/key binding with Ed25519 signature; verified against deployment-controlled trust roots |

| Runtime invariant. The executed action is exactly the canonical material execution request (tool, operation, effect target, parameters) derived from the checked and approved Manifest. The gate derives it from its own sealed Manifest, recomputes the digest, and calls the executor itself; no authorization is returned to another component. |
| --- |

## A2. Gate contract

- Decisions are tri-state and fail closed. ALLOW: every rule passed and every delegated check resolved as passed. DENY: any rule failed, any delegation resolved as failed, or malformed input. INDETERMINATE: no failure, but at least one delegated check unresolved. Only ALLOW is executable. There is no “probably fine.”

- Delegation is explicit. The containment check returns stable ids for what it cannot evaluate structurally (selectors, rule expressions, opaque constraints, live stop state, class membership). The gate resolves them through a deployment-supplied StateProvider and re-runs the check with the resolutions. Unknown ids stay unresolved.

- Review lifetime is separate from execution authority. A Manifest may wait for human review for up to the Profile’s max_review_window_minutes (hours or a day). An ALLOW from the gate is executable only for max_execution_authority_seconds (minutes). Approval within the review window plus a fresh gate ALLOW are both required for execution.

- Preconditions are revalidated before dispatch. execute re-checks live authority, active Profile, approval, credential and request digest, including time elapsed during synchronous dependency calls. These are last-moment checks, not atomic conditions on a remote commit; an adapter needs downstream conditional writes where that distinction matters.

- Approvals are replay-safe. An ApprovalRecord is bound to the Manifest digest and action id, must be given inside the review window by a role in policy (never the agent’s own identity), and is consumed by the first execution that uses it.

- Timestamps fail closed. rfc3339-validator is pinned and required; gate and CLI assert date/date-time validation at startup. Trusted observation_clock_skew_seconds is an integer from 0 to 60 (default 0), recorded in results. It tolerates future source-clock timestamps only; pre-attempt evidence, stale evidence, expired approvals and test deadlines are not relaxed. Adapters still need bounded call timeouts.

- Verification tests are explicit. Each test has a stable test_id. Independent tests name a source and postcondition_index. all_postconditions_verified requires independent coverage of every expected postcondition. designated_postconditions_verified requires a nonempty set of valid independent designated_test_ids; non-designated results are still recorded. Tool return codes cannot satisfy either completion rule.

- Dependency failures are controlled. Exceptions in live-state, identity, credential, threshold, rule, selector, recovery-evidence and Profile-store reads are recorded without leaking exception messages. With no proven denial they produce INDETERMINATE and no dispatch. An explicit false still denies. Observation errors leave tests unverified unless valid scoped independent evidence is available.

- Authority is bound to the active Profile. GateDecisions and approvals record the exact Profile digest. Revoking the Profile, publishing a changed body under the same version, or bumping the version invalidates all pending authority under it.

- Records are the gate’s, not the caller’s. Decisions, approvals, and executions live in the gate’s own ledgers and are sealed (HMAC over the canonical body). A caller presents ids, never records; a structurally valid JSON record supplied from outside is not trusted.

- Local reservation is atomic. The core short lock reserves a Manifest and (profile_id, action_id) while consuming approval; callbacks execute outside it. ManagedGate commits this state and audit together before invocation, and reloads reservations on restart. Core Gate alone is volatile. Neither coordinates replicas or commits atomically with a remote effect.

- The narrower approver requirement wins. Managed feedback preserves an existing narrow role set, and ManagedGate additionally checks a configured authenticated-principal-to-role mapping. Requiring review cannot override a prohibition, expired credential or unresolved mandatory check.

- Multiple approvals mean distinct authenticated principals. Dual approval requires two different principals, each with an authentication assertion the gate verifies, unless the Profile explicitly sets distinct_principals_required to false.

- Free-text rules are typed or documentation-only. At L1+, a prohibition rule or target selector must either carry a rule_id/selector_id the deployment implements (typed — evaluated, delegated, re-checked) or be marked documentation_only (shown to the PM and approver, explicitly not enforced). Anything else is rejected at L1+.

- Recovery evidence resolves to a test. tested_evidence_ref must resolve, via the StateProvider, to a passed recovery test for the same tool.operation within test_max_age_days and not dated in the future. Arbitrary text does not count.

- Callers never author authority. The request schema has no mode, approval, credential, impact, or scope fields; the builder derives all of them from the Profile’s per-operation binding. A request carrying such fields fails ingress validation. The builder records a caller-proposed summary only as a conflict when it differs from the operation’s template.

- Ingress validation is mandatory. Profiles are schema-validated and (at L2+) signature-verified against a configured trust root at publish; requests and gate-built Manifests are schema-validated; unknown enum values anywhere fail closed — the checker raises on an unknown rank instead of treating it as safer.

- Typed thresholds. An operation runs at its declared default mode. It can run higher only when a typed threshold (threshold_id the deployment implements) holds, evaluated by the builder and again by containment and pre-execution re-evaluation. documentation_only thresholds are shown and never elevate. At L1+ an executing mode above the default without a typed threshold is a violation.

- Missing consequence data is a violation. Object count and blast radius are required on every operation binding and every Manifest; absence is C7, never zero.

- Trusted, execution-bound observations. StateProvider.observe(test, manifest, execution) returns an ObservationRecord or None. Scoped HMAC verifier attestations are also supported; human_confirmation requires them. Execution, Manifest/request, test, assertion/postcondition, target, method and source must match. Evidence must follow the completed dispatch attempt and satisfy age, deadline and configured clock policy. All admissible live and attested evidence is retained. Contradictory values leave the test unresolved; no source silently overrides another.

- Authorization is not execution state. States are NOT_DISPATCHED, DISPATCHED, ACKNOWLEDGED, EXECUTION_UNKNOWN, NOT_ATTEMPTED, COMMITTED and NOT_COMMITTED. ACKNOWLEDGED is an adapter receipt, not verified success. ExecutorNotAttempted is a trusted local-preflight assertion before any downstream attempt, never a timeout substitute. It keeps ALLOW but neither restores approval nor releases the action reservation. State changes append linked sealed snapshots.

- Retry identity is explicit. Reuse action_id for the same logical action across rebuilt Manifests. The gate blocks a second dispatch for (profile_id, action_id) in its current ledger. register_executor(..., with_context=True) supplies a stable idempotency_key outside material parameters; the adapter must forward it and the downstream service must enforce it. A new action_id is a new action; the gate does not infer duplicate intent.

- Unknown effects have an explicit reconciliation path. Gate.reconcile calls the read-only StateProvider.reconcile(manifest, execution). Structured terminal transaction evidence binds the execution, request, target, Profile and idempotency key. Under a short lock, the gate compares the original execution seal/sequence before applying COMMITTED or NOT_COMMITTED; stale results cannot overwrite a settlement. NOT_COMMITTED means the attempt cannot commit later, not “not attempted.” Positive postconditions alone never settle uncertainty. No settlement authorizes a retry.

## A3. Containment rules (C0–C17)

JSON Schema validates each document’s structure and encodes non-negotiables (default deny, fail-closed credentials, one approval per action, content is data, kill switch gated, level-dependent requirements). It cannot express cross-document constraints; the containment check does.

| Rule | Checks | Delegated when |
| --- | --- | --- |
| C0 | Inputs well-formed; timestamps parse with timezone. Any failure is DENY. | — |
| C1 | Profile id, version, conformance level match; profile digest verified | Digest absent |
| C2 | Review window valid at evaluation time and ≤ profile max; profile not expired | — |
| C3 | Agent, model, prompt, policy versions equal; prompt and policy hashes equal when pinned | — |
| C4 | Tenant/environment equal; systems ⊆ profile; subject and effect target types declared; identifiers in enumeration; systems in scope | Target type uses a selector |
| C5 | Operation allowlisted; unknown parameters denied; constraints satisfied; mode ≤ operation max; effect-target type/identifier/class per operation; material parameters present and equal to actual parameters | Opaque constraint; class membership of a specific identifier |
| C6 | No prohibition matches tool/operation, with '*' wildcards on either; typed rules delegated; Card 'can never' list equals exactly the enforced prohibitions and 'stated, not enforced' equals exactly the rest | Typed rule expressions |
| C7 | Domains ⊆ envelope; severity ≤ max; object count present and ≤ cap; blast radius present; irreversible only if allowed | — |
| C8 | Mode ≤ profile max; approval required for request mode; approvers ⊆ policy; dual approval where required; evidence ⊇ required; executing above the operation default requires a typed threshold | Typed thresholds |
| C9 | Execution identity equal; privileges ⊆ policy; TTL ≤ max | — |
| C10 | Inference location equal; egress ⊆ allowlist or empty under none; no never-egress field | signed_summary / unrestricted policies |
| C11 | Manifest records ⊇ profile minimum | — |
| C12 | Emergency-stop snapshot allowed | Always: live state must be read from state_source |
| C13 | Executing modes require tested recovery with a resolvable evidence reference, not future-dated, within max age; irreversibility consistent; owner named | Evidence resolution via StateProvider |
| C14 | Verification plan equals the trusted Profile-derived plan; test ids, postcondition mappings, independent coverage, designated selection and freshness limits are valid | — |
| C15 | Untrusted sources consulted ⊆ profile declaration | — |
| C16 | request_digest present and equal to digest(tool, operation, effect_target, parameters) | — |
| C17 | Manifest carries the identity of the gate that built it (callers never author Manifests) | — |

## A4. Hardening history (earlier wording superseded by A2)

| Issue raised | Change / release context | Test |
| --- | --- | --- |
| Delegated checks could look like ok=true | Tri-state decision; INDETERMINATE never executable; resolved-failed is DENY | containment … pure check is INDETERMINATE; INDETERMINATE decision cannot be executed |
| Target not validated against scope | Profile authority_scope.targets by type (enumeration or selector); subject and effect target both checked | effect target type not in profile targets; asset outside enumeration |
| Wildcard prohibitions | '*' on tool and/or operation; matched before allowlist can rescue | wildcard prohibition control_system.*; matches any tool |
| Unknown tool parameters | allowed_parameters per operation; anything else denied | unknown parameter denied by default |
| Arguments could change after authorization | request_digest in Manifest; actual request re-digested at execution | executed request differs from checked Manifest denied |
| Manifest mutable; approval/decision inside it | Manifest immutable; separate GateDecision, ApprovalRecord, ExecutionRecord, OutcomeVerificationRecord | Manifest mutated after approval/gate denied; schema rejects approval_record |
| Approval replay | Approval bound to digest + action id; single-use consumption | approval replay denied |
| Review lifetime vs execution authority | review_expires_at on Manifest; execution_valid_until on ALLOW (seconds) | execution after authority window denied |
| State-sensitive preconditions | authorize_execution revalidates kill switch, credential, class membership, review window | kill switch flipped … denied; effect target left class … denied |
| Malformed/expired timestamps | parse_time raises; every path returns DENY | malformed issued_at fails closed; malformed now fails closed |
| Self-attested recovery / meaningless verification | tested requires tested_evidence_ref within test_max_age_days; verification needs independent method + assertion | self-attested recovery …; only tool return code as verification |
| Card hid material effect | subject vs effect_target; material_parameters on Manifest and checked (C5); never-list copied and checked (C6) | card tamper … vague effect target detected; material parameter differs |
| (v0.3.3) Only some live predicates re-checked | Full containment re-run with all delegations re-resolved in authorize_execution | typed rule / selector flipped between gate and execution -> denied |
| (v0.3.3) Decision not bound to active Profile | profile_digest on GateDecision and ApprovalRecord; ProfileStore consulted at execution | Profile revoked / changed / version bumped after decision -> denied |
| (v0.3.3) Mutable consumed_by field as replay protection | Approval ledger inside the gate; consumption atomic under lock; field informational only | concurrent consumption -> exactly one ALLOW |
| (v0.3.3) Manifest-narrowed approvers not enforced | Required roles = Manifest roles when present | finance_controller (allowed by Profile) denied for a Manifest naming ap_manager |
| (v0.3.3) Dual approval by same person via two roles | distinct_principals_required + principal_authentication_required with auth_ref verified | two roles, same principal -> denied; two authenticated principals -> ALLOW |
| (v0.3.3) PM signs a digest they were not fully shown | Read-back lists every setting in the Profile; readback_coverage() must be complete; Card coverage() likewise | readback coverage; card coverage |
| (v0.3.3) check() defaulted to Manifest issue time | Default now = real current UTC; expired Manifests fail by default | expired Manifest fails by default |
| (v0.3.3) Caller-supplied records trusted on structure | Sealed internal records; callers pass ids | forged decision id; tampered stored decision/approval fail seal |
| (v0.3.3) tested_evidence_ref was free text | Structural shape check + resolution via StateProvider.recovery_evidence (passed, same operation, within age) | evidence ref is arbitrary text; evidence unresolvable at execution |
| (v0.3.3) Free-text rules silently delegated | enforcement: typed (rule_id/selector_id) or documentation_only; undeclared rejected at L1+ | L1+ free-text rule/selector without enforcement kind; documentation_only shown as NOT enforced |
| (v0.3.4) Unknown enum accepted as 'safer' | Ingress schema validation; _rank raises on unknown values (C0) | adv-1; ingress rejects unknown autonomy enum |
| (v0.3.4) Caller-authored authority claims | Trusted builder; action-request schema without authority fields; built_by + gate seal (C17) | builder … authority claims rejected; Manifest imported into another gate fails seal |
| (v0.3.4) Reusable authorization handed out | execute() derives the canonical material request and calls the registered executor itself, in the approval’s critical section | executor called once with the canonical request; no executor -> DENY |
| (v0.3.4) Caller-supplied outcome booleans | StateProvider.observe or sealed verifier attestations only | adv-5; unsealed attestations ignored; unobservable -> not verified |
| (v0.3.4) Future-dated approvals / evidence | approved_at ≤ now; evidence tested_at ≤ now and last_tested not in the future | adv-2; adv-7; future-dated recovery test date |
| (v0.3.4) documentation_only shown as 'can never' | not_permitted_summary = enforced only; documented_not_enforced separate; Card headings distinguish them (C6) | adv-4; 'can never' list includes an unenforced rule |
| (v0.3.4) Integrity placeholder | Ed25519 (or HMAC) Profile signatures verified against trust roots at publish; gate-sealed Manifests | adv-6; L2 profile edited after signing; unknown key |
| (v0.3.4) Policy hash not checked | C3 policy.hash equality when pinned | adv-3 |
| (v0.3.4) Missing object count treated as zero | Required in schema and C7 | adv-9 |
| (v0.3.4) Thresholds free text | Typed thresholds with threshold_id; documentation_only never elevates; C8 typed_threshold_required at L1+ | typed threshold elevates; documentation_only never elevates; executing above default without typed threshold |
| (v0.3.4) render_card.py CLI empty | CLI restored; --json and --coverage | adv-8 |
| (v0.3.4) Egress policies unresolvable | StateProvider.egress_policy_permits for signed_summary / unrestricted | adv-10 |
| (v0.3.4) PM signing engineering bindings blindly | Read-back split into Part A (product) and Part B (engineering) with separate digests; Profile digest binds both | readback split tests |
| (v0.3.5) Unbound or replayable outcome proof | Bind evidence to execution, Manifest, request, test, postcondition, target and scope; validate freshness | boundary_regressions.py: proof binding, time and scope; full live/attested conflict handling completed in v0.3.6 |
| (v0.3.5) Timeout mislabeled DENY; broad atomicity claim | Separate authorization and dispatch state; reserve locally; executor outside lock; unknown requires reconciliation | boundary_regressions.py: commit-then-timeout, history, idempotency and concurrency |
| (v0.3.5) Designated rule had no selection semantics | Explicit independent designated_test_ids; map tests to postconditions; C14 plan equality | boundary_regressions.py: designated/all coverage and plan drift |
| (v0.3.5) Provider exceptions escape; sign-off wording too broad | Controlled unresolved records; Ed25519 at L2/L3; human sign-offs external to CLI | boundary_regressions.py: service errors, time expiry, schema validation |
| (v0.3.6) No modelled exit from unknown | Structured transaction reconciliation; compare execution seal/sequence before transition; no automatic retry | merge_regressions.py: terminal status, binding, missing evidence and stale concurrent readers |
| (v0.3.6) Preflight rejection collapsed into unknown | ExecutorNotAttempted preserves no-attempt fact; approval stays consumed | merge_regressions.py: preflight, timeout, negative settlement and redispatch |
| (v0.3.6) Read-back digest not an authenticated approval | Finalized Ed25519 ReadbackSignoff plus trusted principal/role/part verification; optional publication gate | merge_regressions.py: saved-body verification, mutation, wrong key and publication policy |
| (v0.3.6) Optional timestamp format support; hard-zero skew | Required pinned validator, startup check; trusted bounded future-clock tolerance | merge_regressions.py: missing dependency, malformed dates, skew boundary and deadline preservation |
| (v0.3.6) Live read masked contradictory attestation | Collect and retain all admissible evidence; conflicting truth values remain unresolved | merge_regressions.py: live/attested conflict in both directions; no implicit priority |

## A5. Worksheet → Profile mapping

Engineering transcribes the worksheet; Part A shows product decisions and Part B technical bindings. aam signoff --key signs the finalized ReadbackSignoff; verify-signoff checks the saved signature, exact Profile/read-back digests and a trusted key-to-principal/role/part mapping. Gate(require_readback_signoffs=True) requires valid A and B approvals by distinct principals at publication; default is off. Whole-Profile signing remains separate. An arbitrary key and principal string do not establish organizational identity.

| Worksheet section | Profile fields |
| --- | --- |
| 0. Which agent | identity.agent_name / agent_version / owner; identity.model / prompt / policy (pinned, hashed at L2+) |
| 1. What may it read | authority_scope.systems, targets (types with identifiers or selectors), selector; input_trust.untrusted_sources |
| 2. What may it do | permissions.allowed[] with tool, operation, effect_target, material_parameters, default_mode, max_mode (Part A); allowed_parameters, constraints, impact, privileges_required, egress_fields, verification, summary_template (Part B); autonomy_policy.thresholds (typed or documentation_only) |
| 3. Never | permissions.prohibited[] (tool/operation with wildcards, or rule) |
| 4. Biggest blast radius | impact_envelope.allowed_domains / max_severity / max_affected_objects / irreversible_allowed |
| 5. Approval | approval_policy.approver_roles / required_evidence / dual_approval_for / approval_timeout_minutes; authority_scope.max_review_window_minutes |
| 6. Data leaving / inference | data_boundary.model_hosting / egress_policy / egress_allowlist / never_egress / log_retention_days |
| 7. Credentials | credentials_policy.identity / privileges / max_ttl_minutes / fail_closed_on_expiry |
| 8. Logging | audit_policy.records / readers / alert_on / append_only |
| 9. Emergency stop | emergency_disable.mechanism / state_source / operators / halts_pending |
| 10. Recovery owner | recovery_policy.owner / requires_tested_recovery_for_execution / test_evidence_required / test_max_age_days / templates |
| (engineering) | authority_scope.max_execution_authority_seconds; conformance.level / enforcement / evaluation |
| 11. Monitoring and governed response | monitoring_policy_ref (id/version/digest); resolved feedback-policy.json (typed rules, scope, thresholds, backlog/watchdog); trusted deployment principal/role and restoration ACLs. See A10–A12. |

## A6. When manifest-based enforcement is appropriate

The framework is easiest when an agent’s consequential behaviour is a bounded set of typed operations — draft_vendor_email, create_exception_ticket, open_dependency_pr, draft_work_order — each with a clear effect target, a few material parameters, and a way back. The gate can then decide on structure.

Generic shell, browser/computer-use, arbitrary SQL, and generic HTTP do not have that shape: the effect target and parameters are not knowable from the request. They need stronger wrappers or sandboxing (typed facades over the generic tool, network egress control, transaction rollback, replayable environments) before this framework applies. If consequential behaviour cannot be expressed as a bounded set of typed operations, simple manifest-based enforcement is not yet appropriate.

## A7. Worked examples across three domains

Each example directory holds a demo-signed Profile, a caller request, and a gate-built Manifest. They are reproducible at a fixed historical evaluation time; default real-time evaluation rejects expired examples. The pure checker is unresolved until live state is supplied; synthetic all-green fixtures produce ALLOW. These are specification examples, not integrations with email, AP, GitHub or plant systems.

## Software agent — repository maintainer (L2)

| Profile | github + ci in acme-eng prod; targets: repositories tagged agent-enabled, non-default branches, their PRs. Allowed: read_repo, run_tests, open_pull_request (effect: branch; material: branch, dependency, from, to; max execute_allowlisted), comment, label, update_dependency (semver ∈ patch/minor; max request_approval). Never: merge to main/release, delete, modify workflows/secrets, force-push, change protection. Envelope: code/data integrity + security, max moderate, 1 object, nothing irreversible. Credential: GitHub App token, 60 min. Egress: diff hunks, test output, issue text, advisory; never secrets. Kill switch: flag, live-read. |
| --- | --- |
| Manifest | open_pull_request → effect target branch agent/libfoo-2.3.4 in acme-api; subject repository acme-api; details: branch, libfoo, 2.3.1 → 2.3.4; execute_allowlisted, no per-action approval (thresholds resolved by gate); evidence: advisory, CI run passed, diff; verification checks the non-default-branch PR, attached CI status, and the audit store; recovery: close PR and delete branch (evidenced test run 2026-08-28). |
| Card headline | “Open PR bumping libfoo 2.3.1→2.3.4 on branch agent/libfoo-2.3.4 in acme-api. Will not merge. CI passed.” |

## Physical-consequence agent — plant change response (L3)

| Profile | Plant-A prod; business systems only (evidence, ticketing, maintenance, access management, notify); targets: five enumerated assets, work orders and vendor sessions on Line 3. Allowed: read_evidence, create_ticket, notify_oncall, draft_work_order (type ∈ inspection/verification; effect: work order; max request_approval), request_access_revocation (dual approval). Never: any control_system.* command, network.*, deployment.*, safety_system.*, action outside the approved window (rule). Envelope: operational/physical/safety/security, max high, 2 objects, nothing irreversible. Credential: per-site identity, 120 min. Review window 15 min; execution authority 180 s. Kill switch: site-level, live-read by plant manager or controls lead. |
| --- | --- |
| Manifest | draft_work_order → effect target: a new inspection work order in the maintenance system; subject Asset-12 (CNC, Line 3); details: inspection, Asset-12, vendor session VS-8831; request_approval by plant owner or controls owner with all six evidence classes; open conflict: approved change but anomalous post-change vibration; verification checks the work order, scheduled post-action evidence collection, and no control_system invocation in the audit store; recovery: cancel work order (evidenced). |
| Card headline | “Draft an inspection work order for Asset-12 after an approved configuration change with anomalous vibration. No equipment command will be issued.” |

The industrial case is one lens among several; the never-list is longer than the allowlist, which is the expected shape in physical environments.

## A8. Realistic effort

| Level | Who | Effort | What you have at the end |
| --- | --- | --- | --- |
| L0 Declare | Product owner, with one engineering pass | About a day | A completed, reviewed Profile worksheet; the technical Profile transcribed |
| L1 Enforce | One engineer | 1–2 weeks for an agent with a handful of typed operations | A gate in front of consequential tool calls; Manifests generated; default deny; live kill switch; INDETERMINATE never executes |
| L2 Assure | Engineer + platform/audit support | 2–6 weeks depending on audit and recovery tooling | Approval bound to the exact request, single-use; short execution authority; append-only records; evidenced recovery; system-of-record verification |
| L3 Evaluate | Engineering + QA, ongoing | Part of the release process | Injection, scope-escalation, approval-bypass, prohibited-action, and recovery regression sets gating every version |

Effort ranges are planning assumptions for a bounded agent with existing typed integrations, identity and logging, not measured implementation results. Required maturity depends on consequence and deployment. Conformance measures control maturity, not safety certification.

## A9. Known limitations

- Constraint semantics are minimal (membership, equality, numeric maxima). Selectors and rules are delegated; containment is partly proven, partly attested by the gate. A constraint language or profile-specific binding is needed to close the gap.

- One Manifest binds one operation. Multi-step plans need one Manifest per step and have no plan-level blast radius yet.

- The retained v0.3.7 path does not address delegation; the opt-in v0.4 extension in A13 adds deliberately conservative structural attenuation.

- Live-state and observation adapters remain trusted. Binding, source-version and freshness metadata are validated; the reference cannot prove source truth, independence or that an adapter avoided a cache. It handles returned errors, not indefinitely hung callbacks; adapters need transport deadlines.

- Action-approver authentication remains delegated to StateProvider.authenticated. ReadbackSignoff verifies exact review content and configured principal/role/part bindings. The CLI provides signing and verification, not an identity directory. Optional publication enforcement must be enabled deliberately; key provenance, ongoing revocation distribution and human review quality remain deployment responsibilities.

- L2/L3 Profiles require Ed25519 under configured trust roots. HMAC authentication is allowed only for explicit L0/L1 Profiles; Manifest, record and verifier seals are symmetric HMAC, not transferable digital signatures. Sorted-key JSON canonicalization is reference-specific, not a standardized cross-language signing format. Trust-root distribution and rotation remain out of scope.

- Conformance is self-assessed; there is no independent assessment mechanism.

- The executor registry is in-process: the reference calls a Python function. A production sidecar must ensure the executor cannot be invoked by any path other than the gate’s execute(), which is a deployment property the reference cannot prove.

- Independent verifiers need distinct protected keys and scoped method/source registration; the agent must not receive those keys or a callable seal_attestation endpoint. HMAC verification means the gate also holds the verifier’s secret. Authenticated channels, verifier truthfulness and human identity remain deployment responsibilities.

- Card parity is content parity, not salience parity: the UI can still bury the blast radius. That is a design-review question the framework names but cannot enforce.

- One Profile per agent version can proliferate; inheritance and fleet-level Profiles are unaddressed.

- Conditional autonomy rises only through implemented, reviewed threshold ids, never documentation-only prose. ManagedGate adds a separate restrictive signal loop; it cannot elevate authority. Threshold truth, real detectors, reviewed policy changes, scheduling and fleet composition remain deployment responsibilities.

- Core Gate alone keeps volatile ledgers. ManagedGate persists review evidence, approval use, action reservations, execution/reconciliation history and audit/control state in its single-owner SQLite reference. Process-exit recovery is tested; hardware power loss, replicas, privileged rollback, automatic resume and remote exactly-once behavior are not established. See A10–A12 for the implemented boundary.

- There is no transaction across the last authority check and the remote effect. Reconciliation adapters must prove final transaction status; a missing or still-pending request remains UNKNOWN. A stale concurrent reconciliation result is recorded without overwriting newer state. Completion still requires non-conflicting independent observations. Automatic retries and recovery are deliberately absent.

## A10. Durable audit and the local admission boundary

Entry points and trust

Use ManagedGate(state, secret, runtime_store=..., feedback_policy=..., tenant=..., environment=...). Run the agent outside this trusted process. Never expose the raw Gate, store, constructors, registries, signing keys or administrative methods to agent code. No HTTP/MCP server, general request authentication middleware or sandbox is included. The host authenticates API callers and binds their tenant; Profile identities alone are not requester authentication.

Checkpoint transaction

AuditTransactionLock detects outermost ledger changes, derives allowlisted AuditEvents, applies typed protective feedback, and commits one complete HMAC-authenticated checkpoint with those events. Read-only exits do not write. Approval consumption and Manifest/logical-action reservation commit before the executor callback. Neither exporter nor executor runs under that ledger lock. Admission has an explicit transaction revision, not a claim of remote commit.

| Boundary failure | Reference behavior |
| --- | --- |
| Local write fails before invocation | Roll back memory to the prior checkpoint, latch runtime unavailable, return RuntimeFailure. No executor callback follows that failed admission. |
| Write fails after downstream attempt | Do not label the effect DENY or repeat it. Return non-durable RuntimeFailure; preserve the earlier reservation. Restart recovers a missing disposition as EXECUTION_UNKNOWN. |
| Process ends after admission | Reload the same store and keys. DISPATCHED without disposition becomes unknown; duplicate reservation and consumed approval survive. Reconciliation is read-only; no automatic resume. |
| Remote export fails | Retain local events; retry delivery with stable event_id. A configured backlog limit stops new admissions, while recording and authorized recovery remain available. |

SQLite scope and integrity

SQLiteRuntimeStore uses WAL, synchronous=FULL, explicit transactions, quick_check and a lifetime POSIX flock. One gate owns one local database for one tenant/environment. Application SQL triggers reject audit UPDATE/DELETE; SHA-256 chains detect inconsistent events; checkpoint HMAC detects mutation without the gate key. None protects against a privileged actor restoring an older valid database and keys. Filesystem durability, power loss, backups, disk exhaustion, encryption and tamper-resistant retention require deployment qualification. [S1]

Retained evidence and privacy

Audit export is allowlisted: record ids/digests, source times, scope, result, signal and transaction revision. It excludes raw parameters, prompts, receipts, free-text reasons and authentication handles. Full evidence and receipt references remain in the sensitive checkpoint: protect them with filesystem access, storage encryption and retention controls. Use non-secret auth references. A digest without the retrievable underlying artifact is insufficient for a human audit. No retention purger is shipped. [S2]

## A11. Governed feedback, scope and restoration

Policy binding and operating modes

A managed Profile must pin monitoring_policy_ref (id, version, digest) to the exact feedback-policy JSON and trusted tenant/environment. Ordinary Gate refuses that policy-bearing Profile rather than ignoring it. The policy digest appears in Part A; readback --feedback-policy resolves and checks it. signoff also requires that file for policy-bearing Profiles. Runtime configuration separately binds source, approver and restoration principals.

| Input | Implemented protective behavior |
| --- | --- |
| Gate-owned EXECUTION_UNKNOWN | Preserve the duplicate block; configured rule may hold the action, operation or Profile. Postconditions alone do not settle the dispatch. |
| EVIDENCE_CONFLICT / VERIFICATION_FAILED | Withhold completion; count distinct execution incidents within the configured window. Re-verifying one incident does not multiply samples. |
| EVALUATION_REGRESSION / ADAPTER_MISMATCH | Require an authenticated allowed source, exact Profile digest and allowed operation, fresh observed_at and an evidence reference. Evidence truth is trusted, not inferred by the gate. |
| OVERDUE_EXECUTION / OVERDUE_VERIFICATION | Host calls watchdog(). It emits deduplicated events for stale unresolved or not-yet-verified work; no background scheduler is created. |

The policy supports count thresholds and windows, not arbitrary prose, learned scores or automatic recovery. NORMAL adds no restriction; REQUIRE_APPROVAL tightens autonomous execution using allowed approver roles; SUSPENDED blocks new matching admission. Rules cannot broaden operations, targets, credentials or verification criteria. Malformed/unknown modes are rejected. Legacy alert_on and downgrade_on strings remain declarations, not executable rules.

Concurrency and stale proposals

Lifecycle signals and resulting holds commit in the same transaction; remote metrics/SIEM delivery is not on this control path. Scope epochs detect restriction changes even after restoration (ABA). Adapter registration revisions also bind proposals. Any context mismatch requires rebuilding an unexecuted Manifest and obtaining applicable fresh approval. Do not mutate a sealed Manifest. Keep the same logical action_id; admitted actions cannot be rebuilt to evade duplicate protection.

Manual restoration, not new authority

restore_restriction(id, expected_revision, principal, auth_ref, reason, evidence_ref) checks the configured owner, authentication, active revision and unresolved executions in scope. The evidence reference is the owner’s reviewed assertion, not automatic proof that the repair is correct. Only that hold is cleared; other causes remain. No timer, quiet dashboard or successful history restores permissions. Consumed approval and action reservations never reset. Restoration and rejected attempts produce audit evidence.

Admin configuration and migrations

The store binding fixes key fingerprint, policy, scope, trust settings and administrative ACLs. Reopen with the same reviewed configuration; an intentional change requires a state-preserving migration that retains reservations and holds. Automated migration/key-rotation tooling is not supplied. Do not point at an empty database to bypass an incident. Callable adapter-version assertions are trusted deployment metadata, not binary-attestation proof.

## A12. Operation, evaluation and release evidence

Audit export and telemetry

export_audit(send) drains committed events outside admission; send must explicitly acknowledge durable acceptance. A crash between receiver acceptance and cursor persistence can deliver the same event twice. Receivers deduplicate event_id and reject changed content. SQLiteAuditReceiver is a local demonstration, not a SIEM connector. Stable export cursors never authorize an executor call. Metrics counters reconstruct from retained events; transient process timing/failure counters reset on restart.

metrics_text() emits bounded event/result counters, method timing sums/counts, unresolved executions and oldest age, active restrictions, export backlog and degraded health. No per-action ids or addresses are labels. It provides text, not a hosted endpoint or OpenTelemetry integration. Diagnostic observer failures are isolated; mandatory store failure is not. The host must monitor watchdog/worker liveness and use positive recovery evidence rather than equating silence with health.

Two improvement loops

The fast loop is deterministic protective response under an approved policy. The slower loop is human-reviewed incident → candidate correction → regression evidence → versioned approval/release. audit_review.py groups a complete exported stream into UNREVIEWED cases after structural/chain checks; it cannot execute tools, train a model or rewrite policy. Unkeyed chain consistency does not establish authenticity. Linked artifacts and source verification are still needed. [S2, S3]

Minimal integration sequence

1. Supply trusted StateProvider, persistent secret/trust roots, exact feedback policy and principal/role ACLs. 2. Open the single-owner store; restore/reconcile before normal use. 3. Publish the signed policy-bearing Profile and rehydrate versioned executors. 4. Route proposals and approvals through ManagedGate; handle RuntimeFailure as uncertainty, never as a retry instruction. 5. Schedule watchdog/export work; secure metrics and admin access. 6. Test adapters against independent downstream transaction evidence.

Acceptance evidence and remaining work

The package retains core, prior-review, boundary and merge regressions and adds audit/feedback acceptance tests, including child-process exit after a synthetic fsynced effect, persistence failure injection, restart duplicate protection, source/restriction races, multiple holds, restoration and export replay. `validation/final-package-test-report.json` records actual commands and results for the publication package. These tests overlap and use synthetic providers; they are not an independent security audit, industrial pilot, hardware-power-loss test or production certification.

Complete checkpoints and event retention simplify this bounded reference but are unsuitable for unbounded high-volume operation without redesign. No replicas, remote transaction coordinator, automatic retries/resume, retention compactor, production authentication server, detector fleet, self-modifying controller or automatic model training is included. In industrial settings, suspending agent dispatches does not authorize stopping machinery or disabling a separate safety mechanism.

Supporting references (design context, not conformance certification)

[S1] SQLite documentation: https://sqlite.org/pragma.html and https://www.sqlite.org/wal.html
[S2] OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
[S3] NIST AI RMF Playbook, Manage: https://airc.nist.gov/airmf-resources/playbook/manage/

These sources provide design context only. AAM-specific policies and API behavior are defined by this release and are not certified by the sources.

## A13. v0.4 aggregate execution and trusted orchestration context

v0.4 is an opt-in extension implemented by `v4.V4ManagedGate`. It incorporates the v0.3.8 reader clarifications and does not change the central authority model: only an approved Profile supplies standing authority; an agent supplies an Action Request. The trusted host authenticates callers and context sources, and the gate derives every authority-relevant Manifest field.

### Profile and request boundary

A v0.4 Profile pins `program_context`, `execution_context_ref`, `aggregate_execution_policy_ref`, `delegation_policy` and the existing managed-runtime `monitoring_policy_ref`. An Action Request has no fields for actor group, program, budget, delegation or campaign state. Supplying such fields fails schema validation. The proposal API accepts authenticated host context separately and records the trusted projection in the Manifest and Card.

An accountable actor group is a gate-owned stable identity for principals under common control. Principal or credential rotation must not reset aggregate usage. A program identifies the reviewed course of activity across Profiles. These mappings are security-relevant configuration and form part of the runtime-store binding.

### Aggregate policy and admission

`aggregate-execution-policy.schema.json` defines exact policies for five reference measures:

- `admissions`: actions admitted in a fixed, rolling or lifetime window;
- `in_flight`: dispatched work without verified settlement, including `EXECUTION_UNKNOWN`;
- `objects`: sum of the Profile-derived maximum affected-object claim;
- `distinct_targets`: distinct gate-derived target digests; and
- `egress_bytes`: the UTF-8 byte length of the canonical JSON encoding of one named, allowlisted request parameter, bounded per action by the aggregate policy. The caller supplies the material value, not a cost claim; the adapter must ensure the measured value is the actual egress payload.

Each budget has an exact selector, limit, response and grouping across one or more trusted dimensions. Every budget must include `accountable_actor`, `program` or `delegation_root`; action IDs are deliberately not a grouping dimension. The gate derives the claim from the active Profile, exact material request and authenticated host context. It does not accept a client-supplied cost or grouping key.

The proposal binds the relevant aggregate ledger view. Any changed relevant reservation makes the proposal stale even when usage remains below the limit. At dispatch, the gate re-evaluates current state and inserts the budget reservation in the same local critical section as approval consumption and logical-action reservation. The remote effect remains outside that transaction. A multi-instance deployment therefore needs one serializable aggregate admission authority; the bundled SQLite design is single-owner only.

Admission counts remain until their configured window expires. In-flight counts remain while the execution is dispatched, acknowledged, committed or execution-unknown and lacks a verified outcome. Reconciliation may update execution truth but never authorizes automatic redispatch. Retention and migration must preserve reservations needed by live windows and unresolved executions.

`DENY` blocks admission. `REQUIRE_APPROVAL` may be satisfied only by the normal exact-Manifest approval flow; it is not an approval embedded in the aggregate policy. `SUSPENDED` blocks new dispatch. None of these responses expands the underlying Profile.

### Execution-context binding

An execution-context attestation contains the exact reviewed id, version and digest plus an authenticated source principal. `V4ManagedGate` checks source ACL, host authentication and exact equality with the active Profile. The reference intentionally treats the digest as an opaque host assertion. A production host must define canonical context material, protect its issuer and make revocation/freshness policy explicit.

### Delegation attenuation

Delegation requires a separate authenticated attestation naming the parent Manifest/Profile/action, child Profile/action, child Profile digest, depth and validity interval. The parent action must already be admitted and must not be execution-unknown. The parent Profile must allow the child and depth. The child must preserve tenant/environment, use an exact structural subset of targets and reviewed operation contracts, not increase autonomy or lifetimes, not exceed impact domains, severity, object limits or credential privileges, preserve all parent prohibitions and downgrade triggers, and share the parent's program, context, aggregate, approval, data, audit, recovery and conformance boundaries. Because general semantic subset reasoning is out of scope, the reference rejects a child that changes the parameters or constraints of an inherited operation even when the change might be narrower.

Descendants inherit the root Profile id for `delegation_root` grouping. This prevents a chain of new child Profiles from resetting a root-scoped budget. Structural attenuation does not prove semantic intent or establish that two different targets are equivalent; product policy and adapter validation remain required.

### Campaign observations and holds

Campaign observations are typed host records, separate from action requests and outcome claims. The gate checks source ACL, host authentication, freshness, exact Profile digest, program, execution context, known actor group and operation. Reviewed count/window rules may activate `REQUIRE_APPROVAL` or `SUSPENDED` holds at actor, program, Profile or operation scope.

The implementation counts distinct authenticated observation IDs and records hold revision. It does not detect coordinated behavior, determine whether evidence is true, infer intent, or import any vendor-specific threat taxonomy. Multiple holds compose; a campaign-context change invalidates an unexecuted Manifest. Restoration requires an authenticated allowed principal, exact hold revision, reason and evidence reference. It never expands Profile authority, clears an action reservation or schedules a retry.

### Production responsibilities and non-claims

The host is responsible for authentication, principal-to-actor mapping, context canonicalization, policy approval, durable state, multi-instance serialization, source integrity, detector operation, adapter idempotency, evidence quality, reconciliation, key protection, retention and migration. `V4ManagedGate` is a Python API, not a network service or authorization protocol. The fixtures use public demonstration keys and synthetic sources.

The release makes no claim of semantic duplicate detection, collusion detection, distributed consistency, exactly-once remote effects, production readiness, independent assessment, certification or guaranteed safety. The fourteen focused v0.4 regressions cover ID/principal reset resistance, stale ledger binding, unknown in-flight handling, restrictive campaign control, delegation attenuation, canonical egress measurement and compatibility-boundary failures; they are not a substitute for deployment tests.
