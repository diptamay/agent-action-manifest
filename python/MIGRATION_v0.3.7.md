# Migration from Python v0.3.6 to v0.3.7

This is a distinct reference release. Never mix signatures, read-back digests, schemas or gate state between versions without explicit migration. Old archives are preserved, not overwritten.

## Choose the runtime deliberately

`gate.Gate` remains a volatile conformance engine. Use `managed_gate.ManagedGate` to obtain this release's audit/persistence/feedback behavior. Passing `monitoring_policy_ref` to the volatile Gate refuses publication rather than accepting unenforced controls.

ManagedGate requires a runtime store, one trusted tenant/environment, an exact feedback policy, protected stable gate secret and Profile trust roots. Provide explicit `approval_principals`, `restoration_principals` and `signal_principals` mappings. Use real `StateProvider.authenticated` assertions; names in arguments alone are not identity proof. The raw library object/store/admin API must never be available to the agent.

## Prepare the reviewed Profile and policy

1. Complete worksheet §11 and the logging/stop/recovery sections with the responsible owners.
2. Author `feedback-policy.schema.json` using only supported typed signals/modes/scopes and bounded count/windows. The reference supports manual restoration only.
3. Compute the reference with `feedback.policy_ref(policy)`; set schema_version0.3.7 and monitoring_policy_ref in the Profile. Sign the whole Profile again.
4. Run `aam readback PROFILE --feedback-policy POLICY`; resolve the exact digest, not another similarly named file. Product/engineering review the intent and implementation bindings. `aam signoff` requires that policy file for a policy-bearing Profile. Verify saved sign-offs under the trusted reviewer map.
5. Enable optional distinct Part A/B publication enforcement explicitly when required. It is not switched on merely by signing documents.

Legacy `audit_policy.alert_on` and `autonomy_policy.downgrade_on` strings remain declarations. They do not become executable rules automatically. No live monitoring policy is inferred from prose, logs or historic approvals.

## Persistent state and dispatch

Use SQLiteRuntimeStore on a local POSIX filesystem with one ManagedGate owner. Rehydrate executors with stable adapter ids/versions and the same reviewed keys/configuration. The database binds scope, trust, policy and administrative mappings. A mismatch refuses reopening. No automatic database/key/policy migration is supplied; design a reviewed state-preserving migration that retains unknown executions, consumed approvals, reservations and active holds. Never use a new empty store as a recovery shortcut.

Managed mutations can return `RuntimeFailure` instead of the original method record. It means mandatory recording/state persistence failed; `audit_persisted=false` does not mean no prior effect. Stop submissions, inspect the retained reservation and restart/reconcile. Do not retry automatically.

After restart, DISPATCHED without definitive disposition becomes EXECUTION_UNKNOWN. Reconciliation can establish terminal COMMITTED or NOT_COMMITTED with the existing bound evidence contract. Neither restores the reservation or consumed approval. New action ids are different actions, not a retry workaround.

## Operational context and approvals

The gate adds `operational_context` (policy ref, mode, scope epochs, holds, adapter revision) before sealing a managed Manifest. The Card includes it. Existing narrow approver roles are preserved. A changed restriction epoch or adapter revision invalidates an old proposal, even after restoration returns the displayed mode to NORMAL.

Rebuild only an unadmitted action, preserving its logical action_id, then obtain the applicable fresh approval. Never alter a sealed Manifest. Profile permission and all mandatory checks still apply in REQUIRE_APPROVAL. Suspension blocks new admission, not an already-admitted remote effect.

Card material/all-parameter pairs are now JSON-native lists. Serialized Card parity is tested. Read-back prose has changed; regenerate and re-sign read-back examples rather than reusing old digest/signature fixtures.

## Wire operations explicitly

- Schedule `watchdog()` from the trusted host; it does not create a thread or service.
- Call `export_audit(send)` outside request admission. The receiver acknowledges only durable acceptance, deduplicates event_id and rejects changed content. The supplied receiver is local demonstration code. Retrying export never invokes an executor.
- Expose `metrics_text()` through the host's protected telemetry endpoint; it returns text and does not create a web server. Metrics diagnose, they do not grant permissions.
- Route only ACL-authorized EVALUATION_REGRESSION / ADAPTER_MISMATCH signals through `ingest_signal`; bind current Profile digest/operation/time. A validated source assertion is not independent factual truth.
- Route restoration through an authenticated admin endpoint that supplies exact hold revision, owner, reason and reviewed evidence. The code checks identity/revision/unresolved state; a reviewer evaluates repair sufficiency.
- Use `audit_review.py` for offline UNREVIEWED cases; require tests and owner approval before actual implementation/policy change. No training pipeline is included.

## Data and validation

Protected snapshots may contain material requests, receipts and evidence/authentication references. Use non-secret handles; configure encryption, readers, storage isolation, retention and backups. Export is allowlisted but metadata may still be sensitive. No purge/compaction tool is shipped; preserve duplicate-reservation tombstones in any retention design.

Run all retained and new tests plus your real adapter, storage-failure, identity, bypass and scheduler tests. Child-process exit coverage is not hardware-power-loss or distributed-consistency proof. The bundled synthetic AP demo uses a separately signed autonomous-draft variant to illustrate escalation; it does not authorize production email or payment behavior.
