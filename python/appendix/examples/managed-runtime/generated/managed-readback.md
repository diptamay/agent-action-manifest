# Read-back: invoice-triage v1.4  (profile aap:acme:invoice-triage v1.0.7)
Owner: AP Platform Lead · Tenant ACME · prod · Model <model@2026-05> · prompt v9 · policy v3
Conformance claimed: L2

Review digests alone are not authenticated approvals. Use signoff to sign the exact Part A/B content and verify-signoff to verify the saved signature against trusted principal/role keys. Whole-Profile integrity is a separate check.

## 1. What it may read
Systems: erp.ap, ticketing, email
Records: invoice: invoice.status == 'review'; email_address: address on vendor file; ticket: AP queue
Inputs treated as untrusted: invoice_pdfs, vendor_emails, ocr_output

## 2. What it may do
- erp.ap.read_invoice → affects invoice; up to: execute_allowlisted
- erp.ap.match_po → affects invoice; up to: execute_allowlisted
- email.draft_email → affects email_address (vendor_on_file); approver sees: recipient, invoice, po, variance_usd; up to: execute_allowlisted
- ticketing.create_ticket → affects ticket; approver sees: invoice, reason; up to: execute_allowlisted
- erp.ap.set_status → affects invoice; approver sees: invoice, transition; up to: execute_allowlisted
Default when unsure: request_approval · Never more than: execute_allowlisted
May run at a higher autonomy when: variance <= $2,000 and a PO exists -> ticket and status may run without approval -> execute_allowlisted [ENFORCED typed check small_variance_with_po]; vendor is new -> recommend only -> recommend [documentation only, NOT enforced]

## 3. What it must never do
- Release or schedule any payment  [erp.ap.release_payment]
- Edit vendor bank or remittance details  [erp.ap.update_vendor_bank_details]
- Create or delete vendor master records  [erp.ap.modify_vendor_master]
- Approve the agent's own drafts
- Email any address not on the vendor domain allowlist

## 4. Biggest thing one action may affect
Kinds: financial, external_communication, operational · max severity moderate · at most 2 object(s) · irreversible allowed: no
Worst case: -

## 5. Approval
Roles: ap_manager, finance_controller · must be shown: invoice_image, po_match_evidence, variance, draft_text · two approvers for: none · approval may wait 1440 min · requests expire after 1440 min of review

## 6. Data
Model runs: customer_boundary · may leave: none · never leaves: bank_details, personal_data · logs kept 30 days

## 7. Credentials
Acts as svc:ap-agent · may: erp.ap:read, erp.ap:status_write, ticketing:write, email:draft · credential lasts 240 min and stops the agent when it expires

## 8. Logging
Recorded: tool_calls, evidence_refs, gate_decision, approvals, denials, outcome · readable by: ap_platform_lead, finance_controller, security · alerts on: release_payment_attempt, bank_detail_edit_attempt, email_to_unlisted_domain

## 9. Emergency stop
feature flag ap-agent.enabled · live state at flags://acme/ap-agent.enabled · operated by: ap_platform_lead, finance_controller · stops pending actions: yes

## 10. Recovery
Owner: ap_platform_lead · executing operations need an exercised way back with evidence, no older than 90 days
After the gate says yes, an action must run within 300 seconds or be re-checked.

## 11. Audit and governed response
Reviewed feedback policy: feedback:ap-demo v1 (sha256:36e7f620ba14994e2e63ad96b4c8125001f2291216fd71213284efdb5a69ff8b)
Resolve this exact policy with --feedback-policy before approving it. ManagedGate applies its typed rules; ordinary Gate refuses this policy-bearing Profile.
Runtime feedback can require review or suspend new dispatches, never expand standing authority. Restoration is authenticated, separately recorded, and never retries an action.

# PART A — Product decisions (product owner reviews; approve the exact digest with aam signoff)
Every product-owned setting, exactly as it will be enforced. Rules, selectors, or thresholds marked documentation_only are shown to you but are NOT enforced by the gate.
- identity.agent_name = invoice-triage
- identity.agent_version = 1.4
- identity.owner = AP Platform Lead
- authority_scope.tenant = ACME
- authority_scope.environment = prod
- authority_scope.systems[0] = erp.ap
- authority_scope.systems[1] = ticketing
- authority_scope.systems[2] = email
- authority_scope.targets[0].type = invoice
- authority_scope.targets[0].selector = invoice.status == 'review'
- authority_scope.targets[1].type = email_address
- authority_scope.targets[1].selector = address on vendor file
- authority_scope.targets[2].type = ticket
- authority_scope.targets[2].selector = AP queue
- authority_scope.max_review_window_minutes = 1440
- permissions.default_deny = true
- permissions.allowed[0].tool = erp.ap
- permissions.allowed[0].operation = read_invoice
- permissions.allowed[0].effect_target.type = invoice
- permissions.allowed[0].impact.domains[0] = operational
- permissions.allowed[0].impact.severity = low
- permissions.allowed[0].impact.blast_radius = Read-only; changes nothing.
- permissions.allowed[0].impact.reversible = true
- permissions.allowed[0].impact.max_affected_objects = 0
- permissions.allowed[0].default_mode = execute_allowlisted
- permissions.allowed[0].max_mode = execute_allowlisted
- permissions.allowed[0].summary_template = Read {effect_target}. No changes.
- permissions.allowed[1].tool = erp.ap
- permissions.allowed[1].operation = match_po
- permissions.allowed[1].effect_target.type = invoice
- permissions.allowed[1].impact.domains[0] = operational
- permissions.allowed[1].impact.severity = low
- permissions.allowed[1].impact.blast_radius = Read-only; changes nothing.
- permissions.allowed[1].impact.reversible = true
- permissions.allowed[1].impact.max_affected_objects = 0
- permissions.allowed[1].default_mode = execute_allowlisted
- permissions.allowed[1].max_mode = execute_allowlisted
- permissions.allowed[1].summary_template = Match invoice {subject} to its purchase order. Changes nothing.
- permissions.allowed[2].tool = email
- permissions.allowed[2].operation = draft_email
- permissions.allowed[2].max_mode = execute_allowlisted
- permissions.allowed[2].reversible = true
- permissions.allowed[2].material_parameters[0] = recipient
- permissions.allowed[2].material_parameters[1] = invoice
- permissions.allowed[2].material_parameters[2] = po
- permissions.allowed[2].material_parameters[3] = variance_usd
- permissions.allowed[2].effect_target.type = email_address
- permissions.allowed[2].effect_target.classes[0] = vendor_on_file
- permissions.allowed[2].impact.domains[0] = external_communication
- permissions.allowed[2].impact.domains[1] = financial
- permissions.allowed[2].impact.severity = low
- permissions.allowed[2].impact.blast_radius = One outbound draft to one vendor about one invoice. No money movement.
- permissions.allowed[2].impact.bounded_by[0] = invoice={invoice}
- permissions.allowed[2].impact.bounded_by[1] = vendor=on file
- permissions.allowed[2].impact.reversible = true
- permissions.allowed[2].impact.max_affected_objects = 1
- permissions.allowed[2].default_mode = execute_allowlisted
- permissions.allowed[2].summary_template = Draft (not send) an email to {effect_target} asking them to confirm the ${variance_usd} unit-price variance on invoice {invoice} against PO {po}. Will not release payment, change vendor details, or send without approval.
- permissions.allowed[2].approver_roles[0] = ap_manager
- permissions.allowed[3].tool = ticketing
- permissions.allowed[3].operation = create_ticket
- permissions.allowed[3].max_mode = execute_allowlisted
- permissions.allowed[3].reversible = true
- permissions.allowed[3].material_parameters[0] = invoice
- permissions.allowed[3].material_parameters[1] = reason
- permissions.allowed[3].effect_target.type = ticket
- permissions.allowed[3].impact.domains[0] = operational
- permissions.allowed[3].impact.severity = low
- permissions.allowed[3].impact.blast_radius = One ticket in the AP queue.
- permissions.allowed[3].impact.reversible = true
- permissions.allowed[3].impact.max_affected_objects = 1
- permissions.allowed[3].default_mode = execute_allowlisted
- permissions.allowed[3].summary_template = Open an AP exception ticket for invoice {invoice}: {reason}.
- permissions.allowed[4].tool = erp.ap
- permissions.allowed[4].operation = set_status
- permissions.allowed[4].max_mode = execute_allowlisted
- permissions.allowed[4].reversible = true
- permissions.allowed[4].material_parameters[0] = invoice
- permissions.allowed[4].material_parameters[1] = transition
- permissions.allowed[4].effect_target.type = invoice
- permissions.allowed[4].impact.domains[0] = operational
- permissions.allowed[4].impact.domains[1] = financial
- permissions.allowed[4].impact.severity = moderate
- permissions.allowed[4].impact.blast_radius = Status of one invoice.
- permissions.allowed[4].impact.reversible = true
- permissions.allowed[4].impact.max_affected_objects = 1
- permissions.allowed[4].default_mode = execute_allowlisted
- permissions.allowed[4].summary_template = Set status of invoice {invoice}: {transition}.
- permissions.prohibited[0].description = Release or schedule any payment
- permissions.prohibited[1].description = Edit vendor bank or remittance details
- permissions.prohibited[2].description = Create or delete vendor master records
- permissions.prohibited[3].description = Approve the agent's own drafts
- permissions.prohibited[3].enforcement = typed
- permissions.prohibited[4].description = Email any address not on the vendor domain allowlist
- permissions.prohibited[4].enforcement = typed
- impact_envelope.allowed_domains[0] = financial
- impact_envelope.allowed_domains[1] = external_communication
- impact_envelope.allowed_domains[2] = operational
- impact_envelope.max_severity = moderate
- impact_envelope.max_affected_objects = 2
- impact_envelope.irreversible_allowed = false
- autonomy_policy.default_mode = request_approval
- autonomy_policy.max_mode = execute_allowlisted
- autonomy_policy.thresholds[0].description = variance <= $2,000 and a PO exists -> ticket and status may run without approval
- autonomy_policy.thresholds[0].enforcement = typed
- autonomy_policy.thresholds[0].mode = execute_allowlisted
- autonomy_policy.thresholds[0].operations[0] = ticketing.create_ticket
- autonomy_policy.thresholds[0].operations[1] = erp.ap.set_status
- autonomy_policy.thresholds[1].description = vendor is new -> recommend only
- autonomy_policy.thresholds[1].enforcement = documentation_only
- autonomy_policy.thresholds[1].mode = recommend
- approval_policy.approver_roles[0] = ap_manager
- approval_policy.approver_roles[1] = finance_controller
- approval_policy.required_evidence[0] = invoice_image
- approval_policy.required_evidence[1] = po_match_evidence
- approval_policy.required_evidence[2] = variance
- approval_policy.required_evidence[3] = draft_text
- approval_policy.one_approval_one_action = true
- approval_policy.approval_timeout_minutes = 1440
- approval_policy.distinct_principals_required = true
- approval_policy.principal_authentication_required = true
- input_trust.untrusted_sources[0] = invoice_pdfs
- input_trust.untrusted_sources[1] = vendor_emails
- input_trust.untrusted_sources[2] = ocr_output
- data_boundary.egress_policy = none
- data_boundary.never_egress[0] = bank_details
- data_boundary.never_egress[1] = personal_data
- data_boundary.log_retention_days = 30
- audit_policy.readers[0] = ap_platform_lead
- audit_policy.readers[1] = finance_controller
- audit_policy.readers[2] = security
- audit_policy.alert_on[0] = release_payment_attempt
- audit_policy.alert_on[1] = bank_detail_edit_attempt
- audit_policy.alert_on[2] = email_to_unlisted_domain
- recovery_policy.owner = ap_platform_lead
- emergency_disable.operators[0] = ap_platform_lead
- emergency_disable.operators[1] = finance_controller
- emergency_disable.halts_pending = true
- conformance.level = L2
- monitoring_policy_ref.policy_id = feedback:ap-demo
- monitoring_policy_ref.policy_version = 1
- monitoring_policy_ref.policy_digest = sha256:36e7f620ba14994e2e63ad96b4c8125001f2291216fd71213284efdb5a69ff8b

Part A review digest (identity-bound sign-off supported): sha256:a3b911b4113544c5311a7c24b4bf4fee92d45643f80455045e802316d0ac21a2

# PART B — Engineering binding (engineering reviews; approve the exact digest with aam signoff)
Model/prompt/policy pins, credentials, selectors and rule ids, constraints, parameters, verification templates, recovery evidence, kill-switch mechanism, execution authority.
- profile_id = aap:acme:invoice-triage
- profile_version = 1.0.7
- issued_at = 2026-08-15T00:00:00Z
- identity.model.provider = <provider>
- identity.model.identifier = <model@2026-05>
- identity.prompt.version = 9
- identity.prompt.hash = sha256:5d0c...e7
- identity.policy.version = 3
- identity.policy.hash = sha256:3f0a...b1
- authority_scope.selector = invoices.status == 'review'
- authority_scope.targets[0].enforcement = typed
- authority_scope.targets[0].selector_id = invoice_in_review
- authority_scope.targets[1].enforcement = typed
- authority_scope.targets[1].selector_id = address_on_vendor_file
- authority_scope.targets[2].enforcement = typed
- authority_scope.targets[2].selector_id = ap_ticket_queue
- authority_scope.max_execution_authority_seconds = 300
- permissions.allowed[0].verification.expected_postconditions[0] = Read completed without any write
- permissions.allowed[0].verification.tests[0].method = read_system_of_record
- permissions.allowed[0].verification.tests[0].source = audit_store
- permissions.allowed[0].verification.tests[0].assertion = no write recorded for this manifest
- permissions.allowed[0].verification.tests[0].test_id = postcondition-1
- permissions.allowed[0].verification.tests[0].postcondition_index = 0
- permissions.allowed[0].verification.on_failure = escalate
- permissions.allowed[0].verification.completion_rule = all_postconditions_verified
- permissions.allowed[0].verification.max_observation_age_seconds = 300
- permissions.allowed[0].privileges_required[0] = erp.ap:read
- permissions.allowed[0].allowed_parameters[0] = invoice
- permissions.allowed[1].verification.expected_postconditions[0] = Read completed without any write
- permissions.allowed[1].verification.tests[0].method = read_system_of_record
- permissions.allowed[1].verification.tests[0].source = audit_store
- permissions.allowed[1].verification.tests[0].assertion = no write recorded for this manifest
- permissions.allowed[1].verification.tests[0].test_id = postcondition-1
- permissions.allowed[1].verification.tests[0].postcondition_index = 0
- permissions.allowed[1].verification.on_failure = escalate
- permissions.allowed[1].verification.completion_rule = all_postconditions_verified
- permissions.allowed[1].verification.max_observation_age_seconds = 300
- permissions.allowed[1].privileges_required[0] = erp.ap:read
- permissions.allowed[1].allowed_parameters[0] = invoice
- permissions.allowed[2].constraints.recipient_class = vendor_on_file
- permissions.allowed[2].constraints.max_recipients = 1
- permissions.allowed[2].allowed_parameters[0] = recipient
- permissions.allowed[2].allowed_parameters[1] = invoice
- permissions.allowed[2].allowed_parameters[2] = po
- permissions.allowed[2].allowed_parameters[3] = variance_usd
- permissions.allowed[2].allowed_parameters[4] = subject_line
- permissions.allowed[2].privileges_required[0] = erp.ap:read
- permissions.allowed[2].privileges_required[1] = email:draft
- permissions.allowed[2].systems[0] = erp.ap
- permissions.allowed[2].systems[1] = email
- permissions.allowed[2].verification.expected_postconditions[0] = Draft exists in email system addressed to the vendor on file
- permissions.allowed[2].verification.expected_postconditions[1] = Draft references invoice {invoice} and PO {po}
- permissions.allowed[2].verification.expected_postconditions[2] = Invoice status unchanged
- permissions.allowed[2].verification.tests[0].method = read_system_of_record
- permissions.allowed[2].verification.tests[0].source = email
- permissions.allowed[2].verification.tests[0].assertion = draft for invoice {invoice} exists, unsent, single recipient {recipient}
- permissions.allowed[2].verification.tests[0].timeout_minutes = 5
- permissions.allowed[2].verification.tests[0].test_id = postcondition-1
- permissions.allowed[2].verification.tests[0].postcondition_index = 0
- permissions.allowed[2].verification.tests[1].method = read_system_of_record
- permissions.allowed[2].verification.tests[1].source = erp.ap
- permissions.allowed[2].verification.tests[1].assertion = invoice {invoice} status == 'review' and payment_scheduled == false
- permissions.allowed[2].verification.tests[1].timeout_minutes = 5
- permissions.allowed[2].verification.tests[1].test_id = postcondition-2
- permissions.allowed[2].verification.tests[1].postcondition_index = 2
- permissions.allowed[2].verification.tests[2].test_id = postcondition-3
- permissions.allowed[2].verification.tests[2].postcondition_index = 1
- permissions.allowed[2].verification.tests[2].method = read_system_of_record
- permissions.allowed[2].verification.tests[2].source = email
- permissions.allowed[2].verification.tests[2].assertion = draft for invoice {invoice} references invoice {invoice} and PO {po}
- permissions.allowed[2].verification.tests[2].timeout_minutes = 5
- permissions.allowed[2].verification.on_failure = reopen
- permissions.allowed[2].verification.completion_rule = all_postconditions_verified
- permissions.allowed[2].verification.max_observation_age_seconds = 300
- permissions.allowed[3].allowed_parameters[0] = invoice
- permissions.allowed[3].allowed_parameters[1] = reason
- permissions.allowed[3].privileges_required[0] = ticketing:write
- permissions.allowed[3].verification.expected_postconditions[0] = Ticket exists for invoice {invoice}
- permissions.allowed[3].verification.tests[0].method = read_system_of_record
- permissions.allowed[3].verification.tests[0].source = ticketing
- permissions.allowed[3].verification.tests[0].assertion = ticket exists for invoice {invoice} with reason {reason}
- permissions.allowed[3].verification.tests[0].test_id = postcondition-1
- permissions.allowed[3].verification.tests[0].postcondition_index = 0
- permissions.allowed[3].verification.on_failure = reopen
- permissions.allowed[3].verification.completion_rule = all_postconditions_verified
- permissions.allowed[3].verification.max_observation_age_seconds = 300
- permissions.allowed[4].constraints.transition[0] = review->matched
- permissions.allowed[4].constraints.transition[1] = review->exception
- permissions.allowed[4].allowed_parameters[0] = invoice
- permissions.allowed[4].allowed_parameters[1] = transition
- permissions.allowed[4].privileges_required[0] = erp.ap:status_write
- permissions.allowed[4].verification.expected_postconditions[0] = Invoice {invoice} status updated
- permissions.allowed[4].verification.tests[0].method = read_system_of_record
- permissions.allowed[4].verification.tests[0].source = erp.ap
- permissions.allowed[4].verification.tests[0].assertion = invoice {invoice} status transition {transition} recorded with manifest id
- permissions.allowed[4].verification.tests[0].test_id = postcondition-1
- permissions.allowed[4].verification.tests[0].postcondition_index = 0
- permissions.allowed[4].verification.on_failure = rollback
- permissions.allowed[4].verification.completion_rule = all_postconditions_verified
- permissions.allowed[4].verification.max_observation_age_seconds = 300
- permissions.prohibited[0].tool = erp.ap
- permissions.prohibited[0].operation = release_payment
- permissions.prohibited[1].tool = erp.ap
- permissions.prohibited[1].operation = update_vendor_bank_details
- permissions.prohibited[2].tool = erp.ap
- permissions.prohibited[2].operation = modify_vendor_master
- permissions.prohibited[3].rule = approver.principal != agent.identity
- permissions.prohibited[3].rule_id = no_self_approval
- permissions.prohibited[4].rule = recipient.domain in vendor_domains_on_file
- permissions.prohibited[4].rule_id = recipient_domain_on_file
- autonomy_policy.thresholds[0].threshold_id = small_variance_with_po
- autonomy_policy.downgrade_on[0] = evaluation_regression
- autonomy_policy.downgrade_on[1] = anomaly_alert
- input_trust.content_is_data_not_instructions = true
- input_trust.mitigations[0] = retrieved text rendered as data blocks
- input_trust.mitigations[1] = bank-detail edits denied at gate regardless of content
- input_trust.injection_test_set.identifier = inj-ap-v2
- input_trust.injection_test_set.last_passed_versions = model@2026-05/prompt9/policy3
- input_trust.injection_test_set.last_run = 2026-08-30T00:00:00Z
- credentials_policy.identity = svc:ap-agent
- credentials_policy.privileges[0] = erp.ap:read
- credentials_policy.privileges[1] = erp.ap:status_write
- credentials_policy.privileges[2] = ticketing:write
- credentials_policy.privileges[3] = email:draft
- credentials_policy.max_ttl_minutes = 240
- credentials_policy.fail_closed_on_expiry = true
- data_boundary.model_hosting = customer_boundary
- data_boundary.log_location = in-tenant audit store
- data_boundary.tenant_isolation_tested = true
- audit_policy.records[0] = tool_calls
- audit_policy.records[1] = evidence_refs
- audit_policy.records[2] = gate_decision
- audit_policy.records[3] = approvals
- audit_policy.records[4] = denials
- audit_policy.records[5] = outcome
- audit_policy.append_only = true
- audit_policy.log_store = in-tenant audit store
- recovery_policy.requires_tested_recovery_for_execution = true
- recovery_policy.templates[0].tool = email
- recovery_policy.templates[0].operation = draft_email
- recovery_policy.templates[0].method = delete draft; if sent, send correction email
- recovery_policy.templates[0].tested = true
- recovery_policy.templates[0].last_tested = 2026-08-30
- recovery_policy.templates[0].time_to_recover_minutes = 5
- recovery_policy.templates[0].tested_evidence_ref = testrun:recovery:ap-agent:2026-08-30#7
- recovery_policy.templates[0].owner = ap_platform_lead
- recovery_policy.templates[0].irreversible = false
- recovery_policy.templates[1].tool = erp.ap
- recovery_policy.templates[1].operation = set_status
- recovery_policy.templates[1].method = revert to review
- recovery_policy.templates[1].tested = true
- recovery_policy.templates[1].last_tested = 2026-08-30
- recovery_policy.templates[1].time_to_recover_minutes = 1
- recovery_policy.templates[1].tested_evidence_ref = testrun:recovery:ap-agent:2026-08-30#8
- recovery_policy.templates[1].owner = ap_platform_lead
- recovery_policy.templates[1].irreversible = false
- recovery_policy.templates[2].tool = ticketing
- recovery_policy.templates[2].operation = create_ticket
- recovery_policy.templates[2].method = close ticket with reason
- recovery_policy.templates[2].tested = true
- recovery_policy.templates[2].last_tested = 2026-08-30
- recovery_policy.templates[2].time_to_recover_minutes = 1
- recovery_policy.templates[2].tested_evidence_ref = testrun:recovery:ap-agent:2026-08-30#9
- recovery_policy.templates[2].owner = ap_platform_lead
- recovery_policy.templates[2].irreversible = false
- recovery_policy.templates[3].tool = erp.ap
- recovery_policy.templates[3].operation = read_invoice
- recovery_policy.templates[3].method = none needed (read-only)
- recovery_policy.templates[3].tested = true
- recovery_policy.templates[3].last_tested = 2026-08-30
- recovery_policy.templates[3].time_to_recover_minutes = 0
- recovery_policy.templates[3].tested_evidence_ref = testrun:recovery:ap-agent:2026-08-30#10
- recovery_policy.templates[3].owner = ap_platform_lead
- recovery_policy.templates[3].irreversible = false
- recovery_policy.templates[4].tool = erp.ap
- recovery_policy.templates[4].operation = match_po
- recovery_policy.templates[4].method = none needed (computes only)
- recovery_policy.templates[4].tested = true
- recovery_policy.templates[4].last_tested = 2026-08-30
- recovery_policy.templates[4].time_to_recover_minutes = 0
- recovery_policy.templates[4].tested_evidence_ref = testrun:recovery:ap-agent:2026-08-30#11
- recovery_policy.templates[4].owner = ap_platform_lead
- recovery_policy.templates[4].irreversible = false
- recovery_policy.test_evidence_required = true
- recovery_policy.test_max_age_days = 90
- emergency_disable.mechanism = feature flag ap-agent.enabled
- emergency_disable.execution_state = allowed
- emergency_disable.state_source = flags://acme/ap-agent.enabled
- emergency_disable.checked_at_gate = true
- emergency_disable.halts_in_flight_where_possible = true
- conformance.assessed_at = 2026-08-30
- conformance.assessor = AP Platform Lead
- conformance.enforcement.gate_id = policy-gate:finance-agents-v1
- conformance.enforcement.outside_model = true
- conformance.enforcement.checks_action_target = true
- conformance.enforcement.checks_manifest_within_profile = true
- conformance.enforcement.checks_scope_permissions_credentials_stop = true
- conformance.enforcement.containment_check_implementation = aam-check-containment/0.3.0
- conformance.evaluation.golden_set = golden-ap-v3
- conformance.evaluation.includes_abstention_cases = true
- conformance.evaluation.injection_set = inj-ap-v2
- conformance.evaluation.prohibited_action_set = deny-ap-v1
- conformance.evaluation.ci_or_release_gated = false

Part B review digest (identity-bound sign-off supported): sha256:248b8f667fc2db18ae95a7fcfc53edb9733cb682e5a27d5cfaab7121595ea201

Profile digest (binds Part A and Part B; this is what the gate enforces): sha256:79cdd3622f6348fd38ed01c7e9a2558f3652d7d4d55aebb6f3e3137703532c63
The Profile digest is what the gate enforces. It covers both parts; neither part can change without the digest changing.

# Resolved policy (content bound by the Profile policy digest)
This view does not grant authority and never executes an operation.
- unknown-action: 1 distinct EXECUTION_UNKNOWN incident(s) within 3600 seconds -> SUSPENDED at action scope.
- conflicting-evidence: 1 distinct EVIDENCE_CONFLICT incident(s) within 3600 seconds -> SUSPENDED at operation scope.
- failed-verification: 2 distinct VERIFICATION_FAILED incident(s) within 3600 seconds -> REQUIRE_APPROVAL at operation scope.
- evaluation-regression: 1 distinct EVALUATION_REGRESSION incident(s) within 3600 seconds -> REQUIRE_APPROVAL at operation scope.
- wrong-adapter-effect: 1 distinct ADAPTER_MISMATCH incident(s) within 3600 seconds -> SUSPENDED at operation scope.
- overdue-dispatch: 1 distinct OVERDUE_EXECUTION incident(s) within 3600 seconds -> SUSPENDED at operation scope.
- missing-verification: 1 distinct OVERDUE_VERIFICATION incident(s) within 3600 seconds -> REQUIRE_APPROVAL at operation scope.
Signal maximum age: 300 seconds.
Overdue execution / verification: 300 / 600 seconds.
Export backlog admission limit: 10000 events; consumer primary-audit.
Only authenticated manual restoration is implemented. Principal/role bindings are separately trusted deployment configuration.
Exact resolved JSON (engineering review):
{
  "schema_version": "0.3.7",
  "policy_id": "feedback:ap-demo",
  "policy_version": "1",
  "description": "Synthetic AP policy: predefined restrictions only; authenticated manual restoration. Not customer calibration.",
  "rules": [
    {
      "rule_id": "unknown-action",
      "signal": "EXECUTION_UNKNOWN",
      "mode": "SUSPENDED",
      "scope": "action",
      "threshold": 1,
      "window_seconds": 3600
    },
    {
      "rule_id": "conflicting-evidence",
      "signal": "EVIDENCE_CONFLICT",
      "mode": "SUSPENDED",
      "scope": "operation",
      "threshold": 1,
      "window_seconds": 3600
    },
    {
      "rule_id": "failed-verification",
      "signal": "VERIFICATION_FAILED",
      "mode": "REQUIRE_APPROVAL",
      "scope": "operation",
      "threshold": 2,
      "window_seconds": 3600
    },
    {
      "rule_id": "evaluation-regression",
      "signal": "EVALUATION_REGRESSION",
      "mode": "REQUIRE_APPROVAL",
      "scope": "operation",
      "threshold": 1,
      "window_seconds": 3600
    },
    {
      "rule_id": "wrong-adapter-effect",
      "signal": "ADAPTER_MISMATCH",
      "mode": "SUSPENDED",
      "scope": "operation",
      "threshold": 1,
      "window_seconds": 3600
    },
    {
      "rule_id": "overdue-dispatch",
      "signal": "OVERDUE_EXECUTION",
      "mode": "SUSPENDED",
      "scope": "operation",
      "threshold": 1,
      "window_seconds": 3600
    },
    {
      "rule_id": "missing-verification",
      "signal": "OVERDUE_VERIFICATION",
      "mode": "REQUIRE_APPROVAL",
      "scope": "operation",
      "threshold": 1,
      "window_seconds": 3600
    }
  ],
  "signal_max_age_seconds": 300,
  "overdue_execution_seconds": 300,
  "overdue_verification_seconds": 600,
  "max_export_backlog": 10000,
  "audit_consumer": "primary-audit"
}
