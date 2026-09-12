ACTION ASSURANCE CARD
======================
Operational restrictions (review snapshot) {'policy_id': 'feedback:ap-demo', 'policy_version': '1', 'policy_digest': 'sha256:36e7f620ba14994e2e63ad96b4c8125001f2291216fd71213284efdb5a69ff8b', 'mode': 'REQUIRE_APPROVAL', 'control_revision': 'sha256:0b95de4aded493878ad69859012dca0d57449296d2e223aa0a6c90e3d9d6742d', 'restrictions': [{'restriction_id': 'hold:dfc2e08b085044878348dd64e28b38df', 'revision': 1, 'rule_id': 'evaluation-regression', 'signal_code': 'EVALUATION_REGRESSION', 'mode': 'REQUIRE_APPROVAL'}], 'adapter_revision': 1}
What will happen               Draft (not send) an email to ap@northwind-supply.example (Northwind Supply, vendor on file) asking them to confirm the $312 unit-price variance on invoice 48211 against PO 77102. Will not release payment, change vendor details, or send without approval.
To / on                        ap@northwind-supply.example (Northwind Supply, vendor on file) [ap@northwind-supply.example]
Target kind                    email_address
About                          Invoice 48211 from Northwind Supply ($4,812.00) [48211
Details                        Recipient: ap@northwind-supply.example; Invoice: 48211; Po: 77102; Variance usd: 312
Operation                      email.draft_email
Why (evidence)                 
                              - invoice:48211:image
                              - po:77102
                              - match:48211:77102:variance=312
                              - draft:48211:v1
Uncertainty / open conflicts   
                              - Invoice quantity matches PO; unit price differs by $312.
Untrusted inputs consulted     
                              - invoice_pdfs
                              - ocr_output
Worst case if wrong            One outbound draft to one vendor about one invoice. No money movement.
Severity                       low
Reversible                     True
This agent can never (enforced by the gate) 
                              - Release or schedule any payment
                              - Edit vendor bank or remittance details
                              - Create or delete vendor master records
                              - Approve the agent's own drafts
                              - Email any address not on the vendor domain allowlist
Stated in the Profile but NOT enforced by the gate (none)
Manifest built by              managed-gate/0.3.7
Autonomy                       request_approval
Needs your approval            True
Approver role(s)               
                              - ap_manager
Two approvers required         False
Success means                  
                              - Draft exists in email system addressed to the vendor on file
                              - Draft references invoice 48211 and PO 77102
                              - Invoice status unchanged
Verified by                    
                              - postcondition-1: read_system_of_record via email: draft for invoice 48211 exists, unsent, single recipient ap@northwind-supply.example [postcondition index 0]
                              - postcondition-2: read_system_of_record via erp.ap: invoice 48211 status == 'review' and payment_scheduled == false [postcondition index 2]
                              - postcondition-3: read_system_of_record via email: draft for invoice 48211 references invoice 48211 and PO 77102 [postcondition index 1]
If verification fails          reopen
Way back                       delete draft; if sent, send correction email
Way back tested (evidenced)    True
Recovery owner                 ap_platform_lead
Acting as                      svc:ap-agent
Credential expires (min)       240
Data leaving boundary          (none)
Inference runs                 customer_boundary
Agent / authority profile      invoice-triage 1.4 · profile aap:acme:invoice-triage v1.0.7 (L2)
Review window ends             2026-09-08T14:13:10Z
Manifest id                    aam:acme:invoice-triage:10918ae91c63
All parameters (as they will execute) invoice: 48211; max_recipients: 1; po: 77102; recipient: ap@northwind-supply.example; recipient_class: vendor_on_file; subject_line: Invoice 48211 – price variance vs PO 77102; variance_usd: 312
Scope claimed                  ACME · prod · systems email, erp.ap
Subject kind                   invoice
Target class                   vendor_on_file
Evidence provenance            
                              - customer_supplied
                              - customer_supplied
                              - derived
                              - derived
Impact domains                 
                              - external_communication
                              - financial
Bounded by                     
                              - invoice=48211
                              - vendor=on file
Max objects affected           1
Approval valid for (min)       1440
Evidence you must be shown     
                              - invoice_image
                              - po_match_evidence
                              - variance
                              - draft_text
Privileges used                
                              - erp.ap:read
                              - email:draft
Will be recorded               
                              - tool_calls
                              - evidence_refs
                              - gate_decision
                              - approvals
                              - denials
                              - outcome
Completion rule                all_postconditions_verified
Designated required tests      (none)
Maximum evidence age (s)       300
Recovery test evidence         testrun:recovery:ap-agent:2026-08-30#7
Recovery last tested           2026-08-30
Time to recover (min)          5
Request digest (binding)       sha256:b122269dc15ea9a692bce2f744a74297ec4a8a50e572747615a0cbfeae437d45
Profile digest                 sha256:79cdd3622f6348fd38ed01c7e9a2558f3652d7d4d55aebb6f3e3137703532c63
Issued at                      2026-09-07T14:13:10Z
Versions                       manifest 1.0.0 · model <provider> <model@2026-05> · prompt v9 (sha256:5d0c...e7) · policy v3 (sha256:3f0a...b1)
Parameters summary             recipient_class=vendor_on_file; max_recipients=1; recipient=ap@northwind-supply.example; invoice=48211; po=77102; variance_usd=312; subject_line=Invoice 48211 – price variance vs PO 77102
Action id                      demo-after-regression
Requested at                   2026-09-07T14:13:10Z
Subject system                 erp.ap
Target system                  email

Approve [ ]   Reject [ ]   Request more evidence [ ]
Generated from the exact Manifest the gate checked. Tool success is not outcome success. Transport failure is not proof that no action occurred.
