# Agent Action Manifest

Agent Action Manifest (AAM) is an independently authored, domain-neutral framework for turning standing authority into bounded, reviewable agent actions. This repository contains the reader documents and a runnable Python reference implementation. The optional extended controls cover aggregate execution, trusted execution context, attenuated delegation, and campaign-level restriction.

An agent's ability to call a tool is not, by itself, authority to produce an effect. AAM separates the policy decision from the proposed action and keeps enforcement in a trusted gate:

1. An approved **Agent Authority Profile** defines standing scope, permitted operations, limits, approvals, verification, and recovery expectations.
2. The agent submits an **Action Request** describing the action it wants performed. The request does not supply or expand authority.
3. The trusted gate derives an immutable **Action Manifest** from the active Profile and request, authenticated host context, and gate-owned aggregate state. It evaluates scope and expiry and renders an **Action Assurance Card** with parity to the Manifest.
4. When approval is required, it binds the exact proposal, approver identity, and validity window. The gate refreshes authority, restrictions, campaign holds, and aggregate budgets immediately before dispatch and reserves applicable budgets atomically with local admission.
5. An adapter acknowledgement records that a call was accepted or attempted; it is not proof of the intended outcome. Completion requires fresh, execution-bound evidence.
6. Ambiguous dispatch becomes `EXECUTION_UNKNOWN` and continues to consume applicable in-flight capacity. Reconciliation may settle the recorded execution but never authorizes automatic redispatch. Reviewed feedback and campaign observations may restrict authority; they cannot expand it.

For delegated work, the host authenticates a delegation attestation tied to a previously admitted parent action. A child Profile must be an attenuation of the parent, and descendants share a gate-derived delegation-root budget. Neither an agent-supplied delegation claim nor a new action ID creates fresh authority or resets an aggregate limit.

## Repository contents

- `01_AAM_Workflow_and_Definition.docx` explains the workflow, artifacts, enforcement boundary, results, reconciliation, and governed feedback.
- `02_AAM_Authority_and_Readiness_Worksheet.docx` helps product and engineering owners define one bounded workflow and record readiness evidence.
- `Diagram_Source/` contains the editable draw.io source and its rendered PDF.
- `python/` contains the reference code, JSON Schemas, synthetic examples, tests, implementation notes, migration/release notes, and validation records.
- `LICENSE` and `NOTICE` explain licensing and coverage. `CITATION.cff` provides citation metadata.

## Install and run

The supported reference environment is Python 3.10 or later. From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r python/requirements.txt
python python/appendix/tests/verify_release.py --report /tmp/aam-test-report.json
```

The tests and examples are offline and synthetic.

## Runnable example

Generate a Profile, gate-built Manifest, Card and synthetic dispatch without sending email or making a network call:

```bash
cd python
python appendix/tests/run_managed_demo.py --out /tmp/aam-managed-demo
python appendix/tools/aam.py validate /tmp/aam-managed-demo/managed-profile.json
python appendix/tools/aam.py validate /tmp/aam-managed-demo/managed-manifest.json
python appendix/tools/render_card.py /tmp/aam-managed-demo/managed-manifest.json
```

Bundled private keys are deliberately public demonstration fixtures. Never use them outside tests or examples.

The complete release suite, including aggregate/context/delegation/campaign regressions, can be run directly:

```bash
python python/appendix/tests/verify_release.py --report /tmp/aam-test-report.json
```

## Trust boundary and production responsibilities

This repository is a reference implementation, not an authenticated hosted service. `ManagedGate` and `V4ManagedGate` are trusted Python APIs, not HTTP or MCP servers. A production host must provide authenticated caller and tenant routing, non-bypassable credential isolation, protected keys, least-privilege adapters, trustworthy evidence and context sources, durable aggregate state, retention, scheduling, campaign-monitoring review, reconciliation operations, and deployment-specific assurance.

Keep agents outside that trust boundary: agents submit requests, while the gate obtains authority only from approved Profiles. Actor groups, program identity, execution context, delegation attestations, policy references, observations, and budget state must come from the trusted host and its authenticated, host-controlled sources. The host must preserve approval binding, scope and expiry checks, Manifest/Card parity, reservation durability, and the distinction between acknowledgement and verified outcome.

## Limitations

The reference uses synthetic fixtures and a single-owner local persistence design. Its campaign rules count authenticated typed observations; it does not detect campaigns, infer intent, or validate the truth of evidence. It does not provide a network service, identity provider, distributed quota service, remote transaction coordinator, replicated event store, automatic action retry, exactly-once remote effects, independent security assessment, certification, or guaranteed safety. Passing the test suite does not validate live integrations or a particular deployment.

For implementation details, see `python/README.md` and `python/docs/implementation.md`.
