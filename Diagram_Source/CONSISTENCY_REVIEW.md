# Diagram and documentation consistency review

Reviewed 2026-09-20 against runtime commit `65f00dd`. The three editable diagrams, their PDF export, the embedded overview, the reader documents and the implementation guidance now describe the same boundary. Runtime behavior is unchanged. Two campaign-restoration gaps remain implementation follow-ups.

## Alignment completed

| Area | Correction |
| --- | --- |
| Trusted gate | Replaced ambiguous proxy labels; showed gate-owned consequential credentials and the compromised-agent/runtime/tool/session assumption. |
| Trusted host | Added authenticated caller/context, pinned versions, delegation and credential isolation; identified compromise detection and source integration as host responsibilities. |
| Results and evidence | Kept authorization, execution/outcome and operating mode separate. Any test conflict produces the conflict signal; a required-test conflict withholds completion. Receipts, reconciliation and no-attempt assertions remain distinct. |
| Budgets and feedback | Distinguished admission transactions from later signal/hold transactions. Lifecycle rules count execution incidents; campaign rules count observation IDs, requiring host mapping for repeated incidents. |
| Restoration | Separated feedback restoration guarantees from campaign API limitations in the diagram, workflow, worksheet, READMEs and implementation reference. |
| Published artifacts | Regenerated the PDF directly from the editable source and replaced the embedded overview from its first page. Corrected workflow page count from three to four; worksheet remains five pages. |

## Runtime follow-ups confirmed with synthetic fixtures

These checks used the existing `v4_regressions.py` helpers, in-memory state, synthetic authenticated principals and local executor callbacks. No external system was invoked.

| Check | Observed behavior | Required correction |
| --- | --- | --- |
| Create an unexecuted proposal; activate a campaign hold; restore it as the authorized owner; execute the original proposal | `ALLOW` when the remaining checks pass. The active-hold digest returns to its pre-hold value. | Add a durable monotonic campaign revision to proposal context so a hold activation/restoration cycle cannot revive an earlier proposal. Require a fresh proposal and applicable approval. |
| Dispatch an action whose adapter times out; activate a campaign hold; restore it as the authorized owner | Execution stays `EXECUTION_UNKNOWN`, but campaign restoration returns `restored: true`. | Reject campaign restoration while matching `DISPATCHED` or `EXECUTION_UNKNOWN` work remains unresolved, including races and restart. |

`ManagedGate.restore_restriction` already checks matching unresolved work and advances the feedback epoch. `V4ManagedGate.restore_campaign_hold` currently performs neither safeguard above. Until those runtime changes are implemented and tested, the host must enforce them. Clearing a hold never resets a consumed approval or action reservation and never schedules a retry.

The existing fourteen aggregate/context/campaign/delegation regressions pass. They do not cover these two negative restoration cases. Passing that suite must not be presented as closing the gaps.

## Keeping the artifacts aligned

The editable `.drawio` file is the figure source. `render_diagrams.py` is a narrow source-driven vector renderer for the shapes, HTML labels and anchored arrows used here; it is not a general draw.io exporter. It requires ReportLab and the four Arial TrueType files. The default font directory is the macOS supplemental font directory; use `--font-dir` elsewhere. Review the output after geometry or font changes.

From the repository root, using a Python environment with ReportLab:

```sh
python Diagram_Source/render_diagrams.py \
  Diagram_Source/Agent_Action_Manifest_Workflow_and_Feedback_v0_4_0.drawio
```

For each publication update:

1. Check the affected claims against the implementation; label host requirements and unimplemented behavior explicitly.
2. Update the source, regenerate all three PDF pages, and replace the Word overview with a raster of the first PDF page at its original aspect ratio.
3. Align the workflow, worksheet and code documentation; keep worksheet answer fields empty.
4. Render both Word documents, inspect every page and compare all diagram labels against the PDF text. Do not infer correctness from text extraction alone.
5. Run publication checks and relevant regressions, update page-count/verification metadata, then refresh `SHA256SUMS.txt`.

Validation for this update: 83 source labels matched the corresponding PDF pages; the embedded overview exactly matched the first-page PNG; all three diagram pages and all nine Word pages were visually inspected; fourteen focused runtime regressions passed; publication checks passed on a clean export containing exactly the checksum-manifest files. The checkout-wide publication scan separately flags residual event branding in pre-existing, untracked `.idea/workspace.xml`; that IDE file is outside the package and was not changed. The historical full release-test report was retained; the full release suite and live integrations were not rerun for this documentation change.
