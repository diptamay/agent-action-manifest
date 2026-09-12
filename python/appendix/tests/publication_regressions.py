#!/usr/bin/env python3
"""Focused checks for public-package metadata and known documentation regressions."""
from pathlib import Path
import re
import sys
from zipfile import ZipFile

REPO = Path(__file__).resolve().parents[3]


def fail(message: str) -> None:
    print("FAIL " + message)
    raise SystemExit(1)


required = [
    "README.md", "LICENSE", "NOTICE", "CITATION.cff",
    ".github/workflows/ci.yml",
    "01_AAM_Workflow_and_Definition.docx",
    "02_AAM_Authority_and_Readiness_Worksheet.docx",
    "Diagram_Source/Agent_Action_Manifest_Workflow_and_Feedback_v0_4_0.drawio",
    "python/MIGRATION_v0.4.0.md", "python/RELEASE_NOTES_v0.4.0.md",
    "python/appendix/schemas/aggregate-execution-policy.schema.json",
    "python/appendix/schemas/execution-context-attestation.schema.json",
    "python/appendix/schemas/delegation-attestation.schema.json",
    "python/appendix/schemas/campaign-observation.schema.json",
]
for relative in required:
    if not (REPO / relative).is_file():
        fail("missing publication file: " + relative)

readme = (REPO / "README.md").read_text(encoding="utf-8")
for phrase in (
    "Authority Profile", "Action Request", "Action Manifest", "Action Assurance Card",
    "EXECUTION_UNKNOWN", "automatic redispatch", "reference implementation",
    "aggregate", "delegation", "campaign", "trusted host",
):
    if phrase not in readme:
        fail("README omits required concept: " + phrase)

python_readme = (REPO / "python/README.md").read_text(encoding="utf-8")
if "validation/release-test-report.json" in python_readme:
    fail("Python README contains stale validation report path")
if "validation/final-package-test-report.json" not in python_readme:
    fail("Python README does not link the package validation report")
if not (REPO / "python/VERSION").read_text(encoding="utf-8").strip() == "0.4.0":
    fail("python/VERSION is not 0.4.0")

reader_version = re.compile(r"(?<![A-Za-z0-9])v?0(?:\.|_)3(?:\.|_)8(?![A-Za-z0-9])|(?<![A-Za-z0-9])v?0(?:\.|_)4(?:(?:\.|_)0)?(?![A-Za-z0-9])", re.IGNORECASE)
for path in REPO.rglob("README.md"):
    if reader_version.search(path.read_text(encoding="utf-8")):
        fail("README contains a reader-facing draft/release version: " + str(path.relative_to(REPO)))

for path in (
    REPO / "01_AAM_Workflow_and_Definition.docx",
    REPO / "02_AAM_Authority_and_Readiness_Worksheet.docx",
):
    with ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith(".xml"):
                content = archive.read(name).decode("utf-8", errors="ignore")
                if reader_version.search(content):
                    fail("Word reader document contains a draft/release version: " + path.name + ":" + name)

request_schema = (REPO / "python/appendix/schemas/action-request.schema.json").read_text(encoding="utf-8")
for forbidden in ("actor_group_id", "aggregate_execution", "delegation_attestation", "campaign_observation"):
    if forbidden in request_schema:
        fail("Action Request schema contains authority/context field: " + forbidden)

blocked_branding = re.compile(r"Products That Count|\bPTC(?: Card)?\b", re.IGNORECASE)
private_identity = re.compile(
    "|".join(("Dipta" + "may", "hello@go" + "leap\\.ai", "go" + "leap")),
    re.IGNORECASE,
)
for path in REPO.rglob("*"):
    if path.resolve() == Path(__file__).resolve():
        continue
    if path.is_file() and path.suffix.lower() in {".md", ".txt", ".yml", ".yaml", ".cff", ".drawio", ".json", ".py", ".xml"}:
        content = path.read_text(encoding="utf-8", errors="ignore")
        if blocked_branding.search(content):
            fail("residual event branding in " + str(path.relative_to(REPO)))
        if private_identity.search(content):
            fail("private identity or organization reference in " + str(path.relative_to(REPO)))

for path in (
    REPO / "01_AAM_Workflow_and_Definition.docx",
    REPO / "02_AAM_Authority_and_Readiness_Worksheet.docx",
):
    with ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith(".xml"):
                content = archive.read(name).decode("utf-8", errors="ignore")
                if private_identity.search(content):
                    fail("private identity or organization reference in " + path.name + ":" + name)

print("PASS publication files and known documentation regressions")
