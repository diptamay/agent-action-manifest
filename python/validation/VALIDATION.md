# Validation evidence

`original-v0.3.7-test-report.json` is the source release report, retained without alteration and not represented as a new run.

`final-package-test-report.json` records the synthetic reference suite run for this publication package. It reports the actual interpreter, dependencies, commands and exit codes. The run used a fresh Python 3.12 virtual environment with dependencies installed from `requirements.txt`. Counts overlap and are not independent safety guarantees. This run does not verify a production deployment.

`package-verification.json` records the publication checks, rendered document page counts, diagram inspection, clean-environment test result, quickstart result, hygiene review and explicit limitations.

No live email/payment/industrial/audit service is used by the reference tests. Neither test success nor hash equality proves adapter truth, physical safety, remote exactly-once effects or immunity to privileged rollback.
