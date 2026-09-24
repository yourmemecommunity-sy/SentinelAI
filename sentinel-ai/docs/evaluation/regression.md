# Regression Policy

- `tests/regression/test_detector_regressions.py` pins every defect found by the suite, review, or production incident.
- `tests/security/test_evaluation_suite.py` runs the evaluation gate under pytest; CI also runs the script directly.
- **Any critical regression fails CI.** No `xfail`/skip on critical cases.
- Dataset changes require regeneration (manifest hashes) and reviewer sign-off on the diff.
- Every change under `services/security-engine/` or `datasets/` triggers the gate (see `.github/workflows/ci.yml` at the repository root, one level above `sentinel-ai/`).
