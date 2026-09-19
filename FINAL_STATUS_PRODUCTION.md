# SignalForge production-oriented status

Updated 2026-09-19. This is an evidence-backed status report, not a blanket production-readiness claim.

## Verified in this workspace

- FastAPI imports and starts its application object.
- 30 versioned rule definitions are registered and the evaluator returns 30 rule results with `TRIGGERED`, `NOT_TRIGGERED`, or `NOT_EVALUABLE` states.
- Deterministic bucket scoring, base/final severity, correlation evidence, MITRE mapping, escalation metadata, and approval metadata are returned.
- Original backend regression tests pass with `PYTHONPATH=. pytest -q` (3 passed).
- Expanded backend rule matrix passes with `PYTHONPATH=. pytest -q` (93 passed).
- Frontend `npm run build` passes.
- Python compile and pipeline smoke verification pass across five representative scenarios; each persisted result contains 30 rule results.
- All supplied UiPath XAML files parse as valid XML.
- LAB_MODE implementation includes an isolated Compose network, target login/event generation, telemetry bridge, fixed-scope attacker controller, C2 simulator, CVE lab simulation, `/lab/events`, `/events/stream`, `/lab/status`, reset, automation inbox contracts, and a real `/lab` control center.
- LAB_MODE static validation passed for six Compose services and an `internal: true` lab network; 4 lab ingestion tests are included in the 97 passing backend tests.
- DEMO_MODE remains offline and deterministic; the critical server, credential stuffing, CVE, allowlisted scanner, and alert-burst scenarios were exercised through the Python pipeline.
- SQLite persistence now includes entities for assets, accounts, allowlists, responses, rule definitions, incidents, alerts, notifications, runs, and audit logs.
- API surface includes health/status, auth placeholder, incidents, rule registry/metrics, enrichment/risk, demo, assets, accounts, allowlist, response approval/rejection, reports, notifications, audit, and analytics.
- Provider adapter interfaces are present and explicitly return `UNAVAILABLE` when live credentials/endpoints are not configured.

## Partial or environment-dependent

- Authentication/RBAC is a DEMO_MODE session contract, not a complete production identity system.
- Live VirusTotal, AbuseIPDB, NVD, GeoIP, MITRE, OpenAI, Outlook, PostgreSQL, and secret-manager execution require credentials and deployment configuration; no live call was claimed or made.
- Reports and notifications expose contracts and demo previews; production PDF/email delivery still needs deployment-specific adapters.
- UiPath artifacts preserve the orchestration sequence, but typed Studio activity arguments and an executed UiPath run were not available in this environment.
- Docker Engine is not installed in this workspace, so the containerized cyber range was not runtime-executed here. Docker startup and scenario execution remain host acceptance steps.
- Frontend routes are operationally present and wired to the API for core views; browser Playwright smoke tests and full click-through have not been run in this pass. An in-process HTTP smoke probe was interrupted and is not counted as passed.
- Alembic migrations, Docker/Compose, CI workflow, and the 100+ test target remain follow-up hardening work.

## Demo sequence

Start FastAPI from `backend` with `PYTHONPATH=. uvicorn app.main:app --reload`, start Next.js from `frontend` with `npm run dev`, open `/demo`, select `CRITICAL_SERVER_ATTACK`, run it, then inspect `/incidents`, `/rules`, `/response`, `/audit`, and `/analytics`. Use `/risk-analyzer` to change attempts and compare deterministic output.

## Known limitations

Do not use DEMO_MODE evidence as live threat intelligence. The project is suitable for a polished academic demonstration and as a production-style architecture baseline, but it should not be described as fully production-ready until the environment-dependent items above are implemented and tested.
