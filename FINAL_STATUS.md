# Final status

## Implementation

Implemented as an isolated full-stack project in `soc-platform/`: FastAPI backend, SQLite persistence, Next.js console, deterministic demo pipeline, ATT&CK mapping, AI fallback summaries, audit events, and UiPath orchestration artifacts.

## Working features

Dashboard, alert table, create-alert investigation, incident detail, demo scenarios, rule catalog, risk analyzer, automation view, analytics, and audit log are wired to backend endpoints. Demo mode requires no credentials.

## Tests

Passed `python3 -m pytest -q backend/tests` — 3 tests passed. Passed `npm run build` in `frontend` — Next.js production build compiled successfully. Direct pipeline smoke checks passed for benign login (LOW / 0), port scan (MEDIUM / 30 / T1046), and SSH brute force critical (CRITICAL / 85 / T1110). Uvicorn startup and database initialization were verified. Browser-level clicking was not run in this sandbox.

## Demo

Start FastAPI on `:8000`, start Next on `:3000`, open `/demo`, select SSH Brute Force — Critical, and run it. Expected output: a persisted CRITICAL incident with deterministic evidence, MITRE T1110, rules, recommendations, notification/report-ready flags, and audit timeline. Then inspect `/incidents/{id}`, `/alerts`, `/analytics`, and `/audit`.

## UiPath

Open `uipath/Main.xaml`. It reads Excel alerts, validates, extracts IOCs, retries the backend call, processes the investigation, routes critical severity, generates a report, sends a demo notification, and writes results.

## Environment

Python 3.12+, FastAPI/Uvicorn, Node 20+, npm. Demo mode defaults to true. Optional provider and OpenAI keys are environment variables only.

## Known limitations

Live provider HTTP implementations, production authentication, enterprise queueing, and fully version-specific UiPath activity bindings require deployment-specific configuration. No production containment action is automated.

## Remaining work

Run one browser-level presentation rehearsal and, if desired, bind a specific UiPath Studio version's Excel/HTTP activity namespaces. Live provider credentials remain deployment-specific.
