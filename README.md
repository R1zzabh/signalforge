# SignalForge SOC Automation Platform

SignalForge is a small but functional SOC/SOAR-style academic project: alerts enter a FastAPI pipeline, get enriched, scored with deterministic security rules, mapped to MITRE ATT&CK, explained with a safe fallback, persisted to SQLite, and exposed to a Next.js operator console. UiPath artifacts in `uipath/` orchestrate the same HTTP contract for Excel-driven RPA demonstrations.

## Run locally

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000/lab. `LAB_MODE` is the primary presentation environment and uses an isolated Docker cyber range. `LIVE_MODE` and `PRODUCTION_MODE` are reserved for configured provider/database deployments. The old deterministic `/demo` route is retained only as an internal fixture runner.

## Key features

- Dashboard, alert intake, incident detail, isolated lab control center, risk analyzer, rule catalog, automation view, analytics, and audit log.
- Real LAB_MODE target login, attacker controller, telemetry bridge, C2 simulation, CVE lab simulation, live SSE event stream, and reset behavior.
- Deterministic 100-point risk model with reputation, threat intelligence, behavior, vulnerability, asset, and correlation signals.
- SQLite records complete investigations and every automation stage.
- Critical incidents require analyst approval before disruptive containment (the UI only recommends action).
- `/docs` is generated automatically by FastAPI.

## API

See [docs/API.md](docs/API.md). The live lab contract is `POST /lab/events`; predefined actions are launched through `POST /lab/scenarios/{scenario}` and stream through `GET /events/stream`.

## LAB_MODE presentation

1. Run `docker compose -f docker-compose.lab.yml up --build`.
2. Open `/lab` and confirm `LAB_MODE · ISOLATED` plus component status.
3. Open the real target login page and perform a normal login.
4. Run brute force, credential stuffing, port scan, C2, CVE, and allowlisted scanner actions from the control center.
5. Watch raw telemetry, rule evidence, risk updates, incident creation, response approval, and audit events.
6. For RPA, use `/automation/inbox` with `uipath/Main.xaml` against the same backend.

## Limitations

Live provider adapters and production PDF/email delivery are intentionally gated by credentials and are not enabled in demo mode. The fallback AI narrative is deterministic and designed for offline evaluation. See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
