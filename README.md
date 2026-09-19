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

Open http://localhost:3000. Demo mode is the default and requires no API keys or internet. Set `DEMO_MODE=false` only when provider adapters and credentials are configured; unavailable live providers are reported as unavailable, not fabricated.

## Key features

- Dashboard, alert intake, incident detail, demo lab, risk analyzer, rule catalog, automation view, analytics, and audit log.
- Deterministic 100-point risk model with reputation, threat intelligence, behavior, vulnerability, asset, and correlation signals.
- SQLite records complete investigations and every automation stage.
- Critical incidents require analyst approval before disruptive containment (the UI only recommends action).
- `/docs` is generated automatically by FastAPI.

## API

See [docs/API.md](docs/API.md). The central contract is `POST /investigate`; demo scenarios use `POST /demo/run/{scenario}`.

## Demo

1. Start backend and frontend.
2. Open `/demo`.
3. Select `SSH Brute Force — Critical` and click `RUN SCENARIO`.
4. Watch actual backend stages resolve, then open the stored incident.
5. Show `/audit`, `/analytics`, and `/alerts` to demonstrate persistence.
6. For RPA, open UiPath Studio with `uipath/Main.xaml`, configure the local Excel input, and run it against the same backend.

## Limitations

Live provider adapters and production PDF/email delivery are intentionally gated by credentials and are not enabled in demo mode. The fallback AI narrative is deterministic and designed for offline evaluation. See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
