# Architecture

Next.js renders the operator console. FastAPI owns validation, orchestration, integrations, deterministic rules, scoring, explanations, reporting, notifications, and persistence. SQLite stores alerts, complete incident payloads, audit events, notifications, and system runs. UiPath is an external orchestration client that reads Excel, calls the API, branches on severity, and writes results.
