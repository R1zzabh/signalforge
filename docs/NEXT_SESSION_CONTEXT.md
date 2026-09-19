# SignalForge — Next Session Context

Generated 2026-09-19 for continuing implementation and verification.

## Project and repository

- Local project: `/home/ridgehub/soc-platform`
- Public repository: https://github.com/R1zzabh/signalforge
- Default branch: `main`
- Latest pushed commit: `132186c Add isolated LAB_MODE cyber range`
- Earlier baseline commit: `e51d650 Initial SignalForge platform`
- The working tree was clean after the Phase 2A push.

## Original platform

SignalForge is a Next.js + React + TypeScript frontend with a FastAPI backend,
SQLite persistence, deterministic cybersecurity rules, MITRE mapping, fallback
AI explanation, response recommendations, audit logging, reports/notification
contracts, and UiPath XAML artifacts.

The existing backend rule engine was preserved. The legacy deterministic
`/demo/run/{scenario}` path remains available only as an internal fixture/test
path; it is no longer the intended presentation path.

## Completed core upgrade

The backend now has:

- 30 registered, versioned rule definitions.
- Explicit rule states: `TRIGGERED`, `NOT_TRIGGERED`, `NOT_EVALUABLE`, `ERROR`, `DISABLED`.
- Evidence, explanations, recommendations, MITRE mappings, score weights, and rule versions.
- Bucketed 100-point scoring, base/final severity, correlation adjustment, and deterministic escalation.
- SQLite tables for alerts, incidents, audit logs, notifications, system runs, assets, accounts, allowlists, responses, rule definitions, and lab events.
- API routes for health/status, rules, risk, incidents, assets, accounts, allowlists, response approval/rejection, reports, notifications, analytics, and audit.
- Request IDs, CORS configuration, basic security headers, consistent error shape in the API layer, and provider status reporting.
- Provider adapter interfaces in `backend/app/integrations/`.
- UiPath contracts: `/automation/inbox`, `/automation/claim`, `/automation/complete`.

## Phase 2A LAB_MODE implementation

LAB_MODE is now the primary intended demonstration environment.

### Lab services

Implemented under `lab/`:

- `sf-target`: browser-accessible target login at `http://localhost:8080/login`.
- `sf-telemetry`: event bridge forwarding normalized events to SignalForge.
- `sf-lab-controller`: fixed allowlist of safe scenario actions.
- `sf-c2`: simulated C2 beacon receiver/forwarder.
- `lab/target/app.py`: controlled accounts, authentication events, harmless port stubs, beacon control, and explicit CVE simulation.
- `lab/controller/app.py`: normal login, brute force, credential stuffing, port scan, C2, CVE lab, privileged account, allowlisted scanner, and alert burst actions.
- `lab/telemetry/collector.py`: forwards events to `POST /lab/events`.
- `lab/c2/server.py`: forwards `C2_BEACON` events as a lab-only simulation.

### Compose

- Root file: `docker-compose.lab.yml`
- Convenience include: `lab/docker-compose.yml`
- Services: backend, frontend, target, telemetry, controller, C2.
- Network: `signalforge_lab_isolated` with `internal: true`.
- Backend and frontend Dockerfiles added.

### Lab API

- `GET /lab/status`
- `POST /lab/events`
- `GET /lab/events`
- `GET /events/stream` — SSE live stream.
- `POST /lab/scenarios/{scenario}`
- `POST /lab/reset`
- `GET /automation/inbox`
- `POST /automation/claim`
- `POST /automation/complete`

Lab events are persisted in `lab_events`, published to SSE subscribers, evaluated
by the existing 30-rule engine, and can create persisted incidents when meaningful
thresholds or high-severity conditions are met.

### Frontend

- New route: `/lab`.
- Lab Control Center includes environment/component status, target link, reset,
  predefined scenario controls, live telemetry, risk updates, and incident links.
- Header now displays `LAB_MODE · ISOLATED`.
- `/demo` was relabeled as internal `Fixture Tests` in the navigation.
- Existing visual language is preserved: dark navy, Poppins/Fira Code/Lora,
  outlined cards, offset shadows, aqua/yellow/pink/green accents.

## Scenarios

The fixed lab controller allowlist contains:

1. `normal_login`
2. `brute_force`
3. `credential_stuffing`
4. `port_scan`
5. `c2_simulation`
6. `cve_lab`
7. `privileged_account`
8. `allowlisted_scanner`
9. `alert_burst`

The target uses controlled accounts including `alice`, `bob`, `charlie`, `admin`,
`root`, `security_admin`, and `service_account`.

The CVE scenario is explicitly a `LAB_SIMULATION`; it does not exploit a real
external vulnerability. The C2 scenario is simulated beacon traffic, not malware.

## Verification completed

- Backend tests: `97 passed`.
- Frontend build: `npm run build` passed.
- Lab Python modules compile successfully.
- Compose YAML static validation passed for all six services.
- Compose network static validation passed with `internal: true`.
- Existing 30-rule engine regression tests still pass.
- Four lab ingestion tests were added.
- All supplied UiPath XAML files previously parsed as valid XML.

## Important unverified item

Docker Engine was installed on the host, but the current agent/session still has
the old supplementary groups. Docker reports:

```text
permission denied while trying to connect to /var/run/docker.sock
```

The user was instructed to start a new terminal/session or log out/in so the
`docker` group membership becomes active. No Docker runtime execution has been
claimed yet.

## First commands for the next session

```bash
cd /home/ridgehub/soc-platform
docker info
docker compose -f docker-compose.lab.yml up --build
```

Then open:

```text
http://localhost:3000/lab
http://localhost:8080/login
```

## Recommended runtime verification sequence

1. Confirm `docker info` works without sudo.
2. Start the Compose stack.
3. Verify `GET http://localhost:8000/health`.
4. Verify `GET http://localhost:8000/lab/status` shows isolated connected components.
5. Open the target login page and perform a normal login.
6. Confirm `AUTH_SUCCESS` appears on `/lab`.
7. Run `BRUTE FORCE`; confirm target requests, telemetry, `RULE-BHV-001`, T1110,
   risk updates, incident creation, and response recommendation.
8. Run credential stuffing and confirm `RULE-AUTH-001` and `RULE-AUTH-003`.
9. Run port scan and confirm `RULE-NET-001` and T1046.
10. Run C2, CVE, privileged, allowlist, and alert-burst scenarios.
11. Verify `/incidents/{id}`, `/response`, `/audit`, `/analytics`, and
    `/automation/inbox`.
12. Exercise `/automation/claim` and `/automation/complete`.
13. Run `docker compose -f docker-compose.lab.yml down` after verification.

## Known follow-up work

- Runtime Docker verification and fixes for any container networking/build issues.
- Full Playwright test for `/lab` and SSE event rendering.
- Stronger persistent lab incident correlation/deduplication across repeated thresholds.
- Complete production authentication/RBAC rather than the current DEMO/session contract.
- Full live provider adapters, Alembic migrations, PostgreSQL runtime, production
  reporting/email delivery, and executed UiPath Studio workflow validation.
- Review and refine target service decomposition if the academic demonstration
  requires separate auth/web/database containers instead of the current target
  service with harmless internal service stubs.

## Safety boundary

Never add arbitrary target input or arbitrary shell execution to the attacker
controller. Keep all actions restricted to `sf-target` on the isolated lab
network. Do not turn the CVE simulation into a real exploit or the C2 simulator
into malware.
