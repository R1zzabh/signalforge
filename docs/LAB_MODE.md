# LAB_MODE operations

LAB_MODE replaces the old user-facing Demo Lab with a real isolated cyber range.

## Data flow

```text
sf-target / sf-attacker-controller
        -> sf-telemetry
        -> POST /lab/events
        -> lab_events + existing 30-rule engine
        -> SSE /events/stream
        -> incident / response / audit / UI
```

The target owns the login page and emits structured authentication, network,
C2, and vulnerability-simulation events. The controller has a fixed scenario
allowlist and never accepts arbitrary target or command input. `sf-c2` only
simulates beacon traffic; it is not malware. The CVE action is labeled
`LAB_SIMULATION` and does not exploit a real vulnerability.

## Run

```bash
docker compose -f docker-compose.lab.yml up --build
```

Open `http://localhost:3000/lab`. Target login is available at
`http://localhost:8080/login`.

## Scenarios

`normal_login`, `brute_force`, `credential_stuffing`, `port_scan`,
`c2_simulation`, `cve_lab`, `privileged_account`, `allowlisted_scanner`, and
`alert_burst` are the only controller actions. `POST /lab/reset` clears lab
telemetry and target/controller state while preserving SignalForge incidents.

## Verification boundary

The workspace validates Python, API contracts, frontend build, event ingestion,
rule execution, and Compose structure. Docker runtime execution requires a host
with Docker Engine and Compose; it was not available in the implementation
environment and is therefore not claimed as passed.
