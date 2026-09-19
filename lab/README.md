# SignalForge isolated LAB_MODE

LAB_MODE is the primary presentation path. It runs a target, attacker/controller,
telemetry bridge, and C2 simulator on a private Docker bridge network. The
attacker has only predefined actions against `sf-target`; it accepts no arbitrary
target or command input.

Start from the repository root:

```bash
docker compose -f docker-compose.lab.yml up --build
```

Open `http://localhost:3000/lab` and use `OPEN TARGET` for the real target login
page at `http://localhost:8080/login`. The backend receives normalized events at
`POST /lab/events` and streams them to the lab console at `/events/stream`.

All CVE and C2 actions are explicitly labeled lab simulations. Resetting the lab
clears only `lab_events` and target/controller state; historical SignalForge
incidents are preserved.
