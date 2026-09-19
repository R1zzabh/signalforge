# API

Core routes include `GET /health`, `GET /system/status`, `GET /lab/status`, `POST /lab/events`, `GET /lab/events`, `GET /events/stream`, `POST /lab/scenarios/{scenario}`, `POST /lab/reset`, `GET /automation/inbox`, `POST /automation/claim`, `POST /automation/complete`, alert/investigation/risk/rule/incident/response/report/notification/audit/analytics routes, and the legacy internal-only `/demo/run/{scenario}` fixture routes.

The lab event contract is normalized as:

```json
{"event_id":"EVT-...","timestamp":"...","source_ip":"172.30.0.10","destination_ip":"172.30.0.20","destination_port":22,"protocol":"TCP","event_type":"AUTH_FAILURE","username":"admin","target_asset":"AUTH-SERVER-01","asset_criticality":5,"raw_source":"lab-target","scenario":"brute_force"}
```

The investigation response contains `alert`, `ioc`, `threat_intelligence`, `rules`, `risk`, `mitre`, `ai_summary`, `recommendations`, `automation`, and `audit`.
