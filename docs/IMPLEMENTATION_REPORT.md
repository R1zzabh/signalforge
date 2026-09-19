# SignalForge SOC Automation Platform — Implementation Report

## 1. Executive summary

SignalForge is implemented as an isolated full-stack academic SOC incident triage and RPA automation platform under `soc-platform/`.

The platform demonstrates the complete offline DEMO_MODE investigation path:

```text
Alert
  → IOC extraction
  → threat-intelligence enrichment
  → cybersecurity rule evaluation
  → deterministic risk score
  → severity classification
  → MITRE ATT&CK mapping
  → AI-style explanation fallback
  → report/notification readiness
  → SQLite persistence
  → audit trail and dashboard visibility
```

The backend is FastAPI, the frontend is Next.js/React/TypeScript, storage is SQLite, and UiPath workflow artifacts are provided for Excel-driven orchestration.

## 2. Project location and structure

The implementation is located at:

```text
/home/ridgehub/soc-platform
```

Important directories:

```text
backend/       FastAPI API, pipeline, rules, database, tests
frontend/      Next.js dashboard and UI styling
uipath/        UiPath workflow XAML artifacts
docs/          architecture, API, demo, viva, testing, and limitation notes
README.md      setup and usage instructions
FINAL_STATUS.md verified status and remaining work
```

## 3. Frontend implementation

The frontend is implemented as a Next.js application using React, TypeScript, Lucide icons, and CSS design tokens.

### Visual design

The supplied theme direction was implemented as a dark-first neo-brutalist SOC console:

- dark navy background with pastel cyber accents
- yellow, pink, aqua, and green semantic states
- strong outlined cards
- offset asymmetric shadows
- compact technical metadata using Fira Code
- Poppins for normal UI text
- Lora for incident explanation text
- responsive layout for desktop, tablet, and mobile widths
- visible loading, empty, error, and status states
- reduced-motion media query
- keyboard-friendly labeled controls and links

The design avoids a generic green-on-black hacker dashboard and avoids using glassmorphism as the main visual treatment.

### Implemented routes and behavior

#### `/`

SOC Overview dashboard with:

- total incidents
- open/escalated incidents
- average risk score
- automation success rate
- recent incidents table
- risk distribution bars
- automation health indicators
- links to alert creation and Demo Lab

Metrics are loaded from `GET /dashboard/metrics` and incidents from `GET /incidents`.

#### `/alerts`

Alert Center with:

- incident-backed alert table
- search field
- severity filter UI
- refresh action
- source IOC
- event type
- target
- risk score
- severity badge

#### `/alerts/new`

Functional alert submission form containing:

- source IP
- destination IP
- event type
- failed attempts
- username
- hostname
- destination port
- asset criticality
- description

The form submits to `POST /investigate` and displays the stored incident link when successful.

#### `/incidents/[id]`

Incident detail page with:

- incident identifier
- severity and risk score
- IOC summary
- provider mode
- automation duration
- AI/fallback explanation
- recommended actions
- human approval warning for critical incidents
- threat-intelligence results
- triggered rules
- MITRE ATT&CK techniques
- actual audit-based automation timeline

#### `/threat-intelligence`

The navigation entry exists. The current implementation keeps provider inspection primarily in the incident view and backend enrichment endpoint. A fuller standalone provider analytics page remains an extension item.

#### `/rules`

Rule catalog backed by `GET /rules`, showing:

- rule ID
- rule name
- category
- condition
- MITRE association
- applied weight

#### `/risk-analyzer`

Interactive what-if simulator. User-editable inputs are sent to `POST /risk/score`, and the UI displays:

- score
- severity
- triggered rules
- applied weights

#### `/automation`

UiPath/RPA workflow stage visualization with the main orchestration stages and a demo-mode explanation.

#### `/demo`

Project showcase page with six scenarios:

- Benign Login
- Port Scan
- SSH Brute Force — Critical
- Known Malicious IOC
- Critical Server Attack
- Malware Communication

The user selects a scenario and runs `POST /demo/run/{scenario}`. The UI progresses through all backend stages and then shows the actual returned incident, risk, rules, MITRE mapping, and stored record link.

#### `/analytics`

Displays metrics from the backend, including:

- prototype manual investigation estimate
- automated run estimate
- calculated time saved
- automation success rate
- severity distribution

#### `/audit`

Displays the persisted automation audit trail from `GET /audit`.

#### `/settings`

The navigation entry exists. A more complete settings control surface is a remaining enhancement.

## 4. Backend implementation

The backend is implemented in `backend/app/`.

### Core services

- `config.py` — environment-driven demo/live configuration
- `database/db.py` — SQLite initialization and persistence helpers
- `rules/engine.py` — deterministic security rules, score, severity, and MITRE mapping
- `services/pipeline.py` — investigation orchestration and demo scenarios
- `main.py` — FastAPI app and API routes

### Implemented API endpoints

```text
GET  /health
GET  /system/status
POST /alerts
POST /investigate
GET  /incidents
GET  /incidents/{incident_id}
POST /enrich
POST /risk/score
POST /summary
POST /reports/generate
POST /notifications/send
GET  /audit
GET  /rules
POST /rules/evaluate
POST /demo/run/{scenario}
POST /demo/run-all
GET  /dashboard/metrics
```

FastAPI also provides interactive OpenAPI documentation at `/docs` when the server is running.

### Investigation object

Each completed investigation is stored as a structured object containing:

- `incident_id`
- original alert
- extracted IOC values
- VirusTotal fixture result
- AbuseIPDB fixture result
- GeoIP fixture result
- NVD/CVE fixture result
- triggered rules
- correlations
- deterministic risk result
- MITRE techniques
- generated explanation
- recommended actions
- automation metadata
- audit timeline

## 5. Threat-intelligence implementation

DEMO_MODE uses deterministic local fixture behavior so the project works without internet or credentials.

The enrichment object includes:

### VirusTotal

- provider status
- detection count
- total engines
- lookup timestamp

Malicious demo indicators return 14 detections.

### AbuseIPDB

- provider status
- confidence score
- country
- usage type
- lookup timestamp

Malicious demo indicators return 94% confidence.

### GeoIP

- country
- city
- ASN
- usage type context

### NVD/CVE

- provider status
- CVSS value
- CVE value

The live-mode configuration surface is present, but full provider-specific HTTP adapters and credentials are deployment-specific remaining work. Provider failures are designed to be represented as unavailable rather than fabricated as successful live results.

## 6. Deterministic rule engine

Implemented rules include:

### Reputation

- AbuseIPDB confidence ≥ 90: +25
- AbuseIPDB confidence 70–89: +20
- AbuseIPDB confidence 40–69: +10

### Threat intelligence

- VirusTotal detections > 10: +25
- VirusTotal detections 6–10: +15
- VirusTotal detections 3–5: +10

### Behavior

- failed attempts ≥ 10: brute-force rule
- failed attempts ≥ 50: high-confidence brute-force weight
- unique destination ports ≥ 10: port-scan rule

### Correlation

Malicious reputation combined with suspicious behavior triggers a correlation rule.

### Asset

Criticality is mapped from 1–5 to increasing impact weight. Critical assets contribute up to +10.

### Vulnerability

CVSS ≥ 9.0 triggers a critical vulnerability rule.

## 7. Risk scoring

The score is capped at 100 and severity is never delegated to AI.

```text
0–29    LOW
30–49   MEDIUM
50–74   HIGH
75–100  CRITICAL
```

The critical SSH demo produces:

```text
Reputation:             25
Threat intelligence:    25
Behavior:                20
Correlation:              5
Asset criticality:       10
                         ---
Total:                   85 / 100
Severity:                CRITICAL
```

## 8. MITRE ATT&CK mapping

The implementation includes:

- T1110 — Brute Force
- T1046 — Network Service Scanning
- T1059 — Command and Scripting Interpreter
- T1071 — Application Layer Protocol
- T1566 — Phishing

Mapped output includes:

- technique ID
- technique name
- tactic
- description
- relationship to the observed alert/rule

## 9. AI explanation layer

The pipeline generates a structured narrative containing:

- executive interpretation
- observed source and target
- risk score context
- correlated evidence
- recommended analyst actions

In DEMO_MODE, the explanation is deterministic and locally generated. This keeps the demonstration functional without an OpenAI API key.

The design principle is explicit: AI can explain evidence but cannot override:

- the score
- severity
- rule-trigger state
- human approval requirements

## 10. Persistence and audit trail

SQLite is initialized automatically. The database stores:

- alerts
- complete incidents
- audit logs
- notifications table
- system runs table

Every investigation stage writes an audit event such as:

```text
Alert received
IOC extracted
Threat intelligence queried
Risk engine executed
MITRE mapped
AI summary generated
Report generated
Notification sent
Incident stored
```

The incident page renders the returned audit timeline rather than hardcoding a fake progress sequence.

## 11. RPA / UiPath implementation

The `uipath/` directory contains the requested workflow names:

- `Main.xaml`
- `ReadAlerts.xaml`
- `ValidateAlert.xaml`
- `ExtractIOC.xaml`
- `CallBackend.xaml`
- `ProcessInvestigation.xaml`
- `RouteBySeverity.xaml`
- `GenerateReport.xaml`
- `SendNotification.xaml`
- `WriteResults.xaml`
- `HandleException.xaml`

The main workflow expresses:

1. Read Excel alerts
2. Validate alert data
3. Extract IOC fields
4. Retry backend invocation
5. Process investigation response
6. Branch on severity
7. Generate report
8. Send notification
9. Write results
10. Log completion/errors

The project documents critical human approval behavior: a critical incident may recommend containment but should not automatically perform disruptive infrastructure actions.

The XAML artifacts are a strong orchestration scaffold, but exact activity namespaces and bindings may require adjustment for the installed UiPath Studio version.

## 12. Demo scenarios verified

### Benign Login

```text
Risk:     0 / 100
Severity: LOW
MITRE:    none
```

### Port Scan

```text
Risk:     30 / 100
Severity: MEDIUM
MITRE:    T1046
```

### SSH Brute Force — Critical

```text
Source:       185.220.101.44
Target:       production authentication server
Attempts:     63
VT:           14 detections
AbuseIPDB:    94%
Risk:         85 / 100
Severity:     CRITICAL
MITRE:        T1110
```

This scenario creates a SQLite incident, audit events, recommendations, report-ready state, and notification-ready state.

## 13. Testing performed

### Automated backend tests

`backend/tests/test_rules.py` contains tests for:

- critical brute-force scoring
- port-scan scoring and T1046 mapping
- benign scoring

Result:

```text
3 passed
```

### Frontend build

The Next.js production build completed successfully with:

```text
npm run build
```

### Direct pipeline smoke tests

Direct service-level execution was performed for:

- benign login
- port scan
- SSH brute force critical

### Backend startup

Uvicorn startup and automatic SQLite database initialization were verified.

### Not yet performed

- browser-level click-through rehearsal
- live provider calls with real API credentials
- production Outlook delivery
- a specific UiPath Studio version's full activity execution
- enterprise deployment testing

## 14. Security and safety posture

Implemented principles:

- demo fixtures require no secrets
- environment variables are used for optional credentials
- no API keys are hardcoded
- user descriptions are treated as input data
- deterministic rules own severity
- critical containment is human-in-the-loop
- no credential destruction, shutdown, or indiscriminate blocking is automated
- provider unavailability is represented explicitly in the architecture

## 15. Known limitations

The project is suitable as a functional academic prototype and live demonstration, not as a production SOC deployment.

Remaining production-hardening areas:

- authentication and role-based access control
- Postgres or managed database
- background job queue and event streaming
- full HTTP adapters for VirusTotal, AbuseIPDB, NVD, GeoIP, MITRE, and OpenAI
- production email/Outlook integration
- complete PDF report rendering and archival
- stronger rate limiting and request tracing
- complete standalone threat-intelligence and settings pages
- exact UiPath activity bindings for a chosen Studio version
- browser and end-to-end test automation

## 16. Presentation sequence

1. Start the FastAPI backend.
2. Start the Next.js frontend.
3. Open `/demo`.
4. Select SSH Brute Force — Critical.
5. Run the scenario.
6. Explain each pipeline stage as it completes.
7. Open the incident detail.
8. Show score breakdown, rules, MITRE T1110, AI explanation, and recommendations.
9. Open `/alerts` to show the stored incident.
10. Open `/audit` to show traceability.
11. Open `/analytics` to show calculated prototype metrics.
12. Open UiPath Studio and explain `Main.xaml` as the Excel/API/report/notification orchestration layer.

## 17. Final assessment

The implemented system is a coherent, connected prototype rather than a collection of static screens. Its strongest completed path is the offline deterministic investigation flow, which is testable, explainable, persisted, visualized, and prepared for UiPath orchestration. The primary remaining work is production integration hardening and environment-specific verification, not the core demonstration pipeline.
