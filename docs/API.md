# API

`GET /health`, `GET /system/status`, `POST /alerts`, `POST /investigate`, `GET /incidents`, `GET /incidents/{id}`, `POST /enrich`, `POST /risk/score`, `POST /summary`, `POST /reports/generate`, `POST /notifications/send`, `GET /audit`, `GET /dashboard/metrics`, `GET /rules`, `POST /rules/evaluate`, `POST /demo/run/{scenario}`, and `POST /demo/run-all` are implemented in `backend/app/main.py`.

The investigation response contains `alert`, `ioc`, `threat_intelligence`, `rules`, `risk`, `mitre`, `ai_summary`, `recommendations`, `automation`, and `audit`.
