# SignalForge baseline report

Captured before the upgrade on 2026-09-19.

## Verified baseline

- `frontend`: `npm run build` passed on Next.js 15.5.25.
- `backend`: the original `pytest -q` command failed during collection because the repository root did not expose `app` on `PYTHONPATH`. `PYTHONPATH=. pytest -q` passed the original 3 tests after using the supported project invocation.
- Existing backend had 7 rule definitions, a compact SQLite schema, a single pipeline module, and fixture enrichment embedded in the pipeline.
- Existing UI was a working dark neo-brutalist single catch-all page with dashboard, demo, incident, rules, and risk analyzer behavior.
- Existing UiPath XAMLs had the expected filenames and sequence, but most child workflows were logging placeholders without typed arguments or robust failure contracts.

## Upgrade gaps recorded

The initial implementation did not yet provide all 30 rule evaluations, versioned rule results, provider adapter boundaries, assets/accounts/allowlists, response approvals, RBAC, migrations, or browser-level verification. These are tracked in `FINAL_STATUS_PRODUCTION.md` as verified, partial, or environment-dependent rather than being represented as completed claims.
