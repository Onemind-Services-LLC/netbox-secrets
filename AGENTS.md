# Repository Guidelines

## Project Structure & Module Organization
- Source: `netbox_secrets/` (Django/NetBox plugin code: models, views, API, GraphQL, forms).
- Tests: `netbox_secrets/tests/` (Django TestCase-based; files like `test_*.py`).
- Frontend assets: `netbox_secrets/templates/netbox_secrets/inc/secrets_inline_js.html` (inline JS; no build step).
- Docs: `docs/` (models and REST usage), images in `assets/`.
- Sample config for local NetBox testing: `testing_configuration/configuration.py`.

## Build, Test, and Development Commands
- Install (editable): `pip install -e .`
- Python formatting/lint (pre-commit): `pre-commit run -a`.
- Frontend: no build step; inline JS is served via templates.
- Run tests (inside a NetBox env): `python manage.py test netbox_secrets`
  - Use `testing_configuration/configuration.py` for a quick local setup, or mirror CI’s NetBox version.

## Coding Style & Naming Conventions
- Python: Black (line length 120), isort (profile black), Pylint (120). Run via `pre-commit run -a`.
- Types: Pyright for type checks (`pyproject.toml`).
- Naming: modules/functions `snake_case`, classes `PascalCase`, tests `test_*.py` mirroring target module names.

## Testing Guidelines
- Framework: Django TestCase; tests live in `netbox_secrets/tests/`.
- Conventions: group by area (`test_models.py`, `test_views.py`, etc.); isolate DB state with fixtures/factories.
- Coverage: include tests for new models, filters, API, and permissions. Add minimal, focused assertions.

## Commit & Pull Request Guidelines
- Commits: imperative mood; reference Jira when applicable (e.g., `OMS-1234 short summary`). Conventional types like `feat:`, `fix:`, `chore:` are welcome.
- PRs: target `dev` unless directed otherwise; link issues/Jira; include a clear description, testing notes, and screenshots for UI changes. Follow `.github/pull_request_template.md`.
- CI: GitHub Actions runs pre-commit and NetBox plugin tests against a pinned NetBox version.

## Security & Configuration Tips
- Never commit secrets or private keys. Use the plugin’s key workflow (see `docs/` and README).
- Validate key sizes and crypto via existing utilities in `netbox_secrets/utils/`.
- For local NetBox testing, register the plugin in NetBox settings and keep `PLUGINS_CONFIG['netbox_secrets']` minimal unless a test requires overrides.
