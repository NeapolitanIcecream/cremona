# Contributing to Cremona

Use this guide when you want to change Cremona itself, improve the docs, or add new report fixtures.

## Local setup

```bash
git clone https://github.com/NeapolitanIcecream/cremona.git
cd cremona
uv sync --group dev
```

Run the CLI once before you start editing:

```bash
uv run cremona --help
uv run cremona scan --help
```

## Good first contributions

- Improve quickstart, troubleshooting, or CI recipes.
- Add report examples that explain why a file was queued.
- Add parser fixtures or regression tests for `ruff`, `lizard`, `complexipy`, or `vulture`.
- Improve profile configuration examples.
- Tighten packaging and release automation without changing scan behavior.

## Before you open a pull request

Run the full local quality gate:

```bash
uv run pytest -q
uv run ruff check .
uv run pyright
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uv run cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
uv build
```

If your change affects packaging or release steps, also smoke test the built wheel:

```bash
python -m venv .venv-release
. .venv-release/bin/activate
pip install dist/*.whl
cremona --help
cremona scan --help
deactivate
rm -rf .venv-release
```

## Pull request expectations

- Keep changes focused. Split unrelated packaging, docs, and engine changes into separate pull requests.
- Add or update tests when behavior changes.
- Update docs when the user-visible workflow changes.
- Do not refresh the baseline to hide regressions. Update it only after debt dropped or the schema changed.
- Use a Conventional Commit style subject such as `docs:`, `feat:`, or `refactor:`.

If scan behavior changes, include a short report excerpt or command output in the pull request description.
