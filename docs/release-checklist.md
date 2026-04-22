# Release checklist

Use this checklist when you are publishing a new Cremona release.

## Before the tag

Run the full quality gate:

```bash
uv run pytest -q
uv run ruff check .
uv run pyright
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uv run cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression
uv build
```

Update:

- [CHANGELOG.md](../CHANGELOG.md)
- [README.md](../README.md)
- docs if the install or CI story changed

## Smoke test the wheel

```bash
python -m venv .venv-release
. .venv-release/bin/activate
pip install dist/*.whl
cremona --help
cremona scan --help
deactivate
rm -rf .venv-release
```

## Publish

1. Create the tag and GitHub Release.
2. Publish the distributions to PyPI.
3. Verify that `uvx cremona --help` resolves the new version.
4. Verify that `pipx install cremona` followed by `cremona --help` works.

## GitHub Release sections

Use these sections in every release note:

```md
## Highlights

## Install / Upgrade

## CI Gate

## Agent Workflow

## Breaking Changes

## Sample Output
```

## After publishing

- confirm the GitHub Release renders correctly
- confirm the PyPI page shows the new version and project URLs
- confirm the README install commands still match the published artifact
