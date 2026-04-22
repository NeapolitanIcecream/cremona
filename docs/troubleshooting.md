# Troubleshooting

Use this page when the scan runs but the result is incomplete, or when Codex cannot find Cremona.

## Baseline schema error

Symptom:

- the scan says the baseline schema version is no longer supported

Cause:

- the committed baseline was created with an older Cremona schema

Fix:

```bash
uvx cremona scan /path/to/repo --update-baseline
git add quality/refactor-baseline.json
```

Current public releases use `schema_version = 3`.

## Coverage is missing

Symptoms:

- `signal_health` is `partial`
- the report says coverage is missing

Fix:

```bash
uv run coverage run -m pytest -q
uv run coverage json -o coverage.json
uvx cremona scan /path/to/repo --coverage-json /path/to/repo/coverage.json
```

If your repository uses a different test entrypoint, keep that command and only preserve the `coverage json` export.

## History is missing or too shallow

Symptoms:

- `signal_health` is `partial`
- the queue has weak or missing history signals

Cause:

- the repository clone is shallow, or CI only checked out the latest commit

Fix in GitHub Actions:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Fix in a local clone:

```bash
git fetch --unshallow
```

If the repository is already complete, rerun the scan.

## Codex cannot find Cremona

Symptoms:

- Codex says `cremona` is not on `PATH`
- the skill cannot find a local checkout

Fix:

```bash
python3 .agents/skills/cremona-proactive-refactor-audit/scripts/locate_cremona.py --target-repo /path/to/repo
```

If Cremona lives in another checkout, set `CREMONA_REPO_PATH` and rerun the locator:

```bash
export CREMONA_REPO_PATH=/path/to/cremona
python3 .agents/skills/cremona-proactive-refactor-audit/scripts/locate_cremona.py --target-repo /path/to/repo
```

The locator returns the recommended scan command for the repository you want to audit.
