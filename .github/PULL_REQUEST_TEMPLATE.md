## Summary

- 

## Validation

- [ ] `uv run pytest -q`
- [ ] `uv run ruff check .`
- [ ] `uv run pyright`
- [ ] `uv run coverage run -m pytest -q`
- [ ] `uv run coverage json -o coverage.json`
- [ ] `uv run cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression`
- [ ] `uv build`

## Checklist

- [ ] Added or updated tests when behavior changed
- [ ] Updated docs when user-visible behavior changed
- [ ] Included a report excerpt if scan behavior changed
- [ ] Updated the baseline only because debt dropped or the schema changed
