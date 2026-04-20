# Provenance

This repository was extracted from `recoleta` with fresh Git history.

Initial source of truth:

- `scripts/refactor_audit.py`
- `tests/test_refactor_audit.py`

Source repository:

- `https://github.com/NeapolitanIcecream/recoleta`

Extraction commit:

- `d67fad32c19424fce826664d1c8e80e25d4ad2bd`

What changed during extraction:

- Moved the audit into the `cremona` package and CLI.
- Replaced hard-coded `recoleta` subsystem logic with pluggable profiles.
- Kept a built-in `recoleta` profile for compatibility.
- Kept the report contract and baseline behavior stable where practical.
