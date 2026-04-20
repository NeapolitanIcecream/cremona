# Repository Guidelines

## Project Structure & Module Organization
`src/cremona/` contains the packaged CLI and scan engine. Use `cli.py` for the entry point, `core/` for config, shared models, and orchestration, `python_tools/` for tool integration and symbol lookup, and `profiles/` for built-in and compiled scan profiles. Keep tests in `tests/`; the current suite lives in `tests/test_cremona_scan.py`. Reference material belongs in `docs/`, including [docs/methodology.md](docs/methodology.md).

## Build, Test, and Development Commands
Run `uv sync --group dev` to install runtime and developer dependencies. Use `uv run cremona --help` to confirm the CLI entry point, and `uv run cremona scan [path]` to execute an audit against the current repository or an explicit target. Run `uv run pytest -q` for tests, `uv run ruff check .` for linting, and `uv run pyright` for static typing. Generate coverage input for Cremona with `uv run coverage run -m pytest -q` followed by `uv run coverage json -o coverage.json`. Validate the repo-native regression gate with `uv run cremona scan --baseline quality/refactor-baseline.json --coverage-json coverage.json --fail-on-regression`. Initialize or refresh the committed baseline with `uv run cremona scan --update-baseline` only when debt was genuinely reduced or the baseline schema changed. Build distributable artifacts with `uv build`; wheels and source archives land in `dist/`.

## Coding Style & Naming Conventions
Target Python 3.12+ and use 4-space indentation. Match the existing style: `from __future__ import annotations`, explicit type hints on public functions, and frozen `@dataclass` models for shared state. Use `snake_case` for modules, functions, and variables, `PascalCase` for classes and dataclasses, and `UPPER_SNAKE_CASE` for constants. Keep parser and reporting logic in small functions that are easy to test.

## Testing Guidelines
Write tests with `pytest` under `tests/`, using `test_*.py` module names and `test_*` function names. Prefer focused regression tests that build temporary files with `tmp_path` and assert on parsed findings, profile behavior, and report output. There is no percentage-based coverage gate, but `coverage.json` is part of the Cremona routing and regression workflow, so changes that affect bootstrap, CI gating, or coverage interpretation should also be checked with `coverage run`, `coverage json`, and the gated `cremona scan`. New behavior should ship with tests and keep `pytest`, `ruff`, `pyright`, and the relevant Cremona scan path green locally before review.

## Configuration Notes
Project metadata, dev tools, and default scan settings live in `pyproject.toml`, especially `[tool.cremona]` and `[tool.coverage.run]`. When adding config keys or thresholds, update both `pyproject.toml` and `src/cremona/core/config.py` so defaults and loaded values stay aligned. When changing the default audit scope, committed baseline path, or coverage source roots, keep `pyproject.toml`, `quality/refactor-baseline.json`, and `.github/workflows/ci.yml` consistent with the new workflow.

## Commit & Pull Request Guidelines
Recent commits use Conventional Commit prefixes such as `feat:` and `refactor:` with short, imperative subjects. Follow that pattern. Pull requests should explain the user-visible change, list the commands you ran, and include sample CLI output or report snippets when scan behavior changes. Link the relevant issue when one exists.
