# Development

## Local Setup

This project uses `uv` for dependency management and local command execution.

Install the development dependencies with:

```bash
uv sync --locked --extra dev
```

## Local Hooks

This repository uses `prek` for local Git hooks.

Install the `pre-commit` hook with:

```bash
uv run prek install --hook-type pre-commit
```

Reinstall the hook after deleting `.git/hooks/pre-commit` or after switching to a fresh clone.

Run the hook checks manually across the whole repository with:

```bash
uv run prek run --all-files
```

The local hooks auto-apply the fast fixes they can:

- `uv run ruff format`
- `uv run ruff check --fix`
- `uv run ty check`

If a hook rewrites files during `git commit`, Git may stop the commit so you can review and re-stage the changes. That is expected.

## CI Checks

CI runs the same categories of checks, but in check-only mode, plus tests and build verification:

- `uv run ruff format --check .`
- `uv run ruff check .`
- `uv run ty check`
- `uv run pytest`
- `uv run python -m build`
