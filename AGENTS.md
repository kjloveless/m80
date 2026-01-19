# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds all Zig source code. Entry point is `src/main.zig`, core logic lives under `src/core/`, and hypervisor backends are under `src/vm/`.
- `src/util/` contains logging and small helpers. `src/jailer/` and `src/net/` are scaffolds for future phases.
- Docs and plans live in repo root (`README.md`, `PHASES.md`, `m80-prd.md`, `m80-execution-plan.md`).
- Build outputs are under `zig-out/` and `.zig-cache/` (do not commit).

## Build, Test, and Development Commands
- `zig build` — builds the `m80` CLI.
- `zig build run -- <args>` — runs the CLI (e.g., `zig build run -- help`).
- `zig build test` — runs the full test suite (uses `src/all_tests.zig` and `src/test_runner.zig`).

## Coding Style & Naming Conventions
- Follow Zig standard formatting (use `zig fmt` when in doubt).
- Indentation is 2 spaces, aligned with existing files.
- Use descriptive names for VM-related config keys (e.g., `kernel_path`, `initrd_path`).
- Prefer explicit error handling and early returns.

## Testing Guidelines
- Tests are Zig unit tests co-located with source files and aggregated via `src/all_tests.zig`.
- Name tests with a short scope prefix, e.g., `config: ...`, `state: ...`, `smoke: ...`.
- Run `zig build test` after adding or modifying tests.
- Integration tests may be gated by environment variables (e.g., Windows WHP tests).

## Commit & Pull Request Guidelines
- No formal commit convention is documented. Use short, descriptive commit messages.
- PRs should include a concise summary, testing results (`zig build test` output or note), and any relevant context (e.g., required environment variables for integration tests).

## Security & Configuration Tips
- VM configs live in each VM directory as `m80.conf`.
- Kernel/initrd paths can be relative to the VM directory; validate files before starting.
- Avoid committing local data directories or artifacts.
