# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds Zig source. Entry point is `src/main.zig`.
- `src/cli/` contains argument parsing, help text, runtime control helpers, and command implementations.
- `src/core/` contains config, state, path, and error handling.
- `src/vm/` contains the platform dispatcher, hypervisor backends, virtio devices, boot helpers, guest memory helpers, and snapshot code.
- `src/fs/`, `src/net/`, and `src/jailer/` contain filesystem sharing, DNS wire helpers, and platform hardening code.
- `src/util/` contains logging and path safety helpers.
- `docs/PROJECT.md` is the canonical project guide. Keep active status, roadmap, QA notes, and operational runbooks there.
- Build outputs live under `zig-out/` and `.zig-cache/` and should not be committed.

## Build, Test, and Development Commands
- Current supported Zig toolchain is Zig 0.16.0. The Makefile uses `~/.local/opt/zig-v0.16.0/zig` when available.
- `zig build` builds the `m80` CLI.
- `zig build run -- <args>` runs the CLI, for example `zig build run -- help`.
- `zig build test` runs the full test suite through `src/all_tests.zig` and `src/test_runner.zig`.
- `make initramfs`, `make hvf-smoke`, `make boot-hvf-login`, `make hvf-reliability`, and `make hvf-vsock-smoke` run optional HVF integration helpers when local images and host support are available.

## Coding Style & Naming Conventions
- Follow Zig standard formatting with `zig fmt`.
- Indentation is 2 spaces, matching the existing source.
- Prefer descriptive VM config keys such as `kernel_path`, `initrd_path`, `network_mode`, `network_services`, and `network_metadata_file`.
- Use explicit error handling and early returns.
- Keep `src/main.zig` focused on parsing, dispatch, and top-level error mapping. Put command logic under `src/cli/commands/`.

## Testing Guidelines
- Tests are Zig unit tests co-located with source files and aggregated by `src/all_tests.zig`.
- Name tests with a short scope prefix, for example `config: ...`, `state: ...`, or `smoke: ...`.
- Run `zig build test` after modifying behavior or tests.
- Integration tests must stay gated by explicit environment variables because WHP, HVF, KVM, vsock smoke coverage, and boot images are host-specific.

## Documentation Guidelines
- Do not add new dated phase, TODO, or session-log markdown files.
- Update `docs/PROJECT.md` when status, roadmap, QA snapshots, integration commands, or operational notes change.
- Keep `README.md` as a concise user-facing entry point.

## Commit & Pull Request Guidelines
- Use short, descriptive commit messages.
- PRs should include a concise summary, testing results, and any relevant platform or environment requirements.

## Security & Configuration Tips
- VM configs live in each VM directory as `m80.conf`.
- Kernel/initrd/disk paths can be relative to the VM directory; validate files before starting.
- HVF guest networking uses the `network_*` config model. Use `network_mode=locked_down` with `network_services=dns,metadata` for guest-local DNS and metadata, or `network_mode=allowlist` with `network_allowed_domains`/`network_allowed_ips` for controlled egress.
- Jailer enforcement mode is controlled by `M80_JAILER_ENFORCEMENT=observe|strict|off`.
- Avoid committing local data directories, boot images, disk images, credentials, or generated archives.
