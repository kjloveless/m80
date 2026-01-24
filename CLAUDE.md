# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
zig build              # Build the m80 CLI
zig build run -- help  # Run CLI with args
zig build test         # Run all tests (73+ tests)
```

Tests are aggregated via `src/all_tests.zig` using a custom runner in `src/test_runner.zig`. There's no way to run a single test file - all tests run together.

## Architecture

m80 is a cross-platform microVM runtime written in Zig. It uses platform-specific hypervisor backends (WHP on Windows, HVF on macOS, KVM on Linux).

### Core Flow

```
main.zig (CLI) → Jailer.prepare() → Vm.start(config)
                      ↓                    ↓
              privilege drop      platform backend
              resource limits     (windows/hvf/posix)
              sandbox setup
```

### Key Modules

- **`src/vm/vm.zig`** - Platform dispatcher. Routes to `windows.zig` (WHP), `hvf.zig` (macOS), or `posix.zig` (KVM) based on OS
- **`src/jailer/jailer.zig`** - Security boundary. Handles privilege dropping, resource limits (setrlimit), chroot. Uses `acl.zig` for permissions, `seccomp.zig`/`sandbox_darwin.zig`/`sandbox_windows.zig` for platform sandboxing
- **`src/core/config.zig`** - Parses `m80.conf` files (key=value format). Handles `kernel_path`, `initrd_path`, `network_mode`, `allowed_domains`, `allowed_ips`
- **`src/core/state.zig`** - VM lifecycle management (init/delete/status). Uses safe path validation from `src/util/path.zig`
- **`src/net/policy.zig`** - Network allowlisting with `NetworkMode` (locked_down/allowlist/open), domain wildcards, CIDR IP rules
- **`src/net/dns.zig`** - Pure Zig DNS resolver (no libc). Enforces policy at resolution time
- **`src/fs/mounts.zig`** - Mount configuration with allowed roots validation
- **`src/fs/virtio_fs.zig`** - VirtIO-FS device with FUSE protocol handling

### Data Directories

- Windows: `%LOCALAPPDATA%\m80`
- POSIX: `$XDG_DATA_HOME/m80` or `~/.local/share/m80`

Each VM has a directory under `{data}/vms/{name}/` containing `m80.conf` and a `.status` file.

## Coding Patterns

- Target Zig 0.15 APIs (`std.posix` not `std.c`, `std.os.linux.syscall` for Linux-specific calls)
- Tests are named with scope prefix: `config: ...`, `state: ...`, `smoke: ...`
- Platform checks use `@import("builtin").os.tag` with exhaustive switches
- Resource cleanup uses `defer` immediately after acquisition
- Use `std.ArrayList` with `.empty` initialization pattern (Zig 0.15)

## Environment Variables

- `M80_LOG_LEVEL` - debug/info/warn/error (default: info)
- `M80_ALLOW_OPEN_NETWORK` - Required (along with config) for open network mode
