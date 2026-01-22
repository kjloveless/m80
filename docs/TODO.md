# TODO: Documentation, Refactors, and Tests

Goal: improve clarity (docs/comments), refactor complex areas into smaller units, and raise test quality/coverage (target >=70% measured separately).

## Plan (detailed steps)

- [x] **Survey critical core logic**
  - [x] Read `src/core/state.zig`, `src/core/config.zig`, `src/core/paths.zig`, `src/core/errors.zig`
  - [x] Identify long/complex functions and correctness-sensitive paths
  - [x] List specific refactor targets (function splits, naming, error-handling clarity)

- [ ] **Refactor for clarity (behavior-preserving)**
  - [x] `src/core/config.zig`: isolate config-line parsing and list replacement logic
  - [x] `src/core/state.zig`: extract helpers for filesystem setup and status file handling
  - [x] Add short, targeted comments only where intent isn’t obvious
  - [ ] Keep diffs small; no behavior change without tests

- [ ] **Add meaningful tests (core correctness)**
  - [x] `src/core/config.zig`:
    - [x] parse `allowed_domains`/`allowed_ips` with trimming
    - [x] unknown key behavior (ignored)
    - [x] override semantics for repeated keys
  - [x] `src/core/state.zig`:
    - [x] `getStatus` handling of missing/invalid status file
    - [x] `deleteVm` safety errors map to `InvalidArgs`/`NotFound`
  - [x] `src/core/paths.zig`:
    - [x] boundary conditions on name length

- [ ] **Update TODO as work completes**
  - [x] Check off items and add brief notes per change

- [ ] **VM backend focus (posix/serial first)**
  - [x] Review `src/vm/posix.zig`, `src/vm/serial.zig`, `src/vm/vm.zig`
  - [x] Refactor stub startup/IO helpers for clarity and safety
  - [x] Add tests for byte/IO helpers and edge cases

- [ ] **Security hardening coverage**
  - [x] Path safety (symlink escape + safe delete)
  - [x] ACL hardening (skip symlinks + configurable modes)
  - [x] Windows ACL hardening implementation

- [ ] **VM backend config validation**
  - [x] POSIX/HVF missing kernel/initrd loader errors + unset no-op tests
  - [x] Windows image load oversized/null memory cases
  - [x] Cross-backend start/stop validation parity

## Progress log

- [x] Surveyed core logic and identified refactor targets
- [x] Refactored config parsing into `applyConfigEntry` and list replacement helper
- [x] Centralized status file writes with `writeStatusFile`
- [x] Added core tests for config list parsing, unknown keys, status defaults, and name length bounds
- [x] Added deleteVm NotFound test coverage
- [x] Ran `zig build test` after core changes (78 passed, 5 skipped)
- [x] Added NetworkPolicy tests for allowlist ports, deny rules, resolved IP cache, and open-mode validation
- [x] Ran `zig build test` after network policy changes (83 passed, 5 skipped)
- [x] VM backend pass (posix/serial): env flag helper + readLeU64 tests
- [x] Ran `zig build test` after VM changes (84 passed, 5 skipped)
- [x] HVF: env flag helper + io exit size default test
- [x] Ran `zig build test` after HVF changes (85 passed, 5 skipped)
- [x] Windows: io access size mapping helper + exit reason tests
- [x] Ran `zig build test` after Windows changes (87 passed, 5 skipped)
- [x] Added documentation comments across core/net/vm modules
- [x] Added documentation comments for fs mounts and virtio-fs stubs
- [x] Completed documentation pass across remaining units (net/dns, jailer, util, core, vm, test runner)
- [x] Documented repo root docs (README, PHASES, PRD, execution plan)
- [x] Added additional unit tests across mounts, virtio-fs, dns, and seccomp
- [x] Added additional unit tests across dns parsing, virtio-fs traversal, and config optional paths
- [x] Added DNS resolver integration tests (UDP responder + policy allow/deny)
- [x] Added virtio-fs readdir success path and IO error mapping tests
- [x] Implemented Windows ACL hardening (owner-only DACL) with Windows-gated test
- [x] Added start/stop parity guards/tests across backends (AlreadyRunning)
- [x] Ran `zig build test` after ACL/parity changes (178 passed, 7 skipped)
- [x] Added safeDeleteTree tests and symlink escape validation
- [x] Implemented ACL config support (follow_symlinks, fail_fast, custom modes) with tests
- [x] Extended VM backend config tests (POSIX/HVF missing paths; Windows oversized/null image)
- [x] Latest `zig build test`: 176 passed, 5 skipped, 0 failed
- [x] Added HVF arm64 DTB builder + MMU preconfig + guest memory map (via hv_vm_map)
- [x] Added arm64 boot layout + page table builder + tests
- [x] Latest `zig build test`: 198 passed, 6 skipped, 0 failed
