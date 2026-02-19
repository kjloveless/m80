# m80 Maintainability Plan

Status date: 2026-02-19  
Owner: core maintainers  
Goal: reduce maintenance cost and onboarding time without changing VM behavior.

## Why this plan exists

Recent refactors improved CLI flow, snapshot plumbing, and duplicate request/file handling, but the project still has several very large files and mixed responsibilities. This plan turns those concerns into a tracked execution checklist.

## Success criteria

- Large-module complexity reduced through file splits and clearer ownership boundaries.
- New contributors can identify where to add code without searching the whole tree.
- CI enforces formatting/tests and basic maintainability guardrails.
- Behavior remains stable (`zig build test` stays green throughout).

## Current baseline (2026-02-19)

- Largest files:
  - `src/fs/virtio_fs.zig` (~5.1k)
  - `src/vm/hvf.zig` (~5.1k)
  - `src/vm/virtio.zig` (~3.1k)
  - `src/vm/snapshot.zig` (~1.6k)
  - `src/core/config.zig` (~1.4k)
  - `src/main.zig` (~1.3k)
- Recent completed refactors:
  - CLI request/result helper consolidation
  - VM snapshot/restore helper consolidation
  - DNS/vmnet helper dedupe
  - virtio-fs `setlk`/`setlkw` handler consolidation
- Validation baseline:
  - `zig build test` passing (335 loaded, 0 failed)

## Workstreams

### 1) CLI and command boundaries

- [x] Split `src/main.zig` into command modules under `src/cli/commands/`
- [x] Keep `main.zig` to argument parse + dispatch + top-level error mapping
- [x] Consolidate PID/socket/status helpers in `src/cli/runtime.zig`
- [x] Add command-level unit tests for parse/validation paths

Exit criteria:
- `main.zig` mostly dispatch logic
- Command-specific logic no longer mixed in one file

### 2) VM backend decomposition

- [ ] Split `src/vm/hvf.zig` by domain:
  - `src/vm/hvf/boot.zig`
  - `src/vm/hvf/vcpu.zig`
  - `src/vm/hvf/mmio.zig`
  - `src/vm/hvf/net_console.zig`
  - `src/vm/hvf/state.zig`
- [ ] Extract shared guest memory read/write helpers to `src/vm/guest_mem.zig`
- [ ] Reuse `guest_mem` in `hvf`, `posix`, `windows`, and `virtio` codepaths

Exit criteria:
- HVF logic grouped by concern
- No duplicate guest memory primitive helpers across backends

### 3) Virtio and virtio-fs maintainability

- [ ] Split `src/vm/virtio.zig` into per-device files:
  - `src/vm/virtio/blk.zig`
  - `src/vm/virtio/net.zig`
  - `src/vm/virtio/console.zig`
  - `src/vm/virtio/rng.zig`
  - `src/vm/virtio/fs.zig`
  - `src/vm/virtio/common.zig`
- [ ] Keep MMIO dispatch table in a small orchestration module
- [ ] Continue dedupe pass in `src/fs/virtio_fs.zig` for repeated error/handle validation paths

Exit criteria:
- Device handlers live in device-specific files
- Common queue/MMIO helpers are centralized

### 4) Snapshot compatibility isolation

- [ ] Extract legacy vCPU format adapters from `src/vm/snapshot.zig` into `src/vm/snapshot_compat.zig`
- [ ] Keep `snapshot.zig` focused on read/write flow orchestration
- [ ] Add compatibility tests per legacy version path (v1-v5)

Exit criteria:
- Legacy translation logic isolated from primary load/save paths
- Compatibility behavior covered by targeted tests

### 5) Config and policy boundaries

- [ ] Split `src/core/config.zig` into:
  - parse/load
  - validate
  - write/serialize
- [ ] Keep network policy-specific parsing in policy-owned helpers where possible
- [ ] Document config key ownership and validation stage

Exit criteria:
- Config parsing and validation are clearly separated
- Key handling is easier to audit and extend safely

### 6) Documentation and ownership map

- [ ] Add `docs/ARCHITECTURE.md` with module map and ownership boundaries
- [ ] Add `docs/CONTRIBUTING-MAINTAINERS.md` with:
  - where to place new code
  - expected test updates
  - commit/PR checklist for maintainability
- [ ] Link architecture + maintainer docs from `README.md`

Exit criteria:
- New maintainers can navigate module ownership quickly
- Coding placement rules are explicit

### 7) CI and guardrails

- [ ] Add CI checks for:
  - `zig fmt --check`
  - `zig build`
  - `zig build test`
- [ ] Add lightweight static check script for anti-patterns (e.g., command logic leakage into `main.zig` once split)
- [ ] Ensure checks run on PRs before merge

Exit criteria:
- Formatting/tests are always enforced
- Maintainability boundaries are mechanically protected

## Execution order

1. CLI and command boundaries
2. VM backend decomposition
3. Virtio and virtio-fs decomposition
4. Snapshot compatibility isolation
5. Config and policy boundaries
6. Documentation and ownership map
7. CI and guardrails

## Tracking protocol

- Each PR should:
  - reference this plan
  - check off completed items
  - note any scope changes
- If priorities change, update this file first, then implement.
