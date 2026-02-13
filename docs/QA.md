# QA Progress and Remaining Work

This file tracks test coverage work, key behavior validations, and remaining QA tasks.
It is intended to be a living checklist for correctness and regression prevention.

## Current Status (Historical Session Snapshot: 2026-01-19)

### Test Runs
- `zig build test` executed repeatedly after each change.
- Latest run: **176 passed, 5 skipped, 0 failed**.
- Skipped tests are OS‑gated/integration‑gated (see “Skipped Tests”).

### Latest Local Validation (2026-02-13)
- `zig build` passed.
- `zig build test` passed: **314 passed, 15 skipped, 0 failed**.

### Recent Reliability/Hardening Updates (2026-02-13)
- Detached stop path now writes `stop.request` and waits for graceful runner exit before signal fallback.
- `waitForStopOrSnapshot` now consumes `stop.request` alongside snapshot/restore control files.
- Jailer runtime prepare path now calls platform hardening hooks (Linux seccomp, macOS sandbox, Windows job object) with enforcement mode:
  - `M80_JAILER_ENFORCEMENT=observe|strict|off` (default `observe`).
- Allowlist validation now rejects malformed:
  - `allowed_domains` entries (supports `domain`, `*.domain`, and `domain:port`).
  - `allowed_ips` entries (IPv4/CIDR).
- Blocked DNS queries now produce synthetic DNS `REFUSED` responses consistently in virtio-net logs/behavior.

### Key Fixes Made
- **DNS parsing alignment bug fixed**: `parseResponse` now uses `std.mem.readInt` instead of unaligned pointer reads.
- **DNS query send return value handled**: `_ = sendto(...)` to satisfy Zig “unused value” requirement.
- **skipQuestion bounds check**: now validates QTYPE/QCLASS length to avoid out‑of‑bounds parse.

### High‑Value Tests Added
Core
- `config`: `parseBool`, `parseCommaSeparated` (trim + empty), `writeConfigFile` emits allowlists, `validateStartConfig` missing fields, empty path clears optionals.
- `state`: missing VM errors (`deleteVm`, `setStatus`), invalid names, malformed status -> stopped, empty vm dir iter, NotFound behavior.
- `paths`: `vmDir` invalid name, `dataDir` includes “m80” path segment.

FS / Virtio‑FS
- FUSE round‑trip: lookup/open/write/read/release with assertions.
- Error paths: traversal, short payloads, invalid handle, missing node, non‑dir open, releasedir short payload, readdir short payload.
- Handle lifecycle: release removes handle from map.

Network
- DNS: query buffer too small, oversized label, invalid headers, non‑zero rcode, empty answer, A‑record parsing, skipName/skipQuestion truncation.
- Policy: allowlist order (first match wins), open/locked_down semantics, TTL cap/cleanup, port filtering.

Jailer
- Directory hardening works and rejects loose perms (POSIX).
- `prepare` creates root directory (with/without harden/limits).
- Resource limits defaults.

VM / Serial
- IO mapping defaults, read/write behavior, masking, guest layout bounds.

### Documentation Pass (Completed)
Comments added across:
- `src/core/*`, `src/net/*`, `src/fs/*`, `src/vm/*`, `src/jailer/*`, `src/util/*`
- Repo docs updated: `README.md`, `PHASES.md`, `m80-prd.md`, `m80-execution-plan.md`

### Review Log (2026-01-19)
- Reviewed `src/net/dns.zig`, `src/fs/virtio_fs.zig`, `src/fs/mounts.zig`, `src/core/state.zig`, `src/core/config.zig`, and `src/util/path.zig`.
- **Potential alignment risk**: `dns.parseResponse` uses `@alignCast` on `response.ptr` for `DnsHeader`. Consider reading header fields via `std.mem.readInt` to avoid alignment traps when buffers are not aligned.
- **Potential alignment risk**: `virtio_fs.handleRequest` and sub-handlers cast raw request payloads to `Fuse*` structs with `@alignCast`; guest buffers may not be aligned. Consider `std.mem.bytesToValue` or manual field reads.
- **Potential bounds risk**: `virtio_fs.handleRead` computes `response_buf.len - out_header_size` without guarding for undersized buffers; add an early length check.
- **Testing follow-ups**: add a unit test that feeds unaligned request buffers for virtio-fs + DNS header parsing, and a test covering `handleRead` with a too-small response buffer.

### QA Progress (2026-01-19)
- **Alignment-safe parsing added**: DNS header fields now read with `std.mem.readInt` and virtio-fs request structs are memcpy'd into aligned locals.
- **New tests**: unaligned DNS response parsing, unaligned virtio-fs INIT request, and short response buffer handling for virtio-fs READ.
- **Virtio-FS readdir success path**: implemented basic dirent packing; added test verifying returned entries.
- **Mount access enforcement**: added write-access rejection test for `isPathAccessAllowed`.
- **DNS multi-record parsing**: added test that ignores non-A records.
- **Virtio-FS IO error mapping**: added read/write tests for access-denied modes.
- **DNS resolver integration**: added UDP responder integration test.
- **Resolver + policy integration**: added allowlist caching test that populates resolved IPs.
- **Resolver policy rejection**: added disallowed-domain test for `resolveWithPolicy`.
- **State cleanup**: added init/delete test to verify config/status removal.
- **Wildcard edge cases**: added domain pattern tests for suffix boundaries.
- **Path symlink escape**: added validation test and no-follow symlink detection for POSIX.
- **Windows reparse points**: treat any reparse point as potential escape when symlink following is disabled.
- **ACL symlink safety**: hardening skips symlinks; added test to ensure target perms remain unchanged.
- **ACL config support**: implemented custom modes, follow_symlinks behavior, and fail_fast handling with tests.
- **Safe deletion**: added `safeDeleteTree` tests for shallow-path rejection and deep deletion.
- **VM backend config errors**: added missing kernel/initrd tests for POSIX/HVF and oversized image test for Windows.
- **VM backend config behavior**: added tests for unset kernel/initrd no-ops and null memory handling in Windows image copy.
- **Test run**: `zig build test` → **160 passed, 5 skipped, 0 failed**.

## Skipped Tests (Expected)

These skips are **expected and correct** due to host platform or integration dependencies:
- `vm.hvf` smoke tests: require macOS + HVF support + integration test env vars.
- `vm.posix` smoke tests: require Linux/BSD host.
- `vm.vm` smoke test: delegates to backend (skips for same reasons).
- `vm.windows` smoke/integration: require Windows + WHP + integration env vars and test kernel/initrd.

## QA Coverage Map (By Module)

### `src/core`
- `config.zig`: parsing/validation/IO verified; allowlist emission verified.
- `state.zig`: VM lifecycle files and error mapping validated.
- `paths.zig`: name validation and vmDir invalid name validated.
- `errors.zig`: error names stable.

### `src/fs`
- `mounts.zig`: parsing, access rules, strict/non‑strict, tag lookup validated.
- `virtio_fs.zig`: FUSE happy path + multiple error conditions validated.

### `src/net`
- `dns.zig`: query creation, parse paths (valid/invalid), truncation checks validated.
- `policy.zig`: allowlist/denylist semantics, TTL and cleanup validated.

### `src/jailer`
- `acl.zig`: harden + verification on POSIX.
- `jailer.zig`: prepare flow exercised; defaults verified.
- `seccomp.zig`: allowlist builder and edge cases validated.
- `sandbox_darwin.zig` / `sandbox_windows.zig`: profile/job config tests present (logic only).

### `src/vm`
- `serial.zig`: buffer, write, mask behavior validated.
- `posix.zig` / `hvf.zig`: io mapping + guest layout bounds validated.
- `windows.zig`: io access mapping + exit reason logic validated.
- `vm.zig`: backend dispatch tested (OS‑gated).

## Remaining QA Work (Prioritized)

### High Priority
_None currently listed._

### Medium Priority
- **VM layout ordering**: validate out-of-order guest layout with configurable constants if refactored.
- **Policy: domain wildcard edge cases**
  - Ensure `*.example.com` does not match `example.com`, but matches nested subdomains.
- **State: initVm + deleteVm interplay**
  - Verify delete removes status/config files and list is clean afterward.

### Platform/Integration (Future)
- **Windows WHP integration tests**
  - Run with `M80_WHP_INTEGRATION=1` + `M80_TEST_KERNEL`/`M80_TEST_INITRD`.
- **Mac HVF integration tests**
  - PR cadence: 20-cycle reliability run.
  - Nightly cadence: 200-cycle reliability run.
  - Commands:
    - `make hvf-reliability KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz`
    - `make hvf-reliability-nightly KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz`
  - Deterministic timeout-path test:
    - `M80_TEST_HVF_FORCE_STOP_TIMEOUT=1 ... zig build test -- --test-filter "hvf: stop returns VcpuStopTimeout when forced vcpu-exit delay is enabled"`
  - CI workflow: `.github/workflows/hvf-reliability.yml` (self-hosted `macOS` + `ARM64` runner).
  - CI network profile: default locked-down/no vmnet entitlement required.
- **Linux KVM integration tests**
  - Wire real KVM exit parsing, run smoke tests on Linux CI.

## Notes / Risks

- Some tests use filesystem side effects (tmpDir). They should remain isolated but ensure no reliance on fixed paths.
- Jailer tests log resource limit setup; benign but can be noisy.
- Virtio‑FS tests rely on internal helpers (allocateNode/allocateFileHandle) to simulate kernel behavior.

## HVF Trap Triage Runbook

Strict-fail policy remains in effect for unknown arm64 sysreg traps.

Log extraction:
- `grep -c "VcpuStopTimeout" artifacts/hvf-reliability.log`
- `grep -c "unknown sysreg trap" artifacts/hvf-reliability.log`
- `awk '/unknown sysreg trap/ {print}' artifacts/hvf-reliability.log`

Intake checklist for a new signature:
1. Record decoded trap fields (`syndrome`, `ec`, `op0/op1/crn/crm/op2`, `pc`).
2. Record exact repro command (`kernel`, `initrd`/`disk`, cmdline, cycle count).
3. File a follow-up issue with the first-occurrence log line and repro.
4. Implement only targeted trap support and add a regression test.

## Suggested Next Steps

1. Expand DNS resolver integration tests beyond basic multi-record parsing.
2. Re‑run `zig build test` and update QA.md after each batch.
