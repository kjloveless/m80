# m80 Next 2 Weeks Plan

Timebox: 2026-02-13 to 2026-02-27

Goal: close the highest-risk gaps between current backend/device scaffolding and reliable, testable VM lifecycle behavior on real hosts.

Maintainability tracking: `docs/MAINTAINABILITY-PLAN.md`

## Week 1 (2026-02-13 to 2026-02-20)

- [ ] KVM lifecycle determinism on Linux
  - [ ] Validate real start/stop/restart loops with kernel+initrd payloads (no stub path).
  - [ ] Add/expand Linux-gated integration coverage for boot-to-serial signal.
  - [ ] Ensure failure mapping is deterministic (`InvalidArgs`, `FileNotFound`, `SystemError`, `AlreadyRunning`).
  - [ ] Exit criteria: 20 consecutive start/stop cycles on Linux without leaked resources.

- [ ] WHP/HVF lifecycle parity validation
  - [ ] Re-run platform smoke tests with real payloads and capture known-good logs.
  - [ ] Confirm same user-facing lifecycle behavior across Windows/macOS/Linux.
  - [ ] Exit criteria: platform smoke checklist passes with documented env vars.

- [ ] Snapshot baseline completion (non-compressed path)
  - [ ] Wire CLI snapshot save/restore flow to backend paths where supported.
  - [ ] Add an end-to-end snapshot round-trip test for one backend path.
  - [ ] Exit criteria: save + restore resumes guest state in test harness.

## Week 2 (2026-02-20 to 2026-02-27)

- [ ] Network policy enforcement through virtio-net path
  - [x] Enforce `locked_down` as default deny in device/backend data path.
  - [x] Enforce allowlist mode for DNS + IP policy with explicit test cases.
  - [x] Exit criteria: integration tests prove non-whitelisted destinations fail hard.

- [ ] Jailer enforcement hardening pass
  - [x] Ensure Linux seccomp policy is applied in runtime prepare path (not only generated).
  - [x] Ensure macOS sandbox profile is applied in runtime path (not only generated).
  - [x] Add verification checks for resource limit application.
  - [x] Exit criteria: jailer enforcement paths are exercised in platform-gated tests.

- [ ] Docs + QA sync with live state
  - [ ] Update phase docs to reflect implemented vs validated status.
  - [ ] Replace stale fixed test-count claims with dated snapshots or command-based checks.
  - [ ] Exit criteria: README + docs reference the same active priorities and dates.

## Explicitly Out of Scope (This Timebox)

- REST API/control plane redesign
- vsock/MMDS feature work
- full snapshot compression/lazy fault handler implementation
- performance tuning targets (<100ms boot) beyond correctness/stability blockers

## Completion Gate

- [ ] `zig build` passes
- [ ] `zig build test` passes on primary dev host
- [ ] Platform-gated integration tests documented with exact env vars and expected skips
