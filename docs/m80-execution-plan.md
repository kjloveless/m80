# m80 Execution Plan

## Guiding Rules
- Every phase must ship something runnable
- Hard boundaries per phase
- Windows and POSIX hosts are first-class, Zig-first
- Persistent-by-default, ephemeral opt-in
- Control plane before cleverness

---

## Phase 0 — Repo, Contracts, Guardrails
**Goal:** Prevent chaos before code exists

**Deliverables**
- Repo structure
- Core interfaces
- Non-goals list

---

## Phase 1 — Minimal VM Bring-Up (Windows + POSIX)
**Goal:** Boot a VM reliably

- WHPX / Hyper-V backend
- POSIX hypervisor/backend selected and stubbed (e.g., HVF on macOS, KVM on Linux)
- Start / stop lifecycle
- No networking, no mounts

**Status**
- WHP partition lifecycle stubbed with dynamic loading and error mapping (done)
- WHP guest memory allocation + GPA mapping stubbed (done)
- WHP vCPU create/delete + run loop skeleton added (done)
- Kernel/initrd layout + load stubs wired (done)
- Windows kernel/initrd file loading into guest memory wired (done)
- WHP vCPU run loop with exit handling (CPUID + IO port) wired (done)
- Serial IO (COM1) read/write handling + shared IoExit scaffolding across backends (done)
- HVF backend selected and wired for macOS (done)
- HVF vCPU + layout bring-up wired (done)
- HVF arm64 register setup + DTB builder + MMU preconfig + guest memory mapping (done)
- POSIX backend KVM path + vCPU/layout parity wired (partial)
- Platform-specific backend smoke tests added (done)
- HVF/KVM IO exit decoding into IoExit (done)
- Boot state computation + cmdline/stack prep + Windows register init wired (partial)

**Remaining**
- Validate guest RAM mapping + vCPU create/run loops on real HVF/KVM hosts
- Finalize kernel/initrd loading and boot-handoff parity for HVF/KVM (Windows wired)
- Verify deterministic start/stop on real WHP/HVF backends

**Notes**
- Phase 1 has substantial implementation, but deterministic cross-platform validation is still pending.

## Testing Notes (2026-01-19)
- `zig build test`: 198 passed, 6 skipped, 0 failed (re-verified).
- Skips are OS/integration gated (HVF/POSIX/WHP integration).

---

## Phase 2 — Jailer
**Goal:** Hard isolation

- Restricted Windows token
- Job Objects (CPU/mem caps)
- Kill-on-exit guarantees

**Notes**
- Several jailer components are implemented, but end‑to‑end hardening is not complete.

---

## Phase 3 — Persistent Storage (Default)
**Goal:** Real, stateful VMs

- Persistent disk images
- Explicit create/start/stop lifecycle

---

## Phase 4 — Ephemeral Mode
**Goal:** Safe AI agent containment

- Temp disks
- Auto-destroy on exit
- Zero persistence

---

## Phase 5 — Filesystem Sharing
**Goal:** Controlled host interaction

- Explicit mounts
- Read-only first
- Path allowlisting

---

## Phase 6 — Network Whitelisting
**Goal:** No open internet by default

- DNS-based allowlists
- Firewall enforcement
- Explicit opt-in networking

---

## Phase 7 — Polishing & Contracts
**Goal:** Usability and stability

- Config files
- Better errors
- Logging & docs
