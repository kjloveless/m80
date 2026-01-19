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
- HVF backend selected and stubbed for macOS (done)
- HVF vCPU + layout stubs wired (done)
- POSIX backend stubs + vCPU/layout parity (done)
- Platform-specific backend smoke tests added (done)

**Remaining**
- Implement register setup + real boot flow (entry point, cmdline, stack)
- Decode real HVF/KVM exit structs into IoExit (current mapping is stubbed)
- Verify deterministic start/stop on real WHP/HVF backends

---

## Phase 2 — Jailer
**Goal:** Hard isolation

- Restricted Windows token
- Job Objects (CPU/mem caps)
- Kill-on-exit guarantees

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
