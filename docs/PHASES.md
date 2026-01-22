# m80 Project Phases

This document tracks the execution phases for m80.
Each phase is intentionally small, shippable, and bounded to avoid scope creep.

Principles:
- One phase at a time
- Every phase must compile and run
- Windows and POSIX hosts are first-class targets
- Persistent VMs by default
- Ephemeral VMs are opt-in
- Isolation and safety are non-negotiable

---

## Phase 0 — Repo, Contracts, Guardrails
**Goal:** Prevent chaos before code exists

### Focus
- Repo structure
- Component boundaries
- Explicit non-goals

### Deliverables
- Initial repository layout
- Compiling CLI scaffold
- Defined interfaces (stubbed)

### Exit Criteria
- Repo builds successfully
- CLI prints help output
- Core interfaces compile

---

## Phase 1 — Minimal VM Bring-Up (Windows + POSIX)
**Goal:** Boot a minimal isolated VM

### Focus
- Single VM
- Manual lifecycle
- No networking
- No filesystem sharing

### Deliverables
- VM backend using Windows Hypervisor APIs
- POSIX hypervisor/backend chosen and stubbed (e.g., HVF on macOS, KVM on Linux)
- Fixed CPU and memory configuration

### Status
- WHP partition lifecycle stubbed with dynamic loading and error mapping (done)
- WHP guest memory allocation + GPA mapping stubbed (done)
- WHP vCPU create/delete + run loop skeleton added (done)
- Kernel/initrd layout + load stubs wired (done)
- Windows kernel/initrd file loading into guest memory wired (done)
- WHP vCPU run loop with exit handling (CPUID + IO port) wired (done)
- Serial IO (COM1) read/write handling + shared IoExit scaffolding across backends (done)
- HVF backend wired with real VM create/map + vCPU run loop (arm64 + x86) (done)
- HVF arm64 register setup + DTB builder + MMU preconfig + guest memory mapping (done)
- HVF arm64 PL011 MMIO + GIC SPI wiring for serial (done)
- POSIX backend stubs + vCPU/layout parity (done)
- Platform-specific backend smoke tests added (done)
- HVF/KVM IO exit decoding into IoExit (done)
- Boot state computation + cmdline/stack prep + Windows register init wired (partial)
- HVF arm64 boot-to-serial test gated by env vars (done)

### Exit Criteria
- VM boots reliably on Windows and POSIX
- Start/stop works deterministically across platforms
- No background services required

### Notes
- Current backends are still stubbed; Phase 1 “done” items reflect scaffolding, not full boot.

### Testing Notes (2026-01-19)
- `zig build test`: 200 passed, 8 skipped, 0 failed (re-verified).
- Skips are OS/integration gated (HVF/POSIX/WHP integration).

### Remaining (Phase 1)
- Wire real guest RAM mapping + vCPU create/run loop for KVM (beyond stubs)
- Finalize kernel/initrd loading into KVM guest memory
- Verify deterministic start/stop on real WHP/HVF backends with real boot payloads

---

## Phase 2 — Jailer (Hard Isolation Boundary)
**Goal:** Ensure m80 and VMs cannot escape containment

### Focus
- Process isolation
- Resource limits
- Host protection

### Deliverables
- Restricted Windows security token per VM
- Job Object enforcement (CPU, memory, lifecycle)

### Status
- Path validation (`src/util/path.zig`) with traversal detection, symlink escape prevention (done)
- Safe deletion requiring paths at least 2 levels deep from data root (done)
- `deleteVm()` updated to use safe path validation (done)
- ACL hardening (`src/jailer/acl.zig`) - chmod 0700 dirs, 0600 files on POSIX (done)
- Privilege dropping (`src/jailer/jailer.zig`) - setgroups, setgid, setuid in correct order (done)
- Privilege verification - confirms setuid(0) fails after dropping (done)
- Resource limits via setrlimit (RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU) (done)
- Linux seccomp-bpf (`src/jailer/seccomp.zig`) - syscall allowlist for VMM (done)
- macOS Sandbox.framework (`src/jailer/sandbox_darwin.zig`) - SBPL profile generation (done)
- Windows Job Objects (`src/jailer/sandbox_windows.zig`) - process sandboxing (done)

### Exit Criteria
- Killing m80 kills the VM
- VM cannot access unauthorized host resources
- Escape attempts fail

### Notes
- Some jailer pieces are implemented, but platform hardening remains incomplete.

---

## Phase 3 — Persistent Storage (Default Mode)
**Goal:** Make VMs durable and stateful

### Focus
- Persistent disk images
- Explicit lifecycle management
- No snapshots yet

### Deliverables
- Disk image management
- Deterministic VM storage locations

### Exit Criteria
- Data persists across reboots
- Multiple VMs coexist safely

---

## Phase 4 — Ephemeral Mode (Agent Mode)
**Goal:** Enable safe, disposable execution environments

### Focus
- Opt-in ephemeral VMs
- Automatic cleanup
- Zero persistence

### Deliverables
- Temporary disk creation
- Cleanup hooks tied to VM lifecycle

### Exit Criteria
- Disk destroyed on exit
- No leftover state
- Runs are repeatable and identical

---

## Phase 5 — Filesystem Sharing (Constrained)
**Goal:** Allow explicit, safe host interaction

### Focus
- Explicit mounts only
- Read-only by default
- No auto-discovery

### Deliverables
- Host path validation
- Mount enforcement (RO vs RW)

### Status
- Mount configuration (`src/fs/mounts.zig`) with MountConfig struct (tag, host_path, guest_path, access) (done)
- MountManager with allowed roots validation (done)
- Path traversal prevention on all mount operations (done)
- VirtIO-FS device model (`src/fs/virtio_fs.zig`) with virtqueue handling (done)
- FUSE protocol implementation (LOOKUP, GETATTR, OPEN, READ, WRITE, RELEASE, OPENDIR, READDIR) (done)
- Read-only vs read-write access enforcement at FUSE level (done)

### Exit Criteria
- VM only sees mapped paths
- Read-only mounts cannot be written
- Host filesystem remains protected

### Notes
- VirtIO-FS implementation is currently a stub and not production-safe.

---

## Phase 6 — Network Whitelisting
**Goal:** No open network access by default

### Focus
- Default deny
- Domain allowlist
- DNS-level enforcement first

### Deliverables
- Custom DNS resolver
- VM-bound firewall rules

### Status
- Network policy (`src/net/policy.zig`) with NetworkMode enum (locked_down, allowlist, open) (done)
- NetworkPolicy struct with domain rules, IP rules (CIDR), DNS servers (done)
- Domain wildcard matching (`*.example.com` matches subdomains) (done)
- Pure Zig DNS resolver (`src/net/dns.zig`) - no libc dependency (done)
- DNS query building and response parsing (done)
- Domain allowlist enforcement at DNS resolution time (done)
- Config integration (`src/core/config.zig`) - network_mode, allowed_domains, allowed_ips (done)
- Open network mode requires double opt-in (config flag + M80_ALLOW_OPEN_NETWORK env var) (done)

### Exit Criteria
- Only whitelisted domains resolve
- Non-whitelisted traffic fails hard
- No silent fallbacks

### Notes
- DNS allowlist is implemented, but enforcement still needs full virtio-net integration.

---

## Phase 7 — Polish & Stability
**Goal:** Make m80 usable without tribal knowledge

### Focus
- Configuration files
- Logging
- Debuggability

### Deliverables
- `m80.yaml` support
- Example configs
- Clear documentation

### Exit Criteria
- Reasonable defaults
- Actionable error messages
- Debug mode available

---

## Explicit Non-Goals (For Now)
- OCI / Docker compatibility
- Orchestration or clustering
- Live migration
- Snapshots before lifecycle stability
- Cross-platform support

---
