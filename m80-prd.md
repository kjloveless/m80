# m80 — Product Requirements Document (PRD)

## 1. Overview

**m80** is a **Windows and POSIX microVM runtime** inspired by Firecracker, designed for **fast startup, strong isolation, minimal attack surface**, and **policy-driven workloads** on Windows and POSIX hosts.

m80 supports both **persistent microVMs (default)** and **ephemeral microVMs (opt-in)**, making it suitable for:
- developer tooling
- CI / build isolation
- long-running isolated services
- **ephemeral AI agent sandboxes**

m80 is **not** a general-purpose VM manager and explicitly avoids heavyweight virtualization features.

### Current Status
- Phase 1 in progress
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

### Phase 1 Remaining
- Implement register setup + real boot flow (entry point, cmdline, stack)
- Decode real HVF/KVM exit structs into IoExit (current mapping is stubbed)
- Verify deterministic start/stop on real WHP/HVF backends

---

## 2. Goals & Non-Goals

### 2.1 Goals
- Run **Linux microVMs** on Windows (WHP) and POSIX hosts (KVM on Linux, HVF on macOS)
- Provide **Firecracker-like isolation semantics** adapted to each host platform
- Be **fully implemented in Zig**
- Support **persistent VMs by default**
- Provide **opt-in ephemeral VM mode** for throwaway workloads
- Enforce **strict resource, filesystem, and network controls**
- Fast boot times (seconds → sub-second over time)
- Deterministic behavior (no GC, no hidden runtimes)

### 2.2 Non-Goals
- No Windows guests (initially)
- No GUI / desktop virtualization
- No live migration (initial versions)
- No Kubernetes compatibility out of the gate
- No kernel drivers required for MVP
- No Rust, Go, C#, or managed runtimes

---

## 3. Architecture

### 3.1 Process Model

Two-process architecture (Firecracker-inspired):

```
m80d.exe        (daemon / control plane)
  └─ spawns
     └─ m80-vmm.exe   (per-VM worker)
```

Each VM runs in its **own worker process**.

### 3.2 Language Stack
- **Zig only**
- No runtime, no GC
- Direct Win32 / WHP bindings
- Explicit memory management

---

## 4. Core Components

### 4.1 m80d (Daemon / Control Plane)
Responsibilities:
- API server
- VM lifecycle management
- Config validation
- Windows jailer logic
- Networking and policy orchestration
- Worker process supervision
- Persistent state tracking

### 4.2 m80-vmm (VMM Worker)
Responsibilities:
- WHP partition management
- Guest memory management
- vCPU threads and run loops
- Device model (virtio)
- Filesystem and network enforcement
- Zero-allocation hot paths

---

## 5. Hypervisor Backend

### 5.1 Platform
- Windows Hypervisor Platform (WHP)

### 5.2 Guest OS
- Linux only
- Boot via kernel + initrd
- Minimal init system supported

---

## 6. Device Model (Minimal by Design)

### 6.1 Required Devices (MVP)
- virtio-mmio transport
- virtio-blk (root filesystem)
- virtio-net (user-mode networking)
- serial console

### 6.2 Deferred Devices
- virtio-fs (host filesystem sharing)
- RNG device
- Additional virtio optimizations

---

## 7. Jailer / Security Model (Windows Mapping)

m80 implements a **Windows-native jailer**, functionally equivalent to Firecracker’s jailer.

### 7.1 Isolation Mechanisms
Each `m80-vmm` process is launched with:
- **Restricted access token**
- **Job Object** (kill-on-close, resource limits, no child processes)
- **Process mitigations** (DEP, ASLR, CFG where compatible)
- **ACL-restricted IPC** (named pipes preferred)
- **Filesystem allowlist or handle passing**

### 7.2 Privilege Boundary
- `m80d` may run with elevated privileges
- `m80-vmm` runs unprivileged at all times

Jailer enforcement is **mandatory** in all modes.

---

## 8. Storage & Filesystem Model

### 8.1 Persistent VMs (Default)
- Root filesystem is persistent
- VM state survives restarts
- Suitable for CI, dev, and long-running workloads

### 8.2 Ephemeral VMs (Opt-in)
Enabled explicitly via configuration.

Behavior when enabled:
- Read-only base image
- Writable scratch overlay
- Overlay is destroyed on stop, crash, or TTL expiry
- Optional handoff directory for result extraction
- VM is deleted automatically on exit

Example:
```json
"ephemeral": {
  "enabled": true,
  "ttl_seconds": 900
}
```

---

## 9. Filesystem Sharing

### 9.1 Supported Mechanism
- **virtio-fs** (planned)
- Linux guests only

### 9.2 Policy Controls
Per-share:
- read-only or read-write
- single-root export
- strict path normalization
- symlink escape prevention

---

## 10. Networking & Egress Control

### 10.1 Default Posture
- **Deny by default**

### 10.2 Enforcement Location
- Inside `m80-vmm` virtio-net backend (user-mode)

### 10.3 Domain Whitelisting
- Guest forced to use m80-controlled DNS
- Allowlist of domains (exact or wildcard)
- TTL-based IP allow cache
- Direct IP egress blocked

### 10.4 Optional Strict Mode
- TLS SNI inspection (HTTPS)
- `Host:` header inspection (HTTP)

Network presets:
- `locked_down`
- `allowlist`
- `open`

---

## 11. API Design

### 11.1 Style
- Minimal, Firecracker-inspired
- JSON over HTTP (localhost or named pipe)

### 11.2 Core Endpoints
- `PUT /vms/{id}` — define VM
- `POST /vms/{id}/start`
- `POST /vms/{id}/stop`
- `DELETE /vms/{id}`
- `GET /vms`
- `GET /vms/{id}`

---

## 12. Resource Management

Per-VM:
- vCPU count
- memory size
- job object enforcement
- kill-on-daemon-exit guarantee

---

## 13. Milestones

- **M0**: Skeleton + IPC
- **M1**: Boot-only (kernel + initrd)
- **M2**: virtio-blk
- **M3**: virtio-net
- **M4**: Jailer hardening
- **M5**: Policy enforcement
- **M6**: Ephemeral VM support

---

## 14. Guiding Principles
- Persistence by default, ephemerality by choice
- Minimalism over features
- Explicit > implicit
- Security boundaries are mandatory
- Windows-native primitives first
- No hidden runtimes
