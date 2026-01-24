# PRD: m80 Firecracker Parity

Date: 2026-01-24
Owner: TBD
Status: Draft

## 1. Problem Statement
m80 provides a lightweight microVM runtime, but it lacks several core Firecracker capabilities (API control plane, networking, vsock, metadata service, block hotplug, snapshot/restore, KVM parity, and richer jailer isolation). This gap limits compatibility, automation, and production viability for workloads that expect Firecracker-grade behavior.

## 2. Goals
- Achieve functional parity with Firecracker on core microVM features and operational workflows.
- Preserve m80's cross-platform design while ensuring a first-class Linux/KVM path.
- Provide a stable, scriptable control plane (API) with metrics/logging.
- Maintain secure defaults and isolation consistent with Firecracker's jailer model.

## 3. Non-Goals
- Implement Firecracker's exact internals or performance characteristics.
- Support every Firecracker ancillary tool (e.g., firectl) beyond compatibility.
- Implement full device hotplug across all platforms in the first release.

## 4. Current State (m80)
- Control plane: CLI only (`start/run/console/stop/delete/inspect`).
- Devices: virtio-blk (up to 3), virtio-console, virtio-rng, virtio-fs.
- Networking: virtio-net device model exists, backend currently disabled.
- Backends: HVF (macOS), WHP (Windows), Linux KVM is stub.
- Jailer: chroot + directory hardening + Linux seccomp, macOS sandbox, Windows job object.
- Config: static config file (m80.conf); no API-controlled lifecycle.

## 5. Target Parity Scope (Firecracker Features)
Core parity items to implement:
1) Control plane API
   - REST/HTTP or Unix-socket API for lifecycle + device configuration
   - API equivalent of Firecracker endpoints (create, start, stop, configure)

2) Networking
   - virtio-net backend (tap/vhost-net or platform equivalent)
   - packet rate limiting
   - optional allowlist integration

3) vsock
   - virtio-vsock device model and host<->guest communication

4) MMDS/Metadata
   - metadata service with configurable transport (vsock or HTTP)

5) Block device management
   - rescan / resize
   - backing file switch

6) Snapshot/Restore
   - VM state snapshot
   - restore from snapshot

7) Linux isolation parity
   - cgroups + namespaces (pid/net/mount/etc) on Linux
   - seccomp filters aligned to device/model set

8) KVM backend
   - functional Linux KVM VMM path

9) Observability
   - metrics endpoint (prometheus-style or JSON)
   - structured logs

## 6. Requirements

### Functional Requirements
- API:
  - Create/load VM definition, attach devices, set boot source.
  - Start/stop/pause/resume where supported.
  - Expose metrics and logs configuration.

- Devices:
  - virtio-net functional backend.
  - virtio-vsock for host<->guest comms.
  - Block rescan & backing file switch.
  - MMDS available to guest.

- Snapshots:
  - Save VM state to disk.
  - Restore VM state consistently across supported platforms.

- Security:
  - Linux jailer uses cgroups + namespaces.
  - Preserve existing seccomp; adjust allowlist for new devices.

### Non-Functional Requirements
- Performance: no >10% regression in boot time vs current m80 baseline.
- Reliability: API surface versioned; backwards compatible within minor versions.
- Cross-platform: features may be gated per backend; Linux/KVM is the parity baseline.

## 7. Milestones

### Phase 1: Control Plane + Networking (MVP Parity)
- Add API server (Unix socket or TCP loopback)
- Create VM lifecycle endpoints
- virtio-net backend with rate limiting
- Metrics/log configuration

### Phase 2: Device Parity
- virtio-vsock
- MMDS
- Block rescan and backing file switch

### Phase 3: Snapshots + KVM
- Snapshot/restore
- Linux KVM backend

### Phase 4: Jailer Parity
- cgroups/namespaces integration
- Hardened seccomp filters

## 8. Risks
- Cross-platform feature mismatch (HVF/WHP limitations)
- Snapshot/restore complexity with device models
- Security surface expansion with new API + network features

## 9. Success Metrics
- API covers ≥80% of Firecracker public endpoints.
- Guest boot + console login succeeds via API-driven flows.
- Networking throughput within 20% of Firecracker baseline on Linux/KVM.
- Snapshot/restore validated on Linux with deterministic restore state.

## 10. Open Questions
- Should API be REST-compatible with Firecracker or only semantically aligned?
- Which backend (tap/vhost-user) to prioritize for virtio-net?
- Snapshot format compatibility with Firecracker or m80-specific?
- Do we prioritize Linux parity first or macOS HVF parity?

