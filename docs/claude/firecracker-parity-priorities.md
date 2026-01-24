# m80 Firecracker Parity - Prioritized Work Items

This document lists work items needed to reach feature parity with Firecracker, ordered by priority.

---

## P0 - Critical (Boot Performance)

These items directly impact boot time and are required to beat Firecracker's ~125ms target.

### 1. Memory-Mapped Kernel Loading

**Current:** Streams kernel file in 64KB chunks via `read()`, copies to guest memory.

**Target:** Use `mmap()` for zero-copy loading.

**Impact:** ~50-150ms savings for typical kernels.

**Files:**
- `src/vm/hvf.zig` - `loadGuestKernel()`, `copyFileToGuest()`

**Implementation:**
```zig
fn loadKernelMapped(path: []const u8) ![]align(4096) u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    const stat = try file.stat();
    return std.posix.mmap(null, stat.size, PROT_READ, MAP_PRIVATE, file.handle, 0);
}
```

---

### 2. Lazy Memory Allocation (Demand Paging)

**Current:** Pre-allocates all guest memory at boot (`page_allocator.alloc()`).

**Target:** Map pages on first access using `MAP_NORESERVE` or equivalent.

**Impact:** ~50-100ms savings, reduced memory footprint.

**Files:**
- `src/vm/hvf.zig` - `start()` memory allocation section

**Implementation:**
- Use `mmap()` with `MAP_ANONYMOUS | MAP_NORESERVE`
- Let HVF fault in pages on demand
- Or use HVF's lazy mapping if available

---

### 3. Parallel Kernel/Initrd Loading

**Current:** Sequential loading - kernel first, then initrd.

**Target:** Load both concurrently using threads.

**Impact:** ~20-50ms savings (depends on I/O).

**Files:**
- `src/vm/hvf.zig` - `start()`

**Implementation:**
```zig
const kernel_thread = try std.Thread.spawn(.{}, loadGuestKernel, .{...});
const initrd_thread = try std.Thread.spawn(.{}, loadGuestInitrd, .{...});
kernel_thread.join();
initrd_thread.join();
```

---

### 4. Skip Unused Device Initialization

**Current:** All VirtIO devices initialized at boot.

**Target:** Only initialize configured devices.

**Impact:** ~5-10ms savings.

**Files:**
- `src/vm/hvf.zig` - device setup section
- `src/vm/virtio.zig`

**Implementation:**
- Skip `setupVirtioNet()` if `network_mode=locked_down` and no network config
- Skip `setupVirtioFs()` if no mounts configured
- Skip secondary block devices if not used

---

## P1 - High (Core Functionality)

These items are required for production use.

### 5. Snapshot/Restore

**Current:** Format defined in `src/vm/snapshot.zig`, CLI commands stubbed.

**Target:** Full working snapshot save/restore.

**Impact:** Enables fast cloning, migration, hibernation.

**Files:**
- `src/vm/snapshot.zig` - core implementation
- `src/vm/hvf.zig` - vCPU state save/restore
- `src/main.zig` - CLI commands

**Remaining Work:**
- Implement `saveVcpuState()` using HVF APIs
- Implement `restoreVcpuState()`
- Wire snapshot commands to actual save/load
- Test with real VMs

---

### 6. VirtIO Block I/O Completion

**Current:** Queue processing implemented, needs validation.

**Target:** Verified working disk I/O with real workloads.

**Impact:** Required for any persistent VM.

**Files:**
- `src/vm/virtio.zig` - `processVirtioBlkQueue()`, `processVirtioBlkRequest()`

**Validation Needed:**
- Boot from disk image
- Read/write files in guest
- Verify data integrity
- Test with multiple disks

---

### 7. Console Reliability

**Current:** PL011 UART and virtio-console implemented.

**Target:** Reliable interactive console with proper TTY handling.

**Impact:** Required for debugging and interactive use.

**Files:**
- `src/vm/hvf.zig` - serial handling
- `src/vm/serial.zig`
- `src/main.zig` - console command

**Issues to Address:**
- Raw TTY mode handling
- Signal forwarding (Ctrl+C, etc.)
- Console detach/reattach

---

## P2 - Medium (Security & Stability)

### 8. Seccomp Filter Enforcement (Linux)

**Current:** Filter defined in `src/jailer/seccomp.zig`, not enforced.

**Target:** Active syscall filtering on Linux.

**Impact:** Defense in depth for guest escape.

**Files:**
- `src/jailer/seccomp.zig`
- `src/jailer/jailer.zig` - wire into `prepare()`

---

### 9. macOS Sandbox Enforcement

**Current:** Profile built in `src/jailer/sandbox_darwin.zig`, not applied.

**Target:** Active sandbox via `sandbox_init()`.

**Impact:** Defense in depth on macOS.

**Files:**
- `src/jailer/sandbox_darwin.zig` - `apply()` function

---

### 10. Resource Limit Verification

**Current:** `setrlimit()` called but not verified.

**Target:** Verify limits are actually applied, handle errors.

**Impact:** Prevents resource exhaustion attacks.

**Files:**
- `src/jailer/jailer.zig` - `setResourceLimits()`

---

### 11. Integration Tests

**Current:** 291 unit tests, few integration tests.

**Target:** End-to-end boot tests, I/O tests.

**Impact:** Confidence in real-world behavior.

**Files:**
- `src/vm/hvf.zig` - existing smoke tests
- New test files needed

**Tests Needed:**
- Boot to userspace with real kernel
- Disk read/write verification
- Network connectivity (when enabled)
- Console I/O round-trip

---

## P3 - Low (Nice to Have)

### 12. REST API

**Current:** CLI only.

**Target:** HTTP API for programmatic control.

**Impact:** Enables orchestration, remote management.

**Files:**
- New `src/api/` module

---

### 13. Metrics/Observability

**Current:** Logging only.

**Target:** Prometheus-format metrics endpoint.

**Impact:** Production monitoring.

**Files:**
- New `src/metrics.zig`

---

### 14. Rate Limiting

**Current:** Not implemented.

**Target:** Network and disk I/O rate limiting.

**Impact:** QoS, noisy neighbor prevention.

**Files:**
- `src/vm/virtio.zig` - throttling in I/O paths

---

### 15. Balloon Device

**Current:** Not implemented.

**Target:** VirtIO balloon for memory reclaim.

**Impact:** Dynamic memory management.

**Files:**
- New device in `src/vm/virtio.zig`

---

### 16. vsock Support

**Current:** Not implemented (using VirtIO-FS instead).

**Target:** VirtIO vsock for host-guest communication.

**Impact:** Alternative to VirtIO-FS for some use cases.

**Files:**
- New device in `src/vm/virtio.zig`

---

## Performance Targets

| Metric | Firecracker | m80 Current | m80 Target |
|--------|-------------|-------------|------------|
| Cold boot | 125ms | ~300-500ms | <100ms |
| Memory overhead | <5 MiB | ~10-20 MiB | <3 MiB |
| Snapshot save | N/A | N/A | <50ms/GB |
| Snapshot restore | N/A | N/A | <25ms/GB |
| Binary size | ~3 MB | ~500 KB | <1 MB |

---

## Implementation Order

### Week 1-2: Boot Performance
1. Memory-mapped kernel loading (P0.1)
2. Lazy memory allocation (P0.2)
3. Parallel loading (P0.3)
4. Skip unused devices (P0.4)
5. Measure and validate <100ms boot

### Week 3-4: Core Functionality
6. Snapshot/restore implementation (P1.5)
7. VirtIO block validation (P1.6)
8. Console reliability (P1.7)

### Week 5-6: Security
8. Seccomp enforcement (P2.8)
9. macOS sandbox enforcement (P2.9)
10. Resource limit verification (P2.10)

### Week 7+: Polish
11. Integration tests (P2.11)
12. Documentation
13. P3 items as time permits

---

## Quick Wins (Can Do Now)

These require minimal code changes:

1. **Skip virtio-net if locked_down** - 5 lines in hvf.zig
2. **Skip virtio-fs if no mounts** - Already partially done
3. **Add boot timing to logs** - Already implemented
4. **Verify snapshot format** - Write test that round-trips

---

## Blocked Items

These require external factors:

1. **In-kernel GIC** - Requires KVM (Linux only), not applicable to HVF
2. **Huge pages** - macOS HVF doesn't expose this
3. **vGIC acceleration** - HVF limitation

---

## Test Coverage Priorities

Based on earlier analysis, these modules need more tests:

| Module | Current | Target | Priority |
|--------|---------|--------|----------|
| `virtio.zig` | 37 | 60+ | P1 |
| `jailer.zig` | 18 | 30+ | P1 |
| `sandbox_darwin.zig` | 16 | 25+ | P2 |
| `main.zig` | 2 | 20+ | P2 |
| `hvf.zig` | 25 | 40+ | P2 |
| `posix.zig` | 13 | 25+ | P3 |
| `windows.zig` | 8 | 20+ | P3 |

---

## Summary

**Critical Path to Firecracker Parity:**

```
P0.1 mmap kernel ──┐
P0.2 lazy memory ──┼── Boot <100ms
P0.3 parallel load ┘
         │
         v
P1.5 snapshots ────── Fast cloning
         │
         v
P1.6 block I/O ────── Persistent VMs
         │
         v
P2.8-10 security ──── Production ready
```

**Estimated Total Effort:** 4-6 weeks for core parity, ongoing for full feature set.
