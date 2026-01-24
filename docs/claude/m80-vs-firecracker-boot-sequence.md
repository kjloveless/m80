# m80 vs Firecracker Boot Sequence Comparison

This document compares m80's VM boot sequence with Firecracker's approach, analyzing architectural differences, performance implications, and areas for optimization.

## Architecture Overview

| Aspect | m80 | Firecracker |
|--------|-----|-------------|
| Language | Zig | Rust |
| Primary Backend | HVF (macOS) | KVM (Linux) |
| API Model | Direct CLI | REST API + CLI |
| Process Model | Single process | Daemon (microvm process) |

---

## 1. VM Creation

### Firecracker

```
1. API receives PUT /machine-config
2. Creates KVM VM via ioctl(KVM_CREATE_VM)
3. Memory configured via ioctl(KVM_SET_USER_MEMORY_REGION)
4. Uses hugetlbfs for large page support (optional)
5. Lazy memory population with demand paging
```

### m80

```
1. CLI parses "m80 start <name>"
2. Creates HVF VM via hv_vm_create()
3. Allocates host memory via page_allocator.alloc()
4. Maps to guest via hv_vm_map_space()
5. Immediate full memory allocation (no demand paging)
```

**Key Difference:** Firecracker uses demand paging - pages are allocated as accessed. m80 pre-allocates all memory upfront, which is simpler but uses more memory immediately.

---

## 2. Kernel Loading

### Firecracker

```
1. Validates ELF/bzImage header
2. Uses memory-mapped file I/O (mmap)
3. Loads kernel segments directly from mmap'd region
4. Zero-copy where possible (kernel pages shared until COW)
5. Supports both raw Image and bzImage formats
```

### m80

```
1. Reads kernel header (256 bytes)
2. Detects ARM64 Image or gzip
3. Streams file in 64KB chunks via read()
4. If gzip: decompresses via std.compress.flate
5. Copies to guest memory buffer
```

**Key Difference:** Firecracker uses mmap for zero-copy loading; m80 streams and copies. This is a significant performance difference for large kernels.

---

## 3. Boot Protocol

### Firecracker (x86)

```
1. Uses Linux boot protocol (bzImage format)
2. Builds boot_params struct at 0x7000
3. Sets up E820 memory map
4. Configures real-mode entry (16-bit) or protected mode
5. Kernel at 0x100000 (1MB)
6. Command line at 0x20000
```

### Firecracker (ARM64)

```
1. Raw Image format (no decompression)
2. Device Tree Blob passed in x0
3. Kernel at 0x80000 offset
4. FDT generated dynamically
```

### m80 (ARM64 - primary)

```
1. Raw Image format (supports gzip)
2. Device Tree Blob passed in x0
3. Kernel at 0x40080000 (different base)
4. Custom memory layout:
   - Memory base: 0x40000000
   - Kernel: base + 0x80000
   - Initrd: base + 0x4000000
   - DTB: base + 0x21000
```

### m80 (x86)

```
1. Similar to Firecracker but less mature
2. Uses 0x100000 kernel base
3. Boot params at computed address
```

**Key Difference:** Memory layout addresses differ. Firecracker uses 0x80000000 base on ARM64 typically; m80 uses 0x40000000.

---

## 4. Device Initialization

### Firecracker

```
1. Serial console (COM1: 0x3F8)
2. VirtIO MMIO devices (legacy transport):
   - virtio-block at 0xd0000000+
   - virtio-net
   - virtio-vsock
   - virtio-balloon
3. i8042 keyboard controller (for reboot)
4. RTC (for time)
5. Devices initialized on API call, not at boot
```

### m80

```
1. PL011 UART (ARM64) or COM1 (x86)
2. VirtIO MMIO devices:
   - virtio-blk at 0x0a000000, 0x0a002000, 0x0a004000
   - virtio-console at 0x0a001000
   - virtio-rng at 0x0a003000
   - virtio-net at 0x0a004000
   - virtio-fs at 0x0a005000
3. All devices initialized at boot time
```

**Key Difference:** Firecracker supports runtime device hotplug via API; m80 initializes everything at boot. Firecracker has vsock/balloon; m80 has virtio-fs.

---

## 5. vCPU Initialization

### Firecracker

```
1. KVM_CREATE_VCPU ioctl
2. KVM_SET_REGS for general registers
3. KVM_SET_SREGS for segment/control registers
4. KVM_SET_CPUID2 for CPUID emulation (x86)
5. KVM_SET_MSRS for model-specific registers
6. Uses KVM_RUN in a loop
7. MMIO/IO exit handled in userspace
```

### m80

```
1. hv_vcpu_create()
2. hv_vcpu_set_reg() for GP registers
3. hv_vcpu_set_sys_reg() for system registers
4. No CPUID passthrough needed (HVF handles it)
5. Uses hv_vcpu_run() in a loop
6. Exit handling via HvfArmVcpuExit struct
```

**Key Difference:** API differs (KVM ioctls vs HVF C API), but the conceptual flow is similar. HVF has less configuration surface.

---

## 6. Interrupt Controller

### Firecracker

**ARM64:**
- GICv2 emulation in kernel (vGIC)
- KVM_CREATE_DEVICE for vGIC
- IRQ routing via KVM_SET_GSI_ROUTING

**x86:**
- Split IOAPIC (kernel) + local APIC (KVM)
- Legacy PIC emulation
- MSI support for virtio-pci

### m80

**ARM64:**
- GICv3 emulation in userspace
- Distributor at 0x08000000
- Redistributor at 0x080a0000
- SPI interrupts 32+ for devices
- hv_gic_set_spi() for injection

**x86:**
- Basic PIC emulation (less complete)

**Key Difference:** Firecracker uses kernel vGIC (faster); m80 emulates GIC in userspace. This is a performance tradeoff.

---

## 7. Boot Timing Comparison

### Firecracker (typical)

```
Cold boot: ~125ms
- VM creation: ~5ms
- Memory setup: ~10ms (demand paged)
- Kernel load: ~15ms (mmap'd)
- Device setup: ~10ms
- vCPU to first instruction: ~5ms
- Linux userspace: ~80ms
```

### m80 (current, estimated)

```
Cold boot: Not yet optimized
- VM creation: ~1ms (HVF is fast)
- Memory setup: ~50-100ms (full allocation)
- Kernel load: ~50-200ms (streaming copy)
- Device setup: ~5ms
- vCPU to first instruction: ~10ms
```

**Key Difference:** Firecracker is heavily optimized for boot time. m80 hasn't implemented the performance optimizations yet.

---

## 8. Key Architectural Differences

| Feature | Firecracker | m80 |
|---------|-------------|-----|
| Memory model | Demand paging | Pre-allocation |
| Kernel loading | mmap zero-copy | Stream copy |
| GIC emulation | In-kernel vGIC | Userspace |
| API model | REST + socket | CLI only |
| Snapshot | Full support | In progress |
| Rate limiting | Built-in | Not yet |
| Metrics | Prometheus format | Logging only |
| Jailer | Separate binary | Integrated |
| seccomp | Strict allowlist | In progress |

---

## 9. What m80 Needs for Parity

Based on the Firecracker parity plan:

1. **Memory-mapped kernel loading** - Use mmap instead of read() for zero-copy
2. **Demand paging** - Map pages on first access instead of pre-allocating
3. **In-kernel GIC** - Would require KVM on Linux; HVF limitation on macOS
4. **Parallel loading** - Load kernel and initrd concurrently
5. **Snapshot/restore** - Already in progress
6. **Boot timing instrumentation** - Implemented

---

## 10. m80's Advantages

1. **Cross-platform** - Works on macOS (Firecracker is Linux-only)
2. **Simpler codebase** - Zig vs Rust, ~3K lines vs ~50K lines
3. **VirtIO-FS** - Native filesystem sharing (Firecracker uses vsock workarounds)
4. **Integrated jailer** - No separate binary needed
5. **Smaller binary** - Zig produces smaller executables
6. **No runtime** - No Rust async runtime overhead

---

## m80 Boot Sequence Detail

### High-Level Entry Point (main.zig)

The boot sequence begins when a user runs `m80 start <name>`:

1. CLI parses `start` command and VM name
2. Calls `startVmCommand()` which:
   - Initializes `Jailer` for security sandboxing
   - Loads VM configuration from `m80.conf`
   - Validates configuration
   - Calls `Vm.start(cfg)` - the main dispatcher

### Platform Dispatcher (vm.zig)

The `Vm.start()` function dispatches to platform-specific backends:
- **Windows** -> `windows.zig` (WHP backend)
- **macOS** -> `hvf.zig` (HVF backend)
- **Linux/BSD** -> `posix.zig` (KVM backend)

### HVF Backend Boot Sequence (hvf.zig::start)

#### Phase 1: VM Partition Creation

```
start() begins
|- boot_timing.start_us = bootTimestamp()
|- Hvf.createVm()
|  +- Calls arm64_vm_bindings.create() or x86_vm_bindings.create()
|     (HVF C API: creates VM partition)
|- Hvf.setupVm() with CPU cores and memory_mb
|- active_vm = handle
+- boot_timing.vm_create_us = bootTimestamp()
```

#### Phase 2: Guest Memory Setup

```
|- Convert memory_mb to bytes: size_bytes_u64 = cfg.memory_mb * 1MB
|- Allocate host-backed guest memory buffer
|  +- std.heap.page_allocator.alloc(u8, size_bytes)
|- Zero-initialize memory: @memset(guest_memory, 0)
|- setActiveGuestMemory(guest_memory)
|- mapActiveGuestMemory()
|  +- Maps host memory buffer to HVF VM via hv_vm_map_space()
+- boot_timing.memory_map_us = bootTimestamp()
```

**Guest Memory Layout** (ARM64):
```
0x40000000 - Memory base
0x40020000 - Kernel command line (128 KB)
0x40080000 - Kernel load offset
0x44000000 - Initrd load offset (64 MB from base)
0x40021000 - DTB address
0x40022000 - Page tables
```

#### Phase 3: Guest Image Loading

```
|- prepareGuestImage(size_bytes_u64)
|  +- Validates layout doesn't exceed memory bounds
|
|- loadGuestKernel(size_bytes_u64, cfg.kernel_path)
|  |- Open kernel file
|  |- Read header (256 bytes)
|  |- Detect ARM64 image (check for "ARMd" magic at offset 0x38)
|  |- If gzip: copyGzipToGuest() with flate decompression
|  +- Else: copyFileToGuest() with streaming read (64KB chunks)
|  +- boot_timing.kernel_load_us = bootTimestamp()
|
|- loadGuestInitrd(size_bytes_u64, cfg.initrd_path)
|  |- Open initrd file
|  +- Calls copyFileToGuest()
|  +- boot_timing.initrd_load_us = bootTimestamp()
```

#### Phase 4: Device Initialization

```
|- virtio.initGuestIo()
|  +- Registers read/write callbacks for guest memory access
|- virtio.setInterruptHandler(virtioInterruptHandler)
|- virtio.setupVirtioBlk(cfg)
|  |- Initializes block device state
|  +- Configures disk_path, seed_path, data_disk_path if present
|- virtio.setupVirtioConsole(enable_virtio_console)
|- virtio.setupVirtioRng(true)
+- virtio.setupVirtioFs(allocator, cfg)
```

#### Phase 5: GIC & Interrupt Configuration (ARM64)

```
|- computeGicLayout()
|  |- dist_base = 0x08000000 (GIC distributor)
|  +- redist_base = 0x080a0000 (GIC redistributor)
|- Allocate interrupt IDs from GIC SPI range
|  |- UART (PL011): base_irq + 1
|  |- VirtIO Block 0: base_irq + 0
|  |- VirtIO Block 1: base_irq + 2
|  |- VirtIO Block 2: base_irq + 6
|  |- VirtIO Console: base_irq + 1
|  |- VirtIO RNG: base_irq + 3
|  |- VirtIO Net: base_irq + 4
|  +- VirtIO FS: base_irq + 5
```

#### Phase 6: Boot State & Device Tree

```
|- Compute boot state (entry point, stack, cmdline)
|- writeCmdlineToGuest()
|- dtb.buildVirtDtb(allocator, {...})
|  +- Build device tree with memory, devices, interrupts
|- writeGuestBytes(layout.dtb_addr, dtb_blob)
|- buildArmIdentityMap(allocator, layout.page_table_addr)
+- writeGuestBytes(layout.page_table_addr, page_tables)
```

#### Phase 7: vCPU Creation & Register Setup

```
|- arm64_bindings.createVcpu(&exit_ptr)
|- buildHvfArmRegSet(boot_state, layout)
|  |- x0 = layout.dtb_addr (device tree base)
|  |- pc = boot_state.entry (kernel entry point)
|  +- sp_el1 = boot_state.stack_top
|- arm64_bindings.setRegs(vcpu, hvf_regset.regs)
+- arm64_bindings.setSregs(vcpu, hvf_regset.sregs)
```

#### Phase 8: I/O Setup & vCPU Launch

```
|- setupGic()
|- serial.clearConsoleBacklog()
|- startConsoleSocketServer(allocator)
|- startSerialInputThread()
|- resetPl011State()
|- vcpu_running.store(true, .seq_cst)
+- active_vcpu_thread = std.Thread.spawn(runVcpu, ...)
```

#### Phase 9: vCPU Execution Loop

```
while (vcpu_running.load(.seq_cst)) {
    arm64_bindings.run(vcpu)  // hv_vcpu_run()

    exit = exit_ptr.*
    switch (exit.reason):
    |- .Canceled -> break
    |- .VtimerActivated -> continue
    |- .Exception ->
    |  |- handleArm64SysRegTrap()
    |  +- handleArm64Mmio() for UART, VirtIO, GIC
    +- .Unknown -> break
}
```

---

## Boot Timing Instrumentation

m80 logs boot timing at info level:

```
hvf boot timing: total=15234us vm_create=120us memory_map=450us kernel=2340us initrd=890us vcpu_setup=11434us
```

Phases tracked:
- `total` = vcpu_start_us - start_us
- `vm_create` = vm_create_us - start_us
- `memory_map` = memory_map_us - vm_create_us
- `kernel_load` = kernel_load_us - memory_map_us
- `initrd_load` = initrd_load_us - kernel_load_us
- `vcpu_setup` = vcpu_start_us - initrd_load_us

---

## Summary: Boot Sequence Flow

```
User runs "m80 start myvm"
    |
main.zig: startVmCommand()
    |
Jailer.prepare() (sandboxing)
    |
Vm.start(cfg) - dispatcher
    |
hvf.start(cfg) - HVF backend
    |- 1. Create VM partition (Hvf.createVm)
    |- 2. Allocate & map guest memory
    |- 3. Load kernel to guest memory
    |- 4. Load initrd to guest memory
    |- 5. Setup VirtIO devices
    |- 6. Setup GIC interrupts (ARM64) / APIC (x86)
    |- 7. Build device tree blob (ARM64)
    |- 8. Build page tables (ARM64)
    |- 9. Compute boot state (registers, entry point)
    |- 10. Create vCPU (arm64_bindings.createVcpu)
    |- 11. Initialize vCPU registers (setRegs, setSregs)
    |- 12. Setup serial console socket server
    |- 13. Start vCPU thread (runVcpu)
    +- 14. Enter vCPU run loop (hv_vcpu_run)
        |- Guest executes
        |- On exit: handle MMIO, syscall, exception, I/O
        +- Loop continues until vcpu_running = false
```

---

## File Locations

- `src/main.zig` - CLI entry point, startVmCommand()
- `src/vm/vm.zig` - Platform dispatcher
- `src/vm/hvf.zig` - HVF backend (primary boot logic)
- `src/vm/boot.zig` - Boot state computation
- `src/vm/dtb.zig` - Device tree blob builder
- `src/vm/virtio.zig` - VirtIO device emulation
- `src/vm/posix.zig` - KVM backend
- `src/vm/windows.zig` - WHP backend
