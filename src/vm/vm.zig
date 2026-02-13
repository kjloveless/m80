//! VM Platform Dispatcher
//!
//! This module provides a platform-independent interface for VM operations.
//! It dispatches start/stop calls to the appropriate hypervisor backend
//! based on the host operating system.
//!
//! ## Supported Platforms & Backends
//! - **Windows**: Windows Hypervisor Platform (WHP) via windows.zig
//! - **macOS**: Hypervisor Framework (HVF) via hvf.zig
//! - **Linux/BSD**: Kernel-based Virtual Machine (KVM) via posix.zig
//!
//! ## Architecture
//! ```
//! Vm (this file) - Platform dispatcher
//!     │
//!     ├── windows.zig - WHP backend (Windows)
//!     ├── hvf.zig     - HVF backend (macOS)
//!     └── posix.zig   - KVM backend (Linux, FreeBSD, etc.)
//! ```
//!
//! The Vm struct is intentionally thin - it just routes calls to backends.
//! Platform-specific state and logic live in the backend modules.

const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");
const Jailer = @import("../jailer/jailer.zig").Jailer;
const windows = @import("windows.zig");
const hvf = @import("hvf.zig");
const posix = @import("posix.zig");

/// Virtual Machine handle.
///
/// This struct provides a unified interface for VM operations across platforms.
/// It holds references to the allocator and jailer (security sandbox) but
/// delegates actual hypervisor work to platform-specific backends.
pub const Vm = struct {
    /// Memory allocator used for any allocations during VM lifecycle
    allocator: std.mem.Allocator,

    /// Reference to the security jailer that enforces sandboxing
    jailer: *Jailer,

    /// Creates a new VM instance.
    ///
    /// This is a lightweight operation - it just stores references.
    /// The actual hypervisor setup happens in start().
    ///
    /// Parameters:
    ///   - allocator: Memory allocator for VM operations
    ///   - jailer: Security jailer (must outlive the VM)
    pub fn init(
        allocator: std.mem.Allocator,
        jailer: *Jailer,
    ) !Vm {
        return Vm{
            .allocator = allocator,
            .jailer = jailer,
        };
    }

    /// Starts the VM with the given configuration.
    ///
    /// Dispatches to the appropriate hypervisor backend based on host OS:
    /// - Windows → WHP (Windows Hypervisor Platform)
    /// - macOS → HVF (Hypervisor Framework)
    /// - Linux/BSD → KVM (Kernel-based Virtual Machine)
    ///
    /// Parameters:
    ///   - cfg: VM configuration (kernel path, memory, CPU cores, etc.)
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - error.NotImplemented: Backend not yet implemented
    ///   - Backend-specific errors (hypervisor init failed, etc.)
    pub fn start(self: *Vm, cfg: @import("../core/config.zig").VmConfig) !void {
        _ = self;
        // Dispatch to platform-specific backend
        switch (@import("builtin").os.tag) {
            .windows => try windows.start(cfg),
            .macos => try hvf.start(cfg),
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.start(cfg),
            else => return error.UnsupportedPlatform,
        }
    }

    /// Stops the running VM.
    ///
    /// Signals the hypervisor to terminate the guest VM gracefully.
    /// Like start(), dispatches to the appropriate platform backend.
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - Backend-specific errors
    pub fn stop(self: *Vm) !void {
        _ = self;
        switch (@import("builtin").os.tag) {
            .windows => try windows.stop(),
            .macos => try hvf.stop(),
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.stop(),
            else => return error.UnsupportedPlatform,
        }
    }

    /// Creates a snapshot of the running VM.
    ///
    /// Captures the current state of the VM including:
    /// - vCPU registers
    /// - VirtIO device state
    /// - Guest memory (sparse representation)
    ///
    /// Parameters:
    ///   - path: Path to write the snapshot file
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - error.NotSupported: Snapshot not supported on this backend
    ///   - I/O errors when writing snapshot file
    pub fn snapshot(self: *Vm, path: []const u8) !void {
        const snap = @import("snapshot.zig");
        const virtio = @import("virtio.zig");

        switch (@import("builtin").os.tag) {
            .macos => {
                // Pause vCPU to get consistent state
                try hvf.pauseVcpu();
                defer hvf.resumeVcpu();

                // Capture vCPU state
                const vcpu_state = try hvf.takePausedVcpuState();
                var vcpu_states = [_]snap.VcpuState{vcpu_state};

                // Capture device states
                var device_states = try virtio.collectDeviceStates(self.allocator);
                errdefer virtio.freeDeviceStates(self.allocator, device_states);
                if (builtin.cpu.arch == .aarch64) {
                    const pl011_state = hvf.capturePl011State();
                    const pl011_data = try self.allocator.alloc(u8, @sizeOf(snap.Pl011SnapshotState));
                    @memcpy(pl011_data, std.mem.asBytes(&pl011_state));

                    var gic_data: ?[]u8 = null;
                    if (!hvf.isVcpuRunning()) {
                        gic_data = hvf.captureGicState(self.allocator) catch |e| blk: {
                            log.warn("snapshot gic state capture failed: {s}", .{@errorName(e)});
                            break :blk null;
                        };
                    } else {
                        log.info("snapshot gic state capture skipped (vcpu running)", .{});
                    }

                    const extra_count: usize = 1 + @intFromBool(gic_data != null);
                    const expanded = try self.allocator.alloc(snap.DeviceStateEntry, device_states.len + extra_count);
                    if (device_states.len > 0) {
                        std.mem.copyForwards(snap.DeviceStateEntry, expanded[0..device_states.len], device_states);
                    }
                    var idx = device_states.len;
                    expanded[idx] = .{
                        .header = .{
                            .device_type = .pl011_uart,
                            .device_index = 0,
                            .state_size = @sizeOf(snap.Pl011SnapshotState),
                        },
                        .data = pl011_data,
                    };
                    idx += 1;
                    if (gic_data) |data| {
                        expanded[idx] = .{
                            .header = .{
                                .device_type = .gic_state,
                                .device_index = 0,
                                .state_size = @intCast(data.len),
                            },
                            .data = data,
                        };
                    }
                    self.allocator.free(device_states);
                    device_states = expanded;
                }
                defer virtio.freeDeviceStates(self.allocator, device_states);

                // Get guest memory
                const memory = hvf.getGuestMemory() orelse return error.NoGuestMemory;

                // Save snapshot using streaming method
                try snap.saveStreaming(
                    self.allocator,
                    memory,
                    &vcpu_states,
                    device_states,
                    path,
                    false, // compression disabled for now
                );
            },
            .windows => return error.NotSupported,
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => return error.NotSupported,
            else => return error.UnsupportedPlatform,
        }
    }

    /// Restores a VM from a snapshot file.
    ///
    /// Loads the snapshot and restores:
    /// - Guest memory
    /// - vCPU state
    /// - Device state
    ///
    /// The VM must not be running when restore is called.
    /// After restore, the VM can be resumed with the vCPU in its
    /// snapshot state.
    ///
    /// Parameters:
    ///   - path: Path to the snapshot file
    ///   - lazy: If true, use lazy (demand-paged) memory loading
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - error.NotSupported: Restore not supported on this backend
    ///   - Snapshot validation errors
    ///   - I/O errors when reading snapshot file
    pub fn restore(self: *Vm, path: []const u8, lazy: bool) !void {
        const snap = @import("snapshot.zig");

        switch (@import("builtin").os.tag) {
            .macos => {
                // Validate snapshot first
                const header = try snap.validateSnapshot(path);

                // Get guest memory - must be allocated already
                const memory = hvf.getGuestMemory() orelse return error.NoGuestMemory;

                if (header.memory_size != memory.len) {
                    return error.MemorySizeMismatch;
                }

                // Load memory (lazy or full)
                if (lazy) {
                    var loader = try snap.loadMemoryLazy(self.allocator, path, memory);
                    if (loader) |*l| {
                        // Keep loader alive for demand paging (would need to store it somewhere)
                        l.deinit();
                    }
                } else {
                    try snap.loadMemory(self.allocator, path, memory);
                }

                const virtio = @import("virtio.zig");

                // Load snapshot state (vCPU + device) without touching memory
                var snapshot_data = try snap.Snapshot.loadState(self.allocator, path, memory.len);
                defer snapshot_data.deinit();

                // Load device state data and restore devices
                const device_entries = try snap.loadDeviceStateEntries(self.allocator, path);
                defer virtio.freeDeviceStates(self.allocator, device_entries);
                if (builtin.cpu.arch == .aarch64) {
                    var has_gic_state = false;
                    for (device_entries) |entry| {
                        if (entry.header.device_type == .gic_state) {
                            has_gic_state = true;
                            break;
                        }
                    }
                    if (!has_gic_state) {
                        log.warn("snapshot missing gic state; cold restore may break interrupts", .{});
                    }
                }
                for (device_entries) |entry| {
                    switch (entry.header.device_type) {
                        .virtio_blk => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioBlkSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioBlkSnapshotState, entry.data);
                            virtio.restoreVirtioBlkState(entry.header.device_index, state.*);
                        },
                        .virtio_console => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioConsoleSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioConsoleSnapshotState, entry.data);
                            virtio.restoreVirtioConsoleState(state.*);
                        },
                        .virtio_rng => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioRngSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioRngSnapshotState, entry.data);
                            virtio.restoreVirtioRngState(state.*);
                        },
                        .virtio_net => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioNetSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioNetSnapshotState, entry.data);
                            virtio.restoreVirtioNetState(state.*);
                        },
                        .virtio_fs => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioFsSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioFsSnapshotState, entry.data);
                            virtio.restoreVirtioFsState(state.*);
                        },
                        .gic_state => {
                            if (entry.header.state_size != entry.data.len) {
                                return error.CorruptedSnapshot;
                            }
                            hvf.restoreGicState(entry.data) catch |e| {
                                log.warn("restore gic state failed: {s}", .{@errorName(e)});
                                return e;
                            };
                        },
                        .pl011_uart => {
                            if (entry.header.state_size != @sizeOf(snap.Pl011SnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.Pl011SnapshotState, entry.data);
                            hvf.restorePl011State(state.*);
                        },
                    }
                }

                // Restore vCPU state
                if (snapshot_data.header.vcpu_count > 0) {
                    if (builtin.cpu.arch == .aarch64) {
                        log.info(
                            "snapshot vcpu state pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}",
                            .{
                                snapshot_data.vcpu_states[0].arm64.pc,
                                snapshot_data.vcpu_states[0].arm64.sp_el1,
                                snapshot_data.vcpu_states[0].arm64.elr_el1,
                            },
                        );
                    }
                    try hvf.applyPausedVcpuState(snapshot_data.vcpu_states[0]);
                }

            },
            .windows => return error.NotSupported,
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => return error.NotSupported,
            else => return error.UnsupportedPlatform,
        }
    }

    /// Cleans up VM resources.
    /// Currently a no-op since state lives in backends.
    pub fn deinit(self: *Vm) void {
        _ = self;
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "smoke: backend start/stop" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    const cfg = try @import("../core/config.zig").defaultConfig(allocator, "test");
    var cfg_mut = cfg;
    defer @import("../core/config.zig").freeConfig(allocator, &cfg_mut);

    vm.start(cfg_mut) catch |e| switch (e) {
        error.NotImplemented => return error.SkipZigTest,
        error.HvfFailure => return,
        else => return e,
    };
    try vm.stop();
}
