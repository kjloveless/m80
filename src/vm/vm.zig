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
const sync = @import("../util/sync.zig");
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const log = @import("../util/log.zig");
const config = @import("../core/config.zig");
const Jailer = @import("../jailer/jailer.zig").Jailer;
const windows = @import("windows.zig");
const hvf = @import("hvf.zig");
const posix = @import("posix.zig");

const FsSnapshotEntry = struct {
    slot: []const u8,
    source_path: []const u8,
    snapshot_name: []const u8,
    bytes: u64,
};

const FsSnapshotManifest = struct {
    vda: ?[]u8 = null,
    vdb: ?[]u8 = null,
    vdc: ?[]u8 = null,

    fn deinit(self: *FsSnapshotManifest, allocator: std.mem.Allocator) void {
        if (self.vda) |value| allocator.free(value);
        if (self.vdb) |value| allocator.free(value);
        if (self.vdc) |value| allocator.free(value);
        self.* = .{};
    }
};

fn openPathForRead(path: []const u8) !fs.File {
    if (fs.path.isAbsolute(path)) {
        return fs.openFileAbsolute(path, .{});
    }
    return fs.cwd().openFile(path, .{});
}

fn copyFileContents(
    allocator: std.mem.Allocator,
    src: *fs.File,
    dst: *fs.File,
) !u64 {
    var buf = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(buf);

    var total: u64 = 0;
    while (true) {
        const n = try src.read(buf);
        if (n == 0) break;
        try dst.writeAll(buf[0..n]);
        total += @intCast(n);
    }
    try dst.sync();
    return total;
}

fn copyFileToDir(
    allocator: std.mem.Allocator,
    src_path: []const u8,
    out_dir: fs.Dir,
    out_name: []const u8,
) !u64 {
    var src = try openPathForRead(src_path);
    defer src.close();
    var dst = try out_dir.createFile(out_name, .{ .truncate = true });
    defer dst.close();
    return copyFileContents(allocator, &src, &dst);
}

fn snapshotFileNameForSlot(allocator: std.mem.Allocator, slot: []const u8, src_path: []const u8) ![]u8 {
    const base = fs.path.basename(src_path);
    const name = if (base.len == 0) "disk.img" else base;
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ slot, name });
}

fn appendSnapshotEntry(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(FsSnapshotEntry),
    out_dir: fs.Dir,
    slot: []const u8,
    src_path: ?[]const u8,
) !void {
    if (src_path == null) return;
    const path = src_path.?;

    const snapshot_name = try snapshotFileNameForSlot(allocator, slot, path);
    errdefer allocator.free(snapshot_name);

    const copied_bytes = try copyFileToDir(allocator, path, out_dir, snapshot_name);
    try entries.append(allocator, .{
        .slot = slot,
        .source_path = path,
        .snapshot_name = snapshot_name,
        .bytes = copied_bytes,
    });
}

fn writeFilesystemSnapshotManifest(out_dir: fs.Dir, entries: []const FsSnapshotEntry) !void {
    var manifest = try out_dir.createFile("manifest.txt", .{ .truncate = true });
    defer manifest.close();
    var writer_buf: [1024]u8 = undefined;
    var file_writer = manifest.writer(&writer_buf);
    const w = &file_writer.interface;
    try w.writeAll("format=m80-fs-snapshot-v1\n");
    try w.print("created_unix={d}\n", .{sync.timestamp()});
    for (entries) |entry| {
        try w.print("{s}={s}\n", .{ entry.slot, entry.snapshot_name });
        try w.print("{s}_source={s}\n", .{ entry.slot, entry.source_path });
        try w.print("{s}_bytes={d}\n", .{ entry.slot, entry.bytes });
    }
    try w.flush();
}

fn manifestSlotRef(manifest: *FsSnapshotManifest, key: []const u8) ?*?[]u8 {
    if (std.mem.eql(u8, key, "vda")) return &manifest.vda;
    if (std.mem.eql(u8, key, "vdb")) return &manifest.vdb;
    if (std.mem.eql(u8, key, "vdc")) return &manifest.vdc;
    return null;
}

fn parseFilesystemSnapshotManifest(allocator: std.mem.Allocator, snapshot_dir: fs.Dir) !FsSnapshotManifest {
    var file = try snapshot_dir.openFile("manifest.txt", .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 128 * 1024);
    defer allocator.free(data);

    var manifest = FsSnapshotManifest{};
    errdefer manifest.deinit(allocator);

    var saw_format = false;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidFilesystemSnapshot;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");

        if (std.mem.eql(u8, key, "format")) {
            saw_format = true;
            if (!std.mem.eql(u8, value, "m80-fs-snapshot-v1")) {
                return error.UnsupportedFilesystemSnapshotFormat;
            }
            continue;
        }

        if (manifestSlotRef(&manifest, key)) |slot| {
            if (slot.*) |existing| allocator.free(existing);
            slot.* = try allocator.dupe(u8, value);
        }
    }

    if (!saw_format) return error.InvalidFilesystemSnapshot;
    return manifest;
}

fn openPathForWriteTruncate(path: []const u8) !fs.File {
    if (fs.path.isAbsolute(path)) {
        return fs.createFileAbsolute(path, .{ .truncate = true });
    }
    return fs.cwd().createFile(path, .{ .truncate = true });
}

fn copySnapshotEntryToPath(
    allocator: std.mem.Allocator,
    snapshot_dir: fs.Dir,
    snapshot_name: []const u8,
    target_path: []const u8,
) !u64 {
    var src = try snapshot_dir.openFile(snapshot_name, .{});
    defer src.close();
    var dst = try openPathForWriteTruncate(target_path);
    defer dst.close();
    return copyFileContents(allocator, &src, &dst);
}

fn restoreSlotFromManifest(
    allocator: std.mem.Allocator,
    snapshot_dir: fs.Dir,
    slot: []const u8,
    snapshot_name: ?[]const u8,
    target_path: ?[]const u8,
) !bool {
    const name = snapshot_name orelse return false;
    const target = target_path orelse return error.MissingSnapshotTargetDisk;
    const bytes = try copySnapshotEntryToPath(allocator, snapshot_dir, name, target);
    log.info("filesystem restore slot={s} source={s} target={s} bytes={d}", .{
        slot,
        name,
        target,
        bytes,
    });
    return true;
}

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

    pub fn isRunning(self: *Vm) bool {
        _ = self;
        return switch (@import("builtin").os.tag) {
            .windows => windows.isVcpuRunning(),
            .macos => hvf.isVcpuRunning(),
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => posix.isVcpuRunning(),
            else => false,
        };
    }

    /// Creates a filesystem snapshot of the VM block images while the VM is running.
    ///
    /// This copies configured block-image files (`disk_path`, `seed_path`,
    /// `data_disk_path`) into the target directory and writes a `manifest.txt`.
    /// Unlike full VM snapshots, this does not capture guest memory or vCPU state.
    pub fn snapshotFilesystem(self: *Vm, cfg: config.VmConfig, out_dir_path: []const u8) !void {
        const virtio = @import("virtio.zig");
        var cwd = fs.cwd();

        if (cfg.disk_path == null and cfg.seed_path == null and cfg.data_disk_path == null) {
            return error.NoDiskConfigured;
        }

        switch (@import("builtin").os.tag) {
            .macos => {
                try hvf.pauseVcpu();
                defer hvf.resumeVcpu();
                try virtio.syncVirtioBlkDevices();
            },
            .windows => return error.NotSupported,
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => return error.NotSupported,
            else => return error.UnsupportedPlatform,
        }

        try cwd.makePath(out_dir_path);
        var out_dir = try cwd.openDir(out_dir_path, .{});
        defer out_dir.close();

        var entries = std.ArrayList(FsSnapshotEntry).empty;
        defer {
            for (entries.items) |entry| {
                self.allocator.free(entry.snapshot_name);
            }
            entries.deinit(self.allocator);
        }

        try appendSnapshotEntry(self.allocator, &entries, out_dir, "vda", cfg.disk_path);
        try appendSnapshotEntry(self.allocator, &entries, out_dir, "vdb", cfg.seed_path);
        try appendSnapshotEntry(self.allocator, &entries, out_dir, "vdc", cfg.data_disk_path);
        try writeFilesystemSnapshotManifest(out_dir, entries.items);
    }

    /// Restores VM block-image files from a filesystem snapshot directory.
    ///
    /// Expects a snapshot directory created by `snapshotFilesystem`, including
    /// `manifest.txt` and per-slot image files.
    pub fn restoreFilesystem(self: *Vm, cfg: config.VmConfig, snapshot_dir_path: []const u8) !void {
        const virtio = @import("virtio.zig");
        var cwd = fs.cwd();
        var snapshot_dir = try cwd.openDir(snapshot_dir_path, .{});
        defer snapshot_dir.close();

        var manifest = try parseFilesystemSnapshotManifest(self.allocator, snapshot_dir);
        defer manifest.deinit(self.allocator);

        const should_pause = builtin.os.tag == .macos and hvf.isVcpuRunning();
        if (should_pause) {
            try hvf.pauseVcpu();
            defer hvf.resumeVcpu();
            try virtio.syncVirtioBlkDevices();
        }

        var restored_any = false;
        if (try restoreSlotFromManifest(self.allocator, snapshot_dir, "vda", manifest.vda, cfg.disk_path)) restored_any = true;
        if (try restoreSlotFromManifest(self.allocator, snapshot_dir, "vdb", manifest.vdb, cfg.seed_path)) restored_any = true;
        if (try restoreSlotFromManifest(self.allocator, snapshot_dir, "vdc", manifest.vdc, cfg.data_disk_path)) restored_any = true;

        if (!restored_any) return error.EmptyFilesystemSnapshot;

        if (should_pause) {
            try virtio.syncVirtioBlkDevices();
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
                        .virtio_vsock => {
                            if (entry.header.state_size != @sizeOf(snap.VirtioVsockSnapshotState)) {
                                return error.CorruptedSnapshot;
                            }
                            const state = std.mem.bytesAsValue(snap.VirtioVsockSnapshotState, entry.data);
                            virtio.restoreVirtioVsockState(state.*);
                        },
                        .virtio_net => {
                            return error.UnsupportedLegacySnapshot;
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
    var gpa = std.heap.DebugAllocator(.{}){};
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

test "vm: snapshot file name prefixes slot" {
    const name = try snapshotFileNameForSlot(std.testing.allocator, "vda", "/images/rootfs.ext4");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("vda-rootfs.ext4", name);
}

test "vm: copyFileToDir copies source bytes" {
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var src = try tmp.dir.createFile("src.img", .{ .truncate = true });
    defer src.close();
    try src.writeAll("snapshot-bytes");

    var out_dir = try tmp.dir.openDir(".", .{});
    defer out_dir.close();

    const src_path = try tmp.dir.realpathAlloc(std.testing.allocator, "src.img");
    defer std.testing.allocator.free(src_path);

    const copied = try copyFileToDir(std.testing.allocator, src_path, out_dir, "copy.img");
    try std.testing.expectEqual(@as(u64, 14), copied);

    const copied_data = try out_dir.readFileAlloc(std.testing.allocator, "copy.img", 64);
    defer std.testing.allocator.free(copied_data);
    try std.testing.expectEqualStrings("snapshot-bytes", copied_data);
}

test "vm: parseFilesystemSnapshotManifest reads slot mappings" {
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var manifest = try tmp.dir.createFile("manifest.txt", .{ .truncate = true });
    defer manifest.close();
    try manifest.writeAll(
        "format=m80-fs-snapshot-v1\n" ++
            "created_unix=123\n" ++
            "vda=vda-rootfs.ext4\n" ++
            "vdb=vdb-seed.iso\n",
    );

    var parsed = try parseFilesystemSnapshotManifest(std.testing.allocator, tmp.dir);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("vda-rootfs.ext4", parsed.vda.?);
    try std.testing.expectEqualStrings("vdb-seed.iso", parsed.vdb.?);
    try std.testing.expect(parsed.vdc == null);
}
