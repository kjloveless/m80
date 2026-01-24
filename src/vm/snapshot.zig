//! VM Snapshot/Restore functionality for m80.
//!
//! This module implements VM state serialization for snapshots, enabling:
//! - Saving running VM state to disk
//! - Restoring VMs from snapshots
//! - Fast VM cloning via copy-on-write
//!
//! ## Snapshot Format
//! The snapshot file format consists of:
//! 1. SnapshotHeader - Magic, version, VM configuration
//! 2. VcpuState[] - CPU register state for each vCPU
//! 3. DeviceState[] - VirtIO device state
//! 4. Memory pages - Sparse representation of guest memory
//!
//! ## Performance Targets
//! - Snapshot save: <50ms/GB
//! - Snapshot restore: <25ms/GB

const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");

/// Magic number identifying m80 snapshot files ("M80S")
pub const snapshot_magic: [4]u8 = .{ 'M', '8', '0', 'S' };

/// Current snapshot format version
pub const snapshot_version: u32 = 1;

/// Page size used for memory serialization (4KB)
pub const page_size: usize = 4096;

/// Snapshot file header
pub const SnapshotHeader = extern struct {
    /// Magic number for file identification ("M80S")
    magic: [4]u8 = snapshot_magic,
    /// Snapshot format version
    version: u32 = snapshot_version,
    /// Guest memory size in bytes
    memory_size: u64 = 0,
    /// Number of vCPUs
    vcpu_count: u16 = 1,
    /// Number of devices with saved state
    device_count: u16 = 0,
    /// CPU architecture (0 = x86_64, 1 = aarch64)
    arch: u8 = if (builtin.cpu.arch == .aarch64) 1 else 0,
    /// Reserved for future use
    _reserved: [3]u8 = .{ 0, 0, 0 },
    /// Offset to vCPU state array
    vcpu_state_offset: u64 = 0,
    /// Offset to device state array
    device_state_offset: u64 = 0,
    /// Offset to memory page table
    memory_page_table_offset: u64 = 0,
    /// Offset to memory data
    memory_data_offset: u64 = 0,
    /// Number of non-zero pages
    non_zero_page_count: u64 = 0,
    /// Total pages in guest memory
    total_page_count: u64 = 0,
    /// Checksum of the snapshot (CRC32)
    checksum: u32 = 0,
    /// Reserved padding
    _padding: [4]u8 = .{ 0, 0, 0, 0 },
};

/// x86_64 vCPU register state
pub const VcpuStateX86 = extern struct {
    // General purpose registers
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rbp: u64 = 0,
    rsp: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rip: u64 = 0,
    rflags: u64 = 0,

    // Segment registers (selectors)
    cs: u16 = 0,
    ds: u16 = 0,
    es: u16 = 0,
    fs: u16 = 0,
    gs: u16 = 0,
    ss: u16 = 0,

    // Descriptor table registers
    gdt_base: u64 = 0,
    gdt_limit: u16 = 0,
    idt_base: u64 = 0,
    idt_limit: u16 = 0,

    // Control registers
    cr0: u64 = 0,
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
    cr8: u64 = 0,

    // Extended control registers
    efer: u64 = 0,

    // Reserved for additional state
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

/// ARM64 vCPU register state
pub const VcpuStateArm64 = extern struct {
    // General purpose registers X0-X30
    x: [31]u64 = [_]u64{0} ** 31,
    // Program counter
    pc: u64 = 0,
    // Stack pointer (current EL)
    sp: u64 = 0,
    // Program status register
    cpsr: u64 = 0,
    // Floating point control/status
    fpcr: u64 = 0,
    fpsr: u64 = 0,

    // System registers
    sp_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    sctlr_el1: u64 = 0,
    tcr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    mair_el1: u64 = 0,
    vbar_el1: u64 = 0,
    mpidr_el1: u64 = 0,

    // Reserved for additional state
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

/// Union of architecture-specific vCPU states
pub const VcpuState = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64,
};

/// Device type identifiers
pub const DeviceType = enum(u8) {
    virtio_blk = 1,
    virtio_console = 2,
    virtio_rng = 3,
    virtio_net = 4,
    virtio_fs = 5,
    pl011_uart = 6,
};

/// VirtIO device state (generic for all VirtIO devices)
pub const VirtioDeviceState = extern struct {
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    _padding: u16 = 0,
    // Queue state (single queue for simplicity)
    queue_num: u16 = 0,
    queue_ready: u8 = 0,
    _queue_padding: u8 = 0,
    queue_desc_addr: u64 = 0,
    queue_avail_addr: u64 = 0,
    queue_used_addr: u64 = 0,
    queue_last_avail_idx: u16 = 0,
    queue_used_idx: u16 = 0,
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

/// Device state entry in snapshot
pub const DeviceState = extern struct {
    /// Type of device
    device_type: DeviceType,
    /// Device index (for devices with multiple instances like virtio-blk)
    device_index: u8 = 0,
    /// Reserved
    _reserved: [2]u8 = .{ 0, 0 },
    /// Device-specific state size (device state data follows this header in file)
    state_size: u32 = 0,
};

/// Memory page table entry (for sparse memory representation)
pub const PageTableEntry = extern struct {
    /// Page number (index into guest physical memory)
    page_number: u64,
    /// Offset into the memory data section where this page is stored
    data_offset: u64,
};

/// Errors that can occur during snapshot operations
pub const SnapshotError = error{
    InvalidMagic,
    UnsupportedVersion,
    ArchitectureMismatch,
    CorruptedSnapshot,
    ChecksumMismatch,
    MemorySizeMismatch,
    IoError,
    OutOfMemory,
    InvalidState,
};

/// Checks if a memory page is all zeros
fn isPageZero(page: []const u8) bool {
    for (page) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// Computes CRC32 checksum
fn computeCrc32(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}

/// Saves guest memory to a snapshot file.
/// Uses sparse representation - only non-zero pages are stored.
pub fn saveMemory(
    allocator: std.mem.Allocator,
    memory: []const u8,
    path: []const u8,
) !void {
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    const total_pages = memory.len / page_size;
    var header = SnapshotHeader{
        .memory_size = memory.len,
        .total_page_count = total_pages,
    };

    // First pass: count non-zero pages
    var non_zero_count: u64 = 0;
    for (0..total_pages) |page_idx| {
        const start = page_idx * page_size;
        const end = start + page_size;
        if (!isPageZero(memory[start..end])) {
            non_zero_count += 1;
        }
    }
    header.non_zero_page_count = non_zero_count;

    // Calculate offsets
    const header_size = @sizeOf(SnapshotHeader);
    const page_table_size = non_zero_count * @sizeOf(PageTableEntry);
    header.memory_page_table_offset = header_size;
    header.memory_data_offset = header_size + page_table_size;

    // Build page table and collect non-zero pages
    var page_table = try allocator.alloc(PageTableEntry, @intCast(non_zero_count));
    defer allocator.free(page_table);

    var entry_idx: usize = 0;
    var data_offset: u64 = 0;
    for (0..total_pages) |page_idx| {
        const start = page_idx * page_size;
        const end = start + page_size;
        if (!isPageZero(memory[start..end])) {
            page_table[entry_idx] = .{
                .page_number = page_idx,
                .data_offset = data_offset,
            };
            entry_idx += 1;
            data_offset += page_size;
        }
    }

    // Compute checksum (over header without checksum field)
    var header_bytes: [@sizeOf(SnapshotHeader)]u8 = undefined;
    @memcpy(&header_bytes, std.mem.asBytes(&header));
    header.checksum = computeCrc32(header_bytes[0 .. header_bytes.len - 8]);

    // Write header
    try file.writeAll(std.mem.asBytes(&header));

    // Write page table
    const page_table_bytes = std.mem.sliceAsBytes(page_table);
    try file.writeAll(page_table_bytes);

    // Write non-zero pages
    for (page_table) |entry| {
        const start: usize = @intCast(entry.page_number * page_size);
        const end = start + page_size;
        try file.writeAll(memory[start..end]);
    }

    log.info("snapshot saved: {d} pages, {d} non-zero ({d}% sparse)", .{
        total_pages,
        non_zero_count,
        if (total_pages > 0) 100 - (non_zero_count * 100 / total_pages) else 100,
    });
}

/// Loads guest memory from a snapshot file.
pub fn loadMemory(
    allocator: std.mem.Allocator,
    path: []const u8,
    memory: []u8,
) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    // Read and validate header
    var header: SnapshotHeader = undefined;
    const header_bytes = try file.readAll(std.mem.asBytes(&header));
    if (header_bytes != @sizeOf(SnapshotHeader)) return error.CorruptedSnapshot;

    if (!std.mem.eql(u8, &header.magic, &snapshot_magic)) return error.InvalidMagic;
    if (header.version != snapshot_version) return error.UnsupportedVersion;
    if (header.memory_size != memory.len) return error.MemorySizeMismatch;

    const expected_arch: u8 = if (builtin.cpu.arch == .aarch64) 1 else 0;
    if (header.arch != expected_arch) return error.ArchitectureMismatch;

    // Zero out all memory first
    @memset(memory, 0);

    // Read page table
    const page_table = try allocator.alloc(PageTableEntry, @intCast(header.non_zero_page_count));
    defer allocator.free(page_table);

    try file.seekTo(header.memory_page_table_offset);
    const page_table_bytes = std.mem.sliceAsBytes(page_table);
    const table_read = try file.readAll(page_table_bytes);
    if (table_read != page_table_bytes.len) return error.CorruptedSnapshot;

    // Read non-zero pages
    for (page_table) |entry| {
        const start: usize = @intCast(entry.page_number * page_size);
        const end = start + page_size;
        if (end > memory.len) return error.CorruptedSnapshot;

        try file.seekTo(header.memory_data_offset + entry.data_offset);
        const page_read = try file.readAll(memory[start..end]);
        if (page_read != page_size) return error.CorruptedSnapshot;
    }

    log.info("snapshot loaded: {d} non-zero pages restored", .{header.non_zero_page_count});
}

/// Validates a snapshot file without loading it.
pub fn validateSnapshot(path: []const u8) !SnapshotHeader {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var header: SnapshotHeader = undefined;
    const header_bytes = try file.readAll(std.mem.asBytes(&header));
    if (header_bytes != @sizeOf(SnapshotHeader)) return error.CorruptedSnapshot;

    if (!std.mem.eql(u8, &header.magic, &snapshot_magic)) return error.InvalidMagic;
    if (header.version != snapshot_version) return error.UnsupportedVersion;

    return header;
}

/// Creates a full VM snapshot including vCPU state, device state, and memory.
pub const Snapshot = struct {
    header: SnapshotHeader,
    vcpu_states: []VcpuState,
    device_states: []DeviceState,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, vcpu_count: u16, device_count: u16) !Snapshot {
        return .{
            .header = .{
                .vcpu_count = vcpu_count,
                .device_count = device_count,
            },
            .vcpu_states = try allocator.alloc(VcpuState, vcpu_count),
            .device_states = try allocator.alloc(DeviceState, device_count),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.vcpu_states);
        self.allocator.free(self.device_states);
    }

    /// Saves the complete snapshot to a file.
    pub fn save(self: *Snapshot, memory: []const u8, path: []const u8) !void {
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        self.header.memory_size = memory.len;
        self.header.total_page_count = memory.len / page_size;

        // Count non-zero pages
        var non_zero_count: u64 = 0;
        const total_pages = memory.len / page_size;
        for (0..total_pages) |page_idx| {
            const start = page_idx * page_size;
            const end = start + page_size;
            if (!isPageZero(memory[start..end])) {
                non_zero_count += 1;
            }
        }
        self.header.non_zero_page_count = non_zero_count;

        // Calculate offsets
        const header_size = @sizeOf(SnapshotHeader);
        const vcpu_state_size = self.header.vcpu_count * @sizeOf(VcpuState);
        const device_state_size = self.header.device_count * @sizeOf(DeviceState);
        const page_table_size = non_zero_count * @sizeOf(PageTableEntry);

        self.header.vcpu_state_offset = header_size;
        self.header.device_state_offset = header_size + vcpu_state_size;
        self.header.memory_page_table_offset = header_size + vcpu_state_size + device_state_size;
        self.header.memory_data_offset = self.header.memory_page_table_offset + page_table_size;

        // Write header (will be rewritten with checksum at end)
        try file.writeAll(std.mem.asBytes(&self.header));

        // Write vCPU states
        if (self.header.vcpu_count > 0) {
            try file.writeAll(std.mem.sliceAsBytes(self.vcpu_states));
        }

        // Write device states
        if (self.header.device_count > 0) {
            try file.writeAll(std.mem.sliceAsBytes(self.device_states));
        }

        // Build and write page table
        var page_table = try self.allocator.alloc(PageTableEntry, @intCast(non_zero_count));
        defer self.allocator.free(page_table);

        var entry_idx: usize = 0;
        var data_offset: u64 = 0;
        for (0..total_pages) |page_idx| {
            const start = page_idx * page_size;
            const end = start + page_size;
            if (!isPageZero(memory[start..end])) {
                page_table[entry_idx] = .{
                    .page_number = page_idx,
                    .data_offset = data_offset,
                };
                entry_idx += 1;
                data_offset += page_size;
            }
        }
        try file.writeAll(std.mem.sliceAsBytes(page_table));

        // Write non-zero pages
        for (page_table) |entry| {
            const start: usize = @intCast(entry.page_number * page_size);
            const end = start + page_size;
            try file.writeAll(memory[start..end]);
        }

        // TODO: Rewrite header with computed checksum

        log.info("snapshot saved: {d} vCPUs, {d} devices, {d}/{d} pages", .{
            self.header.vcpu_count,
            self.header.device_count,
            non_zero_count,
            total_pages,
        });
    }

    /// Loads a complete snapshot from a file.
    pub fn load(allocator: std.mem.Allocator, path: []const u8, memory: []u8) !Snapshot {
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        // Read header
        var header: SnapshotHeader = undefined;
        const header_bytes = try file.readAll(std.mem.asBytes(&header));
        if (header_bytes != @sizeOf(SnapshotHeader)) return error.CorruptedSnapshot;

        if (!std.mem.eql(u8, &header.magic, &snapshot_magic)) return error.InvalidMagic;
        if (header.version != snapshot_version) return error.UnsupportedVersion;
        if (header.memory_size != memory.len) return error.MemorySizeMismatch;

        const expected_arch: u8 = if (builtin.cpu.arch == .aarch64) 1 else 0;
        if (header.arch != expected_arch) return error.ArchitectureMismatch;

        var snapshot = Snapshot{
            .header = header,
            .vcpu_states = try allocator.alloc(VcpuState, header.vcpu_count),
            .device_states = try allocator.alloc(DeviceState, header.device_count),
            .allocator = allocator,
        };
        errdefer snapshot.deinit();

        // Read vCPU states
        if (header.vcpu_count > 0) {
            try file.seekTo(header.vcpu_state_offset);
            const vcpu_read = try file.readAll(std.mem.sliceAsBytes(snapshot.vcpu_states));
            if (vcpu_read != header.vcpu_count * @sizeOf(VcpuState)) return error.CorruptedSnapshot;
        }

        // Read device states
        if (header.device_count > 0) {
            try file.seekTo(header.device_state_offset);
            const device_read = try file.readAll(std.mem.sliceAsBytes(snapshot.device_states));
            if (device_read != header.device_count * @sizeOf(DeviceState)) return error.CorruptedSnapshot;
        }

        // Restore memory
        @memset(memory, 0);

        const page_table = try allocator.alloc(PageTableEntry, @intCast(header.non_zero_page_count));
        defer allocator.free(page_table);

        try file.seekTo(header.memory_page_table_offset);
        const table_read = try file.readAll(std.mem.sliceAsBytes(page_table));
        if (table_read != header.non_zero_page_count * @sizeOf(PageTableEntry)) return error.CorruptedSnapshot;

        for (page_table) |entry| {
            const start: usize = @intCast(entry.page_number * page_size);
            const end = start + page_size;
            if (end > memory.len) return error.CorruptedSnapshot;

            try file.seekTo(header.memory_data_offset + entry.data_offset);
            const page_read = try file.readAll(memory[start..end]);
            if (page_read != page_size) return error.CorruptedSnapshot;
        }

        log.info("snapshot loaded: {d} vCPUs, {d} devices, {d} pages", .{
            header.vcpu_count,
            header.device_count,
            header.non_zero_page_count,
        });

        return snapshot;
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "snapshot: header size is correct" {
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(SnapshotHeader));
}

test "snapshot: page table entry size is correct" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PageTableEntry));
}

test "snapshot: isPageZero detects zero pages" {
    var zero_page: [page_size]u8 = [_]u8{0} ** page_size;
    try std.testing.expect(isPageZero(&zero_page));

    zero_page[0] = 1;
    try std.testing.expect(!isPageZero(&zero_page));
}

test "snapshot: save and load memory" {
    const allocator = std.testing.allocator;

    // Create test memory with some non-zero pages
    const test_size = page_size * 4;
    var memory = try allocator.alloc(u8, test_size);
    defer allocator.free(memory);
    @memset(memory, 0);

    // Write data to pages 0 and 2
    memory[0] = 0xAA;
    memory[page_size * 2] = 0xBB;
    memory[page_size * 2 + 1] = 0xCC;

    // Save snapshot
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const snap_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, "test.snap" });
    defer allocator.free(snap_path);

    try saveMemory(allocator, memory, snap_path);

    // Load into fresh memory
    const loaded = try allocator.alloc(u8, test_size);
    defer allocator.free(loaded);

    try loadMemory(allocator, snap_path, loaded);

    // Verify
    try std.testing.expectEqual(@as(u8, 0xAA), loaded[0]);
    try std.testing.expectEqual(@as(u8, 0), loaded[page_size]);
    try std.testing.expectEqual(@as(u8, 0xBB), loaded[page_size * 2]);
    try std.testing.expectEqual(@as(u8, 0xCC), loaded[page_size * 2 + 1]);
}

test "snapshot: validate detects invalid magic" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create invalid snapshot
    var file = try tmp.dir.createFile("bad.snap", .{});
    try file.writeAll("XXXX" ++ ([_]u8{0} ** 76));
    file.close();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, "bad.snap");
    defer allocator.free(tmp_path);

    try std.testing.expectError(error.InvalidMagic, validateSnapshot(tmp_path));
}
