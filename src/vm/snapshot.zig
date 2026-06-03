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
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const log = @import("../util/log.zig");

/// Magic number identifying m80 snapshot files ("M80S")
pub const snapshot_magic: [4]u8 = .{ 'M', '8', '0', 'S' };

/// Current snapshot format version
pub const snapshot_version: u32 = 6;

/// Snapshot format version 5 (legacy, still readable)
pub const snapshot_version_5: u32 = 5;

/// Snapshot format version 4 (legacy, still readable)
pub const snapshot_version_4: u32 = 4;

/// Snapshot format version 3 (legacy, still readable)
pub const snapshot_version_3: u32 = 3;

/// Snapshot format version 2 (legacy, still readable)
pub const snapshot_version_2: u32 = 2;

/// Snapshot format version 1 (legacy, still readable)
pub const snapshot_version_1: u32 = 1;

/// Page size used for memory serialization (4KB)
pub const page_size: usize = 4096;

/// Snapshot flags stored in _reserved[0] of SnapshotHeader
pub const SNAPSHOT_FLAG_COMPRESSED: u8 = 1 << 0;
pub const SNAPSHOT_FLAG_LAZY_COMPATIBLE: u8 = 1 << 1;

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
    sp_el0: u64 = 0,
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
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntp_ctl_el0: u64 = 0,
    cntp_cval_el0: u64 = 0,
    cntp_tval_el0: u64 = 0,
    apia_key_lo: u64 = 0,
    apia_key_hi: u64 = 0,
    apib_key_lo: u64 = 0,
    apib_key_hi: u64 = 0,
    apda_key_lo: u64 = 0,
    apda_key_hi: u64 = 0,
    apdb_key_lo: u64 = 0,
    apdb_key_hi: u64 = 0,
    apga_key_lo: u64 = 0,
    apga_key_hi: u64 = 0,
    vtimer_offset: u64 = 0,
    vtimer_masked: u64 = 0,
    vtimer_valid: u64 = 0,
    icc_pmr_el1: u64 = 0,
    icc_bpr0_el1: u64 = 0,
    icc_bpr1_el1: u64 = 0,
    icc_ctlr_el1: u64 = 0,
    icc_sre_el1: u64 = 0,
    icc_igrpen0_el1: u64 = 0,
    icc_igrpen1_el1: u64 = 0,

    // Reserved for additional state
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

/// Union of architecture-specific vCPU states
pub const VcpuState = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64,
};

/// Snapshot format version 2 arm64 state (without extra sysregs)
pub const VcpuStateArm64V2 = extern struct {
    x: [31]u64 = [_]u64{0} ** 31,
    pc: u64 = 0,
    sp: u64 = 0,
    cpsr: u64 = 0,
    fpcr: u64 = 0,
    fpsr: u64 = 0,
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
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

pub const VcpuStateV2 = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64V2,
};

/// Snapshot format version 3 arm64 state (without PAC keys)
pub const VcpuStateArm64V3 = extern struct {
    x: [31]u64 = [_]u64{0} ** 31,
    pc: u64 = 0,
    sp: u64 = 0,
    cpsr: u64 = 0,
    fpcr: u64 = 0,
    fpsr: u64 = 0,
    sp_el0: u64 = 0,
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
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntp_ctl_el0: u64 = 0,
    cntp_cval_el0: u64 = 0,
    cntp_tval_el0: u64 = 0,
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

pub const VcpuStateV3 = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64V3,
};

/// Snapshot format version 4 arm64 state (without vtimer fields)
pub const VcpuStateArm64V4 = extern struct {
    x: [31]u64 = [_]u64{0} ** 31,
    pc: u64 = 0,
    sp: u64 = 0,
    cpsr: u64 = 0,
    fpcr: u64 = 0,
    fpsr: u64 = 0,
    sp_el0: u64 = 0,
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
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntp_ctl_el0: u64 = 0,
    cntp_cval_el0: u64 = 0,
    cntp_tval_el0: u64 = 0,
    apia_key_lo: u64 = 0,
    apia_key_hi: u64 = 0,
    apib_key_lo: u64 = 0,
    apib_key_hi: u64 = 0,
    apda_key_lo: u64 = 0,
    apda_key_hi: u64 = 0,
    apdb_key_lo: u64 = 0,
    apdb_key_hi: u64 = 0,
    apga_key_lo: u64 = 0,
    apga_key_hi: u64 = 0,
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

pub const VcpuStateV4 = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64V4,
};

/// Snapshot format version 5 arm64 state (without GIC CPU interface sysregs)
pub const VcpuStateArm64V5 = extern struct {
    x: [31]u64 = [_]u64{0} ** 31,
    pc: u64 = 0,
    sp: u64 = 0,
    cpsr: u64 = 0,
    fpcr: u64 = 0,
    fpsr: u64 = 0,
    sp_el0: u64 = 0,
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
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntp_ctl_el0: u64 = 0,
    cntp_cval_el0: u64 = 0,
    cntp_tval_el0: u64 = 0,
    apia_key_lo: u64 = 0,
    apia_key_hi: u64 = 0,
    apib_key_lo: u64 = 0,
    apib_key_hi: u64 = 0,
    apda_key_lo: u64 = 0,
    apda_key_hi: u64 = 0,
    apdb_key_lo: u64 = 0,
    apdb_key_hi: u64 = 0,
    apga_key_lo: u64 = 0,
    apga_key_hi: u64 = 0,
    vtimer_offset: u64 = 0,
    vtimer_masked: u64 = 0,
    vtimer_valid: u64 = 0,
    _reserved: [64]u8 = [_]u8{0} ** 64,
};

pub const VcpuStateV5 = extern union {
    x86: VcpuStateX86,
    arm64: VcpuStateArm64V5,
};

/// Device type identifiers
pub const DeviceType = enum(u8) {
    virtio_blk = 1,
    virtio_console = 2,
    virtio_rng = 3,
    virtio_net = 4,
    virtio_fs = 5,
    pl011_uart = 6,
    gic_state = 7,
    virtio_vsock = 8,
};

/// PL011 UART snapshot state (arm64 console)
pub const Pl011SnapshotState = extern struct {
    cr: u32 = 0,
    lcrh: u32 = 0,
    ibrd: u32 = 0,
    fbrd: u32 = 0,
    imsc: u32 = 0,
    pending: u32 = 0,
};

/// VirtIO queue state (used by all VirtIO devices)
pub const VirtioQueueState = extern struct {
    /// Queue size (number of descriptors)
    num: u16 = 0,
    /// 1 if queue is ready, 0 otherwise
    ready: u8 = 0,
    /// Padding
    _pad: u8 = 0,
    /// Descriptor table address
    desc_addr: u64 = 0,
    /// Available ring address
    avail_addr: u64 = 0,
    /// Used ring address
    used_addr: u64 = 0,
    /// Last processed available index
    last_avail_idx: u16 = 0,
    /// Current used index
    used_idx: u16 = 0,
    /// Reserved for future use
    _reserved: [4]u8 = [_]u8{0} ** 4,
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

/// VirtIO-blk device snapshot state
pub const VirtioBlkSnapshotState = extern struct {
    /// Total capacity in 512-byte sectors
    capacity_sectors: u64 = 0,
    /// 1 if read-only, 0 otherwise
    readonly: u8 = 0,
    /// Padding
    _pad: [7]u8 = [_]u8{0} ** 7,
    /// Common VirtIO state
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    _padding: u16 = 0,
    /// Single queue state
    queue: VirtioQueueState = .{},
};

/// VirtIO-vsock device snapshot state
pub const VirtioVsockSnapshotState = extern struct {
    guest_cid: u64 = 0,
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    _padding: u16 = 0,
    rx_queue: VirtioQueueState = .{},
    tx_queue: VirtioQueueState = .{},
    event_queue: VirtioQueueState = .{},
};

/// VirtIO-console device snapshot state
pub const VirtioConsoleSnapshotState = extern struct {
    /// Common VirtIO state
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    _padding: u16 = 0,
    /// RX queue state
    rx_queue: VirtioQueueState = .{},
    /// TX queue state
    tx_queue: VirtioQueueState = .{},
};

/// VirtIO-rng device snapshot state
pub const VirtioRngSnapshotState = extern struct {
    /// Common VirtIO state
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    _padding: u16 = 0,
    /// Single queue state
    queue: VirtioQueueState = .{},
};

/// VirtIO-fs device snapshot state
pub const VirtioFsSnapshotState = extern struct {
    /// Common VirtIO state
    status: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    num_queues: u16 = 0,
    /// Queue states (up to 8 queues for virtio-fs)
    queues: [8]VirtioQueueState = [_]VirtioQueueState{.{}} ** 8,
};

/// Device state entry in snapshot (fixed-size header)
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

/// Device state entry with variable-size data (used for streaming save)
pub const DeviceStateEntry = struct {
    /// Fixed-size header
    header: DeviceState,
    /// Variable-size device-specific state data
    data: []const u8,
};

/// Compressed page table entry (for compressed snapshots)
pub const CompressedPageTableEntry = extern struct {
    /// Page number (index into guest physical memory)
    page_number: u64,
    /// Offset into the memory data section where this page is stored
    data_offset: u64,
    /// Compressed size in bytes (0 = page stored uncompressed at page_size)
    compressed_size: u32,
    /// Reserved
    _reserved: u32 = 0,
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
    UnsupportedCompression,
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

const HeaderRead = struct {
    header: SnapshotHeader,
    bytes: [@sizeOf(SnapshotHeader)]u8,
};

fn readHeader(file: *fs.File) !HeaderRead {
    var header_bytes: [@sizeOf(SnapshotHeader)]u8 = undefined;
    const header_read = try file.readAll(&header_bytes);
    if (header_read != header_bytes.len) return error.CorruptedSnapshot;

    var header: SnapshotHeader = undefined;
    @memcpy(std.mem.asBytes(&header), header_bytes[0..]);

    return .{ .header = header, .bytes = header_bytes };
}

fn validateHeader(
    header: *const SnapshotHeader,
    header_bytes: []const u8,
    expected_memory_size: ?usize,
) !void {
    if (!std.mem.eql(u8, &header.magic, &snapshot_magic)) return error.InvalidMagic;
    if (header.version != snapshot_version and header.version != snapshot_version_5 and header.version != snapshot_version_4 and header.version != snapshot_version_3 and header.version != snapshot_version_2 and header.version != snapshot_version_1) {
        return error.UnsupportedVersion;
    }

    const expected_arch: u8 = if (builtin.cpu.arch == .aarch64) 1 else 0;
    if (header.arch != expected_arch) return error.ArchitectureMismatch;

    if (expected_memory_size) |size| {
        if (header.memory_size != size) return error.MemorySizeMismatch;
    }

    if (isCompressed(header)) return error.UnsupportedCompression;

    if (header.checksum != 0) {
        const computed = computeCrc32(header_bytes[0 .. header_bytes.len - 8]);
        if (computed != header.checksum) return error.ChecksumMismatch;
    }
}

/// Saves guest memory to a snapshot file.
/// Uses sparse representation - only non-zero pages are stored.
pub fn saveMemory(
    allocator: std.mem.Allocator,
    memory: []const u8,
    path: []const u8,
) !void {
    var file = try fs.cwd().createFile(path, .{});
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
    var file = try fs.cwd().openFile(path, .{});
    defer file.close();

    // Read and validate header
    const header_read = try readHeader(&file);
    const header = header_read.header;
    try validateHeader(&header, &header_read.bytes, memory.len);

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
    var file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const header_read = try readHeader(&file);
    try validateHeader(&header_read.header, &header_read.bytes, null);
    return header_read.header;
}

/// Returns true if the snapshot is compressed.
pub fn isCompressed(header: *const SnapshotHeader) bool {
    return (header._reserved[0] & SNAPSHOT_FLAG_COMPRESSED) != 0;
}

/// Returns true if the snapshot supports lazy loading.
pub fn isLazyCompatible(header: *const SnapshotHeader) bool {
    return (header._reserved[0] & SNAPSHOT_FLAG_LAZY_COMPATIBLE) != 0;
}

fn isLegacyVcpuStateVersion(version: u32) bool {
    return version == snapshot_version_1 or
        version == snapshot_version_2 or
        version == snapshot_version_3 or
        version == snapshot_version_4 or
        version == snapshot_version_5;
}

fn loadVcpuStatesFromFile(
    allocator: std.mem.Allocator,
    file: *fs.File,
    header: *const SnapshotHeader,
    vcpu_states: []VcpuState,
) !void {
    if (header.vcpu_count == 0) return;

    log.info(
        "snapshot vcpu version check v1={} v2={} v3={} v4={} v5={} arch={d}",
        .{
            header.version == snapshot_version_1,
            header.version == snapshot_version_2,
            header.version == snapshot_version_3,
            header.version == snapshot_version_4,
            header.version == snapshot_version_5,
            header.arch,
        },
    );

    try file.seekTo(header.vcpu_state_offset);

    if (isLegacyVcpuStateVersion(header.version)) {
        if (header.arch == 1) {
            if (header.version == snapshot_version_5) {
                const legacy_states = try allocator.alloc(VcpuStateArm64V5, header.vcpu_count);
                defer allocator.free(legacy_states);
                const vcpu_read = try file.readAll(std.mem.sliceAsBytes(legacy_states));
                if (vcpu_read != header.vcpu_count * @sizeOf(VcpuStateArm64V5)) return error.CorruptedSnapshot;
                if (legacy_states.len > 0) {
                    log.info(
                        "snapshot legacy v5 arm64 pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}",
                        .{
                            legacy_states[0].pc,
                            legacy_states[0].sp_el1,
                            legacy_states[0].elr_el1,
                        },
                    );
                }
                for (legacy_states, 0..) |legacy, idx| {
                    vcpu_states[idx] = .{
                        .arm64 = .{
                            .x = legacy.x,
                            .pc = legacy.pc,
                            .sp = legacy.sp,
                            .cpsr = legacy.cpsr,
                            .fpcr = legacy.fpcr,
                            .fpsr = legacy.fpsr,
                            .sp_el0 = legacy.sp_el0,
                            .sp_el1 = legacy.sp_el1,
                            .elr_el1 = legacy.elr_el1,
                            .spsr_el1 = legacy.spsr_el1,
                            .sctlr_el1 = legacy.sctlr_el1,
                            .tcr_el1 = legacy.tcr_el1,
                            .ttbr0_el1 = legacy.ttbr0_el1,
                            .ttbr1_el1 = legacy.ttbr1_el1,
                            .mair_el1 = legacy.mair_el1,
                            .vbar_el1 = legacy.vbar_el1,
                            .mpidr_el1 = legacy.mpidr_el1,
                            .tpidr_el0 = legacy.tpidr_el0,
                            .tpidr_el1 = legacy.tpidr_el1,
                            .tpidrro_el0 = legacy.tpidrro_el0,
                            .cntkctl_el1 = legacy.cntkctl_el1,
                            .cntv_ctl_el0 = legacy.cntv_ctl_el0,
                            .cntv_cval_el0 = legacy.cntv_cval_el0,
                            .cntp_ctl_el0 = legacy.cntp_ctl_el0,
                            .cntp_cval_el0 = legacy.cntp_cval_el0,
                            .cntp_tval_el0 = legacy.cntp_tval_el0,
                            .apia_key_lo = legacy.apia_key_lo,
                            .apia_key_hi = legacy.apia_key_hi,
                            .apib_key_lo = legacy.apib_key_lo,
                            .apib_key_hi = legacy.apib_key_hi,
                            .apda_key_lo = legacy.apda_key_lo,
                            .apda_key_hi = legacy.apda_key_hi,
                            .apdb_key_lo = legacy.apdb_key_lo,
                            .apdb_key_hi = legacy.apdb_key_hi,
                            .apga_key_lo = legacy.apga_key_lo,
                            .apga_key_hi = legacy.apga_key_hi,
                            .vtimer_offset = legacy.vtimer_offset,
                            .vtimer_masked = legacy.vtimer_masked,
                            .vtimer_valid = legacy.vtimer_valid,
                        },
                    };
                }
            } else if (header.version == snapshot_version_4) {
                const legacy_states = try allocator.alloc(VcpuStateArm64V4, header.vcpu_count);
                defer allocator.free(legacy_states);
                const vcpu_read = try file.readAll(std.mem.sliceAsBytes(legacy_states));
                if (vcpu_read != header.vcpu_count * @sizeOf(VcpuStateArm64V4)) return error.CorruptedSnapshot;
                if (legacy_states.len > 0) {
                    log.info(
                        "snapshot legacy v4 arm64 pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}",
                        .{
                            legacy_states[0].pc,
                            legacy_states[0].sp_el1,
                            legacy_states[0].elr_el1,
                        },
                    );
                }
                for (legacy_states, 0..) |legacy, idx| {
                    vcpu_states[idx] = .{
                        .arm64 = .{
                            .x = legacy.x,
                            .pc = legacy.pc,
                            .sp = legacy.sp,
                            .cpsr = legacy.cpsr,
                            .fpcr = legacy.fpcr,
                            .fpsr = legacy.fpsr,
                            .sp_el0 = legacy.sp_el0,
                            .sp_el1 = legacy.sp_el1,
                            .elr_el1 = legacy.elr_el1,
                            .spsr_el1 = legacy.spsr_el1,
                            .sctlr_el1 = legacy.sctlr_el1,
                            .tcr_el1 = legacy.tcr_el1,
                            .ttbr0_el1 = legacy.ttbr0_el1,
                            .ttbr1_el1 = legacy.ttbr1_el1,
                            .mair_el1 = legacy.mair_el1,
                            .vbar_el1 = legacy.vbar_el1,
                            .mpidr_el1 = legacy.mpidr_el1,
                            .tpidr_el0 = legacy.tpidr_el0,
                            .tpidr_el1 = legacy.tpidr_el1,
                            .tpidrro_el0 = legacy.tpidrro_el0,
                            .cntkctl_el1 = legacy.cntkctl_el1,
                            .cntv_ctl_el0 = legacy.cntv_ctl_el0,
                            .cntv_cval_el0 = legacy.cntv_cval_el0,
                            .cntp_ctl_el0 = legacy.cntp_ctl_el0,
                            .cntp_cval_el0 = legacy.cntp_cval_el0,
                            .cntp_tval_el0 = legacy.cntp_tval_el0,
                            .apia_key_lo = legacy.apia_key_lo,
                            .apia_key_hi = legacy.apia_key_hi,
                            .apib_key_lo = legacy.apib_key_lo,
                            .apib_key_hi = legacy.apib_key_hi,
                            .apda_key_lo = legacy.apda_key_lo,
                            .apda_key_hi = legacy.apda_key_hi,
                            .apdb_key_lo = legacy.apdb_key_lo,
                            .apdb_key_hi = legacy.apdb_key_hi,
                            .apga_key_lo = legacy.apga_key_lo,
                            .apga_key_hi = legacy.apga_key_hi,
                        },
                    };
                }
            } else if (header.version == snapshot_version_3) {
                const legacy_states = try allocator.alloc(VcpuStateArm64V3, header.vcpu_count);
                defer allocator.free(legacy_states);
                const vcpu_read = try file.readAll(std.mem.sliceAsBytes(legacy_states));
                if (vcpu_read != header.vcpu_count * @sizeOf(VcpuStateArm64V3)) return error.CorruptedSnapshot;
                if (legacy_states.len > 0) {
                    log.info(
                        "snapshot legacy v3 arm64 pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}",
                        .{
                            legacy_states[0].pc,
                            legacy_states[0].sp_el1,
                            legacy_states[0].elr_el1,
                        },
                    );
                }
                for (legacy_states, 0..) |legacy, idx| {
                    vcpu_states[idx] = .{
                        .arm64 = .{
                            .x = legacy.x,
                            .pc = legacy.pc,
                            .sp = legacy.sp,
                            .cpsr = legacy.cpsr,
                            .fpcr = legacy.fpcr,
                            .fpsr = legacy.fpsr,
                            .sp_el0 = legacy.sp_el0,
                            .sp_el1 = legacy.sp_el1,
                            .elr_el1 = legacy.elr_el1,
                            .spsr_el1 = legacy.spsr_el1,
                            .sctlr_el1 = legacy.sctlr_el1,
                            .tcr_el1 = legacy.tcr_el1,
                            .ttbr0_el1 = legacy.ttbr0_el1,
                            .ttbr1_el1 = legacy.ttbr1_el1,
                            .mair_el1 = legacy.mair_el1,
                            .vbar_el1 = legacy.vbar_el1,
                            .mpidr_el1 = legacy.mpidr_el1,
                            .tpidr_el0 = legacy.tpidr_el0,
                            .tpidr_el1 = legacy.tpidr_el1,
                            .tpidrro_el0 = legacy.tpidrro_el0,
                            .cntkctl_el1 = legacy.cntkctl_el1,
                            .cntv_ctl_el0 = legacy.cntv_ctl_el0,
                            .cntv_cval_el0 = legacy.cntv_cval_el0,
                            .cntp_ctl_el0 = legacy.cntp_ctl_el0,
                            .cntp_cval_el0 = legacy.cntp_cval_el0,
                            .cntp_tval_el0 = legacy.cntp_tval_el0,
                        },
                    };
                }
            } else {
                const legacy_states = try allocator.alloc(VcpuStateArm64V2, header.vcpu_count);
                defer allocator.free(legacy_states);
                const vcpu_read = try file.readAll(std.mem.sliceAsBytes(legacy_states));
                if (vcpu_read != header.vcpu_count * @sizeOf(VcpuStateArm64V2)) return error.CorruptedSnapshot;
                if (legacy_states.len > 0) {
                    log.info(
                        "snapshot legacy v2 arm64 pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}",
                        .{
                            legacy_states[0].pc,
                            legacy_states[0].sp_el1,
                            legacy_states[0].elr_el1,
                        },
                    );
                }
                for (legacy_states, 0..) |legacy, idx| {
                    vcpu_states[idx] = .{
                        .arm64 = .{
                            .x = legacy.x,
                            .pc = legacy.pc,
                            .sp = legacy.sp,
                            .cpsr = legacy.cpsr,
                            .fpcr = legacy.fpcr,
                            .fpsr = legacy.fpsr,
                            .sp_el1 = legacy.sp_el1,
                            .elr_el1 = legacy.elr_el1,
                            .spsr_el1 = legacy.spsr_el1,
                            .sctlr_el1 = legacy.sctlr_el1,
                            .tcr_el1 = legacy.tcr_el1,
                            .ttbr0_el1 = legacy.ttbr0_el1,
                            .ttbr1_el1 = legacy.ttbr1_el1,
                            .mair_el1 = legacy.mair_el1,
                            .vbar_el1 = legacy.vbar_el1,
                            .mpidr_el1 = legacy.mpidr_el1,
                        },
                    };
                }
            }
        } else {
            const legacy_states = try allocator.alloc(VcpuStateX86, header.vcpu_count);
            defer allocator.free(legacy_states);
            const vcpu_read = try file.readAll(std.mem.sliceAsBytes(legacy_states));
            if (vcpu_read != header.vcpu_count * @sizeOf(VcpuStateX86)) return error.CorruptedSnapshot;
            for (legacy_states, 0..) |legacy, idx| {
                vcpu_states[idx] = .{ .x86 = legacy };
            }
        }
    } else {
        const vcpu_read = try file.readAll(std.mem.sliceAsBytes(vcpu_states));
        if (vcpu_read != header.vcpu_count * @sizeOf(VcpuState)) return error.CorruptedSnapshot;
    }
}

fn loadDeviceStateHeadersFromFile(
    file: *fs.File,
    header: *const SnapshotHeader,
    device_states: []DeviceState,
) !void {
    if (header.device_count == 0) return;
    try file.seekTo(header.device_state_offset);
    for (device_states) |*device_state| {
        const device_bytes = std.mem.asBytes(device_state);
        const device_read = try file.readAll(device_bytes);
        if (device_read != device_bytes.len) return error.CorruptedSnapshot;
        if (device_state.state_size > 0) {
            try file.seekBy(@as(i64, @intCast(device_state.state_size)));
        }
    }
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
        var file = try fs.cwd().createFile(path, .{});
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

        // Compute checksum over header fields (excluding checksum and padding)
        var header_bytes: [@sizeOf(SnapshotHeader)]u8 = undefined;
        try file.seekTo(0);
        _ = try file.readAll(&header_bytes);
        self.header.checksum = computeCrc32(header_bytes[0 .. header_bytes.len - 8]);

        // Seek back and rewrite header with checksum
        try file.seekTo(0);
        try file.writeAll(std.mem.asBytes(&self.header));

        log.info("snapshot saved: {d} vCPUs, {d} devices, {d}/{d} pages", .{
            self.header.vcpu_count,
            self.header.device_count,
            non_zero_count,
            total_pages,
        });
    }

    /// Loads a complete snapshot from a file.
    pub fn load(allocator: std.mem.Allocator, path: []const u8, memory: []u8) !Snapshot {
        var file = try fs.cwd().openFile(path, .{});
        defer file.close();

        // Read and validate header
        const header_read = try readHeader(&file);
        const header = header_read.header;
        try validateHeader(&header, &header_read.bytes, memory.len);

        var snapshot = Snapshot{
            .header = header,
            .vcpu_states = try allocator.alloc(VcpuState, header.vcpu_count),
            .device_states = try allocator.alloc(DeviceState, header.device_count),
            .allocator = allocator,
        };
        errdefer snapshot.deinit();

        // Read vCPU and device state headers.
        try loadVcpuStatesFromFile(allocator, &file, &header, snapshot.vcpu_states);
        try loadDeviceStateHeadersFromFile(&file, &header, snapshot.device_states);

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

    /// Loads snapshot header, vCPU state, and device state without touching memory.
    pub fn loadState(allocator: std.mem.Allocator, path: []const u8, expected_memory_size: usize) !Snapshot {
        var file = try fs.cwd().openFile(path, .{});
        defer file.close();

        const header_read = try readHeader(&file);
        const header = header_read.header;
        try validateHeader(&header, &header_read.bytes, expected_memory_size);
        log.info("snapshot loadState version={d} vcpu_count={d}", .{ header.version, header.vcpu_count });

        var snapshot = Snapshot{
            .header = header,
            .vcpu_states = try allocator.alloc(VcpuState, header.vcpu_count),
            .device_states = try allocator.alloc(DeviceState, header.device_count),
            .allocator = allocator,
        };
        errdefer snapshot.deinit();

        try loadVcpuStatesFromFile(allocator, &file, &header, snapshot.vcpu_states);
        try loadDeviceStateHeadersFromFile(&file, &header, snapshot.device_states);

        return snapshot;
    }
};

/// Loads device state entries (header + data) from a snapshot file.
pub fn loadDeviceStateEntries(allocator: std.mem.Allocator, path: []const u8) ![]DeviceStateEntry {
    var file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const header_read = try readHeader(&file);
    const header = header_read.header;
    try validateHeader(&header, &header_read.bytes, null);

    var entries = try allocator.alloc(DeviceStateEntry, header.device_count);
    errdefer {
        for (entries) |entry| {
            if (entry.data.len != 0) allocator.free(entry.data);
        }
        allocator.free(entries);
    }

    if (header.device_count == 0) return entries;

    try file.seekTo(header.device_state_offset);
    var idx: usize = 0;
    while (idx < entries.len) : (idx += 1) {
        var header_buf: DeviceState = undefined;
        const header_bytes = std.mem.asBytes(&header_buf);
        const read_len = try file.readAll(header_bytes);
        if (read_len != header_bytes.len) return error.CorruptedSnapshot;

        var data: []u8 = &[_]u8{};
        if (header_buf.state_size > 0) {
            data = try allocator.alloc(u8, header_buf.state_size);
            const data_read = try file.readAll(data);
            if (data_read != data.len) return error.CorruptedSnapshot;
        }
        entries[idx] = .{
            .header = header_buf,
            .data = data,
        };
    }

    return entries;
}

// =============================================================================
// STREAMING SAVE (Single-Pass)
// =============================================================================

/// Saves a complete VM snapshot using single-pass streaming.
/// This is more efficient than the two-pass approach as it only scans
/// memory once while building the page table in memory.
pub fn saveStreaming(
    allocator: std.mem.Allocator,
    memory: []const u8,
    vcpu_states: []const VcpuState,
    device_states: []const DeviceStateEntry,
    path: []const u8,
    compress: bool,
) !void {
    var file = try fs.cwd().createFile(path, .{});
    defer file.close();

    const total_pages = memory.len / page_size;
    var header = SnapshotHeader{
        .version = snapshot_version,
        .memory_size = memory.len,
        .vcpu_count = @intCast(vcpu_states.len),
        .device_count = @intCast(device_states.len),
        .total_page_count = total_pages,
    };

    // Set compression flag
    if (compress) {
        header._reserved[0] |= SNAPSHOT_FLAG_COMPRESSED;
    }
    // Always set lazy-compatible flag for version 2+
    header._reserved[0] |= SNAPSHOT_FLAG_LAZY_COMPATIBLE;

    // Reserve header space (will rewrite at end)
    try file.seekTo(@sizeOf(SnapshotHeader));
    var write_offset: u64 = @sizeOf(SnapshotHeader);

    // Write vCPU states
    header.vcpu_state_offset = @sizeOf(SnapshotHeader);
    if (vcpu_states.len > 0) {
        try file.writeAll(std.mem.sliceAsBytes(vcpu_states));
        write_offset += @intCast(vcpu_states.len * @sizeOf(VcpuState));
    }

    // Write device states (header + data for each)
    header.device_state_offset = write_offset;
    for (device_states) |ds| {
        try file.writeAll(std.mem.asBytes(&ds.header));
        write_offset += @sizeOf(DeviceState);
        if (ds.data.len > 0) {
            try file.writeAll(ds.data);
            write_offset += ds.data.len;
        }
    }

    // Stream memory pages (single pass) and build page table
    var page_entries = std.ArrayList(PageTableEntry).empty;
    defer page_entries.deinit(allocator);

    header.memory_data_offset = write_offset;
    var data_offset: u64 = 0;

    for (0..total_pages) |page_idx| {
        const start = page_idx * page_size;
        const end = start + page_size;
        const page = memory[start..end];

        if (!isPageZero(page)) {
            try page_entries.append(allocator, .{
                .page_number = page_idx,
                .data_offset = data_offset,
            });

            // TODO: Add LZ4 compression when compress=true
            // For now, write uncompressed
            try file.writeAll(page);
            data_offset += page_size;
            write_offset += page_size;
        }
    }

    // Write page table at current position
    header.memory_page_table_offset = write_offset;
    header.non_zero_page_count = page_entries.items.len;
    if (page_entries.items.len > 0) {
        try file.writeAll(std.mem.sliceAsBytes(page_entries.items));
    }

    // Compute checksum over header (excluding checksum and padding fields)
    var header_bytes: [@sizeOf(SnapshotHeader)]u8 = undefined;
    @memcpy(&header_bytes, std.mem.asBytes(&header));
    header.checksum = computeCrc32(header_bytes[0 .. header_bytes.len - 8]);

    // Rewrite header at start of file
    try file.seekTo(0);
    try file.writeAll(std.mem.asBytes(&header));

    log.info("snapshot saved (streaming): {d} vCPUs, {d} devices, {d}/{d} pages ({d}% sparse)", .{
        vcpu_states.len,
        device_states.len,
        page_entries.items.len,
        total_pages,
        if (total_pages > 0) 100 - (page_entries.items.len * 100 / total_pages) else 100,
    });
}

// =============================================================================
// LAZY RESTORE (Demand Paging)
// =============================================================================

/// Lazy loader state for demand-paged restore.
/// Pages are loaded from the snapshot file on first access.
pub const LazyLoader = struct {
    /// Snapshot file handle
    file: fs.File,
    /// Snapshot header
    header: SnapshotHeader,
    /// Page table (sorted by page number for binary search)
    page_table: []PageTableEntry,
    /// Base address of guest memory
    memory_base: usize,
    /// Allocator used for page table
    allocator: std.mem.Allocator,
    /// Number of pages loaded so far
    pages_loaded: usize = 0,

    /// Cleans up the lazy loader state.
    pub fn deinit(self: *LazyLoader) void {
        self.file.close();
        self.allocator.free(self.page_table);
    }

    /// Finds a page in the page table using binary search.
    /// Returns the page table entry if found, null otherwise.
    pub fn findPage(self: *const LazyLoader, page_number: u64) ?*const PageTableEntry {
        // Binary search for page number
        var left: usize = 0;
        var right: usize = self.page_table.len;
        while (left < right) {
            const mid = left + (right - left) / 2;
            if (self.page_table[mid].page_number == page_number) {
                return &self.page_table[mid];
            } else if (self.page_table[mid].page_number < page_number) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        return null;
    }

    /// Loads a single page from the snapshot file.
    /// Returns true if page was loaded, false if it's a zero page.
    pub fn loadPage(self: *LazyLoader, page_number: u64, dest: []u8) !bool {
        if (dest.len != page_size) return error.InvalidState;

        if (self.findPage(page_number)) |entry| {
            try self.file.seekTo(self.header.memory_data_offset + entry.data_offset);
            const n = try self.file.readAll(dest);
            if (n != page_size) return error.CorruptedSnapshot;
            self.pages_loaded += 1;
            return true;
        } else {
            // Zero page - just zero the destination
            @memset(dest, 0);
            return false;
        }
    }
};

/// Initializes lazy loading from a snapshot file.
/// Returns a LazyLoader that can be used to load pages on demand.
/// The memory region should be mapped with PROT_NONE initially.
pub fn initLazyLoader(
    allocator: std.mem.Allocator,
    path: []const u8,
    memory_base: usize,
) !LazyLoader {
    var file = try fs.cwd().openFile(path, .{});
    errdefer file.close();

    // Read and validate header
    const header_read = try readHeader(&file);
    const header = header_read.header;
    try validateHeader(&header, &header_read.bytes, null);

    // Read page table
    const page_table = try allocator.alloc(PageTableEntry, @intCast(header.non_zero_page_count));
    errdefer allocator.free(page_table);

    try file.seekTo(header.memory_page_table_offset);
    const table_bytes = std.mem.sliceAsBytes(page_table);
    const table_read = try file.readAll(table_bytes);
    if (table_read != table_bytes.len) return error.CorruptedSnapshot;

    log.info("lazy loader initialized: {d} non-zero pages", .{header.non_zero_page_count});

    return .{
        .file = file,
        .header = header,
        .page_table = page_table,
        .memory_base = memory_base,
        .allocator = allocator,
    };
}

/// Loads memory from snapshot using lazy/demand paging.
/// On platforms with mmap support, pages are loaded on first access via fault handler.
/// On other platforms, falls back to full memory load.
pub fn loadMemoryLazy(
    allocator: std.mem.Allocator,
    path: []const u8,
    memory: []u8,
) !?LazyLoader {
    // Check if lazy loading is supported on this platform
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) {
        // Fall back to full load on unsupported platforms
        try loadMemory(allocator, path, memory);
        return null;
    }

    // Initialize the lazy loader
    var loader = try initLazyLoader(allocator, path, @intFromPtr(memory.ptr));

    // For now, we do a full preload since the signal handler setup is complex.
    // A full lazy implementation would:
    // 1. mmap memory with PROT_NONE
    // 2. Install SIGSEGV/mach exception handler
    // 3. Load pages on fault
    //
    // For Phase 1, we just return the loader for potential future use
    // and load all pages upfront.

    // Preload all pages
    @memset(memory, 0);
    for (loader.page_table) |entry| {
        const start: usize = @intCast(entry.page_number * page_size);
        const end = start + page_size;
        if (end > memory.len) return error.CorruptedSnapshot;

        _ = try loader.loadPage(entry.page_number, memory[start..end]);
    }

    log.info("snapshot lazy-loaded: {d} pages (preloaded)", .{loader.pages_loaded});
    return loader;
}

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
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const snap_path = try fs.path.join(allocator, &[_][]const u8{ tmp_path, "test.snap" });
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

test "snapshot: streaming save and load state" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const path = try fs.path.join(allocator, &[_][]const u8{ tmp_path, "snapshot_streaming.bin" });
    defer allocator.free(path);

    // Build memory with a couple non-zero pages.
    var memory: [page_size * 2]u8 = [_]u8{0} ** (page_size * 2);
    memory[0] = 0xAA;
    memory[page_size + 5] = 0xBB;

    const vcpu_states = [_]VcpuState{.{ .x86 = .{ .rip = 0x1234, .rflags = 0x2 } }};

    const device_data0 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const device_data1 = [_]u8{ 9, 10, 11, 12 };

    const device_states = [_]DeviceStateEntry{
        .{
            .header = .{
                .device_type = .virtio_blk,
                .device_index = 0,
                .state_size = device_data0.len,
            },
            .data = &device_data0,
        },
        .{
            .header = .{
                .device_type = .virtio_fs,
                .device_index = 1,
                .state_size = device_data1.len,
            },
            .data = &device_data1,
        },
    };

    try saveStreaming(
        allocator,
        &memory,
        &vcpu_states,
        &device_states,
        path,
        false,
    );

    var snapshot = try Snapshot.loadState(allocator, path, memory.len);
    defer snapshot.deinit();

    try std.testing.expectEqual(@as(u16, 1), snapshot.header.vcpu_count);
    try std.testing.expectEqual(@as(u16, 2), snapshot.header.device_count);
    try std.testing.expectEqual(@as(u64, memory.len), snapshot.header.memory_size);

    try std.testing.expectEqual(@as(u64, 0x1234), snapshot.vcpu_states[0].x86.rip);
    try std.testing.expectEqual(@as(u64, 0x2), snapshot.vcpu_states[0].x86.rflags);

    try std.testing.expectEqual(DeviceType.virtio_blk, snapshot.device_states[0].device_type);
    try std.testing.expectEqual(@as(u32, device_data0.len), snapshot.device_states[0].state_size);
    try std.testing.expectEqual(DeviceType.virtio_fs, snapshot.device_states[1].device_type);
    try std.testing.expectEqual(@as(u32, device_data1.len), snapshot.device_states[1].state_size);
}

test "snapshot: validate detects invalid magic" {
    const allocator = std.testing.allocator;
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    // Create invalid snapshot
    var file = try tmp.dir.createFile("bad.snap", .{});
    try file.writeAll("XXXX" ++ ([_]u8{0} ** 76));
    file.close();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, "bad.snap");
    defer allocator.free(tmp_path);

    try std.testing.expectError(error.InvalidMagic, validateSnapshot(tmp_path));
}
