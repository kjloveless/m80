//! Device Tree Blob (DTB) Builder
//!
//! This module generates Flattened Device Tree (FDT) blobs for ARM64 VMs.
//! The device tree describes the hardware layout to the guest kernel,
//! including memory regions, CPUs, interrupt controllers, and serial ports.
//!
//! ## FDT Structure
//! An FDT blob consists of:
//! - Header: Magic, sizes, offsets to struct/strings blocks
//! - Memory Reservation Block: Reserved memory ranges (usually empty)
//! - Structure Block: Tree of nodes/properties in a binary format
//! - Strings Block: Property names referenced by offset
//!
//! ## Node Format
//! Nodes use tokens: FDT_BEGIN_NODE, properties, FDT_END_NODE
//! Properties: FDT_PROP + length + name offset + value bytes
//!
//! ## Generated Tree
//! The builder creates a minimal "virt" machine compatible tree:
//! - Root node with compatibility string
//! - CPU node
//! - Memory node with base/size
//! - Chosen node with bootargs (kernel cmdline)
//! - GIC-v3 interrupt controller
//! - Arch timer
//! - PSCI firmware interface
//! - PL011 UART serial port

const std = @import("std");

const Fdt = struct {
    const magic: u32 = 0xd00dfeed;
    const version: u32 = 17;
    const last_comp_version: u32 = 16;

    const begin_node: u32 = 1;
    const end_node: u32 = 2;
    const prop: u32 = 3;
    const nop: u32 = 4;
    const end: u32 = 9;
};

pub const DtbConfig = struct {
    memory_base: u64,
    memory_size: u64,
    cmdline: []const u8,
    gic_dist_base: u64,
    gic_redist_base: u64,
    uart_irq: u32,
    initrd_start: ?u64 = null,
    initrd_end: ?u64 = null,
    virtio_blk_base: ?u64 = null,
    virtio_blk_size: u64 = 0x1000,
    virtio_blk_irq: ?u32 = null,
    virtio_blk2_base: ?u64 = null,
    virtio_blk2_size: u64 = 0x1000,
    virtio_blk2_irq: ?u32 = null,
    virtio_blk3_base: ?u64 = null,
    virtio_blk3_size: u64 = 0x1000,
    virtio_blk3_irq: ?u32 = null,
    virtio_console_base: ?u64 = null,
    virtio_console_size: u64 = 0x1000,
    virtio_console_irq: ?u32 = null,
    virtio_rng_base: ?u64 = null,
    virtio_rng_size: u64 = 0x1000,
    virtio_rng_irq: ?u32 = null,
    virtio_vsock_base: ?u64 = null,
    virtio_vsock_size: u64 = 0x1000,
    virtio_vsock_irq: ?u32 = null,
    virtio_fs_base: ?u64 = null,
    virtio_fs_size: u64 = 0x1000,
    virtio_fs_irq: ?u32 = null,
};

pub fn buildVirtDtb(allocator: std.mem.Allocator, cfg: DtbConfig) ![]u8 {
    var struct_buf = std.ArrayList(u8).empty;
    defer struct_buf.deinit(allocator);
    var strings = std.ArrayList(u8).empty;
    defer strings.deinit(allocator);

    try beginNode(allocator, &struct_buf, "");
    try propStrings(allocator, &struct_buf, &strings, "compatible", &.{ "linux,dummy-virt", "simple-bus" });
    try propU32(allocator, &struct_buf, &strings, "#address-cells", 2);
    try propU32(allocator, &struct_buf, &strings, "#size-cells", 2);
    try propEmpty(allocator, &struct_buf, &strings, "ranges");
    try propU32(allocator, &struct_buf, &strings, "interrupt-parent", 1);

    try beginNode(allocator, &struct_buf, "cpus");
    try propU32(allocator, &struct_buf, &strings, "#address-cells", 1);
    try propU32(allocator, &struct_buf, &strings, "#size-cells", 0);
    try beginNode(allocator, &struct_buf, "cpu@0");
    try propString(allocator, &struct_buf, &strings, "device_type", "cpu");
    try propString(allocator, &struct_buf, &strings, "compatible", "arm,armv8");
    try propU32(allocator, &struct_buf, &strings, "reg", 0);
    try endNode(allocator, &struct_buf);
    try endNode(allocator, &struct_buf);

    var mem_node_name_buf: [64]u8 = undefined;
    const mem_node_name = try std.fmt.bufPrint(&mem_node_name_buf, "memory@{x}", .{cfg.memory_base});
    try beginNode(allocator, &struct_buf, mem_node_name);
    try propString(allocator, &struct_buf, &strings, "device_type", "memory");
    try propReg64(allocator, &struct_buf, &strings, "reg", cfg.memory_base, cfg.memory_size);
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "chosen");
    try propString(allocator, &struct_buf, &strings, "bootargs", cfg.cmdline);
    try propString(allocator, &struct_buf, &strings, "stdout-path", "serial0");
    if (cfg.initrd_start != null and cfg.initrd_end != null) {
        try propU64(allocator, &struct_buf, &strings, "linux,initrd-start", cfg.initrd_start.?);
        try propU64(allocator, &struct_buf, &strings, "linux,initrd-end", cfg.initrd_end.?);
    }
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "aliases");
    try propString(allocator, &struct_buf, &strings, "serial0", "/pl011@9000000");
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "intc");
    try propString(allocator, &struct_buf, &strings, "compatible", "arm,gic-v3");
    try propU32(allocator, &struct_buf, &strings, "#interrupt-cells", 3);
    try propEmpty(allocator, &struct_buf, &strings, "interrupt-controller");
    try propU32(allocator, &struct_buf, &strings, "phandle", 1);
    try propReg64x2(
        allocator,
        &struct_buf,
        &strings,
        "reg",
        cfg.gic_dist_base,
        0x00010000,
        cfg.gic_redist_base,
        0x00200000,
    );
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "timer");
    try propString(allocator, &struct_buf, &strings, "compatible", "arm,armv8-timer");
    try propU32x12(
        allocator,
        &struct_buf,
        &strings,
        "interrupts",
        1,
        13,
        4,
        1,
        14,
        4,
        1,
        11,
        4,
        1,
        10,
        4,
    );
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "psci");
    try propStrings(allocator, &struct_buf, &strings, "compatible", &.{ "arm,psci-1.0", "arm,psci-0.2" });
    try propString(allocator, &struct_buf, &strings, "method", "smc");
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "clk24m");
    try propString(allocator, &struct_buf, &strings, "compatible", "fixed-clock");
    try propU32(allocator, &struct_buf, &strings, "#clock-cells", 0);
    try propU32(allocator, &struct_buf, &strings, "clock-frequency", 24_000_000);
    try propU32(allocator, &struct_buf, &strings, "phandle", 2);
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "apb-pclk");
    try propString(allocator, &struct_buf, &strings, "compatible", "fixed-clock");
    try propU32(allocator, &struct_buf, &strings, "#clock-cells", 0);
    try propU32(allocator, &struct_buf, &strings, "clock-frequency", 24_000_000);
    try propU32(allocator, &struct_buf, &strings, "phandle", 3);
    try endNode(allocator, &struct_buf);

    try beginNode(allocator, &struct_buf, "pl011@9000000");
    try propStrings(allocator, &struct_buf, &strings, "compatible", &.{ "arm,pl011", "arm,primecell" });
    try propReg64(allocator, &struct_buf, &strings, "reg", 0x09000000, 0x1000);
    try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.uart_irq, 4);
    try propU32x2(allocator, &struct_buf, &strings, "clocks", 2, 3);
    try propStrings(allocator, &struct_buf, &strings, "clock-names", &.{ "uartclk", "apb_pclk" });
    try propU32(allocator, &struct_buf, &strings, "clock-frequency", 24_000_000);
    try propString(allocator, &struct_buf, &strings, "status", "okay");
    try endNode(allocator, &struct_buf);

    if (cfg.virtio_blk_base != null and cfg.virtio_blk_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_blk@{x}", .{cfg.virtio_blk_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_blk_base.?, cfg.virtio_blk_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_blk_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }

    if (cfg.virtio_blk2_base != null and cfg.virtio_blk2_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_blk@{x}", .{cfg.virtio_blk2_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_blk2_base.?, cfg.virtio_blk2_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_blk2_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }

    if (cfg.virtio_blk3_base != null and cfg.virtio_blk3_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_blk@{x}", .{cfg.virtio_blk3_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_blk3_base.?, cfg.virtio_blk3_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_blk3_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }

    if (cfg.virtio_console_base != null and cfg.virtio_console_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_console@{x}", .{cfg.virtio_console_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_console_base.?, cfg.virtio_console_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_console_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }
    if (cfg.virtio_rng_base != null and cfg.virtio_rng_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_rng@{x}", .{cfg.virtio_rng_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_rng_base.?, cfg.virtio_rng_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_rng_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }
    if (cfg.virtio_vsock_base != null and cfg.virtio_vsock_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_vsock@{x}", .{cfg.virtio_vsock_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_vsock_base.?, cfg.virtio_vsock_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_vsock_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }
    if (cfg.virtio_fs_base != null and cfg.virtio_fs_irq != null) {
        var node_name_buf: [64]u8 = undefined;
        const node_name = try std.fmt.bufPrint(&node_name_buf, "virtio_fs@{x}", .{cfg.virtio_fs_base.?});
        try beginNode(allocator, &struct_buf, node_name);
        try propString(allocator, &struct_buf, &strings, "compatible", "virtio,mmio");
        try propReg64(allocator, &struct_buf, &strings, "reg", cfg.virtio_fs_base.?, cfg.virtio_fs_size);
        try propU32x3(allocator, &struct_buf, &strings, "interrupts", 0, cfg.virtio_fs_irq.?, 4);
        try endNode(allocator, &struct_buf);
    }
    try endNode(allocator, &struct_buf);
    try endStruct(allocator, &struct_buf);

    const mem_rsvmap_len = 16;
    const header_len = 40;
    const struct_len = struct_buf.items.len;
    const strings_len = strings.items.len;
    const off_mem_rsvmap = header_len;
    const off_dt_struct = off_mem_rsvmap + mem_rsvmap_len;
    const off_dt_strings = off_dt_struct + struct_len;
    const total_size = off_dt_strings + strings_len;

    var blob = try allocator.alloc(u8, total_size);
    errdefer allocator.free(blob);
    @memset(blob, 0);

    writeBeU32(blob[0..4], Fdt.magic);
    writeBeU32(blob[4..8], @intCast(total_size));
    writeBeU32(blob[8..12], @intCast(off_dt_struct));
    writeBeU32(blob[12..16], @intCast(off_dt_strings));
    writeBeU32(blob[16..20], @intCast(off_mem_rsvmap));
    writeBeU32(blob[20..24], Fdt.version);
    writeBeU32(blob[24..28], Fdt.last_comp_version);
    writeBeU32(blob[28..32], 0);
    writeBeU32(blob[32..36], @intCast(strings_len));
    writeBeU32(blob[36..40], @intCast(struct_len));

    writeBeU64(blob[off_mem_rsvmap .. off_mem_rsvmap + 8], 0);
    writeBeU64(blob[off_mem_rsvmap + 8 .. off_mem_rsvmap + 16], 0);

    std.mem.copyForwards(u8, blob[off_dt_struct .. off_dt_struct + struct_len], struct_buf.items);
    std.mem.copyForwards(u8, blob[off_dt_strings .. off_dt_strings + strings_len], strings.items);
    return blob;
}

fn beginNode(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), name: []const u8) !void {
    try writeToken(allocator, buf, Fdt.begin_node);
    try buf.appendSlice(allocator, name);
    try buf.append(allocator, 0);
    try padTo4(allocator, buf);
}

fn endNode(allocator: std.mem.Allocator, buf: *std.ArrayList(u8)) !void {
    try writeToken(allocator, buf, Fdt.end_node);
}

fn endStruct(allocator: std.mem.Allocator, buf: *std.ArrayList(u8)) !void {
    try writeToken(allocator, buf, Fdt.end);
}

fn propEmpty(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), strings: *std.ArrayList(u8), name: []const u8) !void {
    try propRaw(allocator, buf, strings, name, &[_]u8{});
}

fn propString(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    value: []const u8,
) !void {
    var tmp = std.ArrayList(u8).empty;
    defer tmp.deinit(allocator);
    try tmp.appendSlice(allocator, value);
    try tmp.append(allocator, 0);
    try propRaw(allocator, buf, strings, name, tmp.items);
}

fn propStrings(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    values: []const []const u8,
) !void {
    var tmp = std.ArrayList(u8).empty;
    defer tmp.deinit(allocator);
    for (values) |value| {
        try tmp.appendSlice(allocator, value);
        try tmp.append(allocator, 0);
    }
    try propRaw(allocator, buf, strings, name, tmp.items);
}

fn propU32(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    value: u32,
) !void {
    var tmp: [4]u8 = undefined;
    writeBeU32(&tmp, value);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propU64(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    value: u64,
) !void {
    var tmp: [8]u8 = undefined;
    writeBeU64(&tmp, value);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propU32x3(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    v0: u32,
    v1: u32,
    v2: u32,
) !void {
    var tmp: [12]u8 = undefined;
    writeBeU32(tmp[0..4], v0);
    writeBeU32(tmp[4..8], v1);
    writeBeU32(tmp[8..12], v2);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propU32x2(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    v0: u32,
    v1: u32,
) !void {
    var tmp: [8]u8 = undefined;
    writeBeU32(tmp[0..4], v0);
    writeBeU32(tmp[4..8], v1);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propU32x12(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    v0: u32,
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
    v5: u32,
    v6: u32,
    v7: u32,
    v8: u32,
    v9: u32,
    v10: u32,
    v11: u32,
) !void {
    var tmp: [48]u8 = undefined;
    writeBeU32(tmp[0..4], v0);
    writeBeU32(tmp[4..8], v1);
    writeBeU32(tmp[8..12], v2);
    writeBeU32(tmp[12..16], v3);
    writeBeU32(tmp[16..20], v4);
    writeBeU32(tmp[20..24], v5);
    writeBeU32(tmp[24..28], v6);
    writeBeU32(tmp[28..32], v7);
    writeBeU32(tmp[32..36], v8);
    writeBeU32(tmp[36..40], v9);
    writeBeU32(tmp[40..44], v10);
    writeBeU32(tmp[44..48], v11);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propReg64(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    base: u64,
    size: u64,
) !void {
    var tmp: [16]u8 = undefined;
    writeBeU64(tmp[0..8], base);
    writeBeU64(tmp[8..16], size);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propReg64x2(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    base0: u64,
    size0: u64,
    base1: u64,
    size1: u64,
) !void {
    var tmp: [32]u8 = undefined;
    writeBeU64(tmp[0..8], base0);
    writeBeU64(tmp[8..16], size0);
    writeBeU64(tmp[16..24], base1);
    writeBeU64(tmp[24..32], size1);
    try propRaw(allocator, buf, strings, name, &tmp);
}

fn propRaw(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    strings: *std.ArrayList(u8),
    name: []const u8,
    value: []const u8,
) !void {
    try writeToken(allocator, buf, Fdt.prop);
    try writeU32(allocator, buf, @intCast(value.len));
    const name_off = try addString(allocator, strings, name);
    try writeU32(allocator, buf, name_off);
    try buf.appendSlice(allocator, value);
    try padTo4(allocator, buf);
}

fn addString(allocator: std.mem.Allocator, strings: *std.ArrayList(u8), value: []const u8) !u32 {
    const off: u32 = @intCast(strings.items.len);
    try strings.appendSlice(allocator, value);
    try strings.append(allocator, 0);
    return off;
}

fn writeToken(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), token: u32) !void {
    var tmp: [4]u8 = undefined;
    writeBeU32(&tmp, token);
    try buf.appendSlice(allocator, &tmp);
}

fn writeU32(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: u32) !void {
    var tmp: [4]u8 = undefined;
    writeBeU32(&tmp, value);
    try buf.appendSlice(allocator, &tmp);
}

fn padTo4(allocator: std.mem.Allocator, buf: *std.ArrayList(u8)) !void {
    const pad_len = (4 - (buf.items.len % 4)) % 4;
    if (pad_len == 0) return;
    try buf.appendNTimes(allocator, 0, pad_len);
}

fn writeBeU32(dest: []u8, value: u32) void {
    dest[0] = @intCast((value >> 24) & 0xff);
    dest[1] = @intCast((value >> 16) & 0xff);
    dest[2] = @intCast((value >> 8) & 0xff);
    dest[3] = @intCast(value & 0xff);
}

fn writeBeU64(dest: []u8, value: u64) void {
    dest[0] = @intCast((value >> 56) & 0xff);
    dest[1] = @intCast((value >> 48) & 0xff);
    dest[2] = @intCast((value >> 40) & 0xff);
    dest[3] = @intCast((value >> 32) & 0xff);
    dest[4] = @intCast((value >> 24) & 0xff);
    dest[5] = @intCast((value >> 16) & 0xff);
    dest[6] = @intCast((value >> 8) & 0xff);
    dest[7] = @intCast(value & 0xff);
}

fn readBeU32(src: []const u8) u32 {
    return (@as(u32, src[0]) << 24) |
        (@as(u32, src[1]) << 16) |
        (@as(u32, src[2]) << 8) |
        (@as(u32, src[3]));
}

// =============================================================================
// TESTS
// =============================================================================

test "dtb: buildVirtDtb produces a valid header" {
    const allocator = std.testing.allocator;
    const blob = try buildVirtDtb(allocator, .{
        .memory_base = 0,
        .memory_size = 512 * 1024 * 1024,
        .cmdline = "console=ttyAMA0",
        .gic_dist_base = 0x08000000,
        .gic_redist_base = 0x080a0000,
        .uart_irq = 33,
    });
    defer allocator.free(blob);

    try std.testing.expect(blob.len > 64);
    try std.testing.expectEqual(Fdt.magic, readBeU32(blob[0..4]));
    const total_size = readBeU32(blob[4..8]);
    try std.testing.expectEqual(@as(u32, @intCast(blob.len)), total_size);
    const off_struct = readBeU32(blob[8..12]);
    const off_strings = readBeU32(blob[12..16]);
    try std.testing.expect(off_struct < blob.len);
    try std.testing.expect(off_strings < blob.len);
    try std.testing.expect(off_strings > off_struct);
}

test "dtb: buildVirtDtb includes cmdline" {
    const allocator = std.testing.allocator;
    const blob = try buildVirtDtb(allocator, .{
        .memory_base = 0,
        .memory_size = 128 * 1024 * 1024,
        .cmdline = "root=/dev/vda",
        .gic_dist_base = 0x08000000,
        .gic_redist_base = 0x080a0000,
        .uart_irq = 33,
    });
    defer allocator.free(blob);

    try std.testing.expect(std.mem.indexOf(u8, blob, "root=/dev/vda") != null);
}

test "dtb: buildVirtDtb includes arch timer" {
    const allocator = std.testing.allocator;
    const blob = try buildVirtDtb(allocator, .{
        .memory_base = 0x40000000,
        .memory_size = 256 * 1024 * 1024,
        .cmdline = "console=ttyAMA0",
        .gic_dist_base = 0x08000000,
        .gic_redist_base = 0x080a0000,
        .uart_irq = 33,
    });
    defer allocator.free(blob);

    try std.testing.expect(std.mem.indexOf(u8, blob, "arm,armv8-timer") != null);
}

test "dtb: buildVirtDtb includes psci smc interface" {
    const allocator = std.testing.allocator;
    const blob = try buildVirtDtb(allocator, .{
        .memory_base = 0x40000000,
        .memory_size = 256 * 1024 * 1024,
        .cmdline = "console=ttyAMA0",
        .gic_dist_base = 0x08000000,
        .gic_redist_base = 0x080a0000,
        .uart_irq = 33,
    });
    defer allocator.free(blob);

    try std.testing.expect(std.mem.indexOf(u8, blob, "arm,psci-1.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, blob, "arm,psci-0.2") != null);
    try std.testing.expect(std.mem.indexOf(u8, blob, "smc") != null);
}

test "dtb: buildVirtDtb includes initrd range when provided" {
    const allocator = std.testing.allocator;
    const blob = try buildVirtDtb(allocator, .{
        .memory_base = 0x40000000,
        .memory_size = 256 * 1024 * 1024,
        .cmdline = "console=ttyAMA0",
        .gic_dist_base = 0x08000000,
        .gic_redist_base = 0x080a0000,
        .initrd_start = 0x44000000,
        .initrd_end = 0x44800000,
        .uart_irq = 33,
    });
    defer allocator.free(blob);

    try std.testing.expect(std.mem.indexOf(u8, blob, "linux,initrd-start") != null);
    try std.testing.expect(std.mem.indexOf(u8, blob, "linux,initrd-end") != null);
}
