const std = @import("std");
const config = @import("../../core/config.zig");
const boot = @import("../boot.zig");

pub const guest_kernel_offset_x86: u64 = 0x100000;
pub const guest_kernel_offset_arm64: u64 = 0x80000;
pub const guest_initrd_offset: u64 = 0x4000000;
pub const guest_cmdline_offset: u64 = 0x20000;
pub const arm64_image_magic: u32 = 0x644d5241;
pub const arm64_memory_base: u64 = 0x40000000;

pub const arm64_page_table_alignment: u64 = 0x1000;
pub const arm64_page_table_bytes: u64 = 0x2000;
pub const arm64_mair_el1: u64 = 0x000004ff;
pub const arm64_tcr_el1: u64 = 0x00003510;
pub const arm64_sctlr_el1: u64 = 0x30d00800;
pub const arm64_default_pstate_el1h: u64 = 0x3c5;

pub fn guestMemoryBase(arch: std.Target.Cpu.Arch) u64 {
    return if (arch == .aarch64) arm64_memory_base else 0;
}

pub fn guestKernelOffset(arch: std.Target.Cpu.Arch) u64 {
    return if (arch == .aarch64) guest_kernel_offset_arm64 else guest_kernel_offset_x86;
}

pub fn guestKernelBase(arch: std.Target.Cpu.Arch) u64 {
    return guestMemoryBase(arch) + guestKernelOffset(arch);
}

pub fn guestInitrdBase(arch: std.Target.Cpu.Arch) u64 {
    return guestMemoryBase(arch) + guest_initrd_offset;
}

pub fn guestCmdlineBase(arch: std.Target.Cpu.Arch) u64 {
    return guestMemoryBase(arch) + guest_cmdline_offset;
}

pub fn defaultCmdlineForConfig(cfg: config.VmConfig, arch: std.Target.Cpu.Arch) []const u8 {
    if (arch == .aarch64) {
        if (cfg.disk_path != null) {
            return if (cfg.disk_readonly)
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait ro quiet loglevel=3 systemd.show_status=false systemd.log_level=warning"
            else
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait rw quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
        }
        return "console=ttyAMA0,115200 earlycon=pl011,0x09000000 quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
    }
    if (cfg.disk_path != null) {
        return if (cfg.disk_readonly)
            "console=ttyS0 root=/dev/vda rootwait ro quiet loglevel=3 systemd.show_status=false systemd.log_level=warning"
        else
            "console=ttyS0 root=/dev/vda rootwait rw quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
    }
    return "console=ttyS0 quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
}

pub fn buildMountSpecString(allocator: std.mem.Allocator, cfg: config.VmConfig) !?[]const u8 {
    if (cfg.mounts.len == 0) return null;

    var total_len: usize = "m80.mounts=".len;
    for (cfg.mounts, 0..) |mount, i| {
        if (i > 0) total_len += 1;
        total_len += mount.tag.len + 1 + mount.guest_path.len;
    }

    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    @memcpy(result[pos..][0.."m80.mounts=".len], "m80.mounts=");
    pos += "m80.mounts=".len;

    for (cfg.mounts, 0..) |mount, i| {
        if (i > 0) {
            result[pos] = ',';
            pos += 1;
        }
        @memcpy(result[pos..][0..mount.tag.len], mount.tag);
        pos += mount.tag.len;
        result[pos] = ':';
        pos += 1;
        @memcpy(result[pos..][0..mount.guest_path.len], mount.guest_path);
        pos += mount.guest_path.len;
    }

    return result;
}

pub fn buildCmdlineWithMounts(allocator: std.mem.Allocator, cfg: config.VmConfig, arch: std.Target.Cpu.Arch) ![]const u8 {
    const base_cmdline = if (cfg.kernel_cmdline) |value| value else defaultCmdlineForConfig(cfg, arch);
    const mount_spec = try buildMountSpecString(allocator, cfg);

    if (mount_spec == null) return try allocator.dupe(u8, base_cmdline);

    const result = try allocator.alloc(u8, base_cmdline.len + 1 + mount_spec.?.len);
    @memcpy(result[0..base_cmdline.len], base_cmdline);
    result[base_cmdline.len] = ' ';
    @memcpy(result[base_cmdline.len + 1 ..][0..mount_spec.?.len], mount_spec.?);
    allocator.free(mount_spec.?);
    return result;
}

pub const ArmBootLayout = struct {
    dtb_addr: u64,
    page_table_addr: u64,
};

pub fn computeArmBootLayout(
    memory_base: u64,
    memory_size_bytes: u64,
    state: boot.BootState,
    dtb_len: usize,
) !ArmBootLayout {
    const cmdline_end = state.cmdline_addr + @as(u64, state.cmdline_len) + 1;
    const dtb_addr = std.mem.alignForward(u64, cmdline_end, arm64_page_table_alignment);
    const dtb_end = dtb_addr + @as(u64, dtb_len);
    const page_table_addr = std.mem.alignForward(u64, dtb_end, arm64_page_table_alignment);
    const page_table_end = page_table_addr + arm64_page_table_bytes;
    const memory_end = memory_base + memory_size_bytes;

    if (page_table_end > memory_end) return error.InvalidGuestLayout;
    if (page_table_end > state.stack_top) return error.InvalidGuestLayout;

    return .{
        .dtb_addr = dtb_addr,
        .page_table_addr = page_table_addr,
    };
}

pub fn buildArmIdentityMap(allocator: std.mem.Allocator, page_table_addr: u64, memory_base: u64) ![]u8 {
    var table = try allocator.alloc(u8, @intCast(arm64_page_table_bytes));
    errdefer allocator.free(table);
    @memset(table, 0);

    const l0_addr = page_table_addr;
    const l1_addr = page_table_addr + arm64_page_table_alignment;
    _ = l0_addr;

    const l0_entry = l1_addr | 0x3;
    const l1_entry_flags_normal = @as(u64, 0x701);
    const l1_entry_flags_device = @as(u64, 0x705);

    std.mem.writeInt(u64, table[0..8], l0_entry, .little);
    const l1_offset: usize = @intCast(arm64_page_table_alignment);
    const l1_entries = table[l1_offset .. l1_offset + 0x1000];
    const block_size: u64 = 0x40000000;

    const low_entry = @as(u64, 0) | l1_entry_flags_device;
    {
        const ptr: *[8]u8 = @ptrCast(l1_entries[0..8].ptr);
        std.mem.writeInt(u64, ptr, low_entry, .little);
    }

    if (memory_base % block_size != 0) return error.InvalidGuestLayout;
    const base_index: usize = @intCast(memory_base / block_size);
    if (base_index != 0) {
        const entry_offset = base_index * 8;
        const base_entry = memory_base | l1_entry_flags_normal;
        const ptr: *[8]u8 = @ptrCast(l1_entries[entry_offset .. entry_offset + 8].ptr);
        std.mem.writeInt(u64, ptr, base_entry, .little);
    }

    return table;
}
